"""
VulnScan Pro - Web App
Flask + Socket.IO for live scan output, with SSRF-safe target validation,
disk-backed scan/report storage (survives pod restarts) and Prometheus metrics.
"""
import eventlet
eventlet.monkey_patch()

import logging
import os
import sys
import threading
import uuid
from datetime import datetime

from flask import Flask, abort, jsonify, render_template, request, send_file
from flask_socketio import SocketIO

sys.path.insert(0, os.path.dirname(__file__))

from scan_store import ScanStore, valid_scan_id          # noqa: E402
from security import (TargetNotAllowed, allow_private_targets,            # noqa: E402
                      is_allowed_redirect_target, validate_target_url)

try:
    from scanner_core import VulnScanner, generate_html_report, generate_json_report
except ImportError:
    print("[!] scanner_core.py not found next to app.py")
    sys.exit(1)

try:
    from metrics import (ACTIVE_SCANS, FINDINGS, SCAN_DURATION, SCANS_COMPLETED,
                         SCANS_FAILED, SCANS_REJECTED, SCANS_STARTED,
                         start_metrics_server)
    METRICS_AVAILABLE = True
except ImportError:  # prometheus_client not installed -> app still runs
    METRICS_AVAILABLE = False

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("vulnscan")


def create_app():
    app = Flask(__name__)

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        if os.environ.get("FLASK_ENV") == "production":
            raise RuntimeError("SECRET_KEY environment variable is required in production")
        secret_key = "dev-only-insecure-secret-key"
        log.warning("SECRET_KEY not set - using an insecure development default. "
                   "Set SECRET_KEY (e.g. via a Kubernetes Secret) for any real deployment.")
    app.config["SECRET_KEY"] = secret_key

    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # scan requests are tiny JSON bodies
    app.config["DATA_DIR"] = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "reports"))
    app.config["MAX_CONCURRENT_SCANS"] = int(os.environ.get("MAX_CONCURRENT_SCANS", 5))
    app.config["SCAN_THREADS"] = int(os.environ.get("SCAN_THREADS", 10))
    app.config["SCAN_TIMEOUT"] = int(os.environ.get("SCAN_TIMEOUT", 8))

    store = ScanStore(app.config["DATA_DIR"])
    app.extensions = getattr(app, "extensions", {})
    app.extensions["scan_store"] = store

    socketio = SocketIO(app, cors_allowed_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "*"),
                        async_mode="eventlet", logger=False, engineio_logger=False)

    metrics_port = os.environ.get("METRICS_PORT")
    if METRICS_AVAILABLE and metrics_port:
        start_metrics_server(metrics_port)
        log.info("Prometheus metrics exposed on port %s (/metrics)", metrics_port)

    def emit_log(scan_id, level, msg):
        payload = {"scan_id": scan_id, "level": level, "msg": msg,
                  "ts": datetime.now().strftime("%H:%M:%S")}
        store.add_event(scan_id, "log", payload)
        socketio.emit("log", payload)

    def emit_finding(scan_id, finding):
        payload = {"scan_id": scan_id, "finding": finding}
        store.add_event(scan_id, "finding", payload)
        socketio.emit("finding", payload)
        if METRICS_AVAILABLE:
            FINDINGS.labels(severity=finding.get("severity", "UNKNOWN"),
                            type=finding.get("type", "unknown")).inc()

    def run_scan(scan_id, target, full_scan, threads, timeout):
        start = datetime.now()
        try:
            emit_log(scan_id, "INFO", f"Starting scan on {target}...")
            allow_private = allow_private_targets()
            scanner = VulnScanner(
                target=target, threads=threads, timeout=timeout, verbose=False,
                crawl=full_scan,
                socket_callback=lambda level, msg: emit_log(scan_id, level, msg),
                finding_callback=lambda f: emit_finding(scan_id, f),
                ssrf_guard=lambda u: is_allowed_redirect_target(u, allow_private=allow_private),
            )
            findings = scanner.run(full_scan=full_scan)

            scan_dir = store.scan_dir(scan_id)
            os.makedirs(scan_dir, exist_ok=True)
            html_path = generate_html_report(findings, target, scan_dir)
            json_path = generate_json_report(findings, target, scan_dir)
            os.replace(html_path, os.path.join(scan_dir, "report.html"))
            os.replace(json_path, os.path.join(scan_dir, "report.json"))

            counts = {"total": len(findings)}
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                counts[sev.lower()] = sum(1 for f in findings if f["severity"] == sev)
            store.complete(scan_id, findings, counts)

            socketio.emit("scan_complete", {
                "scan_id": scan_id, **counts,
                "html_report": f"/report/{scan_id}/html",
                "json_report": f"/report/{scan_id}/json",
            })
            if METRICS_AVAILABLE:
                SCANS_COMPLETED.inc()
                SCAN_DURATION.observe((datetime.now() - start).total_seconds())
        except Exception as exc:  # scanner/network failures must not crash the worker
            log.exception("Scan %s failed", scan_id)
            store.fail(scan_id, str(exc))
            socketio.emit("scan_error", {"scan_id": scan_id, "error": "Scan failed - see server logs"})
            if METRICS_AVAILABLE:
                SCANS_FAILED.inc()
        finally:
            if METRICS_AVAILABLE:
                ACTIVE_SCANS.dec()
            store.forget_live(scan_id)

    # ── Routes ────────────────────────────────────────────
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/healthz")
    def healthz():
        """Liveness/readiness probe target. Checks the report volume is writable."""
        ok = store.writable()
        return jsonify({"status": "ok" if ok else "degraded",
                        "report_storage_writable": ok}), (200 if ok else 503)

    @app.route("/api/scan", methods=["POST"])
    def start_scan():
        data = request.get_json(silent=True) or {}
        raw_target = data.get("url", "")

        try:
            target = validate_target_url(raw_target)
        except TargetNotAllowed as exc:
            if METRICS_AVAILABLE:
                SCANS_REJECTED.labels(reason="invalid_target").inc()
            return jsonify({"error": str(exc)}), 400

        if store.active_count() >= app.config["MAX_CONCURRENT_SCANS"]:
            if METRICS_AVAILABLE:
                SCANS_REJECTED.labels(reason="capacity").inc()
            return jsonify({"error": "Server is at capacity, please try again shortly"}), 429

        full_scan = bool(data.get("full_scan", True))
        threads = max(1, min(int(data.get("threads", app.config["SCAN_THREADS"]) or 10), 20))
        timeout = max(1, min(int(data.get("timeout", app.config["SCAN_TIMEOUT"]) or 8), 30))

        scan_id = uuid.uuid4().hex[:16]
        store.create(scan_id, target, {"full_scan": full_scan, "threads": threads, "timeout": timeout})
        if METRICS_AVAILABLE:
            SCANS_STARTED.inc()
            ACTIVE_SCANS.inc()

        t = threading.Thread(target=run_scan, args=(scan_id, target, full_scan, threads, timeout),
                             daemon=True)
        t.start()
        return jsonify({"scan_id": scan_id, "status": "started"})

    @app.route("/report/<scan_id>/<fmt>")
    def download_report(scan_id, fmt):
        path = store.report_path(scan_id, fmt)
        if not path:
            abort(404)
        mimetype = "text/html" if fmt == "html" else "application/json"
        return send_file(path, mimetype=mimetype, as_attachment=True,
                         download_name=f"vuln_report_{scan_id}.{fmt}")

    @app.route("/api/status/<scan_id>")
    def scan_status(scan_id):
        if not valid_scan_id(scan_id):
            abort(404)
        meta = store.get(scan_id)
        if meta is None:
            abort(404)
        return jsonify({
            "scan_id": scan_id,
            "status": meta["status"],
            "done": meta["status"] in ("completed", "failed"),
            "findings_count": len(meta.get("findings", [])),
            "findings": meta.get("findings", []),
            "counts": meta.get("counts", {}),
            "error": meta.get("error"),
        })

    return app, socketio


app, socketio = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    socketio.run(app, host="0.0.0.0", port=port, debug=debug)
