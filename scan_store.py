"""
Persistent scan state.

Layout on disk (DATA_DIR is a PersistentVolume in Kubernetes):

    DATA_DIR/<scan_id>/meta.json     status, target, counts, timestamps
    DATA_DIR/<scan_id>/report.html
    DATA_DIR/<scan_id>/report.json

Reports and final scan status therefore survive pod restarts. Live state of a
*running* scan (log buffer, worker thread) is process-local - see README
"Scaling limitations" for what is required before running >1 replica.
"""
import json
import os
import re
import shutil
import threading
import time
from collections import deque
from datetime import datetime, timezone

SCAN_ID_RE = re.compile(r"^[a-f0-9]{16}$")
MAX_BUFFERED_EVENTS = 2000


def valid_scan_id(scan_id):
    return isinstance(scan_id, str) and bool(SCAN_ID_RE.match(scan_id))


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ScanStore:
    def __init__(self, data_dir):
        self.data_dir = os.path.abspath(data_dir)
        os.makedirs(self.data_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._live = {}  # scan_id -> {"meta": dict, "events": deque}

    # -- paths ------------------------------------------------------------
    def scan_dir(self, scan_id):
        if not valid_scan_id(scan_id):
            raise ValueError("invalid scan id")
        return os.path.join(self.data_dir, scan_id)

    def report_path(self, scan_id, fmt):
        if fmt not in ("html", "json") or not valid_scan_id(scan_id):
            return None
        path = os.path.realpath(os.path.join(self.scan_dir(scan_id), f"report.{fmt}"))
        # Defence in depth: never serve anything outside DATA_DIR
        if not path.startswith(os.path.realpath(self.data_dir) + os.sep):
            return None
        return path if os.path.isfile(path) else None

    # -- writes -----------------------------------------------------------
    def _write_meta(self, meta):
        d = self.scan_dir(meta["scan_id"])
        os.makedirs(d, exist_ok=True)
        tmp = os.path.join(d, "meta.json.tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        os.replace(tmp, os.path.join(d, "meta.json"))  # atomic on POSIX

    def create(self, scan_id, target, options):
        meta = {"scan_id": scan_id, "target": target, "options": options,
                "status": "running", "created_at": _now(), "finished_at": None,
                "findings": [], "counts": {}, "error": None}
        with self._lock:
            self._live[scan_id] = {"meta": meta,
                                   "events": deque(maxlen=MAX_BUFFERED_EVENTS)}
        self._write_meta(meta)
        return meta

    def add_event(self, scan_id, event, payload):
        with self._lock:
            live = self._live.get(scan_id)
            if live:
                live["events"].append((event, payload))
                if event == "finding":
                    live["meta"]["findings"].append(payload["finding"])

    def complete(self, scan_id, findings, counts):
        with self._lock:
            live = self._live.get(scan_id)
            meta = live["meta"] if live else self._load_meta(scan_id)
            meta.update(status="completed", findings=findings, counts=counts,
                        finished_at=_now())
        self._write_meta(meta)
        return meta

    def fail(self, scan_id, error):
        with self._lock:
            live = self._live.get(scan_id)
            meta = live["meta"] if live else self._load_meta(scan_id)
            meta.update(status="failed", error=error, finished_at=_now())
        self._write_meta(meta)

    # -- reads ------------------------------------------------------------
    def _load_meta(self, scan_id):
        try:
            with open(os.path.join(self.scan_dir(scan_id), "meta.json"),
                      encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    def get(self, scan_id):
        if not valid_scan_id(scan_id):
            return None
        with self._lock:
            live = self._live.get(scan_id)
            if live:
                return json.loads(json.dumps(live["meta"]))  # deep copy
        return self._load_meta(scan_id)

    def replay_events(self, scan_id):
        with self._lock:
            live = self._live.get(scan_id)
            return list(live["events"]) if live else []

    def forget_live(self, scan_id):
        """Drop the in-memory log buffer once a scan is finished and replayed."""
        with self._lock:
            self._live.pop(scan_id, None)

    def active_count(self):
        with self._lock:
            return sum(1 for v in self._live.values()
                       if v["meta"]["status"] == "running")

    def writable(self):
        probe = os.path.join(self.data_dir, ".probe")
        try:
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            return True
        except OSError:
            return False

    # -- housekeeping (storage cost optimisation) ---------------------------
    def purge_older_than(self, days):
        if days <= 0:
            return 0
        cutoff = time.time() - days * 86400
        removed = 0
        for name in os.listdir(self.data_dir):
            path = os.path.join(self.data_dir, name)
            if valid_scan_id(name) and os.path.isdir(path) and os.path.getmtime(path) < cutoff:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        return removed
