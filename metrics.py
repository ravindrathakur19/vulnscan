"""Prometheus metrics. Served on a *separate* port (METRICS_PORT) so that /metrics
is never reachable through the public ingress."""
from prometheus_client import Counter, Gauge, Histogram, start_http_server

SCANS_STARTED = Counter("vulnscan_scans_started_total", "Scans started")
SCANS_COMPLETED = Counter("vulnscan_scans_completed_total", "Scans completed successfully")
SCANS_FAILED = Counter("vulnscan_scans_failed_total", "Scans that ended with an error")
SCANS_REJECTED = Counter("vulnscan_scans_rejected_total",
                         "Scan requests rejected", ["reason"])
SCAN_DURATION = Histogram("vulnscan_scan_duration_seconds", "Scan duration in seconds",
                          buckets=(5, 15, 30, 60, 120, 300, 600, 1200))
FINDINGS = Counter("vulnscan_findings_total", "Vulnerability findings reported",
                   ["severity", "type"])
ACTIVE_SCANS = Gauge("vulnscan_active_scans", "Scans currently running")
HTTP_REQUESTS = Counter("vulnscan_http_requests_total", "HTTP requests handled",
                        ["endpoint", "method", "status"])

_started = False


def start_metrics_server(port):
    """Idempotent - safe to call from multiple app factories."""
    global _started
    if _started or not port:
        return False
    start_http_server(int(port))
    _started = True
    return True
