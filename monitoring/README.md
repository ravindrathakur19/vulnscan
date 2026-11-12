# monitoring/

Minimal, resource-efficient Prometheus + Node Exporter + Grafana + Alertmanager
stack for the EC2/K3s host. Everything here binds to localhost / the cluster's
internal network - nothing is exposed on the public security group.

## Quick start (Docker Compose, run on the EC2 host)

```yaml
# monitoring/docker-compose.yml (not auto-created - add it if you want Compose
# instead of separate `docker run` commands or K8s manifests)
```

Or run as plain containers:

```bash
docker run -d --name node-exporter --net host prom/node-exporter
docker run -d --name prometheus -p 127.0.0.1:9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v $(pwd)/alerts.yml:/etc/prometheus/alerts.yml \
  prom/prometheus
docker run -d --name alertmanager -p 127.0.0.1:9093:9093 \
  -v $(pwd)/alertmanager.yml:/etc/alertmanager/alertmanager.yml \
  prom/alertmanager
docker run -d --name grafana -p 127.0.0.1:3000:3000 grafana/grafana
```

View dashboards via an SSH tunnel: `ssh -L 3000:localhost:3000 ubuntu@<ec2-ip>`,
then open http://localhost:3000 on your own machine.

## Grafana setup (manual, one-time)

1. Log in (default admin/admin, change it immediately).
2. Add a data source -> Prometheus -> URL `http://prometheus:9090` (or
   `http://localhost:9090` if running outside Docker's default network).
3. Import dashboard ID **1860** ("Node Exporter Full") for infrastructure
   metrics, and build a small custom panel for `vulnscan_scans_started_total`,
   `vulnscan_scan_duration_seconds`, and `vulnscan_findings_total` by
   `severity` for the application-level view.

## Application metrics

`app.py` exposes Prometheus metrics (via `metrics.py`) on a **separate** port
set by the `METRICS_PORT` env var (e.g. `9200`) - not on the same port as the
public web app - specifically so `/metrics` is never reachable through the
public ingress/security group. Point Prometheus at
`<pod-or-host>:9200` as in `prometheus.yml`.
