# VulnScan Pro

**DevSecOps-based cloud-native web vulnerability scanner.**
Flask + Socket.IO scanning engine, containerized with Docker, deployed on
Kubernetes (K3s) on AWS EC2 via Terraform, built and shipped through a Jenkins
CI/CD pipeline with a Trivy security gate, and observed with
Prometheus/Grafana/Alertmanager.

Built for **INT378 – Advancements in Cloud and DevOps** (LPU, 2026–27), as a
continuation of a previous-semester project (not a rewrite).

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit
> written permission to test. The app blocks scans of private/loopback/cloud-
> metadata addresses by default (see "Security" below) — this is a safety
> rail, not a substitute for authorization.

---

## 1. What changed this semester, and what's inherited

| Area | Inherited (previous semester) | Added/changed this semester |
|---|---|---|
| Scanning engine | `scanner_core.py` — SQLi, blind SQLi, XSS, LFI, CSRF, open redirect, broken auth, headers, cookies, WAF fingerprint, subdomain enum, HTTPS, crawler | Redirects are now re-validated per hop (SSRF guard) instead of followed blindly |
| Web app | `app.py`, `templates/index.html`, live Socket.IO terminal | Rewritten around: SSRF-safe input validation, disk-backed scan/report storage, concurrency cap, `/healthz`, Prometheus metrics |
| Docker | Single-stage `python:3.9-slim` + nmap | Multi-stage build, Python 3.12, non-root user, healthcheck, nmap **removed** (unused — see §5), smaller image |
| CI/CD | Jenkins: clone → build → push → `docker run` | Full pipeline: pytest → Docker build → **Trivy scan gate** → push (SHA-tagged) → `kubectl` deploy → health check |
| Tests | None | 68 pytest tests across scanner logic, report generation, storage, and the Flask API (all offline/mocked, see §4) |
| IaC | None | Terraform: EC2 + Security Group, ap-south-1, outputs, `.tfvars.example` |
| Kubernetes | 2 deployments (scanner + report) pointing at the same image, no RBAC/Secrets/limits | 1 deployment (see §6 for why), RBAC, Secret-based `SECRET_KEY`, resource limits, liveness/readiness probes, PVC for reports |
| Monitoring | None | Prometheus + Node Exporter + Grafana + Alertmanager configs, app-level metrics via `prometheus_client` |
| Security | SSRF possible, hardcoded dev `SECRET_KEY` fallback silently used in prod, path traversal possible via unvalidated scan IDs | SSRF guard with private/CGNAT/metadata blocking, required `SECRET_KEY` in production, scan-ID format validation, path-traversal-safe report serving |

This repo **does not** implement AWS CloudFormation, AWS Lambda/API Gateway, or
multi-cloud/Azure deployment, SAFe/LeSS, BDD, or A/B testing — the synopsis
already scopes these out as organizational/team-scale topics not meaningfully
demonstrable in a single-developer project. The synopsis also planned a
reference CloudFormation template "to compare against Terraform" — that was
not built, since the project brief explicitly asks for **Terraform as the
only IaC tool**; mention the comparison conceptually during evaluation
instead of as working code.

---

## 2. Architecture

```
 Browser ── Socket.IO/HTTP ──▶ Flask app (app.py) ──▶ scanner_core.py
                                     │                     │
                                     │              validate target
                                     │              (security.py: SSRF guard)
                                     ▼
                           scan_store.py (writes to PVC-backed DATA_DIR)
                                     │
                                     ▼
                        reports/<scan_id>/{meta.json, report.html, report.json}

 GitHub push ──▶ Jenkins: pytest ──▶ Docker build ──▶ Trivy scan (gate)
                     ──▶ DockerHub push (SHA tag) ──▶ kubectl set image
                     ──▶ rollout status / pod readiness check

 Terraform ──▶ EC2 (Ubuntu) + Security Group (22/80/443 only) ──▶ installs
               Docker + K3s via user_data (app itself is deployed by Jenkins)

 Prometheus (scrapes :9200 in-cluster) ──▶ Grafana dashboard
 Node Exporter (:9100, in-cluster) ──▶ Prometheus ──▶ Alertmanager
```

Single Kubernetes Deployment (`scanner-deployment`), single replica — see §6
for why the previous two-deployment design was consolidated and why replicas
stay at 1 for now.

---

## 3. Local setup

### Windows PowerShell

```powershell
git clone https://github.com/ravindrathakur19/vulnscan-pro.git
cd vulnscan-pro
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
$env:SECRET_KEY = "dev-secret-change-me"
python app.py
# open http://localhost:5000
```

### Ubuntu / WSL

```bash
git clone https://github.com/ravindrathakur19/vulnscan-pro.git
cd vulnscan-pro
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
export SECRET_KEY="dev-secret-change-me"
python3 app.py
# open http://localhost:5000
```

### Run with Docker

```bash
docker build -t vulnscan-pro:local .
docker run -p 5000:5000 -e SECRET_KEY=dev-secret-change-me \
           -v "$(pwd)/reports:/app/reports" vulnscan-pro:local
curl http://localhost:5000/healthz
```

> I was not able to run an actual `docker build` in the environment I prepared
> this in (no Docker daemon available there) — the Dockerfile was reviewed
> stage-by-stage and the app was smoke-tested directly with gunicorn/eventlet
> installed, but please run the `docker build`/`docker run` above yourself
> before you rely on it, and tell me what you see if anything fails.

### Run the test suite

```bash
pip install -r requirements-dev.txt
pytest -v                                 # 68 tests
pytest --cov=. --cov-report=term-missing  # with coverage
```

All 68 tests passed when I ran them (`app.py` 79%, `security.py` 82%,
`scan_store.py` 86%, `scanner_core.py` 42% line coverage — the scanner's
injection-testing branches that need a live HTTP target are the main gap;
see §9b "Known gaps").

---

## 4. Testing approach (Module 1)

- `tests/test_security.py` (22 tests) — SSRF guard: public/private/loopback/
  CGNAT/metadata IPs, scheme validation, malformed URLs, credentials-in-URL.
- `tests/test_scanner.py` (20 tests) — header checks, SQLi/XSS/LFI/open-redirect
  detection and non-detection, CSRF, sensitive-file exposure, finding
  dedup — all against the `responses` library's mocked HTTP layer, **never**
  against a real third-party site.
- `tests/test_reports.py` (12 tests) — HTML/JSON report generation, and the
  disk-backed `ScanStore` (create/complete/purge/path-traversal rejection).
- `tests/test_api.py` (14 tests) — Flask endpoints with `VulnScanner` mocked
  out: validation errors, SSRF rejection, full scan lifecycle, 404s on bad/
  unknown scan IDs, concurrency cap.

Run automatically by Jenkins as the first pipeline stage — a failing test
blocks the Docker build.

---

## 5. Docker (Module 2)

- Multi-stage build (`python:3.12-slim`): wheels built in a `builder` stage,
  runtime image installs from local wheels only (`--no-index`), no compiler
  toolchain in the final image.
- **`nmap` was removed.** I audited `scanner_core.py` and `app.py` for any
  `subprocess`/`os.system`/`shutil.which("nmap")` call — there is none. All
  checks (SQLi, XSS, headers, subdomain enum, etc.) go through
  `requests`/`BeautifulSoup`. Installing it anyway would just add attack
  surface and image weight to a public-facing container for a feature that
  doesn't exist yet. If a future module adds real port-scanning, add it back
  then, deliberately.
- Non-root `vulnscan` user; `HEALTHCHECK` against `/healthz`; config via env
  vars only (`PORT`, `DATA_DIR`, `SECRET_KEY`, etc. — see §8); no credentials
  baked into the image or Dockerfile.

---

## 6. Kubernetes (Module 5) — read this before changing replicas

**I consolidated two deployments into one.** The previous `report-deployment.yaml`
pointed at the identical `ravi12t/vuln-scanner:latest` image as
`scanner-deployment` — there was never a second code path or route that only
it served; `app.py` has always generated *and* served reports from the same
process. A second deployment of the same image isn't a "report service",
it's an extra pod to manage with no functional separation. I removed it and
put report storage on a shared PVC instead (`k8s/storage.yaml`). If you want
scan and report serving to genuinely be separate services, that requires
splitting `app.py` into two Flask apps with a real API or queue between
them — worth raising as a "future work" point in evaluation, but it wasn't in
scope to build this semester.

**Replica count stays at 1, on purpose.** The assignment brief for this
project explicitly warned against "setting replicas to 2 and claiming load
balancing" without shared state, and that's exactly what the old manifest did
— `scanner-deployment` was previously `replicas: 2` with scans and reports
stored in a plain Python dict in each pod's memory. I implemented
`scan_store.py`, which does persist finished scans/reports to a PVC so they
survive a pod restart — but a scan **in progress** still keeps its live log
buffer and worker thread in one pod's memory, and Socket.IO only broadcasts
to clients connected to that same pod. Without sticky sessions at the Service/
Ingress layer and a shared pub-sub (Redis, or Socket.IO's Redis adapter) for
cross-pod broadcast, a second replica would silently drop live scan output
for some users. That's the shared-state layer the brief asked me to build or
explicitly document as missing — I'm documenting it; building a Redis-backed
Socket.IO adapter is a reasonable "if I had another week" extension to
mention in your viva.

What **is** done: RBAC (least-privilege Role/RoleBinding scoped to `pods`/
`pods/log` reads in the `vulnscan` namespace only), the `SECRET_KEY` as a
Kubernetes Secret via `envFrom`, CPU/memory requests+limits, liveness/readiness
probes against `/healthz`, and a PVC so reports survive restarts.

Apply order and commands: see `k8s/README.md`.

---

## 7. Terraform (Module 4)

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: your key_pair_name and ssh_cidr (curl -s ifconfig.me)
terraform init
terraform validate
terraform plan      # review before applying — this is the point where I need your go-ahead
terraform apply
# ... use the instance ...
terraform destroy   # tear down when done, to avoid ongoing cost
```

I have **not** run `terraform apply` and will not create any billed AWS
resource without you explicitly telling me to — see §10. `main.tf` was
syntax-checked with `python-hcl2` (no `terraform` binary was available in the
sandbox I prepared this in); please run `terraform validate` yourself as the
first real check before `apply`.

Provisions: one Ubuntu 22.04 EC2 instance (`t3.micro` by default, Free-Tier
eligible) in `ap-south-1`, a Security Group allowing only 22 (restrict to your
IP via `ssh_cidr`), 80 and 443 inbound, and a 20 GB encrypted gp3 EBS root
volume. `user_data` installs Docker and K3s only — Jenkins deploys the actual
application afterwards, so Terraform never needs DockerHub credentials or the
app's `SECRET_KEY`.

### IAM permissions needed to run this

Attach (or create a custom policy with) at minimum: `ec2:RunInstances`,
`ec2:DescribeInstances`, `ec2:TerminateInstances`, `ec2:CreateSecurityGroup`,
`ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress`,
`ec2:RevokeSecurityGroupIngress`, `ec2:DescribeImages`, `ec2:DescribeVpcs`,
`ec2:CreateTags`. The AWS managed policy `AmazonEC2FullAccess` covers all of
these if you'd rather not hand-write a custom policy for a course project.

### Terraform authentication

```bash
aws configure   # access key, secret key, region = ap-south-1
# or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_DEFAULT_REGION
```
Never commit these, `terraform.tfvars`, `.terraform/`, or `terraform.tfstate`
— all are in `.gitignore`.

---

## 8. Environment variables

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `SECRET_KEY` | **Yes in production** (`FLASK_ENV=production`) | insecure dev default, with a warning | Flask session signing |
| `PORT` | No | `5000` | App listen port |
| `DATA_DIR` | No | `./reports` | Where scan metadata/reports are stored (mount a volume/PVC here) |
| `MAX_CONCURRENT_SCANS` | No | `5` | Requests beyond this get HTTP 429 |
| `SCAN_THREADS` | No | `10` | Default thread count per scan (client can override, capped at 20) |
| `SCAN_TIMEOUT` | No | `8` | Default per-request timeout seconds (capped at 30) |
| `ALLOW_PRIVATE_TARGETS` | No | `false` | Set `true` **only** for local lab targets — disables the SSRF guard |
| `CORS_ALLOWED_ORIGINS` | No | `*` | Tighten this for a real public deployment |
| `METRICS_PORT` | No | unset (metrics disabled) | Internal-only port for Prometheus `/metrics` |
| `FLASK_ENV` | No | unset | Set to `production` to require `SECRET_KEY` |
| `LOG_LEVEL` | No | `INFO` | Python logging level |

---

## 9. Security (Unit V)

- **SSRF protection** (`security.py`): resolves the hostname before scanning
  and rejects loopback, RFC1918 private ranges, link-local/cloud-metadata
  (`169.254.169.254`), carrier-grade NAT, and multicast addresses; also
  rejects non-`http(s)` schemes, credentials embedded in the URL, and
  malformed input. Redirects encountered *during* a scan are re-validated
  per hop (`scanner_core.py`'s `get()`), so a target can't bounce the scanner
  to an internal address after the initial check passes.
- **Known limitation (documented, not silently ignored):** there's a DNS-
  resolve-then-connect TOCTOU window — a hostname could theoretically
  re-resolve to a different IP between validation and the actual HTTP
  request. Closing this completely needs connecting to a pinned IP while
  still sending the original `Host` header, which `requests` doesn't support
  without extra plumbing; flagged here rather than left unmentioned.
- Scan IDs are validated against a strict `^[a-f0-9]{16}$` pattern before
  ever touching the filesystem (`scan_store.valid_scan_id`), and report paths
  are canonicalized and checked to stay inside `DATA_DIR` before serving —
  defence against path traversal on `/report/<scan_id>/<fmt>`.
- `SECRET_KEY` is never hardcoded for production use: it's required via env
  var when `FLASK_ENV=production`, and only falls back to a (loudly logged)
  insecure default for local dev convenience.
- Request bodies are capped at 64 KB (`MAX_CONTENT_LENGTH`) to limit trivial
  abuse of the scan-submission endpoint.
- Jenkins never has DockerHub/AWS/app secrets in plaintext — all via Jenkins
  Credentials, injected only into the step that needs them.
- Kubernetes: `SECRET_KEY` via `Secret`/`envFrom`; least-privilege RBAC (read-
  only `pods`/`pods/log` in-namespace); no cluster-admin anywhere.

## 9b. Known gaps — stated plainly, not hidden

- `scanner_core.py`'s injection-testing code paths (SQLi/XSS/LFI against live
  forms, blind-SQLi timing, subdomain enumeration, broken-auth brute force)
  are exercised directly in unit tests but not through a full `run()` against
  a real multi-page site — that would require a disposable vulnerable target
  app in CI, which wasn't built this semester. Coverage on `scanner_core.py`
  sits at 42% line coverage for this reason; the untested branches are listed
  in the `pytest --cov` output and are the honest next thing to improve.
- Multi-replica horizontal scaling is not implemented — see §6.
- I have not run `docker build`, `terraform apply`, a real Jenkins pipeline,
  or a real `kubectl apply` against a live cluster — none of those tools were
  available in the environment I used to prepare this. Everything was
  validated as far as I could (`py_compile`, the full pytest suite actually
  executing and passing, YAML parsed with PyYAML, HCL parsed with
  `python-hcl2`), but please run the real build/deploy commands yourself and
  tell me what happens — I'd rather you catch a real-environment issue than
  have me claim success I can't verify.

---

## 10. AWS deployment — nothing is created without your go-ahead

I will not run `terraform apply`, create any EC2 instance, or incur any AWS
cost on your behalf. §7 above gives you the exact commands; run `terraform
plan` first, review it, and only run `apply` when you're ready. Likewise for
Jenkins/DockerHub: nothing pushes or deploys until you've created the
`dockerhub-creds` and `kubeconfig-vulnscan` credentials in your own Jenkins.

### Ubuntu commands for the EC2 host, after `terraform apply`

```bash
ssh -i /path/to/vulnscan-key.pem ubuntu@<public_ip>      # from terraform output
sudo k3s kubectl get nodes                                # confirm K3s is up
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
kubectl apply -f k8s/rbac.yaml -f k8s/storage.yaml
# create k8s/secrets.yaml from the .example first
kubectl apply -f k8s/secrets.yaml -f k8s/scanner-deployment.yaml -f k8s/scanner-service.yaml
kubectl get pods,svc -n vulnscan
```

For HTTPS on the public endpoint: put a reverse proxy (Caddy or nginx with
certbot) in front of the NodePort, or add Traefik/cert-manager to K3s — not
pre-built here to keep the single-EC2-instance setup simple; happy to add it
if you want it for the demo.

### Cost optimization (Module 7)

- `t3.micro` is Free-Tier eligible for 12 months; outside Free Tier it's
  roughly $0.0104/hr in `ap-south-1` — **always `terraform destroy` when not
  actively demoing**.
- In the AWS Console: **Billing → Budgets → Create budget**, set a monthly
  cost budget (e.g. $5) with an alert at 80%. This has to be done in the
  Console/CLI with your own account — it isn't something Terraform should
  provision automatically for a student account (needless to create a Budget
  object for a resource that's torn down after each session).
- Check **Cost Explorer** after a demo session to see actual EC2 + EBS spend;
  right-sizing recommendation: stay on `t3.micro` unless scans start timing
  out from CPU starvation, at which point try `t3.small` only for the demo
  window.
- Storage: old scan reports can be pruned with `scan_store.py`'s
  `purge_older_than(days)` — not wired to a scheduler yet; a simple cron job
  or Kubernetes CronJob calling it periodically is a natural next step for
  cost control on long-lived deployments.

---

## 11. Project structure

```
vulnscan-pro/
├── app.py                   # Flask + Socket.IO app
├── scanner_core.py          # Scanning engine (inherited, SSRF-hardened)
├── security.py              # SSRF guard / URL validation
├── scan_store.py            # Disk-backed scan/report persistence
├── metrics.py                # Prometheus metrics
├── requirements.txt / requirements-dev.txt
├── Dockerfile / .dockerignore / Procfile
├── Jenkinsfile
├── templates/index.html
├── tests/
│   ├── conftest.py
│   ├── test_security.py
│   ├── test_scanner.py
│   ├── test_reports.py
│   └── test_api.py
├── terraform/
│   ├── main.tf / variables.tf / outputs.tf
│   ├── terraform.tfvars.example / .gitignore
├── k8s/
│   ├── rbac.yaml / storage.yaml / secrets.yaml.example
│   ├── scanner-deployment.yaml / scanner-service.yaml
│   └── README.md
├── monitoring/
│   ├── prometheus.yml / alerts.yml / alertmanager.yml
│   └── README.md
└── reports/                 # local scan output (git-ignored except .gitkeep)
```

---

## 12. Demonstrating this for evaluation

1. Show the pytest run live (`pytest -v`) — fast, visible pass count, explain
   that network-touching tests are mocked deliberately (ethics + reliability).
2. Show `docker build` + `docker run`, then a live scan against a target you
   control (e.g. a deliberately vulnerable app like OWASP Juice Shop you spin
   up yourself — **never a real third-party site**) with the live terminal UI.
3. Walk through the Jenkinsfile stage list and explain the Trivy gate —
   mention you can show a failed build by lowering `TRIVY_SEVERITY_GATE`.
4. `terraform plan` (even without `apply`, if you'd rather not spend/create
   resources live) to show IaC understanding.
5. Explain the single-replica decision in §6 — this is a good "what would you
   do with more time" talking point for a viva.
6. Show the Grafana dashboard with Node Exporter + the custom
   `vulnscan_scans_started_total`/`vulnscan_scan_duration_seconds` panels, and
   trigger an Alertmanager alert by generating CPU load.

---

## 13. GitHub / version control

```bash
git add .
git commit -m "Add testing, hardened Docker/K8s, Terraform, monitoring, SSRF guard"
git push origin main
```

Double-check before pushing: `git status` should show no `terraform.tfvars`,
no `k8s/secrets.yaml`, no `.pem` files, no `.terraform/` directory — all are
in `.gitignore`, but it's worth a manual look before a public push.
