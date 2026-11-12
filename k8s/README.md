# k8s/ manifests

Apply in this order:

```bash
kubectl apply -f rbac.yaml          # creates the vulnscan namespace too
kubectl apply -f storage.yaml
cp secrets.yaml.example secrets.yaml
# edit secrets.yaml with a real SECRET_KEY, then:
kubectl apply -f secrets.yaml
kubectl apply -f scanner-deployment.yaml
kubectl apply -f scanner-service.yaml
```

Verify:

```bash
kubectl -n vulnscan get pods,svc,pvc
kubectl -n vulnscan logs -f deployment/scanner-deployment
```

## What changed from the previous semester's two-deployment design, and why

The old `report-deployment.yaml` pointed at the exact same image and exposed
no code path that `scanner-deployment` didn't already serve - the Flask app
has always generated and served reports itself (`/report/<id>/<fmt>`), so a
second deployment of the same image added a pod to manage without adding any
real separation of concerns. It has been removed in favour of one
`scanner-deployment` with report storage on a shared PVC, which is simpler to
reason about, cheaper to run, and matches what the code actually does.

If you want genuinely separate scan vs. report services in a future
iteration, that requires splitting `app.py` into two Flask apps with a real
API between them (or a message queue) - worth mentioning as a future
enhancement during evaluation, but out of scope for this semester.

## Replica count

`scanner-deployment` runs a **single replica** on purpose - see the comment at
the top of `scanner-deployment.yaml`. Scaling to multiple replicas before
adding sticky sessions and a shared event bus will cause Socket.IO clients to
silently stop receiving live scan output when the Kubernetes Service
load-balances them to a different pod mid-scan.
