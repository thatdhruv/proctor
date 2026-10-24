# End-to-end test of the Go operator on a real (kind) cluster with an enforcing CNI (Calico).
#   powershell -File scripts/k8s-e2e.ps1 [-Tools <dir containing kind.exe and kubectl.exe>] [-KeepCluster]
# Writes artefacts to evidence/k8s/.
param([string]$Tools = "", [switch]$KeepCluster)
$ErrorActionPreference = "Continue"
if ($Tools) { $env:Path = "$Tools;" + $env:Path }
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$out = Join-Path $root "evidence/k8s"
New-Item -ItemType Directory -Force $out | Out-Null

function Step($m) { Write-Host "`n== $m" -ForegroundColor Cyan }

Step "cluster"
if (-not (kind get clusters 2>$null | Select-String -Quiet "^proctor$")) {
  kind create cluster --name proctor --config deploy/k8s/kind-calico.yaml
  kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml | Out-Null
  kubectl -n kube-system rollout status ds/calico-node --timeout=400s
}

Step "images"
docker build -q -t proctor-operator:dev operator | Out-Null
docker compose -f deploy/docker-compose.yml --profile run build proctor | Out-Null
docker tag proctor-runner:latest proctor-runner:dev
kind load docker-image proctor-operator:dev proctor-runner:dev --name proctor | Out-Null

Step "install"
kubectl apply -f operator/config/crd -f operator/config/rbac/role.yaml -f deploy/k8s/00-namespaces.yaml | Out-Null
kubectl apply -f deploy/k8s/10-datastore.yaml -f deploy/k8s/20-operator.yaml | Out-Null
kubectl -n proctor-system rollout status deploy/proctor-operator --timeout=180s
kubectl -n proctor-demo rollout status deploy/postgres --timeout=300s
kubectl -n proctor-demo rollout status deploy/canary --timeout=300s

Step "submit a ProctorRun and sample the autoscaler"
kubectl -n proctor-demo delete proctorrun demo --ignore-not-found | Out-Null
kubectl apply -f deploy/k8s/sample-run.yaml | Out-Null
$timeline = @()
$t0 = Get-Date
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep 2
  $j = kubectl -n proctor-demo get job demo -o json 2>$null | ConvertFrom-Json
  $phase = kubectl -n proctor-demo get proctorrun demo -o jsonpath="{.status.phase}" 2>$null
  if ($j) {
    $timeline += [pscustomobject]@{ t = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1); phase = $phase;
      parallelism = $j.spec.parallelism; active = [int]$j.status.active; succeeded = [int]$j.status.succeeded; completions = $j.spec.completions }
  } else {
    $timeline += [pscustomobject]@{ t = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1); phase = $phase; parallelism = 0; active = 0; succeeded = 0; completions = 0 }
  }
  if ($phase -in @("Succeeded", "Failed")) { break }
}
$timeline | ConvertTo-Json | Set-Content "$out/autoscale-timeline.json"
$timeline | Format-Table | Out-String | Write-Host
kubectl -n proctor-demo get proctorrun demo -o yaml | Set-Content "$out/proctorrun.yaml"
kubectl -n proctor-demo get pods -o wide | Set-Content "$out/pods.txt"
kubectl -n proctor-demo get netpol demo-egress -o yaml | Set-Content "$out/networkpolicy.yaml"
kubectl -n proctor-demo logs demo-selftest | Set-Content "$out/selftest.log"
kubectl -n proctor-demo exec deploy/postgres -- psql -U proctor -d proctor -tAc "select env, count(*), sum(reward)::int from episodes group by env order by env" | Set-Content "$out/episodes-by-env.txt"

Step "network probe: pod under the policy vs identical control pod"
kubectl -n proctor-demo delete pod probe-covered probe-control --ignore-not-found | Out-Null
kubectl apply -f deploy/k8s/netprobe.yaml | Out-Null
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep 3
  $ph = kubectl -n proctor-demo get pod probe-covered probe-control -o jsonpath="{.items[*].status.phase}"
  if ($ph -notmatch "Pending|Running") { break }
}
kubectl -n proctor-demo logs probe-covered | Set-Content "$out/netprobe-covered.json"
kubectl -n proctor-demo logs probe-control | Set-Content "$out/netprobe-control.json"
Write-Host "covered leaks:"; (Get-Content "$out/netprobe-covered.json" -Raw | ConvertFrom-Json).leaks
Write-Host "control leaks:"; (Get-Content "$out/netprobe-control.json" -Raw | ConvertFrom-Json).leaks

if (-not $KeepCluster) { Write-Host "(cluster kept; delete with: kind delete cluster --name proctor)" }
