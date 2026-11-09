# IntelliSecOps backend

## Existing components and scan execution

The backend retains ZAP and legacy SQLMap report normalization, but does not
run SQLMap or automate injection testing. User-initiated website scans are
handed to Jenkins' asynchronous build queue, where the isolated worker runs the
existing ZAP baseline container. Django does not run shell commands or execute
submitted repository code. Jenkins verifies the target against the authorized
scan record before starting a scanner or accepting a report.

The Jenkins job must have an `isolated-scan-worker` agent label. That agent
must be ephemeral or otherwise isolated and have outbound network controls
that block loopback, private, link-local, and cloud-metadata networks, including
after DNS changes and redirects. Configure this boundary before setting
`SCAN_WORKER_ISOLATED=true`. Django validates public DNS answers and follows
and revalidates at most five HTTP redirects before queueing, but only worker
network policy can close DNS-rebinding and scanner-followed-request gaps.

Public GitHub repositories are cloned shallowly on that agent, are not built
or executed, and are scanned with the existing SonarQube installation. The
pipeline waits for analysis completion and exports SonarQube `VULNERABILITY`
issues through `scripts/sonar_issues_report.py` (maximum 10,000 issues per
report). The SonarQube service account must be able to create/analyze projects
with the generated scan project key. Private repositories and SonarQube
Security Hotspots are not supported by this integration. Mobile-app scanning
is not supported by the current pipeline. SQLMap ingestion is authenticated
and intended only for importing existing reports, not for launching scans.

GitHub Actions runs Django checks/tests, the SonarQube report-exporter tests,
and frontend lint/build on pushes and pull requests to `main`. SonarQube static
analysis runs when `SONAR_HOST_URL` and `SONAR_TOKEN` repository secrets are
configured. Account registration remains administrator-managed. The public
website can submit a website or GitHub target without signing in; that browser
keeps the returned access token and uses it to open the results page.

## API

Obtain JWT access and refresh tokens through the existing SimpleJWT package:

- `POST /api/auth/token/` with `username` and `password`
- `POST /api/auth/token/refresh/` with `refresh`

Use `Authorization: Bearer <access>` for the authenticated endpoints:

- `POST /api/scans/` — JSON: `{"target_type":"website","target":"https://example.com","authorized":true,"include_ai":false}` (or `target_type:"repository"` and an HTTPS `github.com/owner/repo` URL). The authorization flag is a requester attestation, not independent proof of ownership.

Public website scans do not require a Django account:

- `POST /api/public/scans/` — same JSON body. Returns `202` with `scan` and a one-time `access_token`. The token is stored in the submitting browser and sent as `X-Scan-Access-Token`.
- `GET /api/public/scans/<scan-id>/` — status, pipeline stage, and findings for that token.
- `GET /api/public/scans/<scan-id>/download/` — completed report JSON download for that token.

A missing or wrong token returns `404`. Completed public scans are still written through the existing report and Grafana metrics path. Grafana itself stays on its existing authenticated metrics endpoint.
- `GET /api/scans/history/` — current user's scans, optional `limit` 1–100
- `GET /api/scans/<scan-id>/` — current user's status and normalized findings
- `GET /api/scans/<scan-id>/report/` — current user's completed report

Submission returns `202` after Jenkins accepts the job. The scan stays pending
until Jenkins posts a status callback. Missing pipeline configuration or an
unapproved worker fails closed and returns `503`. The callback
`POST /api/scans/<scan-id>/pipeline-result/` is for Jenkins only and requires
`X-Scan-Pipeline-Token`; it is not a user report-ingestion endpoint.

Legacy report ingestion and Grafana routes remain at `/api/analyze-report/`,
`/api/analyze-sqlmap-report/`, `/api/grafana-metrics/`, and
`/api/grafana-logs/`; these routes require JWT authentication. The old
`mode=raw` search option is disabled; search is limited to authenticated,
parameterized ORM queries. Existing Grafana metric names and response
structure are preserved.

Gemini explanations are optional (`include_ai:true`). They are stored with the
label `AI-generated suggestion (unverified)`; a missing API key or failed
generation does not prevent the scanner report from being stored.

## Security-contact notification

Notifications are disabled unless `SECURITY_NOTIFICATIONS_ENABLED=true` and
all SMTP settings are present. After a completed website scan, the backend
checks the target's HTTPS `/.well-known/security.txt` and `/security.txt`,
follows only same-host redirects, and accepts only a same-host `mailto:`
contact whose host has an MX record. It never guesses an address or uses the
requester's email. No verified contact, insecure HTTP target, or unavailable
DNS/policy lookup means no email is sent; the authenticated report remains
available. SMTP delivery errors are logged and do not invalidate a completed
scan.

This discovery check is conservative: it does not infer addresses from WHOIS,
contact forms, or policy prose. Review disclosure policy before enabling
automated delivery. SMTP credentials belong in the deployment secret store,
not in source control or the frontend.

## Environment

Create `backend/.env` from `backend/.env.example` only if it does not already
exist; merge any missing settings into an existing file without overwriting its
values. Never commit `.env` or populate example values with real secrets.

Required for a non-debug deployment:

- `DJANGO_DEBUG=false`
- `DJANGO_SECRET_KEY`: generated random Django secret
- `DJANGO_ALLOWED_HOSTS`: comma-separated explicit hosts
- `CORS_ALLOWED_ORIGINS`: comma-separated trusted frontend origins

Required to trigger website scans:

- `SCAN_WORKER_ISOLATED=true` only after verifying the Jenkins worker network boundary
- `JENKINS_URL`, `JENKINS_SCAN_JOB`, `JENKINS_USER`, `JENKINS_API_TOKEN`
- `SCAN_PIPELINE_TOKEN`: shared secret, identical to the Jenkins credential
- Jenkins Secret Text credentials `SCAN_PIPELINE_TOKEN` and `SCAN_API_BASE_URL`
  (`SCAN_API_BASE_URL` must be the HTTPS URL reachable from the Jenkins agent)
- The corresponding service account/API token and `SCAN_PIPELINE_TOKEN` must
  be supplied to Django through the server's secret manager/environment.

`SCAN_SUBMISSION_RATE` defaults to `5/hour`; `MAX_SCAN_REPORT_BYTES` defaults
to 20 MiB. Optional Gemini uses `GEMINI_API_KEY`.

For email, set `SECURITY_NOTIFICATIONS_ENABLED=true`, `SMTP_HOST`, `SMTP_PORT`,
`SMTP_USER`, `SMTP_PASSWORD`, `SMTP_USE_TLS` or `SMTP_USE_SSL`, and
`SMTP_FROM_EMAIL`. Keep notifications disabled until the SMTP account and
disclosure policy are approved.

## Local Docker / AWS deployment preparation

The Compose file runs the Django backend and static frontend. The backend binds
port 5000 and the frontend binds port 8080 to loopback; put the services behind
an authenticated TLS reverse proxy before remote access. Rebuild and recreate
the frontend after pulling changes so Nginx serves the new Vite `dist` output:

```powershell
if (-not (Test-Path backend\.env)) {
    Copy-Item backend\.env.example backend\.env
}
# Preserve an existing backend\.env; merge required settings without replacing
# its secret values. Set a secret key and actual allowed/CORS hostnames.
docker compose build frontend backend
docker compose up -d frontend backend
docker compose exec backend python manage.py migrate --noinput
docker compose ps
docker compose logs --tail 100 backend
docker compose logs --tail 100 frontend
```

The frontend is reachable locally on `http://127.0.0.1:8080` for a reverse
proxy to route to. `docker compose up -d --build frontend` is sufficient to
rebuild and replace only the frontend after a later frontend-only update.

The default configuration uses the existing SQLite database volume. PostgreSQL
is supported by setting `DATABASE_ENGINE=postgresql` and supplying
`POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_HOST`, and
optionally `POSTGRES_PORT`, `POSTGRES_SSLMODE`, and
`POSTGRES_CONN_MAX_AGE`. The production requirements include the PostgreSQL
driver. Back up and migrate existing data before switching databases. Do not expose
Jenkins, Docker, the database, Grafana, or security-management ports publicly.
Restrict AWS security groups and reverse-proxy routes to approved clients.
Jenkins must be able to reach the Django callback endpoint over HTTPS.

Before enabling scan mode, add the Jenkins credentials listed above, ensure
the job accepts the `PIPELINE_MODE`, `SCAN_ID`, `SCAN_TARGET_TYPE`, and
`SCAN_TARGET` parameters from Django, and bind scanning stages to an isolated
`isolated-scan-worker` agent. Keep Jenkins build permissions restricted; scan
mode requires a valid API-created scan ID and callbacks are bound to that
record's exact target and target type.

The SonarQube server configured in Jenkins must be reachable from the isolated
agent. Prefer HTTPS. If the approved SonarQube service is reachable only over
HTTP on a private network, set `SONAR_API_ALLOW_INSECURE=true` in the Jenkins
agent environment only after restricting that network and protecting its
traffic. The checked-in Jenkins pipeline requires Secret Text credentials
`SCAN_PIPELINE_TOKEN` (same value as Django) and `SCAN_API_BASE_URL`; deployment
also requires the existing `GEMINI_API_KEY` credential and Secret Text
credentials `DJANGO_SECRET_KEY`, `DJANGO_ALLOWED_HOSTS`, and
`CORS_ALLOWED_ORIGINS`.

## Wazuh and Grafana integration

Website scans still run with the ZAP baseline scanner, and public GitHub
repositories still run through SonarQube. Wazuh is not a replacement scanner:
the optional Wazuh Agent container reads the backend's structured scan and
security-audit logs and forwards them to an existing Wazuh Manager. The
backend's existing authenticated `/api/grafana-metrics/` and
`/api/grafana-logs/` endpoints continue to provide scan metrics and logs to
Grafana.

The Wazuh Agent is opt-in and does not expose any ports. In Jenkins, set the
deployment parameter `WAZUH_MANAGER_SERVER` to the private DNS name or IP
address of an already-deployed Manager. The deploy pipeline starts the Agent
only when that parameter is non-empty and shares the backend's persistent log
volume with it. The Manager must allow agent traffic on TCP 1514 only from
approved networks. For a local Compose deployment, configure
`WAZUH_MANAGER_SERVER` in the shell that runs Compose:

```powershell
$env:WAZUH_MANAGER_SERVER = "wazuh-manager.private"
docker compose --profile wazuh up -d --build
docker compose ps
docker compose logs --tail 100 wazuh-agent
```

The Agent reads `scan_metrics.json.log` and `security_audit.json.log` from the
same persistent Docker volume mounted by the backend. For a local Compose
deployment on EC2, set
`INTELLISECOPS_LOG_DIR=/var/log/intellisecops` in the Compose environment and
ensure the directory is writable by the backend and readable by the Agent.
Custom Wazuh rules may be needed on the Manager to turn collected application
events into alerts.

This Compose profile deploys only the Agent. It does not deploy a Wazuh
Manager, Indexer, or Dashboard; size and secure those central components
separately. Grafana still needs its own authenticated datasource configuration
for the existing metrics/log endpoints. Do not expose Wazuh enrollment,
agent, indexer, dashboard, or Grafana management ports publicly.

## Tests

Run backend tests and Django checks from `backend`:

```powershell
python manage.py test api
python manage.py check
python manage.py makemigrations --check --dry-run
```

Run the SonarQube report-exporter tests from the repository root:

```powershell
python -m unittest discover -s scripts -p "test_*.py"
```
