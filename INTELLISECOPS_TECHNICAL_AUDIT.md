# IntelliSecOps Project Audit

**Review date:** 2026-11-14  
**Scope:** Repository implementation, recent scan/report UI and deployment changes, and local backend/frontend readiness checks.  
**Safety:** No target was scanned, no live ZAP or SQLMap run was started, and no Gemini API request was sent. No secret values were copied into this report or printed during the environment checks.

## Executive summary

IntelliSecOps is a Django/React application with an asynchronous Jenkins scan pipeline. The website scan path uses OWASP ZAP Baseline (limited crawling and passive rules); public GitHub repository scans use SonarQube static analysis. Results are returned to Django through an authenticated callback, normalized, stored, and displayed to the scan submitter.

The local application code and development checks are healthy: Django configuration checks pass, all 36 Django API tests pass, and the frontend lint/build complete. The local Gemini key is detected by Django, the GenAI client initializes, and a mocked helper check confirms that `gemini-2.0-flash` is requested. This verifies local configuration and client wiring, **not** a live Gemini API call or successful model response.

**A real scan is not ready to queue from this local setup.** The worker-isolation gate is false, and the Jenkins scan job, service account, API token, and callback token are not configured. Do not enable scans until the worker is isolated and its egress restrictions are verified.

## Current implementation

| Area | Current status | Notes |
|---|---|---|
| React scan form and results | Implemented | Public website/repository submission, authorization attestation, polling, findings, and report download. The UI now describes actual scanner scope and does not present demo metrics or invented findings as live telemetry. |
| Django scan API | Implemented; deployment-gated | Validates targets, creates scan records, verifies callbacks, normalizes reports, and stores history/findings. |
| OWASP ZAP | Implemented as passive Baseline | Limited crawl and passive rules only. No Full Scan, active attack rules, authenticated context, or API specification import is configured. |
| GitHub/SonarQube | Implemented; external services unverified | Public repositories are shallow-cloned on the worker and statically analyzed. Submitted source is not built or run by this path. |
| SQLMap | Partial/manual import only | SQLMap is not installed or invoked by the scan pipeline. The parser reads an existing captured log; missing/unreadable logs now fail instead of producing an empty success-shaped report. |
| Gemini | Locally configured; live API unverified | Optional finding explanations use `gemini-2.0-flash`. Results are labeled unverified. A mocked check exercised the helper without contacting Google. |
| Grafana | Backend endpoints only | Authenticated metrics/log APIs exist. No Grafana service, dashboard provisioning, or datasource configuration is included. The frontend no longer claims that live Grafana dashboards or telemetry are present. |
| Wazuh | Partial; service deployment unverified | Agent/client and custom rules exist, but Manager/Indexer/Dashboard are external. The Wazuh agent configuration still needs deployment-side verification. |
| Email notifications | Optional; delivery unverified | Disabled unless configured. Contact discovery is conservative and does not guess an address. SMTP delivery was not tested. |
| Docker Compose frontend | Implemented | Compose now defines a frontend service, and Nginx proxies `/api/` requests to the backend. Compose configuration validates successfully. |
| AWS deployment | Not automated | Documentation describes deployment considerations; no AWS infrastructure-as-code or provisioning workflow was found. |
| GitHub webhook scan | Not implemented | The current webhook handler does not verify a signature or queue repository scans. |

## Scanner behavior and boundaries

### Website scans: OWASP ZAP Baseline

The Jenkins website stage runs `zap-baseline.py` using the mutable `ghcr.io/zaproxy/zaproxy:stable` image. Baseline performs limited crawling and passive checks; its coverage depends on the pages and responses reached. It is not a full penetration test and a clean report does not prove that the target is secure.

The Jenkins stage now retains ZAP's finding/threshold exit codes (0–2) when a non-empty JSON report exists, while failing on higher runtime errors or a missing/empty report. The ZAP image is still not pinned to an immutable version or digest.

No ZAP report from an actual target scan was reviewed. Therefore, this audit cannot claim that any specific vulnerability was detected.

### Repository scans: SonarQube

The pipeline shallow-clones public GitHub repositories and exports SonarQube vulnerability issues. It does not support private repositories in this flow, build or execute submitted source, or provide a complete dependency/security audit. SonarQube server availability, credentials, permissions, and live results were not verified.

### SQLMap

There is no SQLMap executable, scan stage, automatic parameter discovery, or scan-job callback support. `parse_sqlmap.py` only normalizes a previously captured SQLMap text log; a separate authenticated legacy API can import existing report JSON. No SQL injection test was run.

## Gemini and local environment verification

- `backend/.env` exists and parsed with **zero dotenv warnings**.
- No `SENTRY_DSN` assignment is present in that file; consequently, Sentry DSN configuration is absent. This is not a dotenv syntax warning.
- `GEMINI_API_KEY` was detected in the parsed Django environment. Its value was not displayed or recorded.
- `get_gemini_client()` initialized successfully using the local configuration.
- A mocked call to the shared helper verified that it requests model `gemini-2.0-flash` and returns response text. The model-generation call was mocked; **no external Gemini request occurred**, so API quota, permissions, network access, and real response generation remain unverified.
- The frontend `.env` exists and defines `VITE_API_URL`; the value is intentionally omitted from this report.

## Local checks performed

| Check | Result |
|---|---|
| Dotenv parse / warnings | Pass; zero warnings |
| Sentry DSN assignment | Not configured |
| Django detects Gemini key | Pass; value not shown |
| Gemini client initialization | Pass |
| Gemini helper/model selection | Pass with mocked model response; no live API request |
| `python manage.py check` | Pass; no issues |
| `python manage.py test api` | Pass; 36 tests |
| Frontend lint | Pass with one existing unrelated unused-variable warning in `Services.jsx` |
| Frontend production build | Pass |
| `docker compose config --quiet` | Pass |
| Live scan / live integration checks | Not run |

The frontend has installed dependencies and a Vite development script. The frontend production build was verified, but a browser session and live frontend-to-backend request were not tested as part of this review.

## Final report dashboard implementation

The local implementation now includes a light-themed `/reports/` page that loads an individual report from the existing stored-report API using either the owning user's JWT or the browser's public scan access token. The scan form redirects there after the scan reaches `completed`. The dashboard displays scan metadata and normalized stored findings, calculated severity totals, interactive SVG severity charts, finding search/filter controls, the original raw scanner JSON download, and a generated PDF report.

Saved Gemini output is visually separated and labeled AI-generated/unverified. Follow-up questions use the new `POST /api/scans/<scan-id>/ai-assistant/` endpoint, which applies the same report ownership/public-token check, validates question and finding selection, throttles requests, limits report context, and returns a safe unavailable response if Gemini fails. AI answers are not persisted as scanner findings. Browser text-to-speech and microphone dictation are optional; typed questions remain available without speech recognition.

Dashboard verification after implementation: Django check passed; all 40 API tests passed, including owner/public-token authorization and Gemini-unavailable cases; frontend lint/build passed; Docker Compose configuration passed. Lint reports one unrelated existing unused variable in `Services.jsx`. No target scan or live Gemini API request was performed. PDF generation was verified by production build, not a browser download session.

## Scan pipeline readiness

The local Django settings report:

- `SCAN_WORKER_ISOLATED`: **false**
- Jenkins URL: configured
- Jenkins scan job name: not configured
- Jenkins service account: not configured
- Jenkins API token: not configured
- Shared scan callback token: not configured

Accordingly, the scan API should fail closed rather than enqueue a test scan. Gemini readiness does not remove this Jenkins/worker blocker. To run an authorized test scan, configure the exact Jenkins job and credentials, verify callback connectivity, and enforce worker egress rules that block loopback, private, link-local, and cloud-metadata networks, including after DNS changes and redirects. Only then enable the isolated-worker setting.

## Main risks and outstanding work

1. **High — Scanner worker network boundary:** API-side target validation does not replace worker egress controls. Verify isolation and block internal/metadata destinations before enabling scans.
2. **Medium — Public scan resource use:** Public submissions rely on configured application throttling and deployment-level rate limits; verify edge controls before exposing the service broadly.
3. **Medium — Browser token storage:** Authenticated frontend access/refresh tokens are stored in `localStorage`; maintain a strict XSS prevention posture or choose a deliberate alternative storage design.
4. **Medium — External integrations are unverified:** Jenkins, SonarQube, Gemini live API, Wazuh services, SMTP, and any Grafana installation require deployment credentials/services and were not exercised here.
5. **Low — Mutable ZAP image tag:** Pin an approved scanner version or digest for repeatable builds.
6. **Low — Sentry configuration absent:** Add a DSN only if Sentry is part of the deployment plan; otherwise remove/ignore unused Sentry setup references.
7. **Feature gap — SQLMap:** Active SQL injection testing is not part of this project pipeline. Do not describe the parser/import utility as an automated scanner.
8. **Feature gap — Grafana/AWS/webhook:** Grafana provisioning, AWS infrastructure-as-code, and a verified GitHub webhook workflow are not included.

Positive controls include public-target validation and redirect checks, an authorization attestation, a fail-closed isolated-worker gate, callback token/target binding, report-size limits, shallow public-repository cloning, and transaction-backed report/finding persistence. The attestation is not independent proof of target ownership.

## Recommended next steps

1. Configure Jenkins scan job, service account, callback token, and API base URL in the approved secret store.
2. Verify an isolated/ephemeral worker and outbound network restrictions before setting `SCAN_WORKER_ISOLATED=true`.
3. Confirm the local Gemini key is valid with an operator-approved, non-sensitive test prompt if a live Gemini check is required; this audit intentionally did not make that call.
4. Decide whether Sentry is required; configure its DSN safely or leave it out.
5. Pin the ZAP image and validate the pipeline on a dedicated authorized staging target.
6. Keep UI/documentation claims aligned with actual scan artifacts and configured integrations.

## Safe project demonstration notes

For an OWASP ZAP demonstration, use only a team-owned or explicitly authorized staging website. Have an operator verify Jenkins credentials, the isolated worker, Docker availability, worker network policy, and callback connectivity before submitting a scan through the validated application form. Show the real archived `report.json` and the corresponding result page; do not claim findings in advance.

For SQLMap, demonstrate only parsing an already captured log from an authorized lab. The parser does not contact the target. An empty parsed findings list means only that the parser extracted no finding blocks from that file; it is not evidence that a target was tested or found secure.
