import base64
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


PAGE_SIZE = 500
MAX_ISSUES = 10000
TIMEOUT_SECONDS = 15
ANALYSIS_TIMEOUT_SECONDS = 900


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise RuntimeError("SonarQube redirected an authenticated report request.")


def api_get(url, token):
    encoded_token = base64.b64encode(f"{token}:".encode("utf-8")).decode("ascii")
    request = Request(
        url,
        headers={
            "Authorization": f"Basic {encoded_token}",
            "Accept": "application/json",
            "User-Agent": "IntelliSecOps-Sonar-Report/1.0",
        },
    )
    try:
        with build_opener(_RejectRedirects()).open(
            request, timeout=TIMEOUT_SECONDS
        ) as response:
            return json.load(response)
    except HTTPError as exc:
        raise RuntimeError(
            f"SonarQube report request failed (HTTP {exc.code})."
        ) from exc
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("SonarQube report request could not be completed.") from exc


def fetch_issues(server_url, token, project_key):
    server_url = server_url.rstrip("/")
    issues = []
    page = 1
    total = None
    while total is None or len(issues) < total:
        query = urlencode({
            "componentKeys": project_key,
            "types": "VULNERABILITY",
            "ps": PAGE_SIZE,
            "p": page,
        })
        payload = api_get(f"{server_url}/api/issues/search?{query}", token)
        if not isinstance(payload, dict) or not isinstance(payload.get("paging"), dict):
            raise RuntimeError("SonarQube returned an invalid issue-search response.")
        try:
            total = int(payload["paging"]["total"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("SonarQube returned an invalid issue count.") from exc
        if total < 0:
            raise RuntimeError("SonarQube returned a negative issue count.")
        if total > MAX_ISSUES:
            raise RuntimeError(
                f"SonarQube reported {total} issues; the export limit is {MAX_ISSUES}."
            )
        page_issues = payload.get("issues")
        if not isinstance(page_issues, list):
            raise RuntimeError("SonarQube returned an invalid issue list.")
        if len(page_issues) > PAGE_SIZE or len(issues) + len(page_issues) > total:
            raise RuntimeError("SonarQube returned an inconsistent issue page.")
        issues.extend(page_issues)
        if not page_issues or len(issues) >= total:
            if len(issues) < total:
                raise RuntimeError("SonarQube returned an incomplete issue report.")
            break
        page += 1

    normalized = []
    for issue in issues:
        if not isinstance(issue, dict):
            raise RuntimeError("SonarQube returned an invalid issue.")
        text_range = issue.get("textRange", {})
        if not isinstance(text_range, dict):
            raise RuntimeError("SonarQube returned an invalid issue text range.")
        normalized.append({
            "message": issue.get("message", ""),
            "severity": issue.get("severity", ""),
            "component": issue.get("component", ""),
            "rule": issue.get("rule", ""),
            "textRange": text_range,
        })
    return normalized


def wait_for_analysis(server_url, token, project_directory):
    task_file = os.path.join(project_directory, ".scannerwork", "report-task.txt")
    try:
        with open(task_file, encoding="utf-8") as report_task:
            task_id = next(
                line.partition("=")[2].strip()
                for line in report_task
                if line.startswith("ceTaskId=")
            )
    except (OSError, StopIteration) as exc:
        raise RuntimeError("SonarQube analysis task ID was not produced.") from exc

    deadline = time.monotonic() + ANALYSIS_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        payload = api_get(
            f"{server_url.rstrip('/')}/api/ce/task?{urlencode({'id': task_id})}",
            token,
        )
        task = payload.get("task") if isinstance(payload, dict) else None
        if not isinstance(task, dict):
            raise RuntimeError("SonarQube returned an invalid analysis task.")
        state = task.get("status")
        if state == "SUCCESS":
            return
        if state in {"FAILED", "CANCELED"}:
            raise RuntimeError(f"SonarQube analysis finished with status {state}.")
        if state not in {"PENDING", "IN_PROGRESS"}:
            raise RuntimeError("SonarQube returned an unknown analysis task status.")
        time.sleep(3)
    raise RuntimeError("SonarQube analysis did not finish before the timeout.")


def main():
    server_url = os.environ.get("SONAR_HOST_URL", "")
    token = os.environ.get("SONAR_AUTH_TOKEN", "")
    project_key = os.environ.get("SONAR_PROJECT_KEY", "")
    project_directory = os.environ.get("SONAR_PROJECT_DIRECTORY", "")
    parsed_server = urlsplit(server_url)
    if (
        parsed_server.scheme not in {"http", "https"}
        or not parsed_server.hostname
        or parsed_server.username
        or parsed_server.password
        or (parsed_server.scheme != "https"
            and os.environ.get("SONAR_API_ALLOW_INSECURE") != "true")
        or not token
        or not project_key
        or not project_directory
    ):
        raise RuntimeError("SonarQube URL, token, project key, and project path are required.")

    wait_for_analysis(server_url, token, project_directory)
    report = {
        "status": "completed",
        "scan_type": "SonarQube",
        "target_type": os.environ.get("SCAN_TARGET_TYPE", ""),
        "target": os.environ.get("SCAN_TARGET", ""),
        "report": {
            "issues": fetch_issues(server_url, token, project_key),
        },
    }
    print(json.dumps(report, ensure_ascii=True))


if __name__ == "__main__":
    main()
