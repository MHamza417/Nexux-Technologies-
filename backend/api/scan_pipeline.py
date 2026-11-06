import base64
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from django.conf import settings


class PipelineUnavailable(RuntimeError):
    pass


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise PipelineUnavailable("Jenkins redirected the authenticated build request.")


def trigger_scan_pipeline(scan):
    if not getattr(settings, "SCAN_WORKER_ISOLATED", False):
        raise PipelineUnavailable(
            "The configured scan worker is not approved as an isolated execution environment."
        )

    base_url = getattr(settings, "JENKINS_URL", "").rstrip("/")
    job_name = getattr(settings, "JENKINS_SCAN_JOB", "")
    username = getattr(settings, "JENKINS_USER", "")
    token = getattr(settings, "JENKINS_API_TOKEN", "")
    callback_token = getattr(settings, "SCAN_PIPELINE_TOKEN", "")
    if not all((base_url, job_name, username, token, callback_token)):
        raise PipelineUnavailable("Jenkins scan pipeline credentials are not configured.")

    if not base_url.startswith("https://"):
        raise PipelineUnavailable("Jenkins must be configured with an HTTPS URL.")

    job_path = "/".join(
        f"job/{quote(segment, safe='')}"
        for segment in job_name.strip("/").split("/")
    )
    endpoint = f"{base_url}/{job_path}/buildWithParameters"
    parameters = {
        "PIPELINE_MODE": "scan",
        "SCAN_ID": str(scan.id),
        "SCAN_TARGET_TYPE": scan.target_type,
        "SCAN_TARGET": scan.target,
    }
    credentials = base64.b64encode(
        f"{username}:{token}".encode("utf-8")
    ).decode("ascii")
    request = Request(
        f"{endpoint}?{urlencode(parameters)}",
        data=b"",
        headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with build_opener(_RejectRedirects()).open(request, timeout=10) as response:
            if response.status not in {200, 201, 202}:
                raise PipelineUnavailable(
                    f"Jenkins rejected the scan request (HTTP {response.status})."
                )
    except HTTPError as exc:
        raise PipelineUnavailable(
            f"Jenkins rejected the scan request (HTTP {exc.code})."
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise PipelineUnavailable("Jenkins could not be reached.") from exc
