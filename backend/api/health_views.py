import base64
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


def _check_service(name, base_url, path, headers=None, require_up=False):
    if not base_url:
        return {"status": "error", "detail": f"{name} URL is not configured."}

    try:
        parsed_url = urlsplit(base_url)
    except ValueError:
        return {"status": "error", "detail": f"{name} URL is invalid."}
    if (
        parsed_url.scheme not in {"https", "http"}
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
    ):
        return {"status": "error", "detail": f"{name} URL is invalid."}
    if (
        name == "Jenkins"
        and parsed_url.scheme != "https"
        and not getattr(settings, "ALLOW_INSECURE_JENKINS", False)
    ):
        return {
            "status": "error",
            "detail": "Jenkins must be configured with an HTTPS URL.",
        }

    request = Request(f"{base_url.rstrip('/')}{path}", headers=headers or {})
    try:
        with urlopen(request, timeout=5) as response:
            result = {"status": "OK", "http_status": response.status}
            if require_up:
                try:
                    sonar_status = json.loads(response.read()).get("status")
                except (AttributeError, TypeError, ValueError):
                    return {
                        "status": "error",
                        "detail": "SonarQube returned an invalid status response.",
                        "http_status": response.status,
                    }
                if sonar_status != "UP":
                    return {
                        "status": "error",
                        "detail": f"SonarQube status is {sonar_status or 'unknown'}.",
                        "http_status": response.status,
                    }
            return result
    except HTTPError as exc:
        return {
            "status": "error",
            "detail": f"{name} returned HTTP {exc.code}.",
            "http_status": exc.code,
        }
    except URLError as exc:
        return {"status": "error", "detail": f"{name} could not be reached: {exc.reason}"}
    except (TimeoutError, OSError) as exc:
        return {"status": "error", "detail": f"{name} could not be reached: {exc}"}


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def integrations_health(request):
    sonar_headers = {}
    sonar_token = getattr(settings, "SONAR_TOKEN", "")
    if sonar_token:
        credentials = base64.b64encode(f"{sonar_token}:".encode("utf-8")).decode("ascii")
        sonar_headers["Authorization"] = f"Basic {credentials}"

    return Response({
        "jenkins": _check_service(
            "Jenkins",
            getattr(settings, "JENKINS_URL", ""),
            "/login",
        ),
        "sonarqube": _check_service(
            "SonarQube",
            getattr(settings, "SONAR_URL", ""),
            "/api/system/status",
            headers=sonar_headers,
            require_up=True,
        ),
    })
