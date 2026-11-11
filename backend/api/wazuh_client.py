import base64
import hashlib
import json
import re
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.cache import cache


REQUEST_TIMEOUT = 10
RESULT_CACHE_SECONDS = 60
TOKEN_CACHE_SECONDS = 300
INDEX_PATTERN = "wazuh-states-vulnerabilities-*"


class WazuhClientError(RuntimeError):
    def __init__(self, message, status_code=502):
        super().__init__(message)
        self.status_code = status_code


def _validate_service_url(url, service):
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise WazuhClientError(f"{service} URL is invalid.", 503) from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise WazuhClientError(f"{service} URL is invalid.", 503)
    return url.rstrip("/")


def _ssl_context():
    if settings.WAZUH_VERIFY_TLS:
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def _request_json(url, *, method="GET", headers=None, body=None, service):
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=data, headers=request_headers, method=method)
    try:
        with urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
            context=_ssl_context(),
        ) as response:
            return json.load(response)
    except HTTPError as exc:
        if exc.code in {401, 403}:
            raise WazuhClientError(
                f"{service} rejected the configured credentials.", 502
            ) from exc
        if exc.code == 404:
            raise WazuhClientError(f"{service} resource was not found.", 502) from exc
        raise WazuhClientError(
            f"{service} request failed (HTTP {exc.code}).", 502
        ) from exc
    except (TimeoutError, ssl.SSLError) as exc:
        raise WazuhClientError(f"{service} request timed out or failed TLS validation.", 504) from exc
    except URLError as exc:
        if isinstance(exc.reason, (TimeoutError,)):
            raise WazuhClientError(f"{service} request timed out.", 504) from exc
        raise WazuhClientError(f"{service} could not be reached.", 503) from exc
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise WazuhClientError(f"{service} returned an invalid response.", 502) from exc


def _authorization(username, password):
    value = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {value}"


def _api_token(api_url):
    cached = cache.get("wazuh_api_jwt")
    if cached:
        return cached
    response = _request_json(
        f"{api_url}/security/user/authenticate",
        headers={"Authorization": _authorization(
            settings.WAZUH_API_USER, settings.WAZUH_API_PASSWORD
        )},
        service="Wazuh API",
    )
    token = response.get("data", {}).get("token") if isinstance(response, dict) else None
    if not isinstance(token, str) or not token:
        raise WazuhClientError("Wazuh API returned an invalid authentication response.")
    cache.set("wazuh_api_jwt", token, TOKEN_CACHE_SECONDS)
    return token


def _resolve_agent(identifier, api_url):
    configured_id = getattr(settings, "WAZUH_AGENT_ID", "")
    configured_name = getattr(settings, "WAZUH_AGENT_NAME", "")
    if not identifier and configured_id:
        return {"id": configured_id, "name": configured_name or configured_id}
    identifier = identifier or configured_name
    if not identifier:
        raise WazuhClientError("No Wazuh agent ID or name is configured.", 503)

    if re.fullmatch(r"\d{1,8}", identifier):
        return {"id": identifier.zfill(3), "name": identifier}

    token = _api_token(api_url)
    query = urlencode({"search": identifier})
    response = _request_json(
        f"{api_url}/agents?{query}",
        headers={"Authorization": f"Bearer {token}"},
        service="Wazuh API",
    )
    data = response.get("data", {}) if isinstance(response, dict) else {}
    candidates = data.get("affected_items", []) if isinstance(data, dict) else []
    if not isinstance(candidates, list):
        raise WazuhClientError("Wazuh API returned an invalid agent list.")
    agent = next(
        (
            item for item in candidates
            if isinstance(item, dict)
            and str(item.get("name", "")).casefold() == identifier.casefold()
        ),
        None,
    )
    if agent is None:
        raise WazuhClientError("Wazuh agent was not found.", 404)
    agent_id = str(agent.get("id", ""))
    if not agent_id:
        raise WazuhClientError("Wazuh API returned an agent without an ID.")
    return {"id": agent_id, "name": str(agent.get("name") or identifier)}


def _nested(source, *path):
    value = source
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _as_text(value):
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value) if value is not None else ""


def _severity(value, score):
    text = _as_text(value).strip().lower()
    if text in {"critical", "high", "medium", "low"}:
        return text.title()
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "Low"
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def _vulnerability_item(hit):
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise WazuhClientError("Wazuh Indexer returned an invalid vulnerability document.")
    vulnerability = source.get("vulnerability", {})
    package = source.get("package", {})
    if not isinstance(vulnerability, dict):
        vulnerability = {}
    if not isinstance(package, dict):
        package = {}
    cve_id = _as_text(
        vulnerability.get("id") or vulnerability.get("cve") or source.get("cve")
    )
    score = _nested(vulnerability, "score", "base")
    detected_at = (
        vulnerability.get("detected_at")
        or source.get("@timestamp")
        or source.get("timestamp")
        or ""
    )
    reference = vulnerability.get("reference") or vulnerability.get("references")
    reference_url = _as_text(reference)
    if reference_url:
        try:
            parsed_reference = urlsplit(reference_url)
            if parsed_reference.scheme not in {"http", "https"} or not parsed_reference.hostname:
                reference_url = ""
        except ValueError:
            reference_url = ""
    if not reference_url and cve_id:
        reference_url = f"https://nvd.nist.gov/vuln/detail/{quote(cve_id, safe='')}"
    return {
        "cve_id": cve_id,
        "severity": _severity(vulnerability.get("severity"), score),
        "cvss_score": score,
        "package_name": _as_text(package.get("name") or vulnerability.get("package")),
        "package_version": _as_text(package.get("version")),
        "description": _as_text(vulnerability.get("description")),
        "reference_url": reference_url,
        "detected_at": detected_at,
        "status": _as_text(vulnerability.get("status") or source.get("status") or "Active"),
    }


def _last_scan_time(items):
    timestamps = [item["detected_at"] for item in items if item["detected_at"]]
    return max(timestamps) if timestamps else None


def get_vulnerabilities(identifier=None):
    api_url = _validate_service_url(settings.WAZUH_API_URL, "Wazuh API")
    indexer_url = _validate_service_url(settings.WAZUH_INDEXER_URL, "Wazuh Indexer")
    required_credentials = (
        settings.WAZUH_API_USER,
        settings.WAZUH_API_PASSWORD,
        settings.WAZUH_INDEXER_USER,
        settings.WAZUH_INDEXER_PASSWORD,
    )
    if not all(required_credentials):
        raise WazuhClientError("Wazuh API or Indexer credentials are not configured.", 503)

    resolved_identifier = identifier or settings.WAZUH_AGENT_ID or settings.WAZUH_AGENT_NAME
    cache_digest = hashlib.sha256(resolved_identifier.encode("utf-8")).hexdigest()
    cache_key = f"wazuh_vulnerabilities_{cache_digest}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    agent = _resolve_agent(identifier, api_url)
    query = {
        "size": 500,
        "sort": [{"vulnerability.score.base": {"order": "desc"}}],
        "query": {
            "bool": {
                "should": [
                    {"term": {"agent.id": agent["id"]}},
                    {"term": {"agent.name": agent["name"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    index_path = quote(INDEX_PATTERN, safe="*,-_")
    response = _request_json(
        f"{indexer_url}/{index_path}/_search",
        method="POST",
        headers={
            "Authorization": _authorization(
                settings.WAZUH_INDEXER_USER,
                settings.WAZUH_INDEXER_PASSWORD,
            )
        },
        body=query,
        service="Wazuh Indexer",
    )
    hits = _nested(response, "hits", "hits")
    if not isinstance(hits, list):
        raise WazuhClientError("Wazuh Indexer returned an invalid vulnerability list.")
    if not all(isinstance(hit, dict) for hit in hits):
        raise WazuhClientError("Wazuh Indexer returned an invalid vulnerability document.")
    items = [_vulnerability_item(hit) for hit in hits]
    total_hits = _nested(response, "hits", "total")
    if isinstance(total_hits, dict):
        total_hits = total_hits.get("value")
    try:
        total_hits = int(total_hits) if total_hits is not None else len(items)
    except (TypeError, ValueError) as exc:
        raise WazuhClientError("Wazuh Indexer returned an invalid vulnerability count.") from exc
    if total_hits < len(items):
        raise WazuhClientError("Wazuh Indexer returned an inconsistent vulnerability count.")
    counts = {name: 0 for name in ("Critical", "High", "Medium", "Low")}
    packages = set()
    for item in items:
        counts[item["severity"]] += 1
        if item["package_name"]:
            packages.add(item["package_name"])
    result = {
        "agent": agent,
        "summary": {
            "critical": counts["Critical"],
            "high": counts["High"],
            "medium": counts["Medium"],
            "low": counts["Low"],
            "total": total_hits,
            "affected_packages": len(packages),
            "last_scan_time": _last_scan_time(items),
        },
        "truncated": total_hits > len(items),
        "items": items,
    }
    cache.set(cache_key, result, RESULT_CACHE_SECONDS)
    return result
