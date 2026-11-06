import ipaddress
import http.client
from html import escape
import logging
import re
import smtplib
import socket
import ssl
from datetime import datetime, timezone as datetime_timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

import dns.resolver
import dns.exception
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.core.validators import validate_email
from django.utils import timezone


logger = logging.getLogger("security.scans")
MAX_SECURITY_TXT_BYTES = 64 * 1024
GITHUB_REPOSITORY_PATH = re.compile(r"^/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class UnsafeTarget(ValueError):
    pass


def _resolve_public_host(hostname):
    addresses = set()
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(
                hostname, record_type, lifetime=2, search=False
            )
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            raise UnsafeTarget("Target hostname could not be resolved safely.") from exc
        addresses.update(answer.address for answer in answers)

    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise UnsafeTarget("Target must resolve only to public IP addresses.")
    if len(addresses) > 32:
        raise UnsafeTarget("Target has an unusually large DNS response.")
    return addresses


def validate_website_target(target):
    if not isinstance(target, str) or len(target) > 2048:
        raise UnsafeTarget("Target URL is missing or too long.")

    try:
        parsed = urlsplit(target.strip())
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTarget("Target URL is malformed.") from exc

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise UnsafeTarget("Website targets must use an HTTP or HTTPS URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise UnsafeTarget("Credentials and URL fragments are not allowed.")

    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UnsafeTarget("Target hostname is malformed.") from exc
    if hostname in {"localhost"} or hostname.endswith(
        (".localhost", ".local", ".internal", ".test", ".invalid", ".onion")
    ):
        raise UnsafeTarget("Local and reserved hostnames are not allowed.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise UnsafeTarget("Website targets must use a public DNS hostname.")

    expected_port = 80 if parsed.scheme.lower() == "http" else 443
    if port not in {None, expected_port}:
        raise UnsafeTarget("Only standard HTTP and HTTPS ports are allowed.")

    _resolve_public_host(hostname)
    netloc = hostname
    if port:
        netloc = f"{netloc}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))


def validate_github_target(target):
    if not isinstance(target, str) or len(target) > 2048:
        raise UnsafeTarget("Repository URL is missing or too long.")

    try:
        parsed = urlsplit(target.strip())
        port = parsed.port
    except ValueError as exc:
        raise UnsafeTarget("Repository URL is malformed.") from exc

    if (
        parsed.scheme.lower() != "https"
        or parsed.hostname is None
        or parsed.hostname.lower() != "github.com"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
        or not GITHUB_REPOSITORY_PATH.fullmatch(parsed.path)
    ):
        raise UnsafeTarget("Only public HTTPS GitHub owner/repository URLs are supported.")

    _resolve_public_host("github.com")
    owner, repository = parsed.path.strip("/").removesuffix(".git").split("/", 1)
    return f"https://github.com/{owner}/{repository}.git"


def validate_target(target_type, target):
    if target_type == "website":
        return validate_website_target(target)
    if target_type == "repository":
        return validate_github_target(target)
    raise UnsafeTarget("Target type must be 'website' or 'repository'.")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname, address, port, timeout):
        self.address = address
        super().__init__(hostname, port=port, timeout=timeout)

    def connect(self):
        self.sock = socket.create_connection(
            (self.address, self.port), self.timeout
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, address, port, timeout):
        self.address = address
        super().__init__(
            hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )

    def connect(self):
        sock = socket.create_connection(
            (self.address, self.port), self.timeout
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _pinned_request(url, method, timeout=5, max_bytes=0):
    parsed = urlsplit(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    addresses = sorted(_resolve_public_host(hostname))
    last_error = None

    for address in addresses[:3]:
        connection = (
            _PinnedHTTPSConnection(hostname, address, port, timeout)
            if parsed.scheme == "https"
            else _PinnedHTTPConnection(hostname, address, port, timeout)
        )
        try:
            connection.request(
                method,
                path,
                headers={"User-Agent": "IntelliSecOps-Target-Validation/1.0"},
            )
            response = connection.getresponse()
            body = response.read(max_bytes + 1) if max_bytes else b""
            return response.status, {
                key.lower(): value for key, value in response.getheaders()
            }, body
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()

    raise UnsafeTarget("Could not connect to the public target address.") from last_error


def validate_redirect_chain(target, maximum_redirects=5):
    """Resolve and revalidate each HTTP redirect before a scan is queued."""
    current = validate_website_target(target)
    visited = set()
    for _ in range(maximum_redirects + 1):
        if current in visited:
            raise UnsafeTarget("Target contains a redirect loop.")
        visited.add(current)
        response_status, headers, _body = _pinned_request(current, "HEAD")
        if response_status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if location:
                next_url = validate_website_target(urljoin(current, location))
                if (
                    urlsplit(current).scheme == "https"
                    and urlsplit(next_url).scheme != "https"
                ):
                    raise UnsafeTarget("HTTPS targets may not redirect to HTTP.")
                current = next_url
                continue
            return current
        return current
    raise UnsafeTarget("Target exceeds the redirect limit.")


def discover_security_contact(target):
    """Return only a same-host email published by that host's HTTPS security.txt."""
    try:
        validated_target = validate_website_target(target)
        parsed = urlsplit(validated_target)
        hostname = parsed.hostname
        if parsed.scheme != "https" or parsed.port not in {None, 443}:
            return None

        for path in ("/.well-known/security.txt", "/security.txt"):
            security_url = urlunsplit(("https", hostname, path, "", ""))
            for _ in range(4):
                try:
                    response_status, headers, content = _pinned_request(
                        security_url,
                        "GET",
                        timeout=5,
                        max_bytes=MAX_SECURITY_TXT_BYTES,
                    )
                except UnsafeTarget:
                    content = b""
                    break
                if response_status in {301, 302, 303, 307, 308}:
                    location = headers.get("location")
                    if not location:
                        content = b""
                        break
                    security_url = validate_website_target(
                        urljoin(security_url, location)
                    )
                    if urlsplit(security_url).hostname != hostname:
                        content = b""
                        break
                    continue
                if response_status != 200:
                    content = b""
                break
            if len(content) > MAX_SECURITY_TXT_BYTES:
                continue
            if not content:
                continue

            fields = {}
            for line in content.decode("utf-8", errors="replace").splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    fields.setdefault(key.strip().lower(), []).append(value.strip())
            expirations = fields.get("expires", [])
            if not expirations:
                continue
            try:
                expires_at = datetime.fromisoformat(
                    expirations[0].replace("Z", "+00:00")
                )
            except ValueError:
                continue
            if expires_at.tzinfo is None or expires_at <= datetime.now(datetime_timezone.utc):
                continue

            for contact in fields.get("contact", []):
                if not contact.lower().startswith("mailto:"):
                    continue
                email = contact[7:].split("?", 1)[0].strip()
                try:
                    validate_email(email)
                except ValidationError:
                    continue
                if email.rsplit("@", 1)[1].lower() != hostname:
                    continue
                try:
                    records = dns.resolver.resolve(
                        hostname, "MX", lifetime=2, search=False
                    )
                except dns.exception.DNSException:
                    continue
                if any(str(record.exchange) != "." for record in records):
                    return email
    except (UnsafeTarget, UnicodeError, ValueError):
        logger.info("No verified security contact discovered for submitted target.")
    return None


def send_security_report(scan, findings, failed=False):
    if not getattr(settings, "SECURITY_NOTIFICATIONS_ENABLED", False):
        return False
    recipient = scan.verified_contact
    if not recipient:
        return False
    if scan.notification_attempted_at:
        return False

    is_failed = failed or scan.status in {"failed", "blocked"}
    counts = {}
    if hasattr(scan, "report"):
        counts = scan.report.vulnerability_counts or {}

    lines = [
        f"IntelliSecOps scan {scan.status} for {scan.target}.",
        f"Scan ID: {scan.id}",
        f"Target type: {scan.target_type}",
        f"Completed: {scan.completed_at.isoformat() if scan.completed_at else 'unknown'}",
    ]
    if is_failed:
        lines.extend(["", f"Reason: {scan.failure_reason or 'The scan did not complete.'}"])
    else:
        lines.extend([
            "",
            "Severity summary:",
            *[
                f"- {severity.title()}: {counts.get(severity, 0)}"
                for severity in ("critical", "high", "medium", "low", "informational")
            ],
            "",
            "Important findings:",
        ])
    for finding in findings:
        lines.extend([
            f"- [{finding.severity}] {finding.title}",
            f"  Affected component: {finding.affected_component or 'Not specified'}",
            f"  Remediation: {finding.remediation or 'Not provided by the scanner'}",
        ])
    if not findings:
        if not is_failed:
            lines.append("- No findings were reported by the configured scanner.")

    frontend_url = getattr(settings, "FRONTEND_BASE_URL", "").rstrip("/")
    if frontend_url:
        lines.extend([
            "",
            "Sign in to IntelliSecOps to view the private report:",
            f"{frontend_url}/?scan_id={scan.id}",
        ])

    if not all((
        settings.EMAIL_HOST,
        settings.EMAIL_HOST_USER,
        settings.EMAIL_HOST_PASSWORD,
        settings.DEFAULT_FROM_EMAIL,
    )):
        logger.warning(
            "SMTP is incomplete; report email was not sent for scan %s.", scan.id
        )
        return False

    scan.notification_attempted_at = timezone.now()
    scan.save(update_fields=["notification_attempted_at"])

    subject = f"Security scan report for {scan.target}"
    findings_html = "".join(
        "<li>"
        f"<strong>{escape(finding.severity)}: {escape(finding.title)}</strong>"
        f"<p>Affected component: {escape(finding.affected_component or 'Not specified')}</p>"
        f"<p>Remediation: {escape(finding.remediation or 'Not provided by the scanner')}</p>"
        "</li>"
        for finding in findings
    )
    if not findings_html and not is_failed:
        findings_html = "<li>No findings were reported by the configured scanner.</li>"
    report_link = (
        f'<p><a href="{escape(frontend_url)}/?scan_id={escape(str(scan.id))}">'
        "Sign in to IntelliSecOps to view the private report.</a></p>"
        if frontend_url
        else ""
    )
    html_message = (
        "<!doctype html><html><body>"
        f"<h1>{escape(subject)}</h1>"
        f"<p><strong>Status:</strong> {escape(scan.status)}</p>"
        f"<p><strong>Target:</strong> {escape(scan.target)}</p>"
        f"<p><strong>Scan ID:</strong> {escape(str(scan.id))}</p>"
        f"<p><strong>Completed:</strong> "
        f"{escape(scan.completed_at.isoformat() if scan.completed_at else 'unknown')}</p>"
        + (
            f"<p><strong>Reason:</strong> {escape(scan.failure_reason or 'The scan did not complete.')}</p>"
            if is_failed
            else (
                "<h2>Severity summary</h2><ul>"
                + "".join(
                    f"<li>{severity.title()}: {counts.get(severity, 0)}</li>"
                    for severity in ("critical", "high", "medium", "low", "informational")
                )
                + "</ul><h2>Findings</h2><ul>"
                + findings_html
                + "</ul>"
            )
        )
        + report_link
        + "</body></html>"
    )

    try:
        send_mail(
            subject=subject,
            message="\n".join(lines),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False,
            html_message=html_message,
        )
    except (OSError, smtplib.SMTPException):
        logger.exception("Could not deliver scan notification for scan %s.", scan.id)
        return False
    scan.notification_sent_at = timezone.now()
    scan.save(update_fields=["notification_sent_at"])
    return True
