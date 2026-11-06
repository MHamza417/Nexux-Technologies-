import hmac
import json
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone as django_timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from .models import ScanFinding, ScanJob, VulnerabilityReport
from .serializers import ScanSubmissionSerializer
from .scan_pipeline import PipelineUnavailable, trigger_scan_pipeline
from .scan_security import (
    UnsafeTarget,
    discover_security_contact,
    send_security_report,
    validate_target,
    validate_redirect_chain,
)


class ScanStateConflict(RuntimeError):
    pass


class ScanSubmissionThrottle(ScopedRateThrottle):
    scope = "scan_submission"


class PublicScanThrottle(ScopedRateThrottle):
    scope = "public_scan_submission"


def _finding_values(scan_type, raw_report):
    if scan_type == "ZAP":
        if not isinstance(raw_report, dict) or "site" not in raw_report:
            raise ValueError("ZAP report is missing its site list.")
        sites = raw_report["site"]
        if isinstance(sites, dict):
            sites = [sites]
        if not isinstance(sites, list) or not sites:
            raise ValueError("ZAP report site data must be an object or list.")
        for site in sites:
            if (
                not isinstance(site, dict)
                or "alerts" not in site
                or not isinstance(site["alerts"], list)
            ):
                raise ValueError("ZAP report contains an invalid site or alert list.")
            for alert in site["alerts"]:
                if not isinstance(alert, dict):
                    raise ValueError("ZAP report contains an invalid alert.")
                instances = alert.get("instances", [{}])
                if not isinstance(instances, list):
                    raise ValueError("ZAP report contains an invalid alert instance list.")
                for instance in instances:
                    if not isinstance(instance, dict):
                        raise ValueError("ZAP report contains an invalid alert instance.")
                    yield {
                        "scanner": "ZAP",
                        "title": str(alert.get("name") or "Unnamed ZAP finding")[:500],
                        "severity": _severity(alert.get("riskdesc") or alert.get("risk")),
                        "affected_component": str(
                            instance.get("uri") or site.get("@name") or ""
                        )[:2048],
                        "evidence": str(
                            instance.get("evidence") or instance.get("attack") or ""
                        )[:5000],
                        "remediation": str(alert.get("solution") or "")[:10000],
                    }
    elif scan_type == "SonarQube":
        issues = raw_report.get("issues")
        if not isinstance(issues, list):
            raise ValueError("SonarQube report is missing its issue list.")
        for issue in issues:
            if not isinstance(issue, dict):
                raise ValueError("SonarQube report contains an invalid issue.")
            text_range = issue.get("textRange") or {}
            if not isinstance(text_range, dict):
                raise ValueError("SonarQube report contains an invalid issue text range.")
            component = str(issue.get("component") or "")
            if text_range.get("startLine"):
                component += f":{text_range['startLine']}"
            yield {
                "scanner": "SonarQube",
                "title": str(issue.get("message") or issue.get("rule") or "Sonar finding")[:500],
                "severity": _severity(issue.get("severity")),
                "affected_component": component[:2048],
                "evidence": str(issue.get("code") or "")[:5000],
                "remediation": str(
                    issue.get("remediation") or issue.get("ruleDescription") or ""
                )[:10000],
            }
    else:
        raise ValueError("Unsupported scanner report type.")


def _severity(value):
    normalized = str(value or "").strip().lower()
    if normalized.startswith(("critical", "blocker")):
        return "Critical"
    if normalized.startswith(("high", "major")):
        return "High"
    if normalized.startswith(("medium", "moderate")):
        return "Medium"
    if normalized.startswith(("low", "minor")):
        return "Low"
    return "Informational"


def _scan_payload(scan):
    report = getattr(scan, "report", None)
    counts = report.vulnerability_counts if report else {}
    gate_severity = getattr(settings, "SCAN_GATE_FAIL_SEVERITY", "high")
    severity_order = ["critical", "high", "medium", "low", "informational"]
    gate_index = severity_order.index(gate_severity)
    has_gate_finding = any(
        counts.get(severity, 0) > 0
        for severity in severity_order[:gate_index + 1]
    )
    if scan.status == ScanJob.Status.BLOCKED:
        overall_status = "Blocked"
    elif scan.status == ScanJob.Status.FAILED:
        overall_status = "Failed"
    elif scan.status == ScanJob.Status.COMPLETED:
        overall_status = "Failed" if has_gate_finding else "Passed"
    else:
        overall_status = None
    return {
        "scan_id": str(scan.id),
        "target_type": scan.target_type,
        "target": scan.target,
        "status": scan.status,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "failure_reason": scan.failure_reason,
        "report_id": report.id if report else None,
        "finding_count": getattr(scan, "findings_count", scan.findings.count()),
        "vulnerability_counts": counts,
        "overall_status": overall_status,
    }


@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanSubmissionThrottle])
def scan_submit(request):
    serializer = ScanSubmissionSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    target_type = data["target_type"]
    target = data["target"]
    authorized = data["authorized"]
    include_ai = data.get("include_ai", False)

    if not authorized:
        return Response(
            {"detail": "You must confirm that you own or are authorized to test this target."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if not isinstance(include_ai, bool):
        return Response({"detail": "include_ai must be a boolean."}, status=400)

    try:
        validated_target = (
            validate_redirect_chain(target)
            if target_type == ScanJob.TargetType.WEBSITE
            else validate_target(target_type, target)
        )
    except UnsafeTarget as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    scan = ScanJob.objects.create(
        owner=request.user,
        target_type=target_type,
        target=validated_target,
        authorized=True,
        include_ai=include_ai,
    )
    try:
        trigger_scan_pipeline(scan)
    except PipelineUnavailable as exc:
        scan.status = ScanJob.Status.BLOCKED
        scan.failure_reason = str(exc)
        scan.completed_at = django_timezone.now()
        scan.save(update_fields=["status", "failure_reason", "completed_at"])
        send_security_report(scan, [], failed=True)
        return Response(
            {"scan": _scan_payload(scan), "detail": str(exc)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    return Response(
        {"scan": _scan_payload(scan)},
        status=status.HTTP_202_ACCEPTED,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def scan_history(request):
    try:
        limit = min(max(int(request.query_params.get("limit", 20)), 1), 100)
    except (TypeError, ValueError):
        return Response({"detail": "limit must be an integer from 1 to 100."}, status=400)
    scans = (
        ScanJob.objects.filter(owner=request.user)
        .select_related("report")
        .annotate(findings_count=Count("findings"))
        .order_by("-created_at")[:limit]
    )
    return Response({"scans": [_scan_payload(scan) for scan in scans]})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def dashboard_summary(request):
    scans = ScanJob.objects.filter(owner=request.user)
    status_counts = {
        row["status"]: row["count"]
        for row in scans.values("status").annotate(count=Count("id"))
    }
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }
    for row in ScanFinding.objects.filter(scan__owner=request.user).values(
        "severity"
    ).annotate(count=Count("id")):
        if row["severity"] in severity_counts:
            severity_counts[row["severity"]] = row["count"]

    today = django_timezone.localdate()
    start_date = today - timedelta(days=13)
    trend_rows = (
        scans.filter(created_at__date__gte=start_date)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
    )
    trend_counts = {row["day"]: row["count"] for row in trend_rows}
    trend = [
        {
            "date": (start_date + timedelta(days=offset)).isoformat(),
            "scans": trend_counts.get(start_date + timedelta(days=offset), 0),
        }
        for offset in range(14)
    ]
    recent = (
        scans.select_related("report")
        .annotate(findings_count=Count("findings"))
        .order_by("-created_at")[:8]
    )

    return Response({
        "total_scans": sum(status_counts.values()),
        "completed_scans": status_counts.get(ScanJob.Status.COMPLETED, 0),
        "failed_scans": status_counts.get(ScanJob.Status.FAILED, 0),
        "blocked_scans": status_counts.get(ScanJob.Status.BLOCKED, 0),
        "active_scans": status_counts.get(ScanJob.Status.PENDING, 0)
        + status_counts.get(ScanJob.Status.RUNNING, 0),
        "severity_counts": severity_counts,
        "trend": trend,
        "recent_scans": [_scan_payload(scan) for scan in recent],
    })


def _owned_scan(request, scan_id):
    try:
        return ScanJob.objects.prefetch_related("findings").get(
            id=scan_id, owner=request.user
        )
    except (ScanJob.DoesNotExist, ValueError):
        return None


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def scan_detail(request, scan_id):
    scan = _owned_scan(request, scan_id)
    if scan is None:
        return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
    payload = _scan_payload(scan)
    payload["findings"] = list(scan.findings.values(
        "scanner", "title", "severity", "affected_component", "evidence",
        "remediation", "detected_at",
    ))
    return Response(payload)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def scan_report(request, scan_id):
    scan = _owned_scan(request, scan_id)
    if scan is None:
        return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
    report = getattr(scan, "report", None)
    if scan.status != ScanJob.Status.COMPLETED or report is None:
        return Response(
            {"detail": "The scan report is not available yet.", "status": scan.status},
            status=status.HTTP_409_CONFLICT,
        )
    return Response({
        **_scan_payload(scan),
        "scan_type": report.scan_type,
        "raw_report": report.raw_json_report,
        "ai_generated": report.gemini_analysis.startswith(
            "AI-generated suggestion (unverified):"
        ),
        "ai_analysis": report.gemini_analysis,
        "findings": list(scan.findings.values(
            "scanner", "title", "severity", "affected_component", "evidence",
            "remediation", "detected_at",
        )),
    })


def _save_completed_scan(scan, scan_type, raw_report):
    if not isinstance(raw_report, dict):
        raise ValueError("Scanner report must be a JSON object.")
    if scan_type not in {"ZAP", "SonarQube"}:
        raise ValueError("Unsupported scanner type.")
    expected_scanner = (
        "ZAP"
        if scan.target_type == ScanJob.TargetType.WEBSITE
        else "SonarQube"
    )
    if scan_type != expected_scanner:
        raise ValueError("Scanner type does not match the submitted target type.")

    # Import the existing helpers so all report types retain current severity
    # counts and Grafana structured logging behavior.
    from .views import ask_gemini, log_scan_event, scan_vulnerability_counts

    findings_data = list(_finding_values(scan_type, raw_report))
    ai_analysis = ""
    if scan.include_ai:
        prompt = (
            "Explain these security scan findings and give defensive remediation "
            "guidance. Label uncertainty and do not invent facts.\n"
            + json.dumps(findings_data[:100], ensure_ascii=True)
        )
        analysis = ask_gemini(prompt)
        if analysis and not analysis.lower().startswith("ai analysis unavailable"):
            ai_analysis = f"AI-generated suggestion (unverified):\n{analysis}"
        else:
            ai_analysis = analysis or "AI analysis unavailable."

    with transaction.atomic():
        scan = ScanJob.objects.select_for_update().get(id=scan.id)
        if scan.status != ScanJob.Status.RUNNING:
            raise ScanStateConflict("Only running scans can accept a report.")
        report = VulnerabilityReport.objects.create(
            scan_job=scan,
            project_name=scan.target,
            raw_json_report=raw_report,
            gemini_analysis=ai_analysis,
            scan_type=scan_type,
            vulnerability_counts=scan_vulnerability_counts(scan_type, raw_report),
        )
        ScanFinding.objects.bulk_create([
            ScanFinding(scan=scan, **finding) for finding in findings_data
        ])
        scan.status = ScanJob.Status.COMPLETED
        scan.completed_at = django_timezone.now()
        scan.failure_reason = ""
        scan.save(update_fields=[
            "status", "completed_at", "failure_reason"
        ])

    counts = report.vulnerability_counts
    log_scan_event(
        scan_type,
        scan.target,
        report.id,
        {
            "total_alerts": counts.get("total", len(findings_data)),
            "critical_high_count": counts.get("high_critical", 0),
            "medium_count": counts.get("medium", 0),
            "low_count": counts.get("low", 0),
            "info_count": counts.get("informational", 0),
        },
        raw_report,
    )

    if scan.target_type == ScanJob.TargetType.WEBSITE:
        scan.verified_contact = discover_security_contact(scan.target) or ""
        scan.save(update_fields=["verified_contact"])
    send_security_report(scan, list(scan.findings.all()))
    return scan


def _mark_failed(scan_id, reason):
    with transaction.atomic():
        scan = ScanJob.objects.select_for_update().get(id=scan_id)
        if scan.status in {ScanJob.Status.COMPLETED, ScanJob.Status.FAILED}:
            return False
        scan.status = ScanJob.Status.FAILED
        scan.failure_reason = reason[:2000]
        scan.completed_at = django_timezone.now()
        scan.save(update_fields=["status", "failure_reason", "completed_at"])
    return True


@api_view(["POST"])
@permission_classes([AllowAny])
def pipeline_callback(request, scan_id):
    expected_token = getattr(settings, "SCAN_PIPELINE_TOKEN", "")
    supplied_token = request.headers.get("X-Scan-Pipeline-Token", "")
    if not expected_token or not hmac.compare_digest(supplied_token, expected_token):
        return Response({"detail": "Unauthorized pipeline callback."}, status=401)
    try:
        maximum_bytes = int(getattr(settings, "MAX_SCAN_REPORT_BYTES", 20 * 1024 * 1024))
    except (TypeError, ValueError):
        maximum_bytes = 20 * 1024 * 1024
    try:
        request_bytes = int(request.META.get("CONTENT_LENGTH", 0))
    except (TypeError, ValueError):
        request_bytes = 0
    if request_bytes > maximum_bytes:
        return Response({"detail": "Scanner report exceeds the configured size limit."}, status=413)
    if not isinstance(request.data, dict):
        return Response({"detail": "Request body must be a JSON object."}, status=400)

    try:
        scan = ScanJob.objects.get(id=scan_id)
    except (ScanJob.DoesNotExist, ValueError):
        return Response({"detail": "Scan not found."}, status=404)

    if (
        request.data.get("target_type") != scan.target_type
        or request.data.get("target") != scan.target
    ):
        return Response(
            {"detail": "Pipeline target does not match the authorized scan."},
            status=status.HTTP_403_FORBIDDEN,
        )

    callback_status = request.data.get("status")
    if callback_status == "running":
        with transaction.atomic():
            scan = ScanJob.objects.select_for_update().get(id=scan_id)
            if scan.status != ScanJob.Status.PENDING:
                return Response({"detail": "Invalid scan status transition."}, status=409)
            scan.status = ScanJob.Status.RUNNING
            scan.started_at = django_timezone.now()
            scan.save(update_fields=["status", "started_at"])
        return Response({"status": scan.status})

    if callback_status == "failed":
        reason = str(request.data.get("error") or "Scanner pipeline failed.")[:2000]
        if not _mark_failed(scan_id, reason):
            return Response({"detail": "Invalid scan status transition."}, status=409)
        scan.refresh_from_db()
        send_security_report(scan, [], failed=True)
        return Response({"status": ScanJob.Status.FAILED})

    if callback_status != "completed":
        return Response({"detail": "Unknown callback status."}, status=400)

    raw_report = request.data.get("report")
    scan_type = request.data.get("scan_type")
    try:
        scan = _save_completed_scan(scan, scan_type, raw_report)
    except ScanStateConflict as exc:
        return Response({"detail": str(exc)}, status=409)
    except (ValueError, TypeError) as exc:
        if not _mark_failed(scan_id, str(exc)):
            return Response({"detail": "Scan reached a terminal status."}, status=409)
        return Response({"detail": str(exc)}, status=400)

    return Response({"status": scan.status, "report_id": scan.report.id})


def _access_token_matches(scan, token):
    expected = scan.access_token or ""
    supplied = token if isinstance(token, str) else ""
    if not expected or len(supplied) != len(expected):
        return False
    return hmac.compare_digest(supplied, expected)


def _public_scan(scan_id, token):
    try:
        return (
            ScanJob.objects.select_related("report")
            .prefetch_related("findings")
            .get(id=scan_id)
        )
    except ScanJob.DoesNotExist:
        return None


def _authorized_public_scan(scan_id, token):
    scan = _public_scan(scan_id, token)
    if scan is None or not _access_token_matches(scan, token):
        return None
    return scan


def _pipeline_stage(scan):
    if scan.status == ScanJob.Status.BLOCKED:
        return "blocked"
    if scan.status == ScanJob.Status.FAILED:
        return "failed"
    if scan.status == ScanJob.Status.COMPLETED:
        return "reported"
    if scan.status == ScanJob.Status.RUNNING:
        return "scanning"
    return "queued"


def _public_scan_body(scan):
    payload = _scan_payload(scan)
    report = getattr(scan, "report", None)
    payload["pipeline_stage"] = _pipeline_stage(scan)
    payload["findings"] = list(scan.findings.values(
        "scanner", "title", "severity", "affected_component", "evidence",
        "remediation", "detected_at",
    ))
    if report is not None:
        payload["scan_type"] = report.scan_type
        payload["ai_generated"] = report.gemini_analysis.startswith(
            "AI-generated suggestion (unverified):"
        )
        payload["ai_analysis"] = report.gemini_analysis
    return payload


def _queue_validated_scan(owner, target_type, target, include_ai, access_token=""):
    try:
        validated_target = (
            validate_redirect_chain(target)
            if target_type == ScanJob.TargetType.WEBSITE
            else validate_target(target_type, target)
        )
    except UnsafeTarget as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

    scan = ScanJob.objects.create(
        owner=owner,
        target_type=target_type,
        target=validated_target,
        authorized=True,
        include_ai=include_ai,
        access_token=access_token,
    )
    try:
        trigger_scan_pipeline(scan)
    except PipelineUnavailable as exc:
        scan.status = ScanJob.Status.BLOCKED
        scan.failure_reason = str(exc)
        scan.completed_at = django_timezone.now()
        scan.save(update_fields=["status", "failure_reason", "completed_at"])
        send_security_report(scan, [], failed=True)
        body = {"scan": _scan_payload(scan), "detail": str(exc)}
        if access_token:
            body["access_token"] = access_token
        return Response(body, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    body = {"scan": _scan_payload(scan)}
    if access_token:
        body["access_token"] = access_token
    return Response(body, status=status.HTTP_202_ACCEPTED)


@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([PublicScanThrottle])
def public_scan_submit(request):
    serializer = ScanSubmissionSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    if not data["authorized"]:
        return Response(
            {"detail": "You must confirm that you own or are authorized to test this target."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    include_ai = data.get("include_ai", False)
    if not isinstance(include_ai, bool):
        return Response({"detail": "include_ai must be a boolean."}, status=400)
    return _queue_validated_scan(
        owner=None,
        target_type=data["target_type"],
        target=data["target"],
        include_ai=include_ai,
        access_token=secrets.token_urlsafe(32),
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def public_scan_detail(request, scan_id):
    scan = _authorized_public_scan(
        scan_id, request.headers.get("X-Scan-Access-Token", "")
    )
    if scan is None:
        return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
    return Response(_public_scan_body(scan))


@api_view(["GET"])
@permission_classes([AllowAny])
def public_scan_download(request, scan_id):
    scan = _authorized_public_scan(
        scan_id, request.headers.get("X-Scan-Access-Token", "")
    )
    if scan is None:
        return Response({"detail": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
    report = getattr(scan, "report", None)
    if scan.status != ScanJob.Status.COMPLETED or report is None:
        return Response(
            {"detail": "The scan report is not available yet.", "status": scan.status},
            status=status.HTTP_409_CONFLICT,
        )
    payload = _public_scan_body(scan)
    payload["raw_report"] = report.raw_json_report
    response = Response(payload)
    response["Content-Disposition"] = (
        f'attachment; filename="intellisecops-{scan.id}.json"'
    )
    return response
