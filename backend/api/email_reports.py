import json
import logging

from django.conf import settings
from django.core.mail import EmailMessage

from .models import VulnerabilityReport

logger = logging.getLogger("security.scans")


def send_vulnerability_report(report):
    """Email the saved scan summary and raw JSON report to the configured recipient."""
    required_settings = (
        settings.SMTP_SERVER,
        settings.SENDER_EMAIL,
        settings.SENDER_PASSWORD,
        settings.RECIPIENT_EMAIL,
    )
    if not all(required_settings):
        logger.info("Vulnerability report email skipped: SMTP settings are incomplete.")
        return False

    counts = report.vulnerability_counts or {}
    total_scans = VulnerabilityReport.objects.count()
    body = "\n".join(
        [
            "Automated vulnerability scan report",
            "",
            f"Project/target: {report.project_name}",
            f"Scan type: {report.scan_type}",
            f"Report ID: {report.pk}",
            f"Total scans recorded: {total_scans}",
            "",
            "Findings in this scan:",
            f"Total vulnerabilities: {counts.get('total', 0)}",
            f"Critical: {counts.get('critical', 0)}",
            f"High: {counts.get('high', 0)}",
            f"Medium: {counts.get('medium', 0)}",
            f"Low: {counts.get('low', 0)}",
            f"Informational: {counts.get('informational', 0)}",
            "",
            "AI analysis:",
            report.gemini_analysis or "No analysis available.",
        ]
    )

    email = EmailMessage(
        subject=f"{report.scan_type} vulnerability report: {report.project_name}",
        body=body,
        from_email=settings.SENDER_EMAIL,
        to=[settings.RECIPIENT_EMAIL],
    )
    email.attach(
        f"{report.scan_type.lower()}-report-{report.pk}.json",
        json.dumps(report.raw_json_report, indent=2, ensure_ascii=False),
        "application/json",
    )

    try:
        email.send(fail_silently=False)
    except Exception:
        logger.exception("Failed to email vulnerability report %s.", report.pk)
        return False

    logger.info("Vulnerability report %s emailed successfully.", report.pk)
    return True
