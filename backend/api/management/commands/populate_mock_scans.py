from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from api.models import VulnerabilityReport


ZAP_ALERT_TEMPLATES = [
    [
        ("Content Security Policy Header Not Set", "High"),
        ("Missing Anti-clickjacking Header", "Medium"),
        ("Server Leaks Version Information", "Low"),
    ],
    [
        ("SQL Injection", "Critical"),
        ("Cookie Without Secure Flag", "Medium"),
    ],
    [
        ("Cross-Domain Misconfiguration", "High"),
        ("X-Content-Type-Options Header Missing", "Low"),
        ("Timestamp Disclosure", "Informational"),
        ("CSP: Wildcard Directive", "Medium"),
    ],
    [
        ("Cross-Site Scripting", "Critical"),
        ("CORS Misconfiguration", "High"),
        ("Information Disclosure", "Low"),
    ],
    [
        ("Cookie Without HttpOnly Flag", "Medium"),
        ("Server Banner Disclosure", "Low"),
    ],
    [
        ("Path Traversal", "High"),
        ("Sensitive Information in URL", "Informational"),
        ("Weak Cache-Control Policy", "Medium"),
    ],
]

SQLMAP_FINDING_TEMPLATES = [
    ("Boolean-based blind SQL injection", "High"),
    ("Time-based blind SQL injection", "Critical"),
    ("Error-based SQL injection", "High"),
]


class Command(BaseCommand):
    help = "Seed timestamped mock ZAP and SQLMap reports for Grafana testing."

    def add_arguments(self, parser):
        parser.add_argument(
            "--hours",
            type=int,
            default=36,
            help="Historical window to populate (24 to 48 hours; default: 36).",
        )
        parser.add_argument(
            "--scans",
            type=int,
            default=48,
            help="Number of scan records to create (default: 48).",
        )
        parser.add_argument(
            "--replace",
            action="store_true",
            help="Delete records previously created by this command before seeding.",
        )

    def handle(self, *args, **options):
        hours = options["hours"]
        scan_count = options["scans"]
        if not 24 <= hours <= 48:
            raise CommandError("--hours must be between 24 and 48.")
        if scan_count < 2:
            raise CommandError("--scans must be at least 2.")

        mock_prefix = "MOCK HISTORICAL SCAN "
        if options["replace"]:
            deleted, _ = VulnerabilityReport.objects.filter(
                project_name__startswith=mock_prefix
            ).delete()
            self.stdout.write(f"Removed {deleted} prior mock record(s).")

        end_time = timezone.now()
        start_time = end_time - timedelta(hours=hours)
        records = []

        for index in range(scan_count):
            event_time = start_time + (end_time - start_time) * index / (scan_count - 1)
            scan_type = "ZAP" if index % 2 == 0 else "SQLMap"
            if scan_type == "ZAP":
                alerts = ZAP_ALERT_TEMPLATES[(index // 2) % len(ZAP_ALERT_TEMPLATES)]
                raw_report = {
                    "site": [{
                        "@name": "https://staging.example.test",
                        "alerts": [
                            {
                                "name": name,
                                "riskdesc": severity,
                                "desc": "Synthetic historical finding for dashboard testing.",
                                "solution": "Review and apply the recommended security control.",
                            }
                            for name, severity in alerts
                        ],
                    }],
                    "_mock_data": True,
                }
                counts = self._count_zap_alerts(alerts)
            else:
                finding_count = 1 + ((index // 2) % len(SQLMAP_FINDING_TEMPLATES))
                findings = [
                    {
                        "title": title,
                        "type": title.split(" SQL injection")[0].lower(),
                        "severity": severity,
                        "parameter": "item_id",
                        "location": "GET",
                    }
                    for title, severity in SQLMAP_FINDING_TEMPLATES[:finding_count]
                ]
                raw_report = {
                    "target": "https://staging.example.test/items?item_id=1",
                    "dbms": "mock database",
                    "findings": findings,
                    "_mock_data": True,
                }
                counts = self._count_sqlmap_findings(findings)

            record = VulnerabilityReport.objects.create(
                project_name=f"{mock_prefix}{index + 1:03d}",
                raw_json_report=raw_report,
                gemini_analysis="Synthetic historical record generated for Grafana testing.",
                scan_type=scan_type,
                vulnerability_counts=counts,
            )
            record.scan_date = event_time
            record.created_at = event_time
            record.save(update_fields=["scan_date", "created_at"])
            records.append(record)

        zap_total = sum(record.scan_type == "ZAP" for record in records)
        sqlmap_total = len(records) - zap_total
        self.stdout.write(self.style.SUCCESS(
            f"Created {len(records)} mock scans over {hours} hours "
            f"({zap_total} ZAP, {sqlmap_total} SQLMap)."
        ))

    @staticmethod
    def _count_zap_alerts(alerts):
        counts = {
            "total": len(alerts),
            "critical": 0,
            "high": 0,
            "high_critical": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for _, severity in alerts:
            key = severity.lower()
            if key == "critical":
                counts["critical"] += 1
                counts["high_critical"] += 1
            elif key == "high":
                counts["high"] += 1
                counts["high_critical"] += 1
            elif key == "medium":
                counts["medium"] += 1
            elif key == "low":
                counts["low"] += 1
            else:
                counts["informational"] += 1
        return counts

    @staticmethod
    def _count_sqlmap_findings(findings):
        counts = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "high_critical": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for finding in findings:
            severity = finding["severity"].lower()
            if severity == "critical":
                counts["critical"] += 1
                counts["high_critical"] += 1
            elif severity == "high":
                counts["high"] += 1
                counts["high_critical"] += 1
            elif severity == "medium":
                counts["medium"] += 1
            elif severity == "low":
                counts["low"] += 1
            else:
                counts["informational"] += 1
        return counts