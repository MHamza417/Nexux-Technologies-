from unittest.mock import patch

from django.core.management import call_command
from django.core import mail
from django.test import TestCase
from django.test.utils import override_settings
from rest_framework.test import APIClient

from .email_reports import send_vulnerability_report
from .models import VulnerabilityReport


class ScanReportMetricsTests(TestCase):
	def setUp(self):
		self.client = APIClient()

	@patch("api.views.ask_gemini", return_value="Test analysis")
	@patch("api.views.log_scan_event")
	@patch("api.views.send_vulnerability_report")
	def test_scan_reports_persist_and_metrics_aggregate(
		self, send_report, _log_scan_event, _ask_gemini
	):
		zap_report = {
			"site": [{
				"@name": "https://test.example",
				"alerts": [
					{"name": "Missing CSP", "riskdesc": "High"},
					{"name": "Reflected XSS", "riskdesc": "Critical"},
					{"name": "Cookie Without Secure Flag", "riskdesc": "Medium"},
					{"name": "Server Banner", "riskdesc": "Low"},
				],
			}],
		}
		sqlmap_report = {
			"target": "https://test.example/item?id=1",
			"findings": [
				{
					"title": "Boolean-based blind SQL injection",
					"type": "boolean-based blind",
				},
			],
		}

		zap_response = self.client.post(
			"/api/analyze-report/", zap_report, format="json"
		)
		sqlmap_response = self.client.post(
			"/api/analyze-sqlmap-report/", sqlmap_report, format="json"
		)

		self.assertEqual(zap_response.status_code, 201)
		self.assertEqual(sqlmap_response.status_code, 201)
		self.assertEqual(VulnerabilityReport.objects.count(), 2)
		self.assertEqual(send_report.call_count, 2)

		stored_zap = VulnerabilityReport.objects.get(id=zap_response.data["report_id"])
		self.assertEqual(stored_zap.project_name, "https://test.example")
		self.assertEqual(stored_zap.vulnerability_counts["total"], 4)
		self.assertEqual(stored_zap.vulnerability_counts["high_critical"], 2)

		metrics_response = self.client.get("/api/grafana-metrics/")
		metrics = {item["metric"]: item["value"] for item in metrics_response.data}

		self.assertEqual(metrics["Total Scans"], 2)
		self.assertEqual(metrics["ZAP Scans"], 1)
		self.assertEqual(metrics["SQLMap Scans"], 1)
		self.assertEqual(metrics["Critical Severity"], 1)
		self.assertEqual(metrics["High Severity"], 2)
		self.assertEqual(metrics["Critical & High Severity"], 3)
		self.assertEqual(metrics["Medium Severity"], 1)
		self.assertEqual(metrics["Low Severity"], 1)

	def test_mock_scan_command_creates_timestamped_grafana_data(self):
		call_command("populate_mock_scans", hours=24, scans=6, stdout=None)

		reports = list(VulnerabilityReport.objects.order_by("created_at"))
		self.assertEqual(len(reports), 6)
		self.assertEqual(sum(r.scan_type == "ZAP" for r in reports), 3)
		self.assertEqual(sum(r.scan_type == "SQLMap" for r in reports), 3)
		self.assertTrue(all(r.project_name.startswith("MOCK HISTORICAL SCAN ") for r in reports))
		self.assertGreaterEqual(
			(reports[-1].created_at - reports[0].created_at).total_seconds(),
			23 * 60 * 60,
		)

		metrics_response = self.client.get("/api/grafana-metrics/")
		metrics = {item["metric"]: item["value"] for item in metrics_response.data}
		self.assertEqual(metrics["Total Scans"], 6)
		self.assertEqual(metrics["ZAP Scans"], 3)
		self.assertEqual(metrics["SQLMap Scans"], 3)
		self.assertGreater(metrics["Critical Severity"], 0)
		self.assertGreater(metrics["High Severity"], 0)
		self.assertGreater(metrics["Medium Severity"], 0)
		self.assertGreater(metrics["Low Severity"], 0)

		logs_response = self.client.get("/api/grafana-logs/")
		self.assertEqual(logs_response.data["total_logs"], 6)
		self.assertEqual(
			{entry["scan_type"] for entry in logs_response.data["logs"]},
			{"ZAP", "SQLMap"},
		)
		self.assertTrue(all(entry["scan_count"] == 1 for entry in logs_response.data["logs"]))

	@override_settings(
		EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
		SMTP_SERVER="smtp.example.com",
		SMTP_PORT=587,
		SENDER_EMAIL="scanner@example.com",
		SENDER_PASSWORD="test-password",
		RECIPIENT_EMAIL="security@example.com",
	)
	def test_vulnerability_email_contains_summary_and_json_attachment(self):
		report = VulnerabilityReport.objects.create(
			project_name="https://test.example",
			raw_json_report={"findings": [{"title": "SQL injection"}]},
			gemini_analysis="Use parameterized queries.",
			scan_type="SQLMap",
			vulnerability_counts={
				"total": 1,
				"critical": 0,
				"high": 1,
				"medium": 0,
				"low": 0,
				"informational": 0,
			},
		)

		self.assertTrue(send_vulnerability_report(report))
		self.assertEqual(len(mail.outbox), 1)
		self.assertIn("Total scans recorded: 1", mail.outbox[0].body)
		self.assertIn("High: 1", mail.outbox[0].body)
		self.assertEqual(mail.outbox[0].to, ["security@example.com"])
		self.assertEqual(mail.outbox[0].attachments[0][0], "sqlmap-report-1.json")
		self.assertIn('"SQL injection"', mail.outbox[0].attachments[0][1])
