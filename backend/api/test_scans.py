from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from . import scan_security
from .models import ScanJob, VulnerabilityReport
from .scan_pipeline import PipelineUnavailable, trigger_scan_pipeline
from .scan_views import _finding_values


class TargetValidationTests(TestCase):
    @patch("api.scan_security._resolve_public_host", return_value={"93.184.216.34"})
    def test_website_target_normalizes_scheme_and_host(self, _resolve):
        self.assertEqual(
            scan_security.validate_website_target("HTTPS://Example.com"),
            "https://example.com/",
        )

    @patch("api.scan_security.dns.resolver.resolve")
    def test_website_target_rejects_private_dns_answers(self, resolve):
        resolve.side_effect = [
            [SimpleNamespace(address="10.1.2.3")],
            scan_security.dns.resolver.NoAnswer(),
        ]
        with self.assertRaises(scan_security.UnsafeTarget):
            scan_security.validate_website_target("https://example.com")

    def test_website_target_rejects_ip_literals_and_invalid_schemes(self):
        for target in ("http://127.0.0.1", "file://example.com/report"):
            with self.subTest(target=target), self.assertRaises(scan_security.UnsafeTarget):
                scan_security.validate_website_target(target)

    @patch("api.scan_security._resolve_public_host", return_value={"140.82.112.3"})
    def test_github_repository_restricts_host_and_path(self, _resolve):
        self.assertEqual(
            scan_security.validate_github_target("https://github.com/owner/repo"),
            "https://github.com/owner/repo.git",
        )
        for target in (
            "https://github.example/owner/repo",
            "https://github.com/owner/repo/issues",
            "https://user:pass@github.com/owner/repo",
        ):
            with self.subTest(target=target), self.assertRaises(scan_security.UnsafeTarget):
                scan_security.validate_github_target(target)

    @patch("api.scan_security._resolve_public_host", return_value={"93.184.216.34"})
    @patch(
        "api.scan_security._pinned_request",
        return_value=(302, {"location": "http://10.0.0.5/private"}, b""),
    )
    def test_redirect_target_is_revalidated(self, _request, _resolve):
        with self.assertRaises(scan_security.UnsafeTarget):
            scan_security.validate_redirect_chain("https://example.com")

    @patch("api.scan_security.dns.resolver.resolve", return_value=[object()])
    @patch("api.scan_security._resolve_public_host", return_value={"93.184.216.34"})
    @patch(
        "api.scan_security._pinned_request",
        return_value=(
            200,
            {},
            b"Expires: 2099-01-01T00:00:00Z\nContact: mailto:security@example.com\n",
        ),
    )
    def test_security_txt_contact_requires_same_host_and_mx(
        self, _request, _resolve, _mx
    ):
        _mx.return_value = [SimpleNamespace(exchange="mail.example.com.")]
        self.assertEqual(
            scan_security.discover_security_contact("https://example.com"),
            "security@example.com",
        )


class ScanApiTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.owner = user_model.objects.create_user(username="owner")
        self.other_user = user_model.objects.create_user(username="other")
        self.client = APIClient()

    def authenticated_as(self, user=None):
        self.client.force_authenticate(user=user or self.owner)

    @patch("api.scan_views.trigger_scan_pipeline")
    @patch("api.scan_views.validate_redirect_chain", return_value="https://example.com/")
    def test_submission_requires_auth_and_authorization(
        self, _validate_redirects, trigger_pipeline
    ):
        body = {
            "target_type": "website",
            "target": "https://example.com",
            "authorized": True,
        }
        self.assertEqual(self.client.post("/api/scans/", body, format="json").status_code, 401)
        self.authenticated_as()
        response = self.client.post(
            "/api/scans/", {**body, "authorized": False}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        trigger_pipeline.assert_not_called()

    @patch("api.scan_views.trigger_scan_pipeline")
    @patch("api.scan_views.validate_redirect_chain", return_value="https://example.com/")
    def test_submission_creates_pending_owned_scan(
        self, _validate_redirects, _trigger_pipeline
    ):
        self.authenticated_as()
        response = self.client.post(
            "/api/scans/",
            {
                "target_type": "website",
                "target": "https://example.com",
                "authorized": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 202)
        scan = ScanJob.objects.get(id=response.data["scan"]["scan_id"])
        self.assertEqual(scan.owner, self.owner)
        self.assertEqual(scan.status, ScanJob.Status.PENDING)

    @patch(
        "api.scan_views.validate_redirect_chain",
        side_effect=scan_security.UnsafeTarget("Target must resolve only to public IP addresses."),
    )
    def test_submission_rejects_unsafe_target(self, _validate_redirects):
        self.authenticated_as()
        response = self.client.post(
            "/api/scans/",
            {
                "target_type": "website",
                "target": "http://metadata.internal",
                "authorized": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(ScanJob.objects.count(), 0)

    @patch("api.scan_views.validate_redirect_chain", return_value="https://example.com/")
    def test_pipeline_unavailable_marks_scan_failed(
        self, _validate_redirects
    ):
        self.authenticated_as()

        from .scan_pipeline import PipelineUnavailable

        with patch(
            "api.scan_views.trigger_scan_pipeline",
            side_effect=PipelineUnavailable("Jenkins unavailable"),
        ):
            response = self.client.post(
                "/api/scans/",
                {
                    "target_type": "website",
                    "target": "https://example.com",
                    "authorized": True,
                },
                format="json",
            )
        self.assertEqual(response.status_code, 503)
        scan = ScanJob.objects.get()
        self.assertEqual(scan.status, ScanJob.Status.BLOCKED)
        self.assertEqual(scan.failure_reason, "Jenkins unavailable")

    @override_settings(SCAN_PIPELINE_TOKEN="pipeline-secret")
    @patch("api.scan_views.send_security_report", return_value=False)
    @patch("api.scan_views.discover_security_contact", return_value=None)
    @patch("api.views.log_scan_event")
    def test_callback_stores_findings_metrics_and_enforces_report_ownership(
        self, _log_event, _discover_contact, _send_report
    ):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.WEBSITE,
            target="https://example.com/",
            authorized=True,
            status=ScanJob.Status.RUNNING,
        )
        zap_report = {
            "site": [{
                "@name": "https://example.com/",
                "alerts": [{
                    "name": "Missing CSP",
                    "riskdesc": "High",
                    "solution": "Configure a restrictive Content-Security-Policy.",
                    "instances": [{
                        "uri": "https://example.com/",
                        "evidence": "header absent",
                    }],
                }],
            }],
        }
        response = self.client.post(
            f"/api/scans/{scan.id}/pipeline-result/",
            {
                "status": "completed",
                "target_type": scan.target_type,
                "target": scan.target,
                "scan_type": "ZAP",
                "report": zap_report,
            },
            format="json",
            HTTP_X_SCAN_PIPELINE_TOKEN="pipeline-secret",
        )
        self.assertEqual(response.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanJob.Status.COMPLETED)
        self.assertEqual(scan.findings.count(), 1)
        finding = scan.findings.get()
        self.assertEqual(finding.severity, "High")
        self.assertEqual(finding.affected_component, "https://example.com/")
        self.assertEqual(finding.evidence, "header absent")
        self.assertEqual(VulnerabilityReport.objects.count(), 1)

        self.authenticated_as(self.other_user)
        self.assertEqual(
            self.client.get(f"/api/scans/{scan.id}/report/").status_code, 404
        )
        self.authenticated_as(self.owner)
        report_response = self.client.get(f"/api/scans/{scan.id}/report/")
        self.assertEqual(report_response.status_code, 200)
        self.assertEqual(report_response.data["findings"][0]["title"], "Missing CSP")
        self.assertFalse(report_response.data["ai_generated"])

        self.client.force_authenticate(user=None)
        legacy_reports = self.client.get("/api/analyze-report/")
        self.assertEqual(legacy_reports.status_code, 401)
        audit_search = self.client.get(
            "/api/audit/search/?table=reports&query=example&mode=raw"
        )
        self.assertEqual(audit_search.status_code, 401)
        grafana_logs = self.client.get("/api/grafana-logs/")
        self.assertEqual(grafana_logs.status_code, 401)
        metrics = self.client.get("/api/grafana-metrics/")
        self.assertEqual(metrics.status_code, 401)

        self.authenticated_as(self.owner)
        grafana_logs = self.client.get("/api/grafana-logs/")
        self.assertEqual(grafana_logs.data["logs"][0]["project"], "Authorized scan")
        self.assertIn("Private report", grafana_logs.data["logs"][0]["analysis_preview"])

        metrics = self.client.get("/api/grafana-metrics/")
        values = {item["metric"]: item["value"] for item in metrics.data}
        self.assertEqual(values["Total Scans"], 1)
        self.assertEqual(values["High Severity"], 1)

    @override_settings(SCAN_PIPELINE_TOKEN="pipeline-secret")
    def test_callback_rejects_wrong_token_and_updates_running_status(self):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.REPOSITORY,
            target="https://github.com/owner/repo.git",
            authorized=True,
        )
        url = f"/api/scans/{scan.id}/pipeline-result/"
        denied = self.client.post(url, {"status": "running"}, format="json")
        self.assertEqual(denied.status_code, 401)
        accepted = self.client.post(
            url,
            {
                "status": "running",
                "target_type": scan.target_type,
                "target": scan.target,
            },
            format="json",
            HTTP_X_SCAN_PIPELINE_TOKEN="pipeline-secret",
        )
        self.assertEqual(accepted.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanJob.Status.RUNNING)

    @override_settings(SCAN_PIPELINE_TOKEN="pipeline-secret")
    def test_pipeline_failure_is_terminal_and_report_stays_unavailable(self):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.REPOSITORY,
            target="https://github.com/owner/repo.git",
            authorized=True,
        )
        response = self.client.post(
            f"/api/scans/{scan.id}/pipeline-result/",
            {
                "status": "failed",
                "error": "Repository issue export is not configured.",
                "target_type": scan.target_type,
                "target": scan.target,
            },
            format="json",
            HTTP_X_SCAN_PIPELINE_TOKEN="pipeline-secret",
        )
        self.assertEqual(response.status_code, 200)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanJob.Status.FAILED)
        self.assertEqual(scan.findings.count(), 0)

    @override_settings(SCAN_PIPELINE_TOKEN="pipeline-secret")
    def test_callback_rejects_a_target_not_bound_to_the_scan(self):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.WEBSITE,
            target="https://example.com/",
            authorized=True,
        )
        response = self.client.post(
            f"/api/scans/{scan.id}/pipeline-result/",
            {
                "status": "running",
                "target_type": scan.target_type,
                "target": "https://different.example/",
            },
            format="json",
            HTTP_X_SCAN_PIPELINE_TOKEN="pipeline-secret",
        )
        self.assertEqual(response.status_code, 403)
        scan.refresh_from_db()
        self.assertEqual(scan.status, ScanJob.Status.PENDING)

    def test_sonarqube_findings_map_severity_and_file_line(self):
        findings = list(_finding_values("SonarQube", {
            "issues": [{
                "message": "Unsafe deserialization",
                "severity": "BLOCKER",
                "component": "src/service.py",
                "textRange": {"startLine": 17},
            }],
        }))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertEqual(findings[0]["affected_component"], "src/service.py:17")

    def test_scanner_parsers_reject_incomplete_report_shapes(self):
        with self.assertRaisesRegex(ValueError, "missing its site list"):
            list(_finding_values("ZAP", {}))
        with self.assertRaisesRegex(ValueError, "missing its issue list"):
            list(_finding_values("SonarQube", {}))

    def test_deleting_scan_owner_does_not_orphan_private_report(self):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.WEBSITE,
            target="https://example.com/",
            authorized=True,
        )
        VulnerabilityReport.objects.create(
            scan_job=scan,
            project_name=scan.target,
            raw_json_report={},
            gemini_analysis="",
        )
        scan_id = scan.id
        self.owner.delete()
        self.assertFalse(ScanJob.objects.filter(id=scan_id).exists())
        self.assertEqual(VulnerabilityReport.objects.count(), 0)

    @patch("api.scan_security.send_mail", side_effect=OSError("SMTP unavailable"))
    @override_settings(
        SECURITY_NOTIFICATIONS_ENABLED=True,
        EMAIL_HOST="smtp.example.com",
        EMAIL_HOST_USER="service",
        EMAIL_HOST_PASSWORD="smtp-secret",
        DEFAULT_FROM_EMAIL="scanner@example.com",
    )
    def test_email_delivery_failure_does_not_claim_success(self, send_mail):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.WEBSITE,
            target="https://example.com/",
            authorized=True,
            notification_email="unverified@example.net",
            verified_contact="security@example.com",
        )
        self.assertFalse(scan_security.send_security_report(scan, []))
        send_mail.assert_called_once()
        self.assertEqual(
            send_mail.call_args.kwargs["recipient_list"],
            ["security@example.com"],
        )
        self.assertIn("<html>", send_mail.call_args.kwargs["html_message"])

    @override_settings(SECURITY_NOTIFICATIONS_ENABLED=False)
    @patch("api.scan_security.send_mail")
    def test_email_is_disabled_without_explicit_opt_in(self, send_mail):
        scan = ScanJob.objects.create(
            owner=self.owner,
            target_type=ScanJob.TargetType.WEBSITE,
            target="https://example.com/",
            authorized=True,
            verified_contact="security@example.com",
        )
        self.assertFalse(scan_security.send_security_report(scan, []))
        send_mail.assert_not_called()


class JenkinsPipelineConfigTests(TestCase):
    def setUp(self):
        self.scan = SimpleNamespace(
            id="scan-id",
            target_type="website",
            target="https://example.com/",
        )

    @override_settings(
        SCAN_WORKER_ISOLATED=True,
        JENKINS_URL="http://jenkins.internal:8080",
        JENKINS_SCAN_JOB="IntelliSecOps/Scan",
        JENKINS_USER="scanner",
        JENKINS_API_TOKEN="jenkins-token",
        SCAN_PIPELINE_TOKEN="callback-token",
        ALLOW_INSECURE_JENKINS=False,
    )
    def test_http_jenkins_url_is_rejected_by_default(self):
        with self.assertRaisesRegex(PipelineUnavailable, "HTTPS URL"):
            trigger_scan_pipeline(self.scan)

    @override_settings(
        SCAN_WORKER_ISOLATED=True,
        JENKINS_URL="http://jenkins.internal:8080",
        JENKINS_SCAN_JOB="IntelliSecOps/Scan",
        JENKINS_USER="scanner",
        JENKINS_API_TOKEN="jenkins-token",
        SCAN_PIPELINE_TOKEN="callback-token",
        ALLOW_INSECURE_JENKINS=True,
    )
    def test_allowed_http_request_uses_configured_job_and_timeout(self):
        response = MagicMock()
        response.status = 201
        response.__enter__.return_value = response
        opener = MagicMock()
        opener.open.return_value = response
        with patch("api.scan_pipeline.build_opener", return_value=opener):
            trigger_scan_pipeline(self.scan)

        request = opener.open.call_args.args[0]
        self.assertIn(
            "http://jenkins.internal:8080/job/IntelliSecOps/job/Scan/buildWithParameters",
            request.full_url,
        )
        self.assertIn("PIPELINE_MODE=scan", request.full_url)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 10)


class IntegrationsHealthTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="health-reader")
        self.client = APIClient()
        self.client.force_authenticate(user=user)

    @override_settings(
        JENKINS_URL="https://jenkins.example",
        SONAR_URL="https://sonar.example",
        SONAR_TOKEN="sonar-token",
    )
    def test_health_endpoint_checks_both_services_and_authenticates_sonar(self):
        jenkins_response = MagicMock()
        jenkins_response.status = 200
        jenkins_response.__enter__.return_value = jenkins_response
        sonar_response = MagicMock()
        sonar_response.status = 200
        sonar_response.read.return_value = b'{"status":"UP"}'
        sonar_response.__enter__.return_value = sonar_response
        with patch(
            "api.health_views.urlopen",
            side_effect=[jenkins_response, sonar_response],
        ) as open_url:
            result = self.client.get("/api/integrations/health/")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data["jenkins"]["status"], "OK")
        self.assertEqual(result.data["sonarqube"]["status"], "OK")
        self.assertEqual(open_url.call_count, 2)
        self.assertEqual(open_url.call_args_list[1].kwargs["timeout"], 5)
        self.assertTrue(
            open_url.call_args_list[1].args[0]
            .get_header("Authorization")
            .startswith("Basic ")
        )

    def test_health_endpoint_requires_authentication(self):
        self.client.force_authenticate(user=None)
        response = self.client.get("/api/integrations/health/")
        self.assertEqual(response.status_code, 401)

    @override_settings(
        JENKINS_URL="https://jenkins.example",
        SONAR_URL="https://sonar.example",
        SONAR_TOKEN="",
    )
    def test_health_endpoint_reports_connection_errors(self):
        from urllib.error import URLError

        with patch(
            "api.health_views.urlopen",
            side_effect=URLError("connection refused"),
        ):
            response = self.client.get("/api/integrations/health/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["jenkins"]["status"], "error")
        self.assertIn("connection refused", response.data["jenkins"]["detail"])
        self.assertEqual(response.data["sonarqube"]["status"], "error")


class PublicScanApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    @patch("api.scan_views.trigger_scan_pipeline")
    @patch("api.scan_views.validate_redirect_chain", return_value="https://example.com/")
    def test_public_submission_is_token_gated_and_does_not_require_login(
        self, _validate_redirects, trigger_pipeline
    ):
        response = self.client.post(
            "/api/public/scans/",
            {
                "target_type": "website",
                "target": "https://example.com",
                "authorized": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 202)
        trigger_pipeline.assert_called_once()
        scan = ScanJob.objects.get()
        self.assertIsNone(scan.owner)
        token = response.data["access_token"]
        self.assertEqual(scan.access_token, token)
        self.assertEqual(
            self.client.get(f"/api/public/scans/{scan.id}/").status_code,
            404,
        )
        visible = self.client.get(
            f"/api/public/scans/{scan.id}/",
            HTTP_X_SCAN_ACCESS_TOKEN=token,
        )
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.data["pipeline_stage"], "queued")
        self.assertNotIn("access_token", visible.data)
        self.assertEqual(
            self.client.get(f"/api/scans/{scan.id}/").status_code,
            401,
        )

    @patch(
        "api.scan_views.validate_target",
        side_effect=scan_security.UnsafeTarget("Unsupported repository URL."),
    )
    def test_public_submission_rejects_unsafe_repository(self, _validate_target):
        response = self.client.post(
            "/api/public/scans/",
            {
                "target_type": "repository",
                "target": "https://github.com/owner/repo",
                "authorized": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(ScanJob.objects.count(), 0)

    @override_settings(SCAN_PIPELINE_TOKEN="pipeline-secret")
    @patch("api.scan_views.send_security_report", return_value=False)
    @patch("api.scan_views.discover_security_contact", return_value=None)
    @patch("api.views.log_scan_event")
    def test_public_download_and_grafana_include_completed_scan(
        self, _log_event, _discover_contact, _send_report
    ):
        scan = ScanJob.objects.create(
            owner=None,
            target_type=ScanJob.TargetType.WEBSITE,
            target="https://example.com/",
            authorized=True,
            status=ScanJob.Status.RUNNING,
            access_token="public-token",
        )
        response = self.client.post(
            f"/api/scans/{scan.id}/pipeline-result/",
            {
                "status": "completed",
                "target_type": scan.target_type,
                "target": scan.target,
                "scan_type": "ZAP",
                "report": {
                    "site": [{
                        "@name": "https://example.com/",
                        "alerts": [{
                            "name": "Missing CSP",
                            "riskdesc": "Medium",
                            "solution": "Set a Content-Security-Policy header.",
                            "instances": [{"uri": "https://example.com/", "evidence": "absent"}],
                        }],
                    }],
                },
            },
            format="json",
            HTTP_X_SCAN_PIPELINE_TOKEN="pipeline-secret",
        )
        self.assertEqual(response.status_code, 200)
        denied = self.client.get(f"/api/public/scans/{scan.id}/download/")
        self.assertEqual(denied.status_code, 404)
        downloaded = self.client.get(
            f"/api/public/scans/{scan.id}/download/",
            HTTP_X_SCAN_ACCESS_TOKEN="public-token",
        )
        self.assertEqual(downloaded.status_code, 200)
        self.assertIn("attachment;", downloaded["Content-Disposition"])
        self.assertEqual(downloaded.data["findings"][0]["severity"], "Medium")
        self.assertIn("site", downloaded.data["raw_report"])

        user = get_user_model().objects.create_user(username="metrics")
        self.client.force_authenticate(user=user)
        metrics = self.client.get("/api/grafana-metrics/")
        values = {item["metric"]: item["value"] for item in metrics.data}
        self.assertGreaterEqual(values["Total Scans"], 1)
        self.assertGreaterEqual(values["Medium Severity"], 1)
