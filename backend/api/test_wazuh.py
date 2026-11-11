import json
from io import BytesIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIClient


class MockResponse(BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def response(payload):
    return MockResponse(json.dumps(payload).encode("utf-8"))


@override_settings(
    WAZUH_API_URL="https://wazuh.example:55000",
    WAZUH_API_USER="api-user",
    WAZUH_API_PASSWORD="api-password",
    WAZUH_INDEXER_URL="https://wazuh.example:9200",
    WAZUH_INDEXER_USER="indexer-user",
    WAZUH_INDEXER_PASSWORD="indexer-password",
    WAZUH_VERIFY_TLS=False,
    WAZUH_AGENT_ID="",
    WAZUH_AGENT_NAME="Docker",
)
class WazuhVulnerabilityApiTests(TestCase):
    def setUp(self):
        cache.clear()
        user = get_user_model().objects.create_user(username="wazuh-reader")
        self.client = APIClient()
        self.client.force_authenticate(user=user)

    @patch(
        "api.wazuh_client.urlopen",
        side_effect=[
            response({"data": {"token": "mock-jwt"}}),
            response({"data": {"affected_items": [{"id": "001", "name": "Docker"}]}}),
            response({
                "hits": {
                    "total": {"value": 2},
                    "hits": [
                        {
                            "_source": {
                                "@timestamp": "2026-11-10T12:00:00Z",
                                "agent": {"id": "001", "name": "Docker"},
                                "vulnerability": {
                                    "id": "CVE-2026-1111",
                                    "severity": "Critical",
                                    "score": {"base": 9.8},
                                    "description": "A critical library issue.",
                                    "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-1111",
                                    "status": "Active",
                                },
                                "package": {"name": "openssl", "version": "3.0.1"},
                            },
                        },
                        {
                            "_source": {
                                "@timestamp": "2026-11-09T12:00:00Z",
                                "agent": {"id": "001", "name": "Docker"},
                                "vulnerability": {
                                    "id": "CVE-2026-2222",
                                    "severity": "High",
                                    "score": {"base": 8.1},
                                    "description": "A high severity package issue.",
                                },
                                "package": {"name": "curl", "version": "8.0"},
                            },
                        },
                    ],
                },
            }),
        ],
    )
    def test_authenticated_endpoint_resolves_agent_and_returns_summary(self, mocked_urlopen):
        result = self.client.get("/api/wazuh/vulnerabilities/")

        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.data["agent"], {"id": "001", "name": "Docker"})
        self.assertEqual(result.data["summary"], {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "total": 2,
            "affected_packages": 2,
            "last_scan_time": "2026-11-10T12:00:00Z",
        })
        self.assertEqual(result.data["items"][0]["cve_id"], "CVE-2026-1111")
        self.assertEqual(result.data["items"][0]["package_name"], "openssl")
        self.assertEqual(mocked_urlopen.call_count, 3)
        cached_result = self.client.get("/api/wazuh/vulnerabilities/")
        self.assertEqual(cached_result.data, result.data)
        self.assertEqual(mocked_urlopen.call_count, 3)
        self.assertTrue(all(
            call.kwargs["timeout"] == 10
            for call in mocked_urlopen.call_args_list
        ))

        index_request = mocked_urlopen.call_args_list[-1].args[0]
        query = json.loads(index_request.data.decode("utf-8"))
        self.assertEqual(query["size"], 500)
        self.assertEqual(
            query["sort"][0],
            {"vulnerability.score.base": {"order": "desc"}},
        )
        self.assertEqual(
            index_request.full_url,
            "https://wazuh.example:9200/wazuh-states-vulnerabilities-*/_search",
        )

    def test_endpoint_requires_authentication(self):
        self.client.force_authenticate(user=None)
        result = self.client.get("/api/wazuh/vulnerabilities/")
        self.assertEqual(result.status_code, 401)

    @patch("api.wazuh_client.urlopen", return_value=response({
        "data": {"affected_items": []},
    }))
    def test_unknown_agent_returns_clear_not_found_error(self, _mocked_urlopen):
        from django.core.cache import cache

        cache.set("wazuh_api_jwt", "mock-jwt", 60)
        result = self.client.get("/api/wazuh/vulnerabilities/?agent=Missing")
        self.assertEqual(result.status_code, 404)
        self.assertEqual(result.data["detail"], "Wazuh agent was not found.")
