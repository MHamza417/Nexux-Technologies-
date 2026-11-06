import os
import tempfile
import unittest
from unittest.mock import patch

from sonar_issues_report import fetch_issues, wait_for_analysis


class SonarReportTests(unittest.TestCase):
    @patch("sonar_issues_report.api_get")
    def test_fetch_issues_collects_all_pages(self, api_get):
        api_get.side_effect = [
            {
                "paging": {"total": 2},
                "issues": [{
                    "message": "First",
                    "severity": "CRITICAL",
                    "component": "src/a.py",
                    "rule": "python:S123",
                    "textRange": {"startLine": 7},
                    "unneeded": "omitted",
                }],
            },
            {
                "paging": {"total": 2},
                "issues": [{
                    "message": "Second",
                    "severity": "MAJOR",
                    "component": "src/b.py",
                }],
            },
        ]

        issues = fetch_issues("https://sonar.example", "token", "scan-uuid")

        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]["severity"], "CRITICAL")
        self.assertNotIn("unneeded", issues[0])
        self.assertIn("p=1", api_get.call_args_list[0].args[0])
        self.assertIn("p=2", api_get.call_args_list[1].args[0])

    @patch("sonar_issues_report.api_get", return_value={})
    def test_fetch_issues_rejects_invalid_response_instead_of_empty_report(self, _api_get):
        with self.assertRaisesRegex(RuntimeError, "invalid issue-search response"):
            fetch_issues("https://sonar.example", "token", "scan-uuid")

    @patch("sonar_issues_report.api_get", return_value={"task": {"status": "SUCCESS"}})
    def test_wait_for_analysis_requires_scanner_task_file(self, _api_get):
        with tempfile.TemporaryDirectory() as project_directory:
            scanner_work = os.path.join(project_directory, ".scannerwork")
            os.makedirs(scanner_work)
            with open(
                os.path.join(scanner_work, "report-task.txt"),
                "w",
                encoding="utf-8",
            ) as task_file:
                task_file.write("ceTaskId=task-id\n")

            wait_for_analysis("https://sonar.example", "token", project_directory)
