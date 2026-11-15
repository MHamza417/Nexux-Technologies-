import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import parse_sqlmap


class ParseSQLMapTests(unittest.TestCase):
    def test_missing_log_fails_without_writing_an_empty_report(self):
        with tempfile.TemporaryDirectory() as directory:
            missing_log = Path(directory) / "missing.log"
            output_file = Path(directory) / "report.json"
            stderr = io.StringIO()

            with patch(
                "sys.argv",
                ["parse_sqlmap.py", "https://authorized.example", str(missing_log), str(output_file)],
            ), contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
                parse_sqlmap.main()

            self.assertEqual(error.exception.code, 1)
            self.assertIn("cannot read SQLMap log", stderr.getvalue())
            self.assertFalse(output_file.exists())

    def test_existing_log_is_normalized_to_json(self):
        with tempfile.TemporaryDirectory() as directory:
            log_file = Path(directory) / "sqlmap.log"
            output_file = Path(directory) / "report.json"
            log_file.write_text(
                "back-end DBMS: PostgreSQL\n"
                "Parameter: item (GET)\n"
                "    Type: boolean-based blind\n"
                "    Title: Boolean-based blind\n"
                "    Payload: item=1\n",
                encoding="utf-8",
            )

            with patch(
                "sys.argv",
                ["parse_sqlmap.py", "https://authorized.example/item?id=1", str(log_file), str(output_file)],
            ):
                parse_sqlmap.main()

            report = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(report["dbms"], "PostgreSQL")
            self.assertEqual(len(report["findings"]), 1)
            self.assertEqual(report["findings"][0]["parameter"], "item")


if __name__ == "__main__":
    unittest.main()
