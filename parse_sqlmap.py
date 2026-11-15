#!/usr/bin/env python3
"""
parse_sqlmap.py

SQLMap doesn't produce clean JSON by default — it prints results to stdout/log
in plain text. This script reads SQLMap's captured text output, extracts the
vulnerable parameters and injection details using regex, and writes a clean
JSON file in the format expected by the Django endpoint:

    /api/analyze-sqlmap-report/

Usage:
    python3 parse_sqlmap.py <target_url> <sqlmap_log_file> <output_json_file>

Example:
    python3 parse_sqlmap.py "https://authorized.example/item?id=1" \
        sqlmap-reports/sqlmap_output.log \
        sqlmap-reports/sqlmap_findings.json
"""

import sys
import re
import json


def parse_sqlmap_log(log_text):
    """
    Extracts vulnerable parameter blocks from SQLMap's plain-text output.

    SQLMap typically prints blocks like:

        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1 AND 1=1

        Type: time-based blind
            Title: MySQL >= 5.0.12 AND time-based blind
            Payload: id=1 AND SLEEP(5)
    """
    findings = []

    # Split the log into per-parameter blocks
    param_blocks = re.split(r"\nParameter:\s*", log_text)

    for block in param_blocks[1:]:  # skip text before the first "Parameter:"
        param_header_match = re.match(r"([^\s(]+)\s*\(([^)]+)\)", block)
        param_name = param_header_match.group(1) if param_header_match else "unknown"
        param_place = param_header_match.group(2) if param_header_match else "unknown"

        # A single parameter block can contain multiple injection "Type" sections
        type_sections = re.split(r"\n\s*Type:\s*", block)

        for section in type_sections[1:]:  # skip the header part
            type_match = re.match(r"([^\n]+)", section)
            title_match = re.search(r"Title:\s*([^\n]+)", section)
            payload_match = re.search(r"Payload:\s*([^\n]+)", section)

            findings.append({
                "parameter": param_name,
                "location": param_place,
                "type": type_match.group(1).strip() if type_match else "unknown",
                "title": title_match.group(1).strip() if title_match else "SQL Injection",
                "payload": payload_match.group(1).strip() if payload_match else ""
            })

    return findings


def detect_dbms(log_text):
    """Try to pull the back-end DBMS name if SQLMap identified one."""
    match = re.search(r"back-end DBMS:\s*([^\n]+)", log_text)
    return match.group(1).strip() if match else "unknown"


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 parse_sqlmap.py <target_url> <sqlmap_log_file> <output_json_file>")
        sys.exit(1)

    target_url = sys.argv[1]
    log_file = sys.argv[2]
    output_file = sys.argv[3]

    try:
        with open(log_file, "r", errors="ignore") as f:
            log_text = f.read()
    except OSError as exc:
        print(f"ERROR: cannot read SQLMap log: {exc}", file=sys.stderr)
        sys.exit(1)

    findings = parse_sqlmap_log(log_text)
    dbms = detect_dbms(log_text)

    result = {
        "target": target_url,
        "dbms": dbms,
        "findings": findings
    }

    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Parsed {len(findings)} finding(s) from SQLMap log.")
    print(f"Output written to: {output_file}")


if __name__ == "__main__":
    main()