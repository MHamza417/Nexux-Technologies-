import os
import json
import logging
from datetime import datetime, timezone
from google import genai

from decouple import config
from django.db import connection
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny

from .models import VulnerabilityReport, Service, Project, Team, ContactMessage
from .serializers import (
    ServiceSerializer,
    ProjectSerializer,
    TeamSerializer,
    ContactMessageSerializer,
)

scan_logger = logging.getLogger("security.scans")
audit_logger = logging.getLogger("security.audit")


def zap_alerts_from_report(data):
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []

    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]
    if not isinstance(sites, list):
        return []

    return [
        alert
        for site in sites
        if isinstance(site, dict)
        for alert in site.get("alerts", [])
        if isinstance(alert, dict)
    ]


def scan_vulnerability_counts(scan_type, raw_report):
    counts = {
        "total": 0,
        "critical": 0,
        "high": 0,
        "high_critical": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    if scan_type == "ZAP":
        for alert in zap_alerts_from_report(raw_report):
            risk = str(alert.get("riskdesc") or alert.get("risk") or "").lower()
            counts["total"] += 1
            if "critical" in risk:
                counts["critical"] += 1
                counts["high_critical"] += 1
            elif "high" in risk:
                counts["high"] += 1
                counts["high_critical"] += 1
            elif "medium" in risk:
                counts["medium"] += 1
            elif "low" in risk:
                counts["low"] += 1
            else:
                counts["informational"] += 1
    elif scan_type == "SQLMap" and isinstance(raw_report, dict):
        findings = raw_report.get("findings", [])
        if isinstance(findings, list):
            counts["total"] = len(findings)
            for finding in findings:
                severity = str(
                    finding.get("severity") or finding.get("risk") or "High"
                ).lower()
                if "critical" in severity:
                    counts["critical"] += 1
                    counts["high_critical"] += 1
                elif "high" in severity:
                    counts["high"] += 1
                    counts["high_critical"] += 1
                elif "medium" in severity:
                    counts["medium"] += 1
                elif "low" in severity:
                    counts["low"] += 1
                else:
                    counts["informational"] += 1

    return counts


def get_gemini_client():
    """
    Configure and return the modern Google GenAI client.
    """
    api_key = config("GEMINI_API_KEY", default=None)

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is missing.")

    client = genai.Client(api_key=api_key)
    return client


def ask_gemini(prompt):
    """
    Shared helper: sends a prompt to Gemini and safely returns text,
    falling back to a placeholder if the API fails or quota is hit.
    """
    try:
        client = get_gemini_client()
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        return response.text or "Analysis generated placeholder."
    except Exception as ai_err:
        print("AI Generation Skipped due to Quota/Error:", str(ai_err))
        return (
            "AI Analysis unavailable due to API quota limits or network issue. "
            "Please check the raw JSON report data for complete vulnerability details."
        )


def log_scan_event(scan_type, project_name, report_id, summary_metrics, raw_data):
    """
    Logs scan outputs in structured JSON format for Grafana dashboard integration
    and automated SIEM/log analyzer consumption.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "timestamp": now_iso,
        "event_type": "security_scan_analyzed",
        "scan_type": scan_type,
        "project_name": str(project_name),
        "report_id": report_id,
        "metrics": summary_metrics,
        "status": "PROCESSED",
    }
    json_line = json.dumps(log_entry)
    scan_logger.info(json_line)

    # Export structured JSON to dedicated Grafana log file
    try:
        logs_dir = getattr(settings, "LOGS_DIR", None)
        if logs_dir:
            os.makedirs(logs_dir, exist_ok=True)
            export_path = os.path.join(str(logs_dir), "grafana_scans.json")
            existing_logs = []
            if os.path.exists(export_path):
                try:
                    with open(export_path, "r", encoding="utf-8") as f:
                        existing_logs = json.load(f)
                        if not isinstance(existing_logs, list):
                            existing_logs = []
                except Exception:
                    existing_logs = []
            existing_logs.append(log_entry)
            # Keep latest 150 scans in active export
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(existing_logs[-150:], f, indent=2)
    except Exception as err:
        print("Grafana log export error:", str(err))

    return log_entry


def log_audit_event(query_param, table_name, mode, result_count, exec_time_ms, client_ip):
    """
    Logs dynamic query audit evaluation events in structured JSON format.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "timestamp": now_iso,
        "event_type": "security_audit_query",
        "query_param": query_param,
        "table": table_name,
        "mode": mode,
        "result_count": result_count,
        "execution_time_ms": round(exec_time_ms, 2),
        "client_ip": client_ip or "127.0.0.1",
        "status": "AUDITED",
    }
    json_line = json.dumps(log_entry)
    audit_logger.info(json_line)
    return log_entry


# --- OWASP ZAP Report Analysis & Audit Endpoint ---

class AnalyzeReportView(APIView):
    """
    POST: Receives OWASP ZAP JSON report, summarizes it, sends to Gemini,
          and logs structured scan outputs for Grafana dashboard integration.
    GET:  Allows querying reports by ID (with raw query handling for security auditing labs).
    """

    def get(self, request):
        report_id = request.GET.get("id")
        if report_id is not None:
            start_time = datetime.now()
            results = []
            error_message = None

            # Educational security auditing: raw SQL query demonstration for SQLMap integration
            sql_query = f"SELECT id, project_name, scan_type, created_at, gemini_analysis FROM api_vulnerabilityreport WHERE id = {report_id}"
            try:
                with connection.cursor() as cursor:
                    cursor.execute(sql_query)
                    cols = [col[0] for col in cursor.description] if cursor.description else []
                    for row in cursor.fetchall():
                        item = dict(zip(cols, row))
                        if "created_at" in item and item["created_at"]:
                            item["created_at"] = str(item["created_at"])
                        results.append(item)
            except Exception as e:
                error_message = str(e)

            elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000
            client_ip = request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR")
            log_audit_event(report_id, "api_vulnerabilityreport", "raw_sql", len(results), elapsed_ms, client_ip)

            if error_message:
                return Response(
                    {
                        "status": "error",
                        "message": error_message,
                        "query_executed": sql_query,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response(
                {
                    "status": "success",
                    "query_executed": sql_query,
                    "count": len(results),
                    "results": results,
                },
                status=status.HTTP_200_OK,
            )

        # If no id passed, return recent scans list
        reports = VulnerabilityReport.objects.all().order_by("-created_at")[:20]
        summary_list = [
            {
                "id": r.id,
                "project_name": r.project_name,
                "scan_type": r.scan_type,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "has_analysis": bool(r.gemini_analysis),
            }
            for r in reports
        ]
        return Response(
            {
                "status": "success",
                "count": len(summary_list),
                "reports": summary_list,
            },
            status=status.HTTP_200_OK,
        )

    def post(self, request):
        try:
            data = request.data
            sites = data.get("site", []) if isinstance(data, dict) else []
            first_site = sites[0] if isinstance(sites, list) and sites else {}
            project_name = (
                first_site.get("@name") or first_site.get("name")
                if isinstance(first_site, dict)
                else None
            ) or "IntelliSecOps Project"

            # --- TOKEN OPTIMIZATION ---
            alerts_summary = [
                {
                    "risk": alert.get("riskdesc") or alert.get("risk"),
                    "name": alert.get("name"),
                    "description": alert.get("desc"),
                    "solution": alert.get("solution"),
                }
                for alert in zap_alerts_from_report(data)
            ]

            report_payload = alerts_summary if alerts_summary else data

            prompt = f"""
You are a cybersecurity expert.

Analyze the following OWASP ZAP security report summary:

{json.dumps(report_payload, indent=2)}

Provide:
1. Executive summary
2. Total vulnerabilities count
3. Critical and high-risk vulnerabilities
4. Medium and low-risk vulnerabilities
5. Explanation of important security issues
6. Recommended fixes
7. Overall security assessment
"""

            gemini_text = ask_gemini(prompt)

            # Save report in database
            report_obj = VulnerabilityReport.objects.create(
                project_name=str(project_name),
                raw_json_report=data,
                gemini_analysis=gemini_text,
                scan_type="ZAP",
                vulnerability_counts=scan_vulnerability_counts("ZAP", data),
            )

            # Calculate risk metrics breakdown for Grafana structured logging
            saved_counts = report_obj.vulnerability_counts

            scan_metrics = {
                "total_alerts": len(alerts_summary),
                "critical_high_count": saved_counts["high_critical"],
                "medium_count": saved_counts["medium"],
                "low_count": saved_counts["low"],
                "info_count": saved_counts["informational"],
            }

            # Log scan output in structured JSON format
            log_scan_event("ZAP", project_name, report_obj.id, scan_metrics, data)

            return Response(
                {
                    "status": "success",
                    "message": "Report analyzed, logged in structured JSON, and saved successfully!",
                    "report_id": report_obj.id,
                    "metrics": scan_metrics,
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            print("Server Error:", str(e))
            return Response(
                {
                    "status": "error",
                    "message": str(e),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


# --- SQLMap Report Analysis ---

class AnalyzeSQLMapReportView(APIView):
    """
    POST: Receives SQLMap scan findings, summarizes them, generates security assessment,
          stores result, and outputs structured JSON logs for Grafana.
    GET:  Allows querying SQLMap scan results.
    """

    def get(self, request):
        reports = VulnerabilityReport.objects.filter(scan_type="SQLMap").order_by("-created_at")[:10]
        data = [
            {
                "id": r.id,
                "project_name": r.project_name,
                "scan_type": r.scan_type,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reports
        ]
        return Response({"status": "success", "count": len(data), "reports": data})

    def post(self, request):
        try:
            data = request.data
            project_name = data.get("target", "IntelliSecOps Project")
            findings = data.get("findings", [])

            report_payload = findings if findings else data

            prompt = f"""
You are a cybersecurity expert specializing in database security.

Analyze the following SQLMap scan findings:

{json.dumps(report_payload, indent=2)}

Provide:
1. Executive summary
2. Total injection points found
3. Type of SQL injection (boolean-based, time-based, union-based, etc.)
4. Risk severity assessment
5. Explanation of how each vulnerability could be exploited
6. Recommended fixes (parameterized queries, ORM usage, input validation, etc.)
7. Overall database security assessment
"""

            gemini_text = ask_gemini(prompt)

            report_obj = VulnerabilityReport.objects.create(
                project_name=str(project_name),
                raw_json_report=data,
                gemini_analysis=gemini_text,
                scan_type="SQLMap",
                vulnerability_counts=scan_vulnerability_counts("SQLMap", data),
            )

            scan_metrics = {
                "total_findings": len(findings),
                "targets": [str(project_name)],
                "injection_types": [f.get("type", "unknown") for f in findings[:5]],
            }

            # Log scan output in structured JSON format
            log_scan_event("SQLMap", project_name, report_obj.id, scan_metrics, data)

            return Response(
                {
                    "status": "success",
                    "message": "SQLMap report analyzed, logged in structured JSON, and saved successfully!",
                    "report_id": report_obj.id,
                    "metrics": scan_metrics,
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            print("Server Error:", str(e))
            return Response(
                {
                    "status": "error",
                    "message": str(e),
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


# --- Custom Search & Dynamic Query Audit Endpoint ---

@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def custom_security_search(request):
    """
    Custom search endpoint for dynamic database filtering & security audit evaluation.
    Accepts query parameters:
      - 'q' or 'query': search query or filter string
      - 'table': target table ('services', 'reports', 'projects', 'team')
      - 'id': specific record identifier
      - 'mode': 'raw' (raw SQL query for security audit labs) or 'safe' (ORM filtered)

    Returns detailed JSON responses and writes structured logs for external log analyzers (Grafana/SIEM).
    """
    data = request.data if request.method == "POST" else request.GET
    query_param = data.get("query") or data.get("q") or ""
    table = data.get("table", "services").lower()
    record_id = data.get("id")
    mode = data.get("mode", "raw").lower()

    start_time = datetime.now()
    results = []
    error_message = None
    executed_sql = None

    table_mapping = {
        "services": ("api_service", "id, title, description, icon"),
        "reports": ("api_vulnerabilityreport", "id, project_name, scan_type, created_at"),
        "projects": ("api_project", "id, title, description, technologies"),
        "team": ("api_team", "id, name, position"),
    }

    db_table, select_fields = table_mapping.get(table, ("api_service", "id, title, description, icon"))

    if mode == "safe":
        # Safe ORM execution
        if table == "services":
            qs = Service.objects.filter(title__icontains=query_param)
            results = [{"id": s.id, "title": s.title, "description": s.description} for s in qs]
        elif table == "projects":
            qs = Project.objects.filter(title__icontains=query_param)
            results = [{"id": p.id, "title": p.title, "technologies": p.technologies} for p in qs]
        else:
            qs = VulnerabilityReport.objects.filter(project_name__icontains=query_param)
            results = [{"id": r.id, "project_name": r.project_name, "scan_type": r.scan_type} for r in qs]
        executed_sql = "ORM filter (safe parameterized)"
    else:
        # Dynamic raw SQL query execution for security auditing evaluation
        if record_id:
            executed_sql = f"SELECT {select_fields} FROM {db_table} WHERE id = {record_id}"
        elif query_param:
            executed_sql = f"SELECT {select_fields} FROM {db_table} WHERE title LIKE '%{query_param}%' OR description LIKE '%{query_param}%'" if table in ["services", "projects"] else f"SELECT {select_fields} FROM {db_table} WHERE project_name LIKE '%{query_param}%'"
        else:
            executed_sql = f"SELECT {select_fields} FROM {db_table} LIMIT 20"

        try:
            with connection.cursor() as cursor:
                cursor.execute(executed_sql)
                cols = [col[0] for col in cursor.description] if cursor.description else []
                for row in cursor.fetchall():
                    row_dict = dict(zip(cols, row))
                    if "created_at" in row_dict and row_dict["created_at"]:
                        row_dict["created_at"] = str(row_dict["created_at"])
                    results.append(row_dict)
        except Exception as e:
            error_message = str(e)

    elapsed_ms = (datetime.now() - start_time).total_seconds() * 1000
    client_ip = request.META.get("HTTP_X_FORWARDED_FOR") or request.META.get("REMOTE_ADDR")

    # Log structured event for Grafana / SIEM analysis
    log_audit_event(
        query_param=query_param or str(record_id),
        table_name=db_table,
        mode=mode,
        result_count=len(results),
        exec_time_ms=elapsed_ms,
        client_ip=client_ip,
    )

    if error_message:
        return Response(
            {
                "status": "error",
                "message": error_message,
                "query_executed": executed_sql,
                "table": table,
                "mode": mode,
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    return Response(
        {
            "status": "success",
            "table": table,
            "mode": mode,
            "query_param": query_param,
            "query_executed": executed_sql,
            "execution_time_ms": round(elapsed_ms, 2),
            "count": len(results),
            "results": results,
        },
        status=status.HTTP_200_OK,
    )


# --- Grafana Log Exporter API ---

@api_view(["GET"])
@permission_classes([AllowAny])
def grafana_logs_api(request):
    """
    Exports scan findings and audit events in structured JSON format
    for direct ingestion into Grafana dashboards, Loki, and SIEM pipelines.
    """
    reports = list(VulnerabilityReport.objects.all().order_by("-created_at")[:50])
    reports.reverse()
    log_stream = []

    for r in reports:
        raw_data = r.raw_json_report or {}
        alerts_summary = []
        if r.scan_type == "ZAP":
            sites = raw_data.get("site", []) if isinstance(raw_data, dict) else []
            if isinstance(sites, list):
                for site in sites:
                    for a in site.get("alerts", []):
                        alerts_summary.append({
                            "name": a.get("name"),
                            "risk": a.get("riskdesc"),
                        })
        elif r.scan_type == "SQLMap":
            findings = raw_data.get("findings", []) if isinstance(raw_data, dict) else []
            for f in findings:
                alerts_summary.append({
                    "name": f.get("title", "SQL Injection"),
                    "risk": f.get("type", "High"),
                })

        counts = scan_vulnerability_counts(r.scan_type, raw_data)
        if isinstance(r.vulnerability_counts, dict) and r.vulnerability_counts:
            counts.update(r.vulnerability_counts)

        log_stream.append({
            "timestamp": r.created_at.isoformat() if r.created_at else datetime.now(timezone.utc).isoformat(),
            "level": "CRITICAL" if counts.get("critical", 0) > 0 else (
                "ERROR" if counts.get("high", 0) > 0 else (
                    "WARN" if counts.get("medium", 0) > 0 else "INFO"
                )
            ),
            "scan_type": r.scan_type,
            "project": r.project_name,
            "report_id": r.id,
            "scan_count": 1,
            "zap_scans": int(r.scan_type == "ZAP"),
            "sqlmap_scans": int(r.scan_type == "SQLMap"),
            "total_alerts": counts.get("total", len(alerts_summary)),
            "severity_counts": {
                "critical": counts.get("critical", 0),
                "high": counts.get("high", 0),
                "medium": counts.get("medium", 0),
                "low": counts.get("low", 0),
                "informational": counts.get("informational", 0),
            },
            "high_risk_alerts": counts.get("high_critical", 0),
            "medium_risk_alerts": counts.get("medium", 0),
            "analysis_preview": r.gemini_analysis[:200] + "..." if r.gemini_analysis else "No analysis available",
        })

    return Response(
        {
            "status": "success",
            "stream_name": "pipeline_security_scans",
            "total_logs": len(log_stream),
            "logs": log_stream,
        },
        status=status.HTTP_200_OK,
    )


# --- Grafana Metrics API ---

@api_view(["GET"])
@permission_classes([AllowAny])
def grafana_metrics_api(request):
    """
    Endpoint for Grafana to fetch vulnerability metrics/summary from SQLite database.
    Separates ZAP vs SQLMap findings and severity tiers for dashboard panels.
    """
    reports = VulnerabilityReport.objects.all().order_by("-created_at")
    total_reports = reports.count()

    vulnerability_counts = {}
    scan_type_counts = {"ZAP": 0, "SQLMap": 0}
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "High/Critical": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for report in reports:
        scan_type = getattr(report, "scan_type", "ZAP") or "ZAP"
        scan_type_counts[scan_type] = scan_type_counts.get(scan_type, 0) + 1

        raw_data = report.raw_json_report
        saved_counts = scan_vulnerability_counts(scan_type, raw_data)
        if isinstance(report.vulnerability_counts, dict) and report.vulnerability_counts:
            saved_counts.update(report.vulnerability_counts)

        severity_counts["Critical"] += saved_counts.get("critical", 0)
        severity_counts["High"] += saved_counts.get("high", 0)
        severity_counts["High/Critical"] += saved_counts.get("high_critical", 0)
        severity_counts["Medium"] += saved_counts.get("medium", 0)
        severity_counts["Low"] += saved_counts.get("low", 0)
        severity_counts["Informational"] += saved_counts.get("informational", 0)

        if scan_type == "ZAP":
            alerts = zap_alerts_from_report(raw_data)
            for alert in alerts:
                vuln_name = alert.get("name", "Unknown Vulnerability")
                vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1

        elif scan_type == "SQLMap":
            findings = raw_data.get("findings", []) if isinstance(raw_data, dict) else []
            for finding in findings:
                vuln_name = finding.get("title", "SQL Injection")
                vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1

    data = [
        {"metric": "Total Scans", "value": total_reports},
        {"metric": "ZAP Scans", "value": scan_type_counts.get("ZAP", 0)},
        {"metric": "SQLMap Scans", "value": scan_type_counts.get("SQLMap", 0)},
        {"metric": "Critical Severity", "value": severity_counts["Critical"]},
        {"metric": "High Severity", "value": severity_counts["High"]},
        {"metric": "Critical & High Severity", "value": severity_counts["High/Critical"]},
        {"metric": "Medium Severity", "value": severity_counts["Medium"]},
        {"metric": "Low Severity", "value": severity_counts["Low"]},
        {"metric": "Informational", "value": severity_counts["Informational"]},
    ]

    for key, value in vulnerability_counts.items():
        data.append({"metric": key, "value": value})

    return Response(data, status=status.HTTP_200_OK)


# --- Core Web APIs ---

@api_view(["GET"])
def home(request):
    return Response({
        "message": "Welcome to Aqevora Technologies DevSecOps API",
        "status": "success",
        "version": "2.0.0",
        "endpoints": {
            "services": "/api/services/",
            "projects": "/api/projects/",
            "team": "/api/team/",
            "contact": "/api/contact/",
            "security_search": "/api/audit/search/",
            "vulnerable_search": "/api/vulnerable/search/",
            "grafana_metrics": "/api/grafana-metrics/",
            "grafana_logs": "/api/grafana-logs/",
            "analyze_zap": "/api/analyze-report/",
            "analyze_sqlmap": "/api/analyze-sqlmap-report/",
        }
    })


@api_view(["GET"])
def service_list(request):
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many=True)
    return Response(serializer.data)


@api_view(["GET"])
def project_list(request):
    projects = Project.objects.all()
    serializer = ProjectSerializer(projects, many=True)
    return Response(serializer.data)


@api_view(["GET"])
def team_list(request):
    team = Team.objects.all()
    serializer = TeamSerializer(team, many=True)
    return Response(serializer.data)


@api_view(["POST"])
@permission_classes([AllowAny])
def contact_submit(request):
    serializer = ContactMessageSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {"message": "Message saved successfully!", "status": "success"},
            status=201,
        )
    print("VALIDATION ERRORS:", serializer.errors)
    return Response(
        {"message": "Validation failed", "status": "error", "errors": serializer.errors},
        status=400,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def github_webhook(request):
    print("GitHub Webhook Received:", request.data)
    return Response(
        {"message": "Webhook received successfully!", "status": "success"},
        status=200,
    )