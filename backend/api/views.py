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
            project_name = data.get("site", "IntelliSecOps Project")

            # --- TOKEN OPTIMIZATION ---
            alerts_summary = []
            sites = data.get("site", [])
            if isinstance(sites, list):
                for site_item in sites:
                    for alert in site_item.get("alerts", []):
                        alerts_summary.append({
                            "risk": alert.get("riskdesc"),
                            "name": alert.get("name"),
                            "description": alert.get("desc"),
                            "solution": alert.get("solution"),
                        })
            elif isinstance(data, list):
                for alert in data:
                    alerts_summary.append({
                        "risk": alert.get("riskdesc") or alert.get("risk"),
                        "name": alert.get("name"),
                        "description": alert.get("desc"),
                        "solution": alert.get("solution"),
                    })

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
            )

            # Calculate risk metrics breakdown for Grafana structured logging
            high_count = sum(1 for a in alerts_summary if "High" in str(a.get("risk", "")) or "Critical" in str(a.get("risk", "")))
            med_count = sum(1 for a in alerts_summary if "Medium" in str(a.get("risk", "")))
            low_count = sum(1 for a in alerts_summary if "Low" in str(a.get("risk", "")))
            info_count = sum(1 for a in alerts_summary if "Informational" in str(a.get("risk", "")))

            scan_metrics = {
                "total_alerts": len(alerts_summary),
                "critical_high_count": high_count,
                "medium_count": med_count,
                "low_count": low_count,
                "info_count": info_count,
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
    reports = VulnerabilityReport.objects.all().order_by("-created_at")[:50]
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

        high_count = sum(1 for a in alerts_summary if "High" in str(a.get("risk", "")) or "Critical" in str(a.get("risk", "")))
        med_count = sum(1 for a in alerts_summary if "Medium" in str(a.get("risk", "")))

        log_stream.append({
            "timestamp": r.created_at.isoformat() if r.created_at else datetime.now(timezone.utc).isoformat(),
            "level": "CRITICAL" if high_count > 0 else ("WARN" if med_count > 0 else "INFO"),
            "scan_type": r.scan_type,
            "project": r.project_name,
            "report_id": r.id,
            "total_alerts": len(alerts_summary),
            "high_risk_alerts": high_count,
            "medium_risk_alerts": med_count,
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
    severity_counts = {"High/Critical": 0, "Medium": 0, "Low": 0, "Informational": 0}

    for report in reports:
        scan_type = getattr(report, "scan_type", "ZAP") or "ZAP"
        scan_type_counts[scan_type] = scan_type_counts.get(scan_type, 0) + 1

        raw_data = report.raw_json_report

        if scan_type == "ZAP":
            sites = raw_data.get("site", []) if isinstance(raw_data, dict) else []
            if isinstance(sites, list):
                for site_item in sites:
                    for alert in site_item.get("alerts", []):
                        vuln_name = alert.get("name", "Unknown Vulnerability")
                        risk = alert.get("riskdesc", "")
                        vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1
                        if "High" in risk or "Critical" in risk:
                            severity_counts["High/Critical"] += 1
                        elif "Medium" in risk:
                            severity_counts["Medium"] += 1
                        elif "Low" in risk:
                            severity_counts["Low"] += 1
                        else:
                            severity_counts["Informational"] += 1
            elif isinstance(raw_data, list):
                for alert in raw_data:
                    vuln_name = alert.get("name", "Unknown Vulnerability")
                    vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1

        elif scan_type == "SQLMap":
            findings = raw_data.get("findings", []) if isinstance(raw_data, dict) else []
            for finding in findings:
                vuln_name = finding.get("title", "SQL Injection")
                vulnerability_counts[vuln_name] = vulnerability_counts.get(vuln_name, 0) + 1
                severity_counts["High/Critical"] += 1

    data = [
        {"metric": "Total Scans", "value": total_reports},
        {"metric": "ZAP Scans", "value": scan_type_counts.get("ZAP", 0)},
        {"metric": "SQLMap Scans", "value": scan_type_counts.get("SQLMap", 0)},
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
        "message": "Welcome to Nexus Technologies DevSecOps API",
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