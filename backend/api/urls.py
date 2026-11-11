from django.urls import path
from .scan_views import (
    pipeline_callback,
    public_scan_detail,
    public_scan_download,
    public_scan_submit,
    scan_detail,
    scan_history,
    scan_report,
    scan_submit,
)
from .scan_views import dashboard_summary
from .views import (
    home,
    service_list,
    project_list,
    team_list,
    contact_submit,
    github_webhook,
    AnalyzeReportView,
    AnalyzeSQLMapReportView,
    grafana_metrics_api,
    grafana_logs_api,
    custom_security_search,
)
from .health_views import integrations_health
from .wazuh_views import wazuh_vulnerabilities

urlpatterns = [
    path('', home, name='home'),
    path('services/', service_list, name='services'),
    path('projects/', project_list, name='projects'),
    path('team/', team_list, name='team'),
    path('contact/', contact_submit, name='contact_submit'),

    # DevSecOps & Scan Analysis
    path('integrations/health/', integrations_health, name='integrations-health'),
    path(
        'wazuh/vulnerabilities/',
        wazuh_vulnerabilities,
        name='wazuh-vulnerabilities',
    ),
    path('scans/', scan_submit, name='scan-submit'),
    path('public/scans/', public_scan_submit, name='public-scan-submit'),
    path('public/scans/<uuid:scan_id>/', public_scan_detail, name='public-scan-detail'),
    path(
        'public/scans/<uuid:scan_id>/download/',
        public_scan_download,
        name='public-scan-download',
    ),
    path('dashboard/', dashboard_summary, name='dashboard-summary'),
    path('scans/history/', scan_history, name='scan-history'),
    path('scans/<uuid:scan_id>/', scan_detail, name='scan-detail'),
    path('scans/<uuid:scan_id>/report/', scan_report, name='scan-report'),
    path(
        'scans/<uuid:scan_id>/pipeline-result/',
        pipeline_callback,
        name='scan-pipeline-callback',
    ),
    path('github/webhook/', github_webhook, name='github_webhook'),
    path('analyze-report/', AnalyzeReportView.as_view(), name='analyze-report'),
    path('analyze-sqlmap-report/', AnalyzeSQLMapReportView.as_view(), name='analyze-sqlmap-report'),

    # Security Auditing & Dynamic Search Endpoints
    path('audit/search/', custom_security_search, name='security-search'),
    path('vulnerable/search/', custom_security_search, name='vulnerable-search'),
    path('vulnerable/query/', custom_security_search, name='vulnerable-query'),

    # Grafana Dashboards & Structured Log Exporter
    path('grafana-metrics/', grafana_metrics_api, name='grafana-metrics'),
    path('grafana-logs/', grafana_logs_api, name='grafana-logs'),
    path('logs/export/', grafana_logs_api, name='logs-export'),
]