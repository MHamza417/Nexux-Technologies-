from django.urls import path
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

urlpatterns = [
    path('', home, name='home'),
    path('services/', service_list, name='services'),
    path('projects/', project_list, name='projects'),
    path('team/', team_list, name='team'),
    path('contact/', contact_submit, name='contact_submit'),

    # DevSecOps & Scan Analysis
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