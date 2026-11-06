from django.contrib import admin
from .models import (
    ContactMessage,
    Project,
    ScanFinding,
    ScanJob,
    Service,
    Team,
    VulnerabilityReport,
)


@admin.register(VulnerabilityReport)
class VulnerabilityReportAdmin(admin.ModelAdmin):
    list_display = ("id", "project_name", "created_at")
    search_fields = ("project_name",)
    readonly_fields = ("created_at",)


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("id", "owner", "target_type", "status", "created_at")
    list_filter = ("status", "target_type", "created_at")
    search_fields = ("id", "owner__username", "target")
    readonly_fields = ("id", "created_at", "started_at", "completed_at")


@admin.register(ScanFinding)
class ScanFindingAdmin(admin.ModelAdmin):
    list_display = ("id", "scan", "severity", "title", "detected_at")
    list_filter = ("scanner", "severity", "detected_at")
    search_fields = ("title", "affected_component", "scan__id")
    readonly_fields = ("detected_at",)


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ("id", "title")
    search_fields = ("title",)


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "technologies")
    search_fields = ("title", "technologies")


@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "position")
    search_fields = ("name", "position")


@admin.register(ContactMessage)
class ContactMessageAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "email", "created_at")
    search_fields = ("name", "email")
    readonly_fields = ("created_at",)