from django.db import models
from django.conf import settings
import uuid


class VulnerabilityReport(models.Model):
    scan_job = models.OneToOneField(
        "ScanJob",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="report",
    )
    project_name = models.CharField(max_length=255)
    scan_date = models.DateTimeField(auto_now_add=True)
    raw_json_report = models.JSONField()
    gemini_analysis = models.TextField()
    scan_type = models.CharField(max_length=20, default="ZAP")  # "ZAP" or "SQLMap"
    vulnerability_counts = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.project_name} - {self.scan_date}"


class ScanJob(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        BLOCKED = "blocked", "Blocked"

    class TargetType(models.TextChoices):
        WEBSITE = "website", "Website"
        REPOSITORY = "repository", "GitHub repository"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scan_jobs",
        null=True,
        blank=True,
    )
    access_token = models.CharField(max_length=64, blank=True, db_index=True)
    target_type = models.CharField(max_length=20, choices=TargetType.choices)
    target = models.URLField(max_length=2048)
    authorized = models.BooleanField(default=False)
    status = models.CharField(
        max_length=12, choices=Status.choices, default=Status.PENDING
    )
    include_ai = models.BooleanField(default=False)
    notification_email = models.EmailField(blank=True)
    notification_attempted_at = models.DateTimeField(null=True, blank=True)
    notification_sent_at = models.DateTimeField(null=True, blank=True)
    verified_contact = models.EmailField(blank=True)
    failure_reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.id} - {self.target} ({self.status})"


class ScanFinding(models.Model):
    scan = models.ForeignKey(
        ScanJob, on_delete=models.CASCADE, related_name="findings"
    )
    scanner = models.CharField(max_length=40)
    title = models.CharField(max_length=500)
    severity = models.CharField(max_length=20)
    affected_component = models.CharField(max_length=2048, blank=True)
    evidence = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-detected_at", "title")

    def __str__(self):
        return f"{self.severity}: {self.title}"


class Service(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    icon = models.CharField(max_length=100)

    def __str__(self):
        return self.title


class Project(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    image = models.URLField(blank=True, null=True)
    technologies = models.CharField(max_length=255)
    github_link = models.URLField(blank=True, null=True)
    live_demo = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.title


class Team(models.Model):
    name = models.CharField(max_length=100)
    position = models.CharField(max_length=100)
    image = models.URLField(blank=True, null=True)
    facebook = models.URLField(blank=True, null=True)
    linkedin = models.URLField(blank=True, null=True)
    github = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.name


class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Message from {self.name} - {self.email}"