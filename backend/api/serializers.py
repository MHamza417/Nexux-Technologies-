from rest_framework import serializers
from .models import ScanJob, Service, Project, Team, ContactMessage


class ScanSubmissionSerializer(serializers.Serializer):
    target_type = serializers.ChoiceField(choices=ScanJob.TargetType.choices)
    target = serializers.CharField(max_length=2048)
    authorized = serializers.BooleanField()
    include_ai = serializers.BooleanField(required=False, default=False)


class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Service
        fields = "__all__"


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = "__all__"


class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Team
        fields = "__all__"

class ContactMessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactMessage
        fields = "__all__"        
        
        