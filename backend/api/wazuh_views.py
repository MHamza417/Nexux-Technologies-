from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .wazuh_client import WazuhClientError, get_vulnerabilities


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def wazuh_vulnerabilities(request):
    agent = request.query_params.get("agent", "").strip()
    if len(agent) > 255:
        return Response(
            {"detail": "Agent name or ID must be 255 characters or fewer."},
            status=400,
        )
    if agent == "default":
        agent = ""
    try:
        result = get_vulnerabilities(agent or None)
    except WazuhClientError as exc:
        return Response({"detail": str(exc)}, status=exc.status_code)
    return Response(result)
