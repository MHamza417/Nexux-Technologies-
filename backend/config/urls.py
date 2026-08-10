from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
)


# ==========================
# ROOT VIEW
# ==========================

def home_view(request):
    return HttpResponse(
        "Welcome to Nexus Technologies Backend. "
        "Go to /api/ for endpoints."
    )

# ==========================
# SENTRY TEST VIEW
# ==========================
def trigger_error(request):
    division_by_zero = 1 / 0


# ==========================
# URLS
# ==========================

urlpatterns = [

    # Root
    path('', home_view, name='home'),

    # Sentry Test Route
    path('sentry-debug/', trigger_error),

    # Django Admin
    path('admin/', admin.site.urls),

    # API
    path('api/', include('api.urls')),

    # ==========================
    # SWAGGER / OPENAPI
    # ==========================

    # OpenAPI schema
    path(
        'api/schema/',
        SpectacularAPIView.as_view(),
        name='schema'
    ),

    # Swagger UI
    path(
        'api/docs/',
        SpectacularSwaggerView.as_view(
            url_name='schema'
        ),
        name='swagger-ui'
    ),
]