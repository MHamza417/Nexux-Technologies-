import os
from pathlib import Path
import dotenv
from django.core.exceptions import ImproperlyConfigured

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# ==========================
# LOAD .ENV FILE
# ==========================

dotenv_file = BASE_DIR / '.env'

if dotenv_file.exists():
    dotenv.load_dotenv(dotenv_file)


# Gemini API Key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")


# ==========================
# SECURITY
# ==========================

DEBUG = os.getenv("DJANGO_DEBUG", "true").strip().lower() in {"1", "true", "yes"}
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DEBUG is disabled.")
    SECRET_KEY = "django-insecure-change-this-later"

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("DJANGO_ALLOWED_HOSTS", "*" if DEBUG else "").split(",")
    if host.strip()
]
if not ALLOWED_HOSTS or (not DEBUG and "*" in ALLOWED_HOSTS):
    raise ImproperlyConfigured(
        "Set DJANGO_ALLOWED_HOSTS to explicit hostnames when DEBUG is disabled."
    )


# ==========================
# INSTALLED APPS
# ==========================

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third Party
    'rest_framework',
    'corsheaders',
    'drf_spectacular',

    # Local App
    'api',
]


# ==========================
# MIDDLEWARE
# ==========================

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',

    'corsheaders.middleware.CorsMiddleware',

    'django.contrib.sessions.middleware.SessionMiddleware',

    'django.middleware.common.CommonMiddleware',

    'django.middleware.csrf.CsrfViewMiddleware',

    'django.contrib.auth.middleware.AuthenticationMiddleware',

    'django.contrib.messages.middleware.MessageMiddleware',

    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


# ==========================
# URL CONFIGURATION
# ==========================

ROOT_URLCONF = 'config.urls'


# ==========================
# TEMPLATES
# ==========================

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',

        'DIRS': [],

        'APP_DIRS': True,

        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',

                'django.contrib.auth.context_processors.auth',

                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# ==========================
# WSGI
# ==========================

WSGI_APPLICATION = 'config.wsgi.application'


# ==========================
# DATABASE
# ==========================

DATABASE_ENGINE = os.getenv("DATABASE_ENGINE", "sqlite").strip().lower()
if DATABASE_ENGINE == "sqlite":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.getenv("DATABASE_PATH", str(BASE_DIR / "db.sqlite3")),
        }
    }
elif DATABASE_ENGINE in {"postgres", "postgresql"}:
    postgres_name = os.getenv("POSTGRES_DB", "")
    postgres_user = os.getenv("POSTGRES_USER", "")
    postgres_password = os.getenv("POSTGRES_PASSWORD", "")
    postgres_host = os.getenv("POSTGRES_HOST", "")
    if not all((postgres_name, postgres_user, postgres_password, postgres_host)):
        raise ImproperlyConfigured(
            "POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, and POSTGRES_HOST "
            "must be set when DATABASE_ENGINE=postgresql."
        )
    postgres_options = {}
    postgres_sslmode = os.getenv("POSTGRES_SSLMODE", "").strip()
    if postgres_sslmode:
        postgres_options["sslmode"] = postgres_sslmode
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": postgres_name,
            "USER": postgres_user,
            "PASSWORD": postgres_password,
            "HOST": postgres_host,
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
            "CONN_MAX_AGE": int(os.getenv("POSTGRES_CONN_MAX_AGE", "60")),
            "OPTIONS": postgres_options,
        }
    }
else:
    raise ImproperlyConfigured(
        "DATABASE_ENGINE must be either sqlite or postgresql."
    )


# ==========================
# PASSWORD VALIDATION
# ==========================

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME':
            'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },

    {
        'NAME':
            'django.contrib.auth.password_validation.MinimumLengthValidator',
    },

    {
        'NAME':
            'django.contrib.auth.password_validation.CommonPasswordValidator',
    },

    {
        'NAME':
            'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# ==========================
# INTERNATIONALIZATION
# ==========================

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# ==========================
# STATIC FILES
# ==========================

STATIC_URL = 'static/'


# ==========================
# DEFAULT PRIMARY KEY
# ==========================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ==========================
# CORS
# ==========================

CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
CORS_ALLOW_ALL_ORIGINS = DEBUG and not CORS_ALLOWED_ORIGINS


# ==========================
# DJANGO REST FRAMEWORK
# ==========================

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.AllowAny",
    ),

    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),

    # Swagger / OpenAPI
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_RATES": {
        "scan_submission": os.getenv("SCAN_SUBMISSION_RATE", "5/hour"),
        "public_scan_submission": os.getenv("PUBLIC_SCAN_SUBMISSION_RATE", "20/hour"),
    },
}


# ==========================
# Scanner handoff and notifications
# ==========================

SCAN_WORKER_ISOLATED = os.getenv(
    "SCAN_WORKER_ISOLATED", "false"
).strip().lower() in {"1", "true", "yes"}
JENKINS_URL = os.getenv("JENKINS_URL", "").rstrip("/")
ALLOW_INSECURE_JENKINS = os.getenv("ALLOW_INSECURE_JENKINS", "false").lower() == "true"
JENKINS_SCAN_JOB = os.getenv("JENKINS_SCAN_JOB", "")
JENKINS_USER = os.getenv("JENKINS_USER", "")
JENKINS_API_TOKEN = os.getenv("JENKINS_API_TOKEN", "")
SCAN_PIPELINE_TOKEN = os.getenv("SCAN_PIPELINE_TOKEN", "")
SONAR_URL = os.getenv("SONAR_URL", "").rstrip("/")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "").rstrip("/")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "true").strip().lower() in {
    "1", "true", "yes",
}
WAZUH_AGENT_ID = os.getenv("WAZUH_AGENT_ID", "").strip()
WAZUH_AGENT_NAME = os.getenv("WAZUH_AGENT_NAME", "Docker").strip()
MAX_SCAN_REPORT_BYTES = int(os.getenv("MAX_SCAN_REPORT_BYTES", str(20 * 1024 * 1024)))
FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "http://localhost:3000").rstrip("/")
SCAN_GATE_FAIL_SEVERITY = os.getenv(
    "SCAN_GATE_FAIL_SEVERITY", "high"
).strip().lower()
if SCAN_GATE_FAIL_SEVERITY not in {
    "critical", "high", "medium", "low", "informational"
}:
    raise ImproperlyConfigured(
        "SCAN_GATE_FAIL_SEVERITY must be critical, high, medium, low, or informational."
    )
DATA_UPLOAD_MAX_MEMORY_SIZE = MAX_SCAN_REPORT_BYTES
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = (
    os.getenv("DJANGO_SECURE_SSL_REDIRECT", "false").strip().lower()
    in {"1", "true", "yes"}
)
SECURE_HSTS_SECONDS = int(os.getenv("DJANGO_HSTS_SECONDS", "0"))

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("SMTP_HOST", "")
EMAIL_PORT = int(os.getenv("SMTP_PORT", "587"))
EMAIL_HOST_USER = os.getenv("SMTP_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_USE_TLS = os.getenv("SMTP_USE_TLS", "true").strip().lower() in {"1", "true", "yes"}
EMAIL_USE_SSL = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes"}
EMAIL_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))
DEFAULT_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL", "")
SECURITY_NOTIFICATIONS_ENABLED = (
    os.getenv("SECURITY_NOTIFICATIONS_ENABLED", "false").strip().lower()
    in {"1", "true", "yes"}
)
if EMAIL_USE_TLS and EMAIL_USE_SSL:
    raise ImproperlyConfigured("SMTP_USE_TLS and SMTP_USE_SSL cannot both be enabled.")


# ==========================
# SWAGGER / OPENAPI
# ==========================

SPECTACULAR_SETTINGS = {
    "TITLE": "Aqevora Technologies API",
    "DESCRIPTION": "REST API documentation for Aqevora Technologies DevSecOps platform.",
    "VERSION": "1.0.0",

    "SERVE_INCLUDE_SCHEMA": False,
}



# ==========================
# STRUCTURED AUDIT & SCAN LOGGING (FOR GRAFANA INTEGRATION)
# ==========================

LOGS_DIR = BASE_DIR / 'logs'
LOGS_DIR.mkdir(parents=True, exist_ok=True)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'raw_json': {
            'format': '%(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'scan_json_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOGS_DIR / 'scan_metrics.json.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'raw_json',
        },
        'audit_json_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOGS_DIR / 'security_audit.json.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'raw_json',
        },
        'scan_events_json_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': str(LOGS_DIR / 'security_events.log'),
            'maxBytes': 10 * 1024 * 1024,
            'backupCount': 5,
            'formatter': 'raw_json',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': True,
        },
        'security.scans': {
            'handlers': ['console', 'scan_json_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.audit': {
            'handlers': ['console', 'audit_json_file'],
            'level': 'INFO',
            'propagate': False,
        },
        'security.scan_events': {
            'handlers': ['scan_events_json_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
