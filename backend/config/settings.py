import os
from pathlib import Path
import dotenv

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

SECRET_KEY = 'django-insecure-change-this-later'

DEBUG = True

ALLOWED_HOSTS = ['*']


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

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


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

CORS_ALLOW_ALL_ORIGINS = True


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
}


# ==========================
# SWAGGER / OPENAPI
# ==========================

SPECTACULAR_SETTINGS = {
    "TITLE": "Nexus Technologies API",
    "DESCRIPTION": "REST API documentation for Nexus Technologies DevSecOps platform.",
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
    },
}
