"""
Copyright (C) 2023-2024 Nikhil Ashok Hegde (@ka1do9)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
from pathlib import Path
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / "subdir".
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "django-insecure-elfen-sandbox"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["127.0.0.1"]


# Application definition

INSTALLED_APPS = [
    "bootstrap5",
    "api.apps.ApiConfig",
    "django_extensions",
    "web.apps.WebConfig",
    "rest_framework",
    "analysis.apps.AnalysisConfig",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ELFEN.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "web", "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "ELFEN.wsgi.application"

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=7),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ]
}

# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "elfen_db",
        "USER": "elfen",
        "PASSWORD": "elfen",
        "HOST": "mysql",
        # "HOST": "localhost",
        "PORT": 3306,
        "TEST": {
            "DEPENDENCIES": [
                "elfen",
            ]
        },
    },
    "elfen": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "elfen_db",
        "USER": "elfen",
        "PASSWORD": "elfen",
        "HOST": "postgres",
        # "HOST": "localhost",
        "PORT": 5432,
        "TEST": {
            "DEPENDENCIES": []
        }
    }
}
APP_DATABASE_MAPPINGS = {
    "web": "elfen",
    "analysis": "elfen",
}
DATABASE_ROUTERS = [
    "ELFEN.router.ElfenRouter"
]

CELERY_BROKER_URL = "amqp://elfen:elfen@rabbitmq:5672"
# CELERY_BROKER_URL = "amqp://elfen:elfen@localhost:5672"
CELERY_RESULT_BACKEND = "db+postgresql://elfen:elfen@postgres/elfen_db"
# CELERY_RESULT_BACKEND = "db+postgresql://elfen:elfen@localhost/elfen_db"
CELERY_QUEUES = {
    "submission": {
        "binding_key": "submission"
    },
    "static_analysis": {
        "binding_key": "static_analysis"
    },
    "dynamic_analysis": {
        "binding_key": "dynamic_analysis"
    },
    "network_analysis": {
        "binding_key": "network_analysis"
    },
    "detection_analysis": {
        "binding_key": "detection_analysis"
    },
    "periodic_analysis": {
        "binding_key": "periodic_analysis"
    },
}

# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

APPEND_SLASH = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = "/static/"
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]

MEDIA_ROOT = os.path.join(BASE_DIR, "media")
FILE_SUBMISSIONS_ROOT = os.path.join(MEDIA_ROOT, "web")
FILE_SUBMISSIONS_URL = "media/web"


# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/web/login/"
LOGIN_REDIRECT_URL = "/web/"
LOGOUT_REDIRECT_URL = "/web/"
