"""
using Django 4.2.5.
Project - Skycode - lifecell
"""

from dotenv import load_dotenv
load_dotenv()
import logging  # Log file creation(added in end of this file)
import os
from celery.schedules import crontab
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler
from datetime import timedelta  # JWT (use if you need) - mohan

# BASE_DIR = Path(__file__).resolve().parent.parent  # Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # modified by laxmi praba

SECRET_KEY = 'django-insecure-_zw7k@8s@nj%f+7n@_uobzuqwg1hc9_@*ayid=k&aee-0_ysw3'  # SECURITY WARNING: keep the
# secret key used in production secret!

# # DEV url
# SITE_URL = 'http://65.1.213.42:3001'  # Frontend Url
# BASE_URL = 'http://65.1.213.42:8010'  # Backend Url
# # QA url
# SITE_URL = 'http://65.1.213.42:4001'  # Frontend Url
# BASE_URL = 'http://65.1.213.42:8020'  # Backend Url
# Projects url
# SITE_URL = 'http://65.1.213.42:5001'  # Frontend Url
# BASE_URL = 'http://65.1.213.42:8030'  # Backend Url
# LIVE url
SITE_URL = 'http://65.1.213.42:1001'  # Frontend Url
BASE_URL = 'http://65.1.213.42:8040'  # Backend Url

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True  # False

# DEV
# ALLOWED_HOSTS = ['*', 'http://65.1.213.42:8010']
# # QA
# ALLOWED_HOSTS = ['*', 'http://65.1.213.42:8020']
# # Projects
# ALLOWED_HOSTS = ['*', 'http://65.1.213.42:8030']
# LIVE
ALLOWED_HOSTS = ['*', 'http://65.1.213.42:8040']



# DEV
# CSRF_TRUSTED_ORIGINS = ['http://65.1.213.42:8010']  # if we need to connect to Domain use as 'http://domain.com'
# CORS_ALLOWED_ORIGINS = ['http://65.1.213.42:8010']
# # QA
# CSRF_TRUSTED_ORIGINS = ['http://65.1.213.42:8020']  # if we need to connect to Domain use as 'http://domain.com'
# CORS_ALLOWED_ORIGINS = ['http://65.1.213.42:8020']
# # Projects
# CSRF_TRUSTED_ORIGINS = ['http://65.1.213.42:8030']  # if we need to connect to Domain use as 'http://domain.com'
# CORS_ALLOWED_ORIGINS = ['http://65.1.213.42:8030']
# LIVE
CSRF_TRUSTED_ORIGINS = ['http://65.1.213.42:8040']  # if we need to connect to Domain use as 'http://domain.com'
CORS_ALLOWED_ORIGINS = ['http://65.1.213.42:8040']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'form_generator',  # added by mohan
    'custom_components',  # added by mohan
    'rest_framework',  # added by mohan
    'corsheaders',  # added by mohan
    'rest_framework.authtoken',
    'django_celery_beat',  # added by Praba
    'automation.apps.AutomationConfig',  # Added By Harish
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',  # added by mohan
]

# CSRF settings
CSRF_COOKIE_NAME = 'csrftoken'
CSRF_COOKIE_HTTPONLY = False  # Set to True if you want the CSRF cookie to be accessible only via HTTP(S) and not JavaScript
CSRF_COOKIE_SECURE = False  # Set to True if you want the CSRF cookie to be sent only over HTTPS

REST_FRAMEWORK = {  # JWT Authentication # added by mohan new
    'DEFAULT_AUTHENTICATION_CLASSES': [
        # 'rest_framework.permissions.AllowAny',
        # 'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        # 'rest_framework.authentication.TokenAuthentication',
        # 'rest_framework.permissions.IsAuthenticated',
    ],
}

SIMPLE_JWT = {  # JWT Authentication
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
}

CORS_ALLOW_ALL_ORIGINS = True
# Configure session storage
SESSION_ENGINE = 'django.contrib.sessions.backends.db'  # added by laxmi Praba
# Allow insecure transport for local development
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS

CORS_ORIGIN_ALLOW_ALL = True  # added by mohan
CORS_ALLOW_CREDENTIALS = True  # added by mohan

ROOT_URLCONF = 'formbuilder_backend.urls'
DATA_UPLOAD_MAX_MEMORY_SIZE = None
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
AUTHENTICATION_BACKENDS = [
    'form_generator.backends.MailIDBackend',
    'django.contrib.auth.backends.ModelBackend',
    # 'django.contrib.auth.backends.ModelBackend',  # Default fallback
]
WSGI_APPLICATION = 'formbuilder_backend.wsgi.application'

# Google Drive Authentication starts - added by Praba
GOOGLE_OAUTH2_CLIENT_ID = '1005976585380-n7nqmsb80t67apg2bfjdrr6pak95icee.apps.googleusercontent.com'
GOOGLE_OAUTH2_CLIENT_SECRET = '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'
GOOGLE_OAUTH2_SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

# Add the path to your service account key file
SERVICE_ACCOUNT_KEY_FILE = os.path.join(BASE_DIR, 'credentials/new_service_account.json')  # 06-09-2025 by Harish
# drive and stored in credentials folder

TIME_ZONE = 'UTC'  # or set to your specific timezone, e.g., 'America/New_York'
USE_TZ = True  # Ensure this is True to use timezone-aware datetimes

# Celery settings
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True



# #DEV
# CELERY_BROKER_URL = 'redis://redis_dev:6379/0'
# CELERY_RESULT_BACKEND = 'redis://redis_dev:6379/0'
#QA
# CELERY_BROKER_URL = 'redis://redis_qa:6379/0'
# CELERY_RESULT_BACKEND = 'redis://redis_qa:6379/0'
##Projects
# CELERY_BROKER_URL = 'redis://redis_projects:6379/0'
# CELERY_RESULT_BACKEND = 'redis://redis_projects:6379/0'
# #DEV
CELERY_BROKER_URL = 'redis://redis_live:6379/0'
CELERY_RESULT_BACKEND = 'redis://redis_live:6379/0'

# Common safety / performance
CELERY_TASK_ACKS_LATE = True  # ack after task completes
CELERY_WORKER_PREFETCH_MULTIPLIER = 1  # avoid starving DB with prefetched tasks
CELERY_TASK_SOFT_TIME_LIMIT = 300  # optional
CELERY_TASK_TIME_LIMIT = 600
CELERY_WORKER_MAX_TASKS_PER_CHILD = 100  # avoid memory leaks
CELERY_TASK_IGNORE_RESULT = True  # if you don't need task results
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_STORE_ERRORS_EVEN_IF_IGNORED = True
CELERY_TASK_ALWAYS_EAGER = False
CELERY_IMPORTS = ("custom_components.tasks", "automation.tasks")
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'
# CELERY_RESULT_BACKEND = 'django-db'
CELERY_BEAT_SCHEDULE = {
    'evaluate-sla-every-1-minutes': {
        'task': 'automation.tasks.evaluate_all_slas_task',
        # 'schedule': crontab(minute='*/15'),
        # 'schedule': crontab(minute='0'),  # Runs every hour at minute 0
        'schedule': crontab(hour=23, minute=0),  # Runs every day at 11:00 PM
    },
}

# from django.db.backends.signals import connection_created
#
# def activate_wal(sender, connection, **kwargs):
#     if connection.vendor == 'sqlite':
#         cursor = connection.cursor()
#         cursor.execute('PRAGMA journal_mode=WAL;')
#         cursor.execute('PRAGMA synchronous=NORMAL;')
#
# connection_created.connect(activate_wal)


# Redirect URI after authentication
GOOGLE_OAUTH2_REDIRECT_URI = 'http://localhost:8000/api/oauth2callback/'
# Google Drive Authentication ends

#
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'skycode_db_live',
        'USER': 'admin_user',
        'PASSWORD': 'Skycode@2025',
        'HOST': 'db_live',
        # 'HOST': 'localhost',
        'PORT': '5432',
    }
}
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'skycode_db_dev',
#         'USER': 'admin_user',
#         'PASSWORD': 'Skycode@2025',
#         'HOST': 'db_dev',
#         # 'HOST': 'localhost',
#         'PORT': '5432',
#     }
# }
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'skycode_db_qa',
#         'USER': 'admin_user',
#         'PASSWORD': 'Skycode@2025',
#         'HOST': 'db_qa',
#         'PORT': '5432',
#     }
# }
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': 'skycode_db_projects',
#         'USER': 'admin_user',
#         'PASSWORD': 'Skycode@2025',
#         'HOST': 'db_projects',
#         # 'HOST': 'localhost',
#         'PORT': '5432',
#     }
# }
#
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#     }
# }

AUTH_PASSWORD_VALIDATORS = [  # Password validation
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

TIME_ZONE = "Asia/Kolkata"
USE_I18N = True

STATIC_URL = 'static/'

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email settings
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_USE_TLS = True
EMAIL_PORT = 587
EMAIL_HOST_USER = 'lowcodesky2024@gmail.com'
EMAIL_HOST_PASSWORD = 'xplp bgrf nmzp wikc'

# OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
