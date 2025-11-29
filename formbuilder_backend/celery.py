from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

from celery.schedules import crontab

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'formbuilder_backend.settings')

app = Celery('formbuilder_backend')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')
# app.config_from_object("django.conf:settings")
# Load task modules from all registered Django app configs.
app.autodiscover_tasks(['custom_components','automation'])


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


# app.conf.beat_schedule = {
#     'check-emails-every-5-minutes': {
#         'task': 'custom_components.tasks.monitor_emails_task',  # Use monitor_emails_task to match your function
#         'schedule': crontab(minute='*/5'),  # Every 5 minutes
#         # 'args': [scheduler.id]  # Pass scheduler_id as an argument
#     },
# }

