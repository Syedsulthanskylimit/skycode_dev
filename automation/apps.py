from django.apps import AppConfig
from django.db.models.signals import post_migrate


class SlaAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'automation'

class AutomationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'automation'

    def ready(self):
        from . import signals

        # Import the cron registration function
        from automation.utils.register_agent_cron_jobs import register_agent_cron_jobs

        # Create periodic tasks for existing agents at startup
        # Run after migrations complete
        post_migrate.connect(lambda **kwargs: register_agent_cron_jobs(), sender=self)
