from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from automation.utils.register_agent_cron_jobs import register_agent_cron_jobs
from custom_components.models import Agent

# Trigger cron registration/update when an Agent is saved
@receiver(post_save, sender=Agent)
def update_agent_cron(sender, instance, **kwargs):
    register_agent_cron_jobs()

# Trigger cron removal when an Agent is deleted
@receiver(post_delete, sender=Agent)
def delete_agent_cron(sender, instance, **kwargs):
    register_agent_cron_jobs()
