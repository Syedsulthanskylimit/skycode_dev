from django_celery_beat.models import PeriodicTask, CrontabSchedule
import json
from custom_components.models import Agent

def register_agent_cron_jobs():
    agents = Agent.objects.all()

    for agent in agents:
        task_name = f"run_mail_automation_agent_{agent.id}"
        cron_expr = agent.cron_timing.strip() if agent.cron_timing else None

        if not cron_expr:
            try:
                task = PeriodicTask.objects.get(name=task_name)
                task.delete()
            except PeriodicTask.DoesNotExist:
                continue
            continue

        try:
            minute, hour, day_of_month, month, day_of_week = cron_expr.split()
        except ValueError:
            continue

        schedule, _ = CrontabSchedule.objects.get_or_create(
            minute=minute,
            hour=hour,
            day_of_month=day_of_month,
            month_of_year=month,
            day_of_week=day_of_week,
        )

        # No args passed here
        periodic_task, _ = PeriodicTask.objects.update_or_create(
            name=task_name,
            defaults={
                "crontab": schedule,
                "task": "automation.tasks.run_mail_automation_agents",
                "enabled": agent.is_active,
            }
        )
