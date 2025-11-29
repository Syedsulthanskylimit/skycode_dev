# task for Email Monitoring

from celery import shared_task
import os
import logging
from custom_components.models import Scheduler
from django_celery_beat.models import PeriodicTask
logger = logging.getLogger('custom_components')


@shared_task
def monitor_emails_task(scheduler_id):
    logger.info("Starting email monitoring...")
    from custom_components.views import MailMonitorSetting
    logger.info("Starting email monitoring...")
    logger.info(f"Task triggered with scheduler_id: {scheduler_id}")

    try:
        # Retrieve the scheduler instance
        scheduler = Scheduler.objects.get(id=scheduler_id)
        scheduler_config = scheduler.scheduler_config
        # Retrieve email configuration from scheduler_config
        receiver_mail = scheduler_config['receiver_mail']
        receiver_password = scheduler_config['receiver_password']
        imap_server = scheduler_config['imap_server']
        sender_email = scheduler_config['sender_email']
        scheduler_name= scheduler_config['scheduler_name']
        attachment_dir = "attachments"


        # Ensure the attachment directory exists
        if not os.path.exists(attachment_dir):
            os.makedirs(attachment_dir)
            logger.info(f"Created directory {attachment_dir} for attachments.")

        logger.info("Starting email monitoring...")

        # Call the authenticate_mail function
        result = MailMonitorSetting.authenticate_mail(
            imap_server, receiver_mail, receiver_password, sender_email,scheduler_id ,attachment_dir,scheduler_name
        )
        logger.info(f"Result from authenticate_mail: {result}")
        if isinstance(result, dict) and "error" in result:
            logger.error(f"Email processing error: {result['error']}")
            return {"status": "error", "message": result["error"]}
        # Check if there was an error
        # if "error" in result:
        #     logger.error(f"Email processing error: {result['error']}")
        #     return {"status": "error", "message": result["error"]}

        # Process attachments and generate download URLs (if needed)
        download_urls = []
        for filepath in result.get("attachments", []):
            download_url = f"/download/{os.path.basename(filepath)}"
            download_urls.append(download_url)

        result["download_urls"] = download_urls
        logger.info(f"Email processing successful: {result}")
        # Return the result as a dictionary (which Celery can serialize)
        return {
            "status": "success",
            "message": result.get("message", "Email processed successfully."),
            "attachments": result.get("attachments", []),
            "download_urls": download_urls,
            "email_body": result.get("email_body", ""),
            "scheduler_id":scheduler_id
        }
    except Exception as e:
        logger.error(f"An error occurred in the task: {e}")
        # Return an error message in a dictionary (serializable)
        return {"status": "error", "message": str(e)}


