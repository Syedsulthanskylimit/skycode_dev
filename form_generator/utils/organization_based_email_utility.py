from django.core.mail import EmailMultiAlternatives, get_connection
from django.conf import settings
from form_generator.models import NotificationConfig  # Adjust import if needed
import json
import logging  # log messages

logger = logging.getLogger(__name__)

def send_notification_email(
    to_email,
    subject,
    html_body,
    plain_text_body=None,
    organization_id=None,
    cc_emails=None,
    bcc_emails=None
):
    """
    Sends an email using organization-specific email configuration.

    Args:
        to_email (str | list): Recipient email address(es).
        subject (str): Email subject.
        html_body (str): HTML content of the email.
        plain_text_body (str, optional): Plain text fallback. If None, uses a default.
        organization_id (int, optional): Organization ID to fetch SMTP config.
        cc_emails (list, optional): CC recipients.
        bcc_emails (list, optional): BCC recipients.
    """

    if not plain_text_body:
        plain_text_body = "This email contains HTML content. Please view it in an HTML-compatible email viewer."

    if isinstance(to_email, str):
        to_email = [email.strip() for email in to_email.split(';') if email.strip()]
        logger.info(f"to_email: {to_email}")

    # Get NotificationConfig
    try:
        config = NotificationConfig.objects.get(organization=organization_id)
        config_data = config.config_details  # Assuming this is a JSONField or dict
        if isinstance(config_data, str):
            config_data = json.loads(config_data)
    except NotificationConfig.DoesNotExist:
        raise Exception("Email configuration not found for this organization.")

    # Set up connection using the organization's SMTP config
    connection = get_connection(
        host=config_data.get("email_host"),
        port=config_data.get("email_port"),
        username=config_data.get("email_host_user"),
        password=config_data.get("email_host_password"),
        use_tls=config_data.get("use_tls", True),
        use_ssl=config_data.get("use_ssl", False),
    )

    # Build and send email
    from_email = config_data.get("email_host_user")

    email = EmailMultiAlternatives(
        subject=subject,
        body=plain_text_body,
        from_email=from_email,
        to=to_email,
        cc=cc_emails or [],
        bcc=bcc_emails or [],
        connection=connection
    )
    email.attach_alternative(html_body, "text/html")
    email.send()
