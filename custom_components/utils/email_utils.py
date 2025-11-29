import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

def send_email(subject, body, recipient_email):
    try:
        smtp_server = settings.EMAIL_HOST
        smtp_port = settings.EMAIL_PORT
        sender_email = settings.EMAIL_HOST_USER
        sender_password = settings.EMAIL_HOST_PASSWORD

        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = recipient_email
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, message.as_string())

        logger.info(f"Email sent to {recipient_email}")

    except Exception as e:
        logger.error(f"Error sending email to {recipient_email}: {str(e)}")
        raise
