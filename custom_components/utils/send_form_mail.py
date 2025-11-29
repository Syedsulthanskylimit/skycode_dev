import json
import traceback

from django.core.mail import send_mail
from django.conf import settings
from django.core.signing import TimestampSigner, SignatureExpired, BadSignature
from django.db.backends.utils import logger
from django.urls import reverse
from form_generator.utils.organization_based_email_utility import send_notification_email
from rest_framework.response import Response

from custom_components.models import IntegrationDetails, NotificationData, BotData
from form_generator.models import FilledFormData
from form_generator.utils.exceptions import ReceiverEmailResolutionError



signer = TimestampSigner()

def generate_secure_token(data, max_age_seconds=86400):  # default: 1 day
    signed_data = signer.sign(data)
    return signed_data

def verify_secure_token(token, max_age_seconds=86400):
    try:
        unsigned_data = signer.unsign(token, max_age=max_age_seconds)
        return unsigned_data
    except (SignatureExpired, BadSignature):
        return None

def send_form_mail_with_token(case_id, process_id, organization_id, form_schema,form_uid):
    schema = form_schema.form_send_mail_schema

    receiver_mail = schema.get("receiver_mail",[])
    receiver_type = schema.get("receiver_type","")
    subject_text = schema.get("subject_text", '')
    subject_field_id = schema.get("subject_field_id", "")
    mail_title = schema.get("mail_title", '')
    mail_body_text = schema.get("mail_body", "")
    
    mail_fields = schema.get('mailFields', [])
    mail_content = {
        "mailSubject": {'subject_text':subject_text,'subject_field_id':subject_field_id},
    }
    # Generate one-time token with relevant data
    token_data = f"{organization_id}:{process_id}:{case_id}"
    token = generate_secure_token(token_data)


    ############# filtering data for Mail SUbject, Mail ID STARTS###########

    # Step 2: Query all relevant models for the case_id
    all_data = []
    try:
        filtered_filled_form_table = FilledFormData.objects.filter(
            caseId=case_id)
        logger.info("filtered_filled_form_table %s",
                    filtered_filled_form_table)
    except Exception as e:
        logger.error(f"Error filtering FilledFormData: {e}")
        traceback.print_exc()

    try:
        filtered_integration_details = IntegrationDetails.objects.filter(
            case_id=case_id)
        logger.info("filtered_integration_details %s",
                    filtered_integration_details)
    except Exception as e:
        logger.error(
            f"Error filtering IntegrationDetails: {e}")
        traceback.print_exc()
    try:
        logger.info('hhhhhhhhhhhhhhhhhhhhhhhhh')
        filterd_notification_table = NotificationData.objects.filter(case_id=case_id)
        logger.info("filterd_notification_table %s", filterd_notification_table)
    except Exception as e:
        print(f"Error filtering NotificationData: {e}")
        traceback.print_exc()
    try:
        filtered_bot_table = BotData.objects.filter(
            case_id=case_id)
        logger.info("filtered_bot_table %s",
                    filtered_bot_table)
    except Exception as e:
        logger.error(f"Error filtering BotData: {e}")
        traceback.print_exc()

    # Load JSON data
    for form in filtered_filled_form_table:
        try:
            json_data = json.loads(form.data_json) if isinstance(form.data_json,
                                                                 str) else form.data_json
            all_data.append(json_data)
        except Exception as e:
            logger.error(
                f"Error processing filled form data: {e}")
            traceback.print_exc()

    for item in filtered_bot_table:
        try:
            json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                   str) else item.data_schema
            all_data.append(json_data)
        except Exception as e:
            logger.error(f"Error processing bot data: {e}")
            traceback.print_exc()
    for notification in filterd_notification_table:
        try:
            json_data = json.loads(notification.data_json) if isinstance(notification.data_json,
                                                                         str) else notification.data_json
            all_data.append(json_data)
        except Exception as e:
            print(f"Error processing notification data: {e}")
            traceback.print_exc()
    for item in filtered_integration_details:
        try:
            json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                   str) else item.data_schema
            all_data.append(json_data)
        except Exception as e:
            logger.error(
                f"Error processing integration details: {e}")
            traceback.print_exc()
    logger.info("all_data %s", all_data)

    # (Optional) Gather field values for use in the mail – customize this to your use case
    field_values = {}  # A dict like {'field1': 'value1', ...}
    # Usually the same as mail_fields if you want to populate those
    mail_data_ids = mail_fields
    field_labels = {}
    # assuming all_data is a list containing a list of field dicts
    for submission in reversed(all_data):
        for data_item in submission:
            # for data_item in all_data[0]:
            if isinstance(data_item, dict):
                current_field_id = data_item.get("field_id")
                if current_field_id in mail_data_ids:
                    value = data_item.get("value")
                    label = data_item.get("label")
                    # Handle a special case like data table with a list of dicts
                    if isinstance(value, list) and all(
                            isinstance(v, dict) and "label" in v and "value" in v for v in value):
                        field_values[current_field_id] = value
                        field_labels[current_field_id] = label
                    else:
                        field_values[current_field_id] = value
                        field_labels[current_field_id] = label
        if field_values:
            break  # Stop after the first valid (latest) submission with match
    logger.info("Final field_values: %s", field_values)
    ########## Receiver mail Extraction from filled data STARTS ###################
    from form_generator.views import CaseRelatedFormView
    try:
        case_handler = CaseRelatedFormView()
        receiver_email_extracted = case_handler.extract_receiver_email(
            receiver_type=receiver_type, receiver_mail=receiver_mail,
    all_data=all_data)
        logger.info("receiver_email_+extracted %s",
                    receiver_email_extracted)
    except ReceiverEmailResolutionError as e:
        logger.error(f"Receiver email error: {e.message}")
        return Response({"error": e.message}, status=400)
    ########## Receiver mail Extraction from filled data ENDS ###################
    # sending mail Subject with field_id concate with subject text
    subject = case_handler.resolve_mail_subject(
        mail_content, all_data)

    ############# filtering data for Mail SUbject, Mail ID STARTS###########

    # Construct frontend or backend URL
    # Example: reverse("form-proceed-view") => /form/proceed/
    # proceed_url =  f"{settings.SITE_URL}/form-proceed/{token}"
    proceed_url = f"{settings.SITE_URL}/form-proceed/{organization_id}/{process_id}/{case_id}/{form_uid}/{token}/"

    html_body = f"""
    <html>
      <head>
        <style>
          body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            padding: 20px;
            margin: 0;
          }}
          .container {{
            background-color: #ffffff;
            max-width: 600px;
            margin: auto;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
          }}
          .title {{
            color: #333333;
            font-size: 24px;
            margin-bottom: 20px;
          }}
          .message {{
            color: #555555;
            font-size: 16px;
            line-height: 1.5;
            margin-bottom: 30px;
          }}
          .button {{
            display: inline-block;
            padding: 12px 25px;
            font-size: 16px;
            color: #ffffff;
            background-color: #28a745;
            text-decoration: none;
            border-radius: 5px;
          }}
          .footer {{
            font-size: 12px;
            color: #888888;
            margin-top: 40px;
            text-align: center;
          }}
        </style>
      </head>
      <body>
        <div class="container">
          <div class="title">{mail_title}</div>
          <div class="message">{mail_body_text}</div>
          <a href="{proceed_url}" class="button">Proceed</a>
          <div class="footer">
            If you did not request this, please ignore this email.
          </div>
        </div>
      </body>
    </html>
    """



    send_notification_email(
        receiver_email_extracted,
        subject,
        html_body,
        plain_text_body=None,
        organization_id=organization_id,
        cc_emails=None,
        bcc_emails=None
    )
    return True
