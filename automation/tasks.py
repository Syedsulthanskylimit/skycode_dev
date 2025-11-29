import json
import traceback

from celery import shared_task
from django.utils import timezone
from datetime import timedelta

from rest_framework.response import Response

from .models import *
from datetime import datetime
import logging

from custom_components.models import Agent, NotificationBotSchema

from form_generator.views import CaseRelatedFormView


from custom_components.utils.generate_notification_email_template import generate_notification_email_template

from form_generator.models import FilledFormData

from custom_components.models import IntegrationDetails

from custom_components.models import NotificationData, BotData
from form_generator.models import Case

from form_generator.utils.exceptions import ReceiverEmailResolutionError
from form_generator.utils.organization_based_email_utility import send_notification_email
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from rest_framework.parsers import JSONParser
logger = logging.getLogger('automation')
from rest_framework.settings import api_settings

def escalate_step(step_name,action, case_id, sla_id):
    """
    Dummy escalation handler.
    """
    logger.info(f"[Escalate] Triggered Step & Action: {step_name} & {action}")

    case_handler = CaseRelatedFormView()
    case = Case.objects.filter(id=case_id).first()

    process_id = case.processId
    case_id = case.id
    organization_name = case.organization
    organization_id = organization_name.id

    parent_case_id = case.parent_case or None

    if step_name == 'notify_step':

        notification_bot = NotificationBotSchema.objects.filter(
            notification_uid=action).first()


        """ Step 1: Extract all notification details """
        notification_type = notification_bot.type
        notification_uid = notification_bot.notification_uid
        notification_name = notification_bot.notification_name
        notification_field_id = notification_bot.notification_field_id
        receiver_type = notification_bot.receiver_type
        receiver_mail = notification_bot.receiver_mail
        approved_id = notification_bot.notification_field_id
        mail_content = notification_bot.mail_content or {}

        # Extract fields from nested mail_content
        mail_title = mail_content.get('mailTitle', '')
        mail_body = mail_content.get('mailBody', '')
        mail_footer = mail_content.get('mailFooter', '')
        mail_fields = mail_content.get('mailFields', [])
        mail_subject_notification = mail_content.get(
            'mailSubject', '')
        mail_pallet = mail_content.get('mailPallet', {})

        primary_color = mail_pallet.get('primaryColor', '#007BFF')
        secondary_color = mail_pallet.get(
            'secondaryColor', '#f2f2f2')

        # Step 2: Query all relevant models for the case_id
        all_data = []
        try:
            filtered_filled_form_table = FilledFormData.objects.filter(
                caseId=case_id)

        except Exception as e:
            logger.error(f"Error filtering FilledFormData: {e}")
            traceback.print_exc()

        try:
            filtered_integration_details = IntegrationDetails.objects.filter(
                case_id=case_id)
            # print("filtered_integration_details : ",filtered_integration_details)


        except Exception as e:
            logger.error(
                f"Error filtering IntegrationDetails: {e}")
            traceback.print_exc()

        try:
            filtered_notification_table = NotificationData.objects.filter(case_id=case_id)


        except Exception as e:
            # print(f"Error filtering NotificationData: {e}")
            traceback.print_exc()

        try:
            filtered_bot_table = BotData.objects.filter(
                case_id=case_id)

        except Exception as e:
            logger.error(f"Error filtering BotData: {e}")
            traceback.print_exc()

        # Load JSON data
        # print("filtered_filled_form_table : ", filtered_filled_form_table)

        for form in filtered_filled_form_table:
            try:
                json_data = json.loads(form.data_json) if isinstance(form.data_json,
                                                                     str) else form.data_json
                all_data.append(json_data)
            except Exception as e:
                logger.error(
                    f"Error processing filled form data: {e}")
                traceback.print_exc()
        # print("filtered_bot_table : ",filtered_bot_table)

        for item in filtered_bot_table:
            try:
                json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                       str) else item.data_schema
                all_data.append(json_data)
            except Exception as e:
                logger.error(f"Error processing bot data: {e}")
                traceback.print_exc()

        # print("filtered_notification_table : ",filtered_notification_table)

        for notification in filtered_notification_table:
            try:
                json_data = json.loads(notification.data_json) if isinstance(notification.data_json,
                                                                             str) else notification.data_json
                all_data.append(json_data)
            except Exception as e:
                print(f"Error processing notification data: {e}")
                traceback.print_exc()

        # print("filtered_integration_details : ",filtered_integration_details)

        for item in filtered_integration_details:
            try:
                json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                       str) else item.data_schema
                all_data.append(json_data)
            except Exception as e:
                logger.error(
                    f"Error processing integration details: {e}")
                traceback.print_exc()

        ######## added global data filter - 23.07.2025
        logger.info('case Global instance started ')

        case_global_data = case.parent_case_data

        if not isinstance(case_global_data, list):
            logger.warning("parent_case_data is not a list; setting empty list")
            case_global_data = []

        valid_case_global_data = [
            item for item in case_global_data
            if isinstance(item, dict) and item.get('value') not in [None, '', [], {}, ()]
        ]



        all_data.append(valid_case_global_data)

        # (Optional) Gather field values for use in the mail – customize this to your use case
        field_values = {}  # A dict like {'field1': 'value1', ...}
        # Usually the same as mail_fields if you want to populate those
        mail_data_ids = mail_fields
        field_labels = {}
        for submission in reversed(all_data):
            if not submission or not isinstance(submission, list):
                logger.warning(f"Skipping invalid submission: {submission}")
                continue
            # print("submission : ", submission)
            for data_item in submission:
                if not isinstance(data_item, dict):
                    continue

                current_field_id = data_item.get("field_id")
                if current_field_id in mail_data_ids and current_field_id not in field_values:
                    value = data_item.get("value")
                    label = data_item.get("label")

                    if isinstance(value, list) and all(
                            isinstance(v, dict) and "label" in v and "value" in v for v in value):
                        field_values[current_field_id] = value
                        field_labels[current_field_id] = label
                    else:
                        field_values[current_field_id] = value
                        field_labels[current_field_id] = label

        try:
            receiver_email_extracted = case_handler.extract_receiver_email(
                receiver_type, receiver_mail, all_data)

        except ReceiverEmailResolutionError as e:
            logger.error(f"Receiver email error: {e.message}")
            return Response({"error": e.message}, status=400)
            ########## Receiver mail Extraction from filled data ENDS ###################

        # sending mail Subject with field_id concate with subject text
        mail_subject = case_handler.resolve_mail_subject(
            mail_content, all_data)
        logging.info("Generate Notify Mail")
        html_content = generate_notification_email_template(
            mail_title=mail_title,
            mail_body_text=mail_body,
            mail_footer=mail_footer,
            mail_data_ids=mail_fields,
            field_values=field_values,
            field_labels=field_labels,
            primary_color=primary_color,
            secondary_color=secondary_color,
            url='https://example.com/approve',
            type_=notification_type
        )

        send_notification_email(to_email=receiver_email_extracted,
                                subject=mail_subject,
                                html_body=html_content,
                                organization_id=organization_id  # Make sure you pass it
                                )

        logger.info('Mail sent successfully')


        return None


    elif step_name == 'move_next_step':
        # case = Case.objects.filter(next_step=action).order_by('-updated_on').first()

        # parent_case_id = case.parent_case or None
        # request = action
        factory = APIRequestFactory()
        django_request = factory.post('/', {'action': action}, format='json')
        # drf_request = Request(django_request)
        drf_request = Request(
            django_request,
            parsers=[JSONParser()]
        )

        #
        case_handler.handle_case_step(drf_request,case.id)

        try:
            sla_case_instance = SlaCaseInstance.objects.get(case_id=case_id, sla_id=sla_id)
            sla_case_instance.is_completed = True
            sla_case_instance.save()
            logger.info(f"SlaCaseInstance marked as completed for case_id {case_id} and sla_id {sla_id}")
        except SlaCaseInstance.DoesNotExist:
            logger.warning(f"SlaCaseInstance not found for case_id {case_id} and sla_id {sla_id}")
        except Exception as e:
            logger.error(f"Error updating SlaCaseInstance: {e}")
        # return None
    return None


def get_duration_date(duration_date,case_id):

    # Query all relevant models for the case_id
    all_data = []
    try:
        filtered_filled_form_table = FilledFormData.objects.filter(
            caseId=case_id)
    except Exception as e:
        logger.error(f"Error filtering FilledFormData: {e}")
        traceback.print_exc()

    try:
        filtered_integration_details = IntegrationDetails.objects.filter(
            case_id=case_id)

    except Exception as e:
        logger.error(
            f"Error filtering IntegrationDetails: {e}")
        traceback.print_exc()

    try:
        filtered_notification_table = NotificationData.objects.filter(case_id=case_id)

    except Exception as e:
        # print(f"Error filtering NotificationData: {e}")
        traceback.print_exc()

    try:
        filtered_bot_table = BotData.objects.filter(
            case_id=case_id)
    except Exception as e:
        logger.error(f"Error filtering BotData: {e}")
        traceback.print_exc()

    # Load JSON data
    # print("filtered_filled_form_table : ", filtered_filled_form_table)

    for form in filtered_filled_form_table:
        try:
            json_data = json.loads(form.data_json) if isinstance(form.data_json,
                                                                 str) else form.data_json
            all_data.append(json_data)
        except Exception as e:
            logger.error(
                f"Error processing filled form data: {e}")
            traceback.print_exc()
    # print("filtered_bot_table : ",filtered_bot_table)

    for item in filtered_bot_table:
        try:
            json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                   str) else item.data_schema
            all_data.append(json_data)
        except Exception as e:
            logger.error(f"Error processing bot data: {e}")
            traceback.print_exc()

    # print("filtered_notification_table : ",filtered_notification_table)

    for notification in filtered_notification_table:
        try:
            json_data = json.loads(notification.data_json) if isinstance(notification.data_json,
                                                                         str) else notification.data_json
            all_data.append(json_data)
        except Exception as e:
            print(f"Error processing notification data: {e}")
            traceback.print_exc()

    # print("filtered_integration_details : ",filtered_integration_details)

    for item in filtered_integration_details:
        try:
            json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                   str) else item.data_schema
            all_data.append(json_data)
        except Exception as e:
            logger.error(
                f"Error processing integration details: {e}")
            traceback.print_exc()

    ######## added global data filter - 23.07.2025
    logger.info('case Global instance started ')
    case = Case.objects.filter(id=case_id).first()
    case_global_data = case.parent_case_data

    if not isinstance(case_global_data, list):
        logger.warning("parent_case_data is not a list; setting empty list")
        case_global_data = []

    valid_case_global_data = [
        item for item in case_global_data
        if isinstance(item, dict) and item.get('value') not in [None, '', [], {}, ()]
    ]


    all_data.append(valid_case_global_data)

    ####### duration_date may be date from previous steps,assigned date,created date
    # date_str = time_value_json.get(duration_date)
    date_str = None
    # 08-10-2025 by Harish (Latest Date value)[Project TI]
    # Step 1: Find the matching field_id in all_data
    for entry_list in reversed(all_data):
        if isinstance(entry_list, list):
            for item in entry_list:
                if isinstance(item, dict)and item.get("field_id") == duration_date and item.get("value"):
                    date_str = item["value"]
                    break
        if date_str:
            break

    if not date_str:
        logger.warning(f"[Warning] No date found for duration_date '{duration_date}'")
        return None

        # Try parsing with known formats
    for fmt in ("%d-%m-%Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return timezone.make_aware(dt)
        except ValueError:
            continue

    logger.error(f"Could not parse date for '{duration_date}': {date_str}")
    return None


@shared_task(name='automation.tasks.evaluate_all_slas_task')
def evaluate_all_slas_task():
    """
    Celery task wrapper to run the SLA evaluation.
    """
    evaluate_all_slas()

def evaluate_all_slas():
    """
    Evaluate SLA JSON conditions and return the summary as response.
    """
    current_time = timezone.now()
    # all_slas = Sla.objects.all()
    # Only fetch SLAs that are referenced in SlaCaseInstance
    all_sla_instances = SlaCaseInstance.objects.filter(is_completed=False, sla_id__isnull=False)

    logger.info(
        f"[SLA Evaluation] Started at {current_time.isoformat()}. Found {all_sla_instances.count()} SLA instances")

    summary = {
        "started_at": str(current_time),
        "sla_instance_count": all_sla_instances.count(),
        "results": []
    }

    for instance in all_sla_instances:
        sla = instance.sla_id
        case_id = instance.case_id.id if instance.case_id else None

        sla_result = {
            "sla_name": sla.sla_name,
            "process_id": sla.process_id.id if sla.process_id else None,
            "case_id": case_id,
            "conditions": []
        }

        schema = sla.sla_json_schema

        if not schema:
            msg = f"SLA '{sla.sla_name}' has empty schema. Skipping."
            logger.warning(msg)
            sla_result["warning"] = msg
            summary["results"].append(sla_result)
            continue

        for condition in schema:
            try:
                step_name = condition.get("sla_type")
                logger.debug(f"Inside loop step_name: {step_name}")
                if step_name == "regular_step":
                    sla_result["conditions"].append({"step_name": step_name, "skipped": True})
                    continue

                time_selection = condition.get("time_selection")
                operator = condition.get("operator")
                duration_date = condition.get("duration_date")
                comparison = condition.get("comparison", {})
                offset_type = comparison.get("offset_type")
                offset_value = comparison.get("value")
                action = comparison.get("action")

                if not all([time_selection, operator, duration_date, offset_type, action]):
                    msg = f"Incomplete condition in SLA '{sla.sla_name}': {condition}"
                    logger.warning(msg)
                    sla_result["conditions"].append({"error": msg})
                    continue

                # Step 1: get the current system date as base for time_selection

                if time_selection == "current_date":
                    base_time = current_time
                else:
                    msg = f"Unknown time_selection '{time_selection}'"
                    logger.warning(msg)
                    sla_result["conditions"].append({"error": msg})
                    continue

                logger.debug(f"base_time: {base_time}")

                # Step 2: get process field value for duration_date

                process_duration_date = get_duration_date(duration_date,case_id)
                print("process_duration_date : ",process_duration_date)
                logger.debug(f"process_duration_date: {process_duration_date}")

                if not isinstance(process_duration_date, datetime):
                    msg = f"Invalid duration date for '{duration_date}'"
                    logger.warning(msg)
                    sla_result["conditions"].append({"error": msg})
                    continue

                # Step 3: apply offset to process_duration_date

                try:
                    days_offset = int(offset_value)
                    logger.debug(f"days_offset: {days_offset}")

                except (ValueError, TypeError):
                    msg = f"Invalid offset value '{offset_value}'"
                    logger.warning(msg)
                    sla_result["conditions"].append({"error": msg})
                    continue


                if offset_type == "plus":
                    target_time = process_duration_date + timedelta(days=days_offset)
                elif offset_type == "minus":
                    target_time = process_duration_date - timedelta(days=days_offset)
                else:
                    msg = f"Unknown offset_type '{offset_type}'"
                    logger.warning(msg)
                    sla_result["conditions"].append({"error": msg})
                    continue

                logger.debug(f"target_time: {target_time}")
                print(f"target_time ----: {target_time}")

                # Step 4: evaluate operator

                condition_matched = False
                if operator == "greater_than":
                    condition_matched = base_time > target_time
                elif operator == "less_than":
                    condition_matched = base_time < target_time
                elif operator == "is_equal_to":
                    condition_matched = base_time.date() == target_time.date()
                else:
                    msg = f"Unknown operator '{operator}'"
                    logger.warning(msg)
                    sla_result["conditions"].append({"error": msg})
                    continue
                
                logger.debug(f"condition_matched: {condition_matched}")

                # Step 5: Condition Checked and escalation

                if condition_matched:
                    logger.debug(f"[Match] Process ID {sla.process_id} matched condition → calling escalate('{action}')")
                    escalate_step(step_name=step_name,action=action,case_id=case_id,sla_id=sla)
                    sla_result["conditions"].append({
                        "step_name": step_name,
                        "matched": True,
                        "action_triggered": action
                    })
                else:
                    logger.warning(f"Not Going to escalation")

                    sla_result["conditions"].append({
                        "step_name": step_name,
                        "matched": False
                    })

            except Exception as e:
                msg = f"Error evaluating SLA '{sla.sla_name}': {str(e)}"
                logger.error(msg)
                sla_result["conditions"].append({"error": msg})

        summary["results"].append(sla_result)

    summary["completed_at"] = str(timezone.now())
    return summary

@shared_task
def run_mail_automation_agents(*args, **kwargs):
    """
    This Celery task executes MailAutomationView for all active Agents based on cron schedule.
    """
    from .views import MailAutomationView

    try:
        factory = APIRequestFactory()
        view = MailAutomationView.as_view()

        active_agents = Agent.objects.filter(is_active=True)
        print(f"Found {active_agents.count()} active agents to process")

        for agent in active_agents:
            print(f"Running agent: {agent.agent_name}")
            request = factory.get(f"/automation/mail_automation/")
            response = view(request)
            print(f"Agent {agent.agent_name} result: {response.data}")

    except Exception as e:
        print(f"Error while running mail automation: {e}")
        traceback.print_exc()

