"""
author : mohan
app_name : form_generator
"""
import calendar
import re

from django.contrib.auth.hashers import make_password
from django.db.models.functions import Cast
from django.utils.dateparse import parse_date
from django.utils.timezone import now
import uuid
from django.forms.models import model_to_dict
from django.db.models import Q
from itertools import chain
import threading
from sqlite3 import IntegrityError

from custom_components.utils.generate_uid import generate_uid
from openai import OpenAI
import requests

from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.request import Request

from .serializer import *

# function based api_view decorator
from rest_framework.decorators import api_view, authentication_classes

from django.contrib.auth import authenticate, login  # user authentication
from rest_framework.permissions import AllowAny  # JWT custom login
from rest_framework_simplejwt.tokens import RefreshToken  # JWT Token

import traceback
# pdf imports bgn
import os
from .models import FilledFormData  # Import your model
from django.http import HttpResponse, FileResponse, JsonResponse
from rest_framework.authtoken.models import Token  # login_authentication
from django.contrib.auth.mixins import LoginRequiredMixin  # login required decorator
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser
# add date in created date and eta date comparison
from datetime import datetime, date, time, timedelta
from django.shortcuts import get_object_or_404
# cron schedule imports bgn
# import datetime
# import time
import schedule
# cron schedule imports end
from custom_components.models import Bot, BotSchema, BotData, Integration, IntegrationDetails, Organization, UserGroup, \
    Ocr, Dms, Dms_data, Ocr_Details, Scheduler, SchedulerData, NotificationBotSchema, NotificationData
from custom_components.serializer import IntegrationDetailsSerializer, BotDataSerializer, OrganizationSerializer, \
    OcrSerializer, Ocr_DetailsSerializer, DmsDataSerializer, SchedulerDataSerializer, NotificationDataSerializer
from automation.models import SlaCaseInstance, SlaConfig

import json
import operator
from django.contrib.auth.models import User
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import UserData
from .serializer import UserDataSerializer
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail, get_connection

from rest_framework.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import IntegrityError, transaction
import logging  # log messages

from custom_components.views import activate_and_run_scheduler_task
from custom_components.utils.generate_notification_email_template import generate_notification_email_template

from .utils.exceptions import ReceiverEmailResolutionError
from .utils.organization_based_email_utility import send_notification_email
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from custom_components.utils.send_form_mail import verify_secure_token

from custom_components.utils.send_form_mail import send_form_mail_with_token

from rest_framework.pagination import PageNumberPagination
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Func, Q, F, TextField

# logger = logging.getLogger(__name__)
logger = logging.getLogger('form_generator')


# logger = logging.getLogger('formbuilder_backend')


class FormGeneratorAPIView(APIView):
    """
    1.1
    form-generator begins here.
    Users can create multiple forms and perform actions such as retrieving, updating, and deleting them.
    """

    def get(self, request, organization_id, form_id=None):
        try:
            if form_id:
                form = FormDataInfo.objects.get(
                    organization_id=organization_id, id=form_id)
                serializer = FormDataInfoSerializer(form)
                form_data = serializer.data

                # Get related permissions
                form_permissions = FormPermission.objects.filter(form_id=form.id).values('user_group', 'read', 'write',
                                                                                         'edit')
                form_data['permissions'] = list(
                    form_permissions) if form_permissions else None

                # Get form_rule_schema from Rule model
                # form_rules = Rule.objects.filter(form=form.id).values('form_rule_schema')
                # form_data['form_rule_schema'] = list(form_rules) if form_rules else []
                form_rules = Rule.objects.filter(form=form.id).values_list(
                    'form_rule_schema', flat=True)
                # form_data['form_rule_schema'] = list(form_rules)
                form_data['form_rule_schema'] = list(
                    chain.from_iterable(item for item in form_rules if item))
                return Response(form_data, status=status.HTTP_200_OK)
            else:
                forms = FormDataInfo.objects.filter(organization_id=organization_id, processId__isnull=True,
                                                    core_table=False).filter(
                    Q(Form_uid__isnull=True) | Q(Form_uid='')
                ).values()
                for form in forms:
                    form_permissions = FormPermission.objects.filter(form_id=form['id']).values('user_group', 'read',
                                                                                                'write', 'edit')
                    form['permissions'] = list(
                        form_permissions) if form_permissions else None

                    # form_rules = Rule.objects.filter(form=form['id']).values('form_rule_schema')
                    # form['form_rule_schema'] = list(form_rules) if form_rules else []
                    # form_rules = Rule.objects.filter(form=form.id).values_list('form_rule_schema', flat=True)
                    # form['form_rule_schema'] = list(form_rules)
                return Response(list(forms), status=status.HTTP_200_OK)
        except FormDataInfo.DoesNotExist:
            return Response({"error": "Form(s) not found for the organization"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        data = request.data

        form_name = data.get('form_name')
        form_json_schema = data.get('form_json_schema')
        form_style_schema = data.get('form_style_schema')
        # to filter the form based on usergroup
        form_filter_schema = data.get('form_filter_schema', {})
        form_level_rule = data.get('form_rule_schema', {})
        form_description = data.get('form_description')
        organization_id = data.get('organization')
        user_permissions = data.get('permissions')
        core_table = data.get('core_table', {})

        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Error retrieving organization: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            with transaction.atomic():
                form_data_instance, created = FormDataInfo.objects.update_or_create(
                    organization=organization,
                    form_name=form_name,  # Add form_name to the query parameters
                    defaults={
                        'form_json_schema': form_json_schema,
                        'form_style_schema': form_style_schema,
                        'form_filter_schema': form_filter_schema,  # to filter form
                        'form_description': form_description,
                        'core_table': core_table,
                        'form_send_mail_schema':{},
                    }
                )

                # Save form-level rules
                if form_level_rule:
                    rule_instance, rule_created = Rule.objects.update_or_create(
                        form=form_data_instance,
                        organization=organization,
                        # Assuming 'rule_data' is a JSON field
                        defaults={'form_rule_schema': form_level_rule}
                    )

                if user_permissions is not None:
                    # Clear existing permissions to avoid duplicates
                    FormPermission.objects.filter(
                        form=form_data_instance).delete()

                    # Create or update FormPermissions
                    for permission in user_permissions:
                        user_group_id = permission['user_group']
                        read = permission['read']
                        write = permission['write']
                        edit = permission['edit']

                        try:
                            user_group = UserGroup.objects.get(
                                id=user_group_id)
                        except UserGroup.DoesNotExist:
                            return Response({"error": f"User group with ID {user_group_id} not found"},
                                            status=status.HTTP_404_NOT_FOUND)

                        FormPermission.objects.create(
                            form=form_data_instance,
                            user_group=user_group,
                            read=read,
                            write=write,
                            edit=edit
                        )

            return Response({"message": "Form data and permissions saved successfully"}, status=status.HTTP_201_CREATED)
        except IntegrityError as e:
            return Response({"error": f"Database integrity error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, organization_id, form_id):
        data = request.data

        try:
            form_data_instance = FormDataInfo.objects.get(
                pk=form_id, organization_id=organization_id)
        except FormDataInfo.DoesNotExist:
            return Response({"error": "Form data not found for the given organization and form ID"},
                            status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Error retrieving Forms: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        form_name = data.get('form_name', form_data_instance.form_name)
        form_json_schema = data.get(
            'form_json_schema', form_data_instance.form_json_schema)
        form_style_schema = data.get(
            'form_style_schema', form_data_instance.form_style_schema)
        form_filter_schema = data.get(
            'form_filter_schema', form_data_instance.form_filter_schema) or []  # to filter the form
        # Ensure form level rule data is retrieved
        form_level_rule = data.get('form_rule_schema', {})
        form_description = data.get(
            'form_description', form_data_instance.form_description)
        organization_id = data.get(
            'organization', form_data_instance.organization.id)
        user_permissions = data.get('permissions', [])
        core_table = data.get('core_table', {})
        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Error retrieving organization: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            with transaction.atomic():
                form_data_instance.form_name = form_name
                form_data_instance.form_json_schema = form_json_schema
                form_data_instance.form_style_schema = form_style_schema
                form_data_instance.form_filter_schema = form_filter_schema  # to filter the form
                form_data_instance.form_description = form_description
                form_data_instance.organization = organization
                form_data_instance.core_table = core_table
                form_data_instance.save()

                # Update or create  Form Level Rule
                if form_level_rule:
                    rule_instance, _ = Rule.objects.update_or_create(
                        form=form_data_instance,
                        organization=organization,
                        # Assuming 'form_rule_data' is a JSONField
                        defaults={'form_rule_schema': form_level_rule}
                    )

                if user_permissions is not None:
                    # Clear existing permissions to avoid duplicates
                    FormPermission.objects.filter(
                        form=form_data_instance).delete()

                    # Create or update FormPermissions
                    for permission in user_permissions:
                        user_group_id = permission['user_group']
                        read = permission['read']
                        write = permission['write']
                        edit = permission['edit']

                        user_group = UserGroup.objects.get(id=user_group_id)

                        FormPermission.objects.create(
                            form=form_data_instance,
                            user_group=user_group,
                            read=read,
                            write=write,
                            edit=edit
                        )

            return Response({"message": "Form data and permissions updated successfully"}, status=status.HTTP_200_OK)
        except IntegrityError as e:
            return Response({"error": f"Database integrity error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, organization_id, form_id):
        try:
            form_data_instance = FormDataInfo.objects.get(
                pk=form_id, organization_id=organization_id)
        except FormDataInfo.DoesNotExist:
            return Response({"error": "Form data not found for the given organization and form ID"},
                            status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": f"Error retrieving form data: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            form_data_instance.delete()
            return Response({"message": "Form data and permissions deleted successfully"},
                            status=status.HTTP_204_NO_CONTENT)
        except IntegrityError as e:
            return Response({"error": f"Database integrity error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# 18-09-2025 by Harish (Save to DMS)[Product Level]
class UserFilledDataView(APIView):
    """
    1.2
    user filled data get,post,update and delete function
    """

    def get(self, request, organization_id=None, pk=None):
        """
        List all user data, retrieve particular data, or filter by organization.
        """
        global permissions_list
        try:
            if organization_id and pk:
                filled_data = FilledFormData.objects.get(
                    pk=pk, organization=organization_id)

                filled_data_list = [filled_data]
            elif organization_id:
                filled_data_list = FilledFormData.objects.filter(
                    organization=organization_id, processId__isnull=True)
                print("filled_data.formid", filled_data_list)
                # Extract form IDs from the filled form data
                form_ids = filled_data_list.values_list('formId', flat=True)

                # Filter the FormPermission table using the extracted form IDs
                form_permissions = FormPermission.objects.filter(form_id__in=form_ids).values(
                    'form_id', 'user_group__id', 'read', 'write', 'edit'
                )
                permissions_list = list(form_permissions)

            elif pk:
                filled_data = FilledFormData.objects.get(pk=pk)
                # print("filled_data.formid", filled_data)
                filled_data_list = [filled_data]
            else:
                filled_data_list = FilledFormData.objects.all()
                # print("filled_data.formid", filled_data_list)

            data = []
            for filled_data in filled_data_list:
                filled_data_info = FilledDataInfoSerializer(filled_data).data
                case = filled_data.caseId
                if case is not None:
                    filled_data_info['created_on'] = case.created_on
                    filled_data_info['updated_on'] = case.updated_on
                else:
                    filled_data_info['created_on'] = None
                    filled_data_info['updated_on'] = None
                # filled_data_info['created_on'] = case.created_on
                # filled_data_info['updated_on'] = case.updated_on
                # filled_data_info['process_name'] = filled_data.processId.process_name
                filled_data_info['process_name'] = (
                    filled_data.processId.process_name if filled_data.processId else None
                )
                filled_data_info['user_groups'] = list(
                    filled_data.user_groups.values_list('id', flat=True))
                # Add permissions to filled form data
                # Add permissions by matching form_id from permissions_list with filled_data.formId
                filled_data_info['permissions'] = [perm for perm in permissions_list if
                                                   perm['form_id'] == filled_data.formId]

                # filled_data_info.append(filled_data)

                # filled_data_info['user_groups'] = filled_data.user_groups.id if filled_data.user_groups else None
                data.append(filled_data_info)

            return Response(data if len(data) > 1 else data[0])
        except FilledFormData.DoesNotExist:
            return Response({"error": "Filled form data not found."}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "An unexpected error occurred.", "details": str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            print("Calling UserFilledDataView")
            # Parse jsonData
            json_data = request.data.get('jsonData', [])
            if isinstance(json_data, str):
                try:
                    json_data = json.loads(json_data)
                except json.JSONDecodeError:
                    return Response({'error': 'Invalid JSON format in jsonData'}, status=status.HTTP_400_BAD_REQUEST)

            # Extract required fields
            form_id = request.data.get('formId')
            organization_id = request.data.get('organization')
            user_id = request.data.get('user_id')

            if not form_id or not organization_id:
                return Response({'error': 'formId and organization are required fields'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Validate organization
            try:
                organization = Organization.objects.get(id=organization_id)
            except Organization.DoesNotExist:
                return Response({'error': 'Organization not found'}, status=status.HTTP_404_NOT_FOUND)

            user_instance = None
            if user_id:
                try:
                    user_instance = UserData.objects.get(id=user_id)
                except UserData.DoesNotExist:
                    user_instance = None

            # Extract file field id if present
            file_field_id = None
            for item in json_data:
                if item.get('field_id') and item.get('value'):
                    file_field_id = item['field_id']
                    break

            # Handle file uploads
            if request.FILES:
                dms_entries = Dms.objects.filter(organization=organization)
                if not dms_entries.exists():
                    return Response({'error': 'DMS configuration not found for the organization'},
                                    status=status.HTTP_404_NOT_FOUND)

                dms_config = dms_entries.first()
                drive_types = dms_config.drive_types
                configurations = dms_config.config_details_schema or {}
                configurations['drive_types'] = drive_types
                # Prepare metadata
                metadata = {
                    'form_id': str(form_id),
                    'organization_id': str(organization_id),
                    'data_json': json.dumps(json_data)  # Convert list/dict to string
                }
                # Add to configurations
                configurations['metadata'] = json.dumps(metadata)

                external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'

                for field_name, uploaded_file in request.FILES.items():
                    files = {'files': (uploaded_file.name, uploaded_file.file, uploaded_file.content_type)}
                    try:
                        response = requests.post(external_api_url, data=configurations, files=files)
                        response.raise_for_status()
                        response_json = response.json()

                        file_name = response_json.get('file_name')
                        file_id = response_json.get('file', {}).get('id') or response_json.get('file_id')
                        download_link = response_json.get('download_link')

                        # Save file info in Dms_data
                        try:
                            Dms_data.objects.get_or_create(
                                folder_id=file_id,
                                filename=file_name,
                                case_id=None,
                                download_link=download_link,
                                field_id=file_field_id,
                                user=user_instance,
                                organization=organization,
                                defaults={'meta_data': configurations['metadata']}
                            )
                        except Exception as e:
                            print("Error saving Dms_data:", e)

                    except requests.RequestException as e:
                        return Response({'error': f'Error uploading file {uploaded_file.name}: {str(e)}'},
                                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            uid = generate_uid(FilledFormData,'FFD',organization_id)
            # Save form data
            form_data = FilledFormData.objects.create(
                data_json=json_data,
                formId=form_id,
                organization=organization,
                uid=uid
            )

            return Response({'status': 'success', 'form_data_id': form_data.id}, status=status.HTTP_201_CREATED)

        except KeyError as e:
            return Response({'error': f'Missing required field: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': f'An unexpected error occurred: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):  # edit the particular filled form
        """
            Edit all user filled data
        """
        try:
            filled_data = FilledFormData.objects.get(pk=pk)
        except FilledFormData.DoesNotExist:
            return Response({'error': 'Filled form data not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error retrieving filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        serializer = FilledDataInfoSerializer(filled_data, data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(serializer.data)
            except ValidationError as e:
                return Response({'error': f'Validation error: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error': f'Error saving filled form data: {str(e)}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):  # delete the particular filled form
        try:
            filled_data = FilledFormData.objects.get(pk=pk)
        except FilledFormData.DoesNotExist:
            return Response({'error': 'Filled form data not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error retrieving filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            filled_data.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'error': f'Error deleting filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# organization based filled data used for form components alone
class FilledFormDataView(APIView):
    def casttotext(self, field_name):
        return Func(models.F(field_name), function='CAST', template="%(expressions)s::text", output_field=TextField())

    def get(self, request, organization_id=None, form_id=None, pk=None):
        """
        List all filled forms based on organization and form ID or retrieve a specific filled form by its ID.
        Only include forms that are not tagged with a process or case.
        """
        try:
            if organization_id and form_id and pk:
                try:
                    filled_data = FilledFormData.objects.filter(pk=pk, organization=organization_id, formId=form_id,
                                                                processId__isnull=True,
                                                                caseId__isnull=True).first()
                    filled_data_list = [filled_data] if filled_data else []
                except FilledFormData.DoesNotExist:
                    return Response({"detail": "Filled form not found."}, status=status.HTTP_404_NOT_FOUND)
                data = [{
                    'id': filled_data.id,
                    'formId': filled_data.formId,
                    'data_json': filled_data.data_json,
                    'created_at': filled_data.created_at,
                    'updated_at': filled_data.updated_at,
                    'organization': filled_data.organization.id,
                    'user_groups': list(filled_data.user_groups.values_list('id', flat=True)),
                }]
                return Response(data, status=status.HTTP_200_OK)
            # Retrieve filled forms based on organization and form ID
            elif organization_id and form_id:
                filled_data_list = FilledFormData.objects.filter(organization=organization_id, formId=form_id,
                                                                 processId__isnull=True,
                                                                 caseId__isnull=True)
            # Retrieve all filled forms not tagged with a process or case
            else:
                filled_data_list = FilledFormData.objects.filter(
                    processId__isnull=True, caseId__isnull=True)
            
            # Search fix (LIVE - 24/11/2025 - Harish)
            # --- Search ---
            search_query = request.query_params.get("search", None)
            if search_query:
                # Optional: sanitize search input (safe if user types special characters)
                import re
                search_query = re.sub(r'[^\w\s@.-]', '', search_query)

                filled_data_list = filled_data_list.annotate(
                    data_json_text=Cast('data_json', TextField()),
                    id_text=Cast('id', TextField()),
                    updated_at_text=Cast('updated_at', TextField())
                ).filter(
                    Q(id_text__icontains=search_query) |
                    Q(data_json_text__icontains=search_query) |
                    Q(updated_at_text__icontains=search_query)
                )
            # --- Field-specific searches (dynamic) ---
            # Search fix (LIVE - 24/11/2025 - Harish)
            reserved_params = {"page", "page_size", "search", "start_date", "end_date"}
            for key, value in request.query_params.items():
                if key not in reserved_params:
                    if key == "created_at":
                        start_date, end_date = parse_date_range(value)
                        if start_date and end_date:
                            filled_data_list = filled_data_list.filter(
                                updated_at__date__range=(start_date, end_date)
                            )
                    elif key == "id":
                        filled_data_list = filled_data_list.annotate(
                            id_text=Cast('id', TextField())
                        ).filter(id_text__icontains=value)

                    else:
                        filled_data_list = filled_data_list.annotate(
                            data_json_text=Cast('data_json', TextField())
                        ).filter(data_json_text__icontains=value)


            # Filter by date range if provided
            start_date = self.request.query_params.get("start_date")
            end_date = self.request.query_params.get("end_date")
            if start_date and end_date:
                filled_data_list = filled_data_list.filter(
                    created_at__date__range=[parse_date(start_date), parse_date(end_date)]
                )
            # --- Pagination ---
            filled_data_list = filled_data_list.order_by('-updated_at')
            if pk is None and organization_id and form_id:
                page = request.query_params.get("page", 1)
                page_size = request.query_params.get("page_size", 10)  # default 10
                paginator = Paginator(filled_data_list, page_size)
                try:
                    filled_data_list = paginator.page(page)
                except PageNotAnInteger:
                    filled_data_list = paginator.page(1)
                except EmptyPage:
                    filled_data_list = paginator.page(paginator.num_pages)
            data = []
            for filled_data in filled_data_list:
                filled_data_info = {
                    'id': filled_data.id,
                    'formId': filled_data.formId,
                    'data_json': filled_data.data_json,
                    'created_at': filled_data.created_at,
                    'updated_at': filled_data.updated_at,
                    'organization': filled_data.organization.id,
                    'user_groups': list(filled_data.user_groups.values_list('id', flat=True)),
                }
                data.append(filled_data_info)

            if not data:
                return Response([], status=status.HTTP_200_OK)

            # Return paginated response only if pagination was applied
            if pk is None and organization_id and form_id:
                return Response({
                    "count": paginator.count,
                    "total_pages": paginator.num_pages,
                    "current_page": int(page),
                    "page_size": int(page_size),
                    "results": data
                }, status=status.HTTP_200_OK)
            else:
                return Response(data, status=status.HTTP_200_OK)
            # return Response(data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"error": "Invalid ID provided or resource does not exist."},
                            status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            return Response({"error": f"Validation error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # except Exception as e:
        #     return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def get_form_data_count(request):
    """
    filled form data
    """
    form = FormDataInfo.objects.filter(form_status=True)
    response_data = []
    for f in form:
        filled_form_data = FilledFormData.objects.filter(form_id=f.pk)
        filled_form_serializer = FilledDataInfoSerializer(
            filled_form_data, many=True)
        response_data.extend(filled_form_serializer.data)
    return Response(response_data)


# adding this for process and case management (TWS):
class CreateProcessView(APIView):
    """
    2.1
    process begins with the use of a default JSON configuration, where users fill out an initial form.
    Subsequently, the case is generated, initiating the workflow.
    """

    def get_form_user_id_list(self, step_id, organization_id, process_id):
        '''
        Author: Paramesh
        Desc: Get the List of user ids base On Step id
        Usage: Send Mail to the List of Users Assigned to the Step
        return: int[]
        '''
        try:
            next_step_schema = FormDataInfo.objects.get(
                Form_uid=step_id, organization=organization_id, processId=process_id
            )
        except FormDataInfo.DoesNotExist:
            return []

        form_write_user_group_ids = FormPermission.objects.filter(
            form=next_step_schema,
            write=True
        ).values_list('user_group__id', flat=True)

        list_userGroupIds = list(form_write_user_group_ids)

        if not list_userGroupIds:
            return []

        userIds = list(UserData.objects.filter(
            usergroup__id__in=list_userGroupIds
        ).values_list('id', flat=True))

        return userIds

    def get(self, request, pk=None):
        if pk is None:
            try:
                filled_data = CreateProcess.objects.all().values('id', 'process_name')
                return Response(filled_data)
            except Exception as e:
                return Response({'error': f'An error occurred while fetching processes: {str(e)}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        elif pk is not None:
            # get the process id
            try:
                id_based_form_record = CreateProcess.objects.get(pk=pk)
                organization = id_based_form_record.organization

                process_data = id_based_form_record.participants  # get overall json form data
                process_name = id_based_form_record.process_name
                process_description = id_based_form_record.process_description
                process_user_groups = list(
                    id_based_form_record.user_group.values_list('id', flat=True))
                print("process_user_groups", process_user_groups)
                # Adding process stages on 18.3.25 by Praba
                # process_stages = id_based_form_record.process_stages
                process_stages = id_based_form_record.process_stages or {}

                process_table_configuration = id_based_form_record.process_table_configuration or []

                parent_case_data_schema = id_based_form_record.parent_case_data_schema or []

                # Extract the first currentStepId from flow_1 in the executionFlow
                execution_flow = process_data.get("executionFlow", {})
                print("execution_flow", execution_flow)
                first_current_step_id = process_data["executionFlow"]["flow_1"]["currentStepId"]
                print("first_current_step_id", first_current_step_id)
                current_next_step_id = process_data["executionFlow"]["flow_1"]["nextStepId"]

                print("current_next_step_id", current_next_step_id)
                form = FormDataInfo.objects.filter(
                    Form_uid=first_current_step_id).first()

                scheduler = Scheduler.objects.filter(
                    scheduler_uid=first_current_step_id).first()
                if scheduler:
                    logger.info("######### Scheduler Starts ################")
                    print("___________ Scheduler Starts __________________")
                    result = activate_and_run_scheduler_task(
                        first_current_step_id)
                    print("result", result)
                    if result["status"] == "success":
                        logger.info("Scheduler task activated and running.")
                        return None

                    else:
                        logger.error(
                            f"Failed to activate scheduler task: {result['message']}")
                        return None
                else:
                    logger.info(
                        "################# Start Element is not Scheduler ############### ")
                    # start_element = Scheduler.objects.filter(scheduler_uid=current_next_step_id).first()

                    form = FormDataInfo.objects.filter(
                        Form_uid=current_next_step_id).first()
                    from itertools import chain
                    if form:
                        print('--- Activity starts --- 1')
                        form_id_ref = form.id

                        form_input_data = form.form_json_schema
                        form_style_schema = form.form_style_schema or []
                        form_filter_schema = form.form_filter_schema or []  # to filter the form
                        rule_instance = Rule.objects.filter(
                            form=form_id_ref).values_list("form_rule_schema", flat=True)
                        form_level_rule = list(chain.from_iterable(
                            rule_instance)) if rule_instance else []
                        # rule_instance = Rule.objects.filter(form=form_id_ref)
                        # form_level_rule = rule_instance.form_rule_schema
                        # form_level_rule = list(rule_instance.values_list("form_rule_schema", flat=True))
                        # Extracting related user groups/permissions
                        form_user_groups = form.user_groups.all() if hasattr(form,
                                                                             'user_groups') else []  # Assuming a
                        form_permissions = FormPermission.objects.filter(
                            form=form_id_ref
                        ).values(
                            'user_group__id', 'read', 'write', 'edit'
                        )

                        permissions_list = list(form_permissions)
                        # ManyToMany or related field
                        user_groups_data = [
                            {
                                "id": user_group.id,
                                "name": user_group.group_name,
                            }
                            for user_group in form_user_groups
                        ]

                        response_data = {
                            "form_name": form.form_name,  # Assuming `name` field exists in `FormDataInfo`
                            "form_schema": form_input_data,  # Assuming this is already in the required format
                            "form_userGroups": permissions_list,  # List of user group/permission data
                            "process_name": process_name,
                            "process_description": process_description,
                            "process_user_groups": process_user_groups,
                            "process_stages": process_stages,
                            "process_table_configuration": process_table_configuration,
                            "parent_case_data_schema": parent_case_data_schema,
                            "form_style_schema": form_style_schema,
                            "form_filter_schema": form_filter_schema,
                            "form_rule_schema": form_level_rule,
                            "form_send_mail": form.form_send_mail or False,
                            "form_send_mail_schema": form.form_send_mail_schema or {},

                        }
                        logger.info("response____________________data")

                        return Response(response_data, status=status.HTTP_200_OK)
                    else:
                        return Response({'error': 'Form not found for the given currentStepId'},
                                        status=status.HTTP_404_NOT_FOUND)
            except CreateProcess.DoesNotExist:
                return Response({'error': 'Process not found'}, status=status.HTTP_404_NOT_FOUND)
            except KeyError as e:
                # Handle missing keys in the JSON data
                return Response({'error': f'Missing key in JSON data: {str(e)}'},
                                status=status.HTTP_400_BAD_REQUEST)
            except ObjectDoesNotExist as e:
                # Catch other object does not exist errors
                return Response({'error': f'Resource not found: {str(e)}'},
                                status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                # Handle any other unexpected errors
                return Response({'error': f'An unexpected error occurred: {str(e)}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            # return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)
        return None

    def get_stage_name(self, process_stages, step_id):
        """
        function to return the Process stages name
        """
        if not process_stages:  # Check if process_stages is empty or None
            return None
        for stage, stage_data in process_stages.items():
            for step in stage_data.get("Steps", []):
                if step.get("stepId") == step_id:
                    return stage_data.get("StageName")
        return None  # Return None if step_id is not found

    def post(self, request, pk=None):

        global dms_data
        try:
            # 08-09-2025 By Harish
            user_id = request.data.get('userId', None)
            user_data_id = None
            if user_id:
                try:
                    user_data_id = UserData.objects.get(id=user_id)
                except UserData.DoesNotExist:
                    print(f"UserData with id {user_id} does not exist.")
                except Exception as e:
                    print("Unexpected error while fetching UserData:", e)
            else:
                print("userId not provided in request.")

            if pk is None:
                process_data = CreateProcess.objects.all()
            elif pk is not None:
                try:
                    # get the process id
                    id_based_form_record = CreateProcess.objects.get(pk=pk)
                    organization_id = id_based_form_record.organization.id
                    process_data = id_based_form_record.participants
                    process_id = id_based_form_record.pk
                    print("process_id", process_id)
                except CreateProcess.DoesNotExist:
                    return Response({'error': 'Process not found'}, status=status.HTTP_404_NOT_FOUND)
                if not id_based_form_record:
                    return Response({'error': 'Process not found'}, status=status.HTTP_404_NOT_FOUND)

                # Get the first key in the executionFlow dictionary
                first_key = next(iter(process_data["executionFlow"]))
                if first_key is None:
                    return Response({'error': 'Invalid process data: executionFlow is empty'},
                                    status=status.HTTP_400_BAD_REQUEST)

                flows = []
                # Iterate over the executionFlow to get currentStepId and nextStepId
                for flow_key, flow_value in process_data["executionFlow"].items():
                    start_form_id = flow_value["currentStepId"]
                    end_form_id = flow_value["nextStepId"]
                    if start_form_id is None or end_form_id is None:
                        return Response({'error': 'Invalid flow data'}, status=status.HTTP_400_BAD_REQUEST)
                    flows.append({"start": start_form_id, "end": end_form_id})

                    # field data (request)
                    userId = None  # request.data['userId']
                    form_filled_data_json = None
                    dms_ids_latet_update_case = []

                    res = self.get(request, pk)
                    form_schema = res.data
                    schema = form_schema.get("form_schema")
                    id_based_form_record = CreateProcess.objects.get(pk=pk)
                    organization_id = id_based_form_record.organization.id
                    # target_form_name = id_based_form_record.first_step  # Initial form
                    # get overall json participants data
                    generated_ids = generate_sequence_ids(schema, organization_id) or []
                    if 'data_json' in request.data and request.data['data_json']:
                        try:
                            print('-------------=============')
                            data_json_str = request.data['data_json']
                            if isinstance(data_json_str, str):
                                data_json = json.loads(data_json_str)
                                form_filled_data_json = data_json

                            else:
                                data_json = data_json_str
                                form_filled_data_json = data_json

                            # data_json = json.loads(data_json_str)
                            # Retrieve the parent_process ID from the parsed JSON
                            # # parent_process_id = data_json.get('parent_process_id')
                            if len(generated_ids) > 0 and isinstance(form_filled_data_json, list):
                                form_filled_data_json.extend(generated_ids)

                            ######## Removed beacause i got error in the console ###########
                            parent_case_id = request.data.get(
                                'parent_case_id', None)
                            print("parent_case_id", parent_case_id)
                            # if not parent_case_id:
                            #     return Response({'error': 'parent_case_id ID not found '}, status=400)

                        except json.JSONDecodeError as e:
                            return Response({'error': 'Invalid JSON data', 'details': str(e)},
                                            status=status.HTTP_400_BAD_REQUEST)

                        if request.FILES:  # modified for multiple files
                            # Handle files if present in request.FILES
                            files = []
                            files_with_ids = []  # added to store multiple file names
                            for field_name_id, uploaded_file in request.FILES.items():
                                file_field_id = field_name_id.split('[')[0]
                                files_with_ids.append({
                                    "field_id": file_field_id,
                                    "file_tuple": (
                                        'files',  # field name for requests
                                        (uploaded_file.name, uploaded_file.file, uploaded_file.content_type)
                                    )
                                })

                                # files.append(
                                #     ('files', (uploaded_file.name,
                                #      uploaded_file.file, uploaded_file.content_type))
                                # )

                            # Fetch drive types and configurations for the specific organization
                            dms_entries = Dms.objects.filter(
                                organization=organization_id, flow_id=process_id) # By Harish 31.10.25
                            # drive_types = list(dms_entries.values_list('drive_types', flat=True))
                            drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}

                            configurations = dms_entries.first().config_details_schema
                            # configurations.update("drive_type": drive_types)
                            configurations['drive_types'] = drive_types
                            # configurations['s3_bucket_metadata'] = drive_types

                            # only_values = [{'v': item['value']} for item in data_json] # reduce the size of the data_json
                            if isinstance(data_json, list):
                                only_values = [{'v': item.get('value')} for item in data_json if
                                               isinstance(item, dict) and 'value' in item]
                            else:
                                only_values = []
                            # [] |  sting | number  | [{}]

                            # [ ' ', '' ,'' , ] 

                            string_only_values = json.dumps(only_values)

                            data_json_size = len(string_only_values.encode('utf-8'))
                            if data_json_size > 1900:
                                logger.warning("data_json too large (%d bytes), trimming to empty list", data_json_size)
                                string_only_values = "[]"
                            logger.info("size_in_bytes  %s", data_json_size)
                            metadata = {'form_id': start_form_id, 'organization_id': str(organization_id),
                                        'data_json': string_only_values}
                            # Extract the file from the request
                            configurations['metadata'] = json.dumps(metadata)

                            # external_api_url = 'http://192.168.0.106:8000/custom_components/FileUploadView/'
                            # for field_name, (filename, fileobj, content_type) in files:
                            for file_info in files_with_ids:
                                current_file_field_id = file_info["field_id"]  # ✅ Correct field ID
                                field_name, (filename, fileobj, content_type) = file_info["file_tuple"]
                                f = {
                                    field_name: (filename, fileobj, content_type)
                                }
                                external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                                response = requests.post(
                                    external_api_url,
                                    data=configurations,
                                    files=f
                                )

                                if response.status_code == 200:
                                    # responses.append(response.json())  # Store the response
                                    response_json = response.json()
                                    logger.info("response_json--------------", response_json)

                                    file_name = response_json.get('file_name')
                                    file_id = response_json.get(
                                        'file', {}).get('id')
                                    if not file_id:
                                        file_id = response_json.get('file_id')

                                    download_link = response_json.get(
                                        'download_link')
                                    # Correctly get the file_field_id for this file

                                    try:
                                        organization_instance = Organization.objects.get(
                                            id=organization_id)
                                    except Organization.DoesNotExist:
                                        # Handle the case where the organization does not exist
                                        organization_instance = None
                                    try:
                                        process_instance = CreateProcess.objects.get(
                                            id=process_id)
                                    except CreateProcess.DoesNotExist:
                                        # Handle the case where the organization does not exist
                                        process_instance = None
                                    logger.info(
                                        "Save to Dms data start")
                                    try:
                                        dms_data, created = Dms_data.objects.get_or_create(
                                            folder_id=file_id,
                                            filename=file_name,
                                            case_id=None,
                                            flow_id=process_instance,
                                            download_link=download_link,
                                            field_id=current_file_field_id,
                                            user=user_data_id,
                                            organization=organization_instance,
                                            defaults={
                                                'meta_data': configurations['metadata']}
                                        )

                                        if dms_data.id:
                                            dms_ids_latet_update_case.append(dms_data.id)


                                    except Exception as e:
                                        print("Error during get_or_create:", e)

                                        # Print details of integration_data to see if it is None or has unexpected values
                                    if dms_data is None:
                                        print("dms_data is None")
                                    else:
                                        logger.info("dms_data details: %s", dms_data.__dict__)
                                        print(
                                            f"dms_data details: {dms_data.__dict__}")

                                        # If BotData was found, update the data_schema fieldF
                                    if not created:
                                        try:
                                            logger.info("Save to Dms data start")

                                            dms_data.meta_data = dms_data
                                            dms_data.save()  # Ensure you call save on the correct object

                                        except Exception as e:
                                            print(
                                                "Error during integration_data save:", e)
                                else:
                                    response_json = response.json()
                                    return Response({'error': 'Failed to upload file:', 'details': response_json},
                                                    status=status.HTTP_404_NOT_FOUND)

                                # print("Failed to upload file:", response_json)

                                # responses.append(response_json)

                        # data_json = data_json_str
                        form_status = "In Progress"
                        caseId = None  # request.data['caseId']
                        process_id = id_based_form_record.pk

                        # Assign userId from request or default to 'admin' to
                        userId = request.data.get('userId', None)
                        logger.info(" USer ID%s", userId)
                        user = None
                        if userId:
                            # Replace `UserData` with your user model
                            user = UserData.objects.filter(id=userId).first()
                            logger.info("user %s", user)

                        if user:
                            created_by = user.user_name

                            logger.info("User found: %s", user.user_name)
                        else:
                            created_by = "Admin"
                        # Fetch form name from FormData model
                        step_name = "None"  # Default value if form is not found
                        form_instance = FormDataInfo.objects.filter(
                            Form_uid=end_form_id).first()
                        if form_instance:
                            # Assuming 'name' is the form name field
                            step_name = form_instance.form_name or 'Placeholder Name'
                        Filled_data_json = {
                            'formId': end_form_id,
                            'userId': userId,
                            'processId': process_id,
                            # json list (need to change)
                            'data_json': data_json,
                            'caseId': caseId,
                            'status': form_status,
                            'organization': organization_id
                        }
                        # request.data.get('user_id', 'admin')
                        # FilledFormData
                        serializer = FilledDataInfoSerializer(
                            data=Filled_data_json)

                        if serializer.is_valid():
                            instance = serializer.save()

                            # Case field data (caseSerializer request)
                            today = str(date.today())
                            # request.data.get('created_on', today)
                            created_on = today
                            # created_by = 'admin'  # request.data.get('created_by', 'admin')

                            # request.data.get('userId', 'admin')
                            created_by = created_by
                            # request.data.get('updated_on', today)
                            updated_on = today
                            # request.data.get('updated_by', '')
                            updated_by = ''
                            process_id = id_based_form_record.pk
                            # Store filled form id in case as json (array)
                            filled_form_id = instance.pk
                            filled_form_ids = [filled_form_id]
                            filled_form_id_data = filled_form_ids
                            filled_form_id_data_json = json.dumps(
                                filled_form_id_data)
                            ########### User history to check the history of cases starts #########################
                            # Ensure user_case_history is always a valid list
                            user_case_history = []
                            saved_data = []

                            # If userId, created_on, and form_name exist, append to history
                            if userId and created_on and step_name:
                                user_case_history.append({
                                    'userId': str(userId),
                                    'executed_on': str(created_on),
                                    'step_name': str(step_name),
                                    'user_name': str(user.user_name),
                                    'user_profile_pic': str(user.profile_pic)
                                })
                                # Simulating saving to DB
                                saved_data = json.dumps(user_case_history)
                                # If user_case_history is empty, ensure it's still a valid list:
                                if not user_case_history:
                                    saved_data = []  # Send an empty list instead of an invalid format
                            else:
                                saved_data = '[]'  #

                            ########### User history to check the history of cases Ends #########################
                            # Case field data
                            data_json = {
                                'processId': process_id,
                                'organization': organization_id,
                                'created_on': created_on,
                                'created_by': created_by,
                                'status': 'In Progress',
                                'updated_on': updated_on,
                                'updated_by': updated_by,
                                'next_step': '',
                                # json list (need to change)
                                'data_json': filled_form_id_data_json,
                                'path_json': '',
                                'parent_case': parent_case_id,  # // Removed Beacause I got error
                                # 'parent_case': '',
                                'assigned_users': [],
                                # 'user_case_history': saved_data  # json list to store case history
                                'user_case_history': saved_data  # json list to store case history
                                # of user
                            }
                            # Simulating saving to DB
                            # saved_data = json.dumps(data_to_save)  #

                            # Case
                            case_serializer = CaseSerializer(data=data_json)

                            if case_serializer.is_valid():
                                print('if works---')
                                case_instance = case_serializer.save()
                                print('case_instance--', case_instance)

                                # Apply rule bgn
                                # current filled form data (for apply rule) bgn
                                filled_form_data = FilledFormData.objects.filter(
                                    pk=instance.pk).first()
                                filled_form_data_schema_form_id = filled_form_data.formId

                                if filled_form_data:
                                    current_form_id = filled_form_data.formId
                                    next_step_id = None
                                    current_step_id = None
                                    for flow_key, flow_value in process_data["executionFlow"].items():
                                        if flow_value["currentStepId"] == current_form_id:
                                            next_step_id = flow_value["nextStepId"]
                                            current_step_id = flow_value["currentStepId"]
                                            break

                                    if next_step_id:
                                        case_instance.next_step = next_step_id
                                        case_instance.save()
                                        # step_id = next_step_id
                                        # process_stages = {}
                                        step_id = current_step_id
                                        process_stages = id_based_form_record.process_stages or {}

                                        stage_name = self.get_stage_name(
                                            process_stages, step_id)
                                        if stage_name:
                                            case_instance.status = stage_name
                                            case_instance.stages = stage_name
                                            case_instance.save()
                                        # case_instance.status = stage_name
                                        # case_instance.save()   # saving the case stages

                                        user_id_list = self.get_form_user_id_list(next_step_id, organization_id,
                                                                                  process_id)
                                        if user_id_list is not None and len(user_id_list) > 0:
                                            send_email(organization_id, user_id_list, "ACTION_TWO",
                                                       {"org_id": organization_id, "case_id": case_instance.pk})

                                    else:
                                        print(
                                            "No next step found for the current form.")

                                #
                                # Verify the updated next_step
                                updated_case = Case.objects.get(
                                    pk=case_instance.pk)
                                print("Updated next_step:",
                                      updated_case.next_step)

                                print(
                                    '+++++++++++++++++++++++ END 1+++++++++++++++++++++++++')
                                # find where end form stored in participants from json data  end
                                # Apply rule end

                                # store case id in filled form
                                get_case_id = case_instance.pk

                                # # Dms Data Upded the cse id

                                logger.info('inject data start')
                                case_handler = CaseRelatedFormView()
                                case_handler.inject_parent_case_data(process_id, get_case_id, form_filled_data_json)
                                for dms_id in dms_ids_latet_update_case:
                                    try:
                                        dms_instance = Dms_data.objects.get(id=dms_id)
                                        dms_instance.case_id = case_instance  # Ensure get_case_id is a Case model instance
                                        dms_instance.save()
                                    except Dms_data.DoesNotExist:
                                        logger.warning("DMS data with ID %s does not exist", dms_id)

                                print('get_case_id---', get_case_id)
                                submitted_form_queryset = FilledFormData.objects.filter(
                                    pk=instance.pk)
                                print('submitted_form_queryset---1',
                                      submitted_form_queryset)

                                # Update the attributes of the retrieved object
                                submitted_form_queryset.update(
                                    caseId=get_case_id, status="Completed")

                                # Get the first object from the queryset (assuming there's only one)
                                submitted_form_instance = submitted_form_queryset.first()
                                print('submitted_form_instance---2',
                                      submitted_form_instance)

                                # Access the formId attribute of the retrieved object
                                get_form_schema_id = submitted_form_instance.formId
                                print('get_form_schema_id--3',
                                      get_form_schema_id)

                                # Update the case id in DMS

                                print(
                                    '+++++++++++++++++++++++ END 2+++++++++++++++++++++++++')

                                # trigger_url = f"http://192.168.0.106:8000/process_related_cases/{get_case_id}/"
                                trigger_url = f'{settings.BASE_URL}/process_related_cases/{get_case_id}/'
                                # Adjust the payload as needed
                                payload = {'case_id': get_case_id}

                                try:
                                    trigger_response = requests.post(
                                        trigger_url, data=payload)

                                    trigger_response.raise_for_status()
                                    if trigger_response.status_code == 200:
                                        print("Successfully triggered the URL")
                                    else:
                                        # print(f"Failed to trigger the URL, status code: {trigger_response.status_code}")

                                        error = {
                                            "error": "Failed to trigger the URL",
                                            "status_code": trigger_response.status_code,
                                            "response": trigger_response.text,
                                        }

                                        # Send the error message to the required destination (API response, log file, etc.)
                                        # return error_message
                                        return Response(error, status=trigger_response.status_code)

                                except requests.RequestException as e:
                                    return Response({'error': 'Failed to trigger the URL', 'details': str(e)},
                                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                                # Trigger the get_case_related_forms URL after returning the case_id
                                response = Response(
                                    {
                                        "success": True, 
                                        "message": "Case created successfully", 
                                        "case_id": case_instance.pk,
                                    },
                                    status=status.HTTP_201_CREATED
                                )
                                return response
                            return Response(case_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                    return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print("An unexpected error occurred:", e)
            return Response({'error': 'An unexpected error occurred', 'details': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'error': 'Invalid request'}, status=status.HTTP_400_BAD_REQUEST)


############################## to display case related data ######################################


class CaseDetailView(APIView):
    def get(self, request, organization_id, process_id, case_id):
        try:
            # Fetch the specific case
            case = Case.objects.get(
                id=case_id, organization_id=organization_id, processId=process_id)
        except Case.DoesNotExist:
            return Response({'error': 'Case not found'}, status=404)
        filled_form_data_list = []
        try:
            # Fetch filled form data associated with this case
            filled_form_data = FilledFormData.objects.filter(caseId=case_id, organization_id=organization_id,
                                                             processId=process_id)
            # Serialize the case
            case_data = CaseSerializer(case).data

            if filled_form_data.exists():

                # Retrieve form details and append to filled form data
                for filled_data in filled_form_data:
                    form_id = str(filled_data.formId)

                    form_info = FormDataInfo.objects.filter(
                        Form_uid=form_id).first()
                    form_permissions = FormPermission.objects.filter(
                        form=form_info
                    ).values(
                        'user_group__id', 'read', 'write', 'edit'
                    )

                    permissions_list = list(form_permissions)

                    filled_data_serialized = FilledDataInfoSerializer(
                        filled_data).data
                    if form_info:
                        filled_data_serialized['form_name'] = form_info.form_name
                        filled_data_serialized['form_description'] = form_info.form_description
                        filled_data_serialized['permissions'] = permissions_list if permissions_list else [
                        ]
                    filled_form_data_list.append(filled_data_serialized)
            # else:
            #     return Response({ 'filled_form_data_list': None})
        except Exception as e:
            return Response({'error': f'Error retrieving filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            # Try fetching bot data for the given case_id
            bot_data = BotData.objects.filter(
                case_id=case_id,
                organization_id=organization_id,
                flow_id=process_id
            )

            # Serialize only if data exists
            serialized_bot_data = (
                BotDataSerializer(bot_data, many=True).data if bot_data.exists() else []
            )
            # bot_data = BotData.objects.filter(
            #     case_id=case_id, organization=organization_id, flow_id=process_id)
            # print("bot_data ###########",bot_data)
            # serialized_bot_data = BotDataSerializer(
            #     bot_data, many=True).data if bot_data.exists() else []
            print("serialized_bot_data 1111111111111111", serialized_bot_data)

        except Exception as e:
            return Response({'error': f'Error retrieving bot data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            # Fetch and serialize bot data
            notification_data = NotificationData.objects.filter(
                case_id=case_id)

            serialized_notification_data = NotificationDataSerializer(

                notification_data, many=True).data if notification_data.exists() else []
        except Exception as e:
            return Response({'error': f'Error retrieving bot data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            # Fetch and serialize integration data
            integration_data = IntegrationDetails.objects.filter(case_id=case_id, organization=organization_id,
                                                                 flow_id=process_id)
            serialized_integration_data = IntegrationDetailsSerializer(integration_data,
                                                                       many=True).data if integration_data.exists() else []
        except Exception as e:
            return Response({'error': f'Error retrieving integration data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            # Fetch and serialize OCR data
            ocr_data = Ocr_Details.objects.filter(case_id=case_id, organization=organization_id,
                                                  flow_id=process_id)
            serialized_ocr_data = Ocr_DetailsSerializer(
                ocr_data, many=True).data if ocr_data.exists() else []
        except Exception as e:
            return Response({'error': f'Error retrieving OCR data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            # Fetch and serialize DMS data
            dms_data_qs = Dms_data.objects.filter(case_id=case_id, organization=organization_id,
                                                  flow_id=process_id)
            serialized_dms_data = DmsDataSerializer(
                dms_data_qs, many=True).data if dms_data_qs.exists() else []
        except Exception as e:
            return Response({'error': f'Error retrieving DMS data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            # Fetch and serialize DMS data
            scheduler_data = SchedulerData.objects.filter(case_id=case_id, organization=organization_id,
                                                          process=process_id)
            serialized_scheduler_data = SchedulerDataSerializer(scheduler_data,
                                                                many=True).data if scheduler_data.exists() else []
        except Exception as e:
            return Response({'error': f'Error retrieving DMS data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # Fetch subprocess cases
        subprocess_cases_qs = Case.objects.filter(parent_case=case_id, organization_id=organization_id,
                                                  )
        subprocess_cases = []

        if subprocess_cases_qs.exists():
            for sub_case in subprocess_cases_qs:
                serialized_case = CaseSerializer(sub_case).data  # This should be a dict
                serialized_case["process_name"] = sub_case.processId.process_name if sub_case.processId else None
                subprocess_cases.append(serialized_case)
        case_core_data = case.parent_case_data if case.parent_case_data else []
        # Construct the response data
        response_data = {
            'case': case_data,
            'filled_form_data': filled_form_data_list,
            'bot_data': serialized_bot_data,
            'integration_data': serialized_integration_data,
            'notification_data': serialized_notification_data,
            'ocr_data': serialized_ocr_data,
            'dms_data': serialized_dms_data,
            'scheduler_data': serialized_scheduler_data,
            'subprocess_cases': [subprocess_cases],
            'case_core_data': case_core_data
        }

        # return Response(response_data)
        return Response(response_data)


############################## case releted data ends ################################################


############################### case details related to subprocess and cases which is tagged with parent case [Begins]###################
class CaseDetailsBySubprocessView(APIView):
    def get(self, request, organization_id, process_id, parent_case_id):
        try:
            # Fetch all cases linked to the parent_case_id
            cases = Case.objects.filter(parent_case=parent_case_id, organization_id=organization_id,
                                        processId=process_id)
            print("cases", cases)
            if not cases.exists():
                return Response({'error': 'No cases found for the given parent_case_id'}, status=404)

            all_case_details = []

            for case in cases:
                case_details = CaseSerializer(case).data
                filled_form_data_list = []
                try:
                    # Fetch filled form data for each case
                    filled_form_data = FilledFormData.objects.filter(
                        caseId=case.id,
                        organization_id=organization_id,
                        processId=process_id
                    )
                    ####################### subprocess form permisssion ########################

                    ############ getting case initiating user details Starts ############
                    user_case_history = case_details.get('user_case_history')
                    case_initiated_by = None
                    try:
                        history = json.loads(
                            user_case_history) if user_case_history else []
                        first = history[0] if isinstance(
                            history, list) and history else {}
                        user_id = first.get('userId') if isinstance(
                            first, dict) else None
                        case_initiated_by = int(
                            user_id) if user_id is not None else None
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass

                    case_details['case_initiated_by'] = case_initiated_by

                    ############ getting case initiating user details ENDS############

                    data_json_value = case_details.get(
                        'data_json')  # Safely get the value
                    if data_json_value:
                        # Parse data_json only if it is not None
                        data_json_ids = [
                            int(id.strip()) for id in data_json_value.strip('[]').split(',') if id.strip().isdigit()
                        ]
                        data_json_id = data_json_ids[0] if data_json_ids else None
                    else:
                        data_json_id = None
                    # data_json_ids = [int(id.strip()) for id in data_item['data_json'].strip('[]').split(',') if
                    #                  id.strip().isdigit()]
                    #
                    # data_json_id = data_json_ids[0] if data_json_ids else None

                    try:
                        filled_form_data = FilledFormData.objects.get(
                            pk=data_json_id)
                    except FilledFormData.DoesNotExist:
                        filled_form_data = None

                    dt = FilledDataInfoSerializer(filled_form_data).data
                    data_json_value = dt.get('data_json', None)

                    # If it's a string, try parsing it
                    if isinstance(data_json_value, str):
                        try:
                            data_json_value = json.loads(data_json_value)
                        except json.JSONDecodeError:
                            data_json_value = {}
                    case_details['data_json'] = data_json_value

                    # data_json_value = case_details.get('data_json', None)
                    #
                    #
                    # case_details['data_json'] = data_json_value

                    # Use get() on each dictionary item
                    next_step = case_details.get('next_step')

                    if next_step:
                        try:
                            next_step_schema = FormDataInfo.objects.get(
                                Form_uid=next_step, organization=organization_id, processId=process_id
                            )

                            form_permissions = FormPermission.objects.filter(
                                form=next_step_schema
                            ).values(
                                'user_group__id', 'read', 'write', 'edit'
                            )

                            permissions_list = list(form_permissions)
                            logger.info(
                                "Form Permissions Retrieved: %s", permissions_list)

                            case_details['permissions'] = permissions_list if permissions_list else [
                            ]

                        except FormDataInfo.DoesNotExist:
                            logger.info(
                                "Form schema not found for next_step: %s", next_step)
                            case_details['permissions'] = []

                        try:
                            next_step_schema = FormDataInfo.objects.get(
                                Form_uid=next_step, organization=organization_id, processId=process_id
                            )
                            # added for form filter
                            case_details['form_filter_schema'] = next_step_schema.form_filter_schema

                            form_permissions = FormPermission.objects.filter(form=next_step_schema.id).values(
                                'user_group', 'read', 'write', 'edit'
                            )

                            case_details['permissions'] = list(
                                form_permissions) if form_permissions else None

                        except:
                            pass
                        try:
                            print("************************")
                            next_step_schema = CreateProcess.objects.get(
                                subprocess_UID=next_step, organization=organization_id
                            )

                            print("Next Step Schema ID:", next_step_schema.process_name)

                            table_permissions = next_step_schema.process_table_permission or []

                            case_details['permissions'] = table_permissions
                            case_details['form_filter_schema'] = table_permissions
                        except CreateProcess.DoesNotExist:
                            print("Form schema not found for next_step:", next_step)

                        try:
                            next_step_schema = NotificationBotSchema.objects.filter(notification_uid=next_step).first()

                            if next_step_schema:
                                print("************************ 1")

                                table_permissions = next_step_schema.notification_element_permission or []

                                case_details['permissions'] = table_permissions
                                case_details['form_filter_schema'] = table_permissions
                        except CreateProcess.DoesNotExist:
                            print("Notification not found for next_step:", next_step)
                        ############# subprocess form permission ends ########################
                        try:
                            bot_instance = Bot.objects.get(bot_uid=next_step)
                            bot_element_data = BotSchema.objects.get(
                                bot=bot_instance,
                                organization=organization_id,
                                flow_id=process_id
                            )

                            case_details['form_filter_schema'] = bot_element_data.bot_element_permission or []
                            case_details['permissions'] = bot_element_data.bot_element_permission or []

                        except Bot.DoesNotExist:
                            print("Bot not found for bot_uid:", next_step)
                            # data_item['bot_element_permission'] = None

                        except BotData.DoesNotExist:
                            print("BotData not found for bot:", bot_instance)
                        try:
                            end_step_schema = EndElement.objects.filter(element_uid=next_step).first()
                            if end_step_schema:
                                print("************************ 2")

                                table_permissions = end_step_schema.end_element_schema.get('end_element_permission', [])
                                case_details['permissions'] = table_permissions
                                case_details['form_filter_schema'] = table_permissions
                        except EndElement.DoesNotExist:
                            print("End Element not found for next_step:", next_step)
                    if filled_form_data is not None:

                        for filled_data in filled_form_data:
                            form_id = str(filled_data.formId)
                            form_info = FormDataInfo.objects.filter(
                                Form_uid=form_id).first()
                            filled_data_serialized = FilledDataInfoSerializer(
                                filled_data).data
                            ############ subprocess form permissions #############################

                            if form_info:
                                filled_data_serialized['form_name'] = form_info.form_name
                                filled_data_serialized['form_description'] = form_info.form_description
                            filled_form_data_list.append(
                                filled_data_serialized)

                    case_details['filled_form_data'] = filled_form_data_list
                    case_details['permissions'] = list(
                        form_permissions) if form_permissions else None
                except Exception as e:
                    case_details[
                        'filled_form_data_error'] = f'Error retrieving filled form data: {str(e)}'

                try:
                    # Fetch bot data for each case
                    bot_data = BotData.objects.filter(
                        case_id=case.id, organization=organization_id, flow_id=process_id)
                    case_details['bot_data'] = BotDataSerializer(
                        bot_data, many=True).data if bot_data.exists() else []
                except Exception as e:
                    case_details['bot_data_error'] = f'Error retrieving bot data: {str(e)}'

                try:
                    # Fetch integration data for each case
                    integration_data = IntegrationDetails.objects.filter(
                        case_id=case.id,
                        organization=organization_id,
                        flow_id=process_id
                    )
                    case_details['integration_data'] = IntegrationDetailsSerializer(integration_data,
                                                                                    many=True).data if integration_data.exists() else []
                except Exception as e:
                    case_details[
                        'integration_data_error'] = f'Error retrieving integration data: {str(e)}'

                try:
                    # Fetch OCR data for each case
                    ocr_data = Ocr_Details.objects.filter(case_id=case.id, organization=organization_id,
                                                          flow_id=process_id)
                    case_details['ocr_data'] = Ocr_DetailsSerializer(ocr_data,
                                                                     many=True).data if ocr_data.exists() else []
                except Exception as e:
                    case_details['ocr_data_error'] = f'Error retrieving OCR data: {str(e)}'

                try:
                    # Fetch DMS data for each case
                    dms_data_qs = Dms_data.objects.filter(case_id=case.id, organization=organization_id,
                                                          flow_id=process_id)
                    case_details['dms_data'] = DmsDataSerializer(dms_data_qs,
                                                                 many=True).data if dms_data_qs.exists() else []
                except Exception as e:
                    case_details['dms_data_error'] = f'Error retrieving DMS data: {str(e)}'

                try:
                    # Fetch Scheduler data for each case
                    scheduler_data = SchedulerData.objects.filter(case_id=case.id, organization=organization_id,
                                                                  process=process_id)
                    case_details['scheduler_data'] = SchedulerDataSerializer(scheduler_data,
                                                                             many=True).data if scheduler_data.exists() else []
                except Exception as e:
                    case_details[
                        'scheduler_data_error'] = f'Error retrieving scheduler data: {str(e)}'

                all_case_details.append(case_details)

            return Response(all_case_details)

        except Exception as e:
            return Response({'error': f'Error retrieving cases: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


############################### case details related to subprocess and cases which is tagged with parent case [Ends]-By Praba###################


class CaseRelatedFormView(APIView):
    """
    getting case related filled form and form schema
    """

    def get(self, request, organization_id=None, process_id=None, pk=None):

        # 04-08-2025 By Harish for parent case id
        # try:
        #     process_data = CreateProcess.objects.get(id=process_id, organization=organization_id)
        #     parent_process_id = process_data.parent_process.id if process_data.parent_process else None
        #     print("parent_process_id:", parent_process_id)
        # except CreateProcess.DoesNotExist:
        #     parent_process_id = None
        #     print(f"No process found with id={process_id} and organization={organization_id}")
        # except Exception as e:
        #     parent_process_id = None
        #     print(f"Unexpected error while fetching parent_process_id: {str(e)}")

        logger.info("Case Related Form view")

        if pk is None:
            print("process_id : ", process_id)
            print("pk : ", pk)
            print("###1111111111111111111111")
            cases = Case.objects.filter(
                organization_id=organization_id, processId=process_id)

            parent_process_ids = Case.objects.filter(
                organization_id=organization_id,
                processId=process_id,
                parent_case__isnull=False
            ).values_list('parent_case__processId_id', flat=True).distinct()

            serializer = CaseSerializer(cases, many=True)
            serialized_data = serializer.data

            # data_item['form_permissions'] = permissions_list

            for data_item in serialized_data:
                ############ getting case initiating user details Starts ############
                user_case_history = data_item.get('user_case_history')
                case_initiated_by = None
                # 04-08-2025 By Harish for parent case id
                parent_case = data_item.get('parent_case')
                parent_process_id_filter = case = Case.objects.get(organization_id=organization_id, pk=parent_case)
                parent_process_id = parent_process_id_filter.processId.id
                print("parent_process_id", parent_process_id_filter.processId.id)
                data_item['parent_process_id'] = parent_process_id
                print("data_item : ", data_item)
                # data_item['parent_process_id'] = parent_process_id if parent_process_id else None
                try:
                    history = json.loads(
                        user_case_history) if user_case_history else []
                    first = history[0] if isinstance(
                        history, list) and history else {}
                    user_id = first.get('userId') if isinstance(
                        first, dict) else None
                    case_initiated_by = int(
                        user_id) if user_id is not None else None
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

                data_item['case_initiated_by'] = case_initiated_by

                ############ getting case initiating user details ENDS############

                data_json_value = data_item.get(
                    'data_json')  # Safely get the value
                if data_json_value:
                    # Parse data_json only if it is not None
                    data_json_ids = [
                        int(id.strip()) for id in data_json_value.strip('[]').split(',') if id.strip().isdigit()
                    ]
                    data_json_id = data_json_ids[0] if data_json_ids else None
                else:
                    data_json_id = None
                # data_json_ids = [int(id.strip()) for id in data_item['data_json'].strip('[]').split(',') if
                #                  id.strip().isdigit()]
                #
                # data_json_id = data_json_ids[0] if data_json_ids else None

                try:
                    filled_form_data = FilledFormData.objects.get(
                        pk=data_json_id)
                except FilledFormData.DoesNotExist:
                    filled_form_data = None

                dt = FilledDataInfoSerializer(filled_form_data).data
                data_json_value = dt.get('data_json', None)

                # If it's a string, try parsing it
                if isinstance(data_json_value, str):
                    try:
                        data_json_value = json.loads(data_json_value)
                    except json.JSONDecodeError:
                        data_json_value = {}
                data_item['data_json'] = data_json_value

                # Use get() on each dictionary item
                next_step = data_item.get('next_step')
                print("next_stepppppppppp", next_step)
                logger.info("next_step: %s", next_step)
                if next_step:

                    try:
                        next_step_schema = FormDataInfo.objects.get(
                            Form_uid=next_step, organization=organization_id, processId=process_id
                        )

                        print("Next Step Schema ID:", next_step_schema.form_name)

                        form_permissions = FormPermission.objects.filter(form=next_step_schema.id).values(
                            'user_group', 'read', 'write', 'edit'
                        )

                        print("Form Permissions Retrieved:",
                              list(form_permissions))

                        data_item['permissions'] = list(
                            form_permissions) if form_permissions else None
                        data_item['next_step_schema'] = next_step_schema.form_json_schema
                        # added for form filter
                        data_item['form_filter_schema'] = next_step_schema.form_filter_schema
                    except FormDataInfo.DoesNotExist:
                        print("Form schema not found for next_step:", next_step)
                        data_item['permissions'] = []

                    try:
                        next_step_schema = CreateProcess.objects.get(
                            subprocess_UID=next_step, organization=organization_id
                        )

                        print("Next Step Schema IDadsfadsdfs:", next_step_schema.process_name)

                        table_permissions = next_step_schema.process_table_permission or []

                        data_item['permissions'] = table_permissions
                        data_item['form_filter_schema'] = table_permissions
                    except CreateProcess.DoesNotExist:
                        print("Sub process schema not found for next_step:", next_step)

                    try:
                        next_step_schema = NotificationBotSchema.objects.filter(notification_uid=next_step).first()
                        if next_step_schema:
                            print("Next Step Schema ID rrrrrrrrrr")

                            print("Next Step Schema ID dfsaaaa:", next_step_schema.notification_name)

                            table_permissions = next_step_schema.notification_element_permission or []

                            data_item['permissions'] = table_permissions
                            data_item['form_filter_schema'] = table_permissions
                    except NotificationBotSchema.DoesNotExist:
                        print("Notification not found for next_step:", next_step)

                    try:
                        emd_element_data = EndElement.objects.get(
                            element_uid=next_step, organization=organization_id, process=process_id)

                        # Add the schema to the response
                        data_item['end_element_schema'] = emd_element_data.end_element_schema
                        data_item['form_filter_schema'] = emd_element_data.end_element_schema.get(
                            'end_element_permission',
                            [])
                        data_item['permissions'] = emd_element_data.end_element_schema.get('end_element_permission', [])
                        # return self.handle_case_step(request, pk)


                    except EndElement.DoesNotExist:
                        print("End element not found for next_step:", next_step)
                        # data_item['end_element_schema'] = None

                    try:
                        bot_instance = Bot.objects.get(bot_uid=next_step)
                        bot_element_data = BotSchema.objects.get(
                            bot=bot_instance,
                            organization=organization_id,
                            flow_id=process_id
                        )

                        data_item['form_filter_schema'] = bot_element_data.bot_element_permission or []
                        data_item['permissions'] = bot_element_data.bot_element_permission or []


                    except Bot.DoesNotExist:
                        print("Bot not found for bot_uid:", next_step)
                        # data_item['bot_element_permission'] = None

                    except BotData.DoesNotExist:
                        print("BotData not found for bot:", bot_instance)
                        # data_item['bot_element_permission'] = None

            return Response(serialized_data)

        else:

            try:
                case = Case.objects.get(
                    pk=pk, organization_id=organization_id, processId=process_id)
            except Case.DoesNotExist:
                return Response({'error': 'Case not found'}, status=404)
            process = CreateProcess.objects.get(
                id=process_id, organization=organization_id)
            # response_data['process_name'] = process.process_name,
            # response_data['process_stages'] = process.process_name,
            case_id = case.id
            next_step = case.next_step
            print("next_step", next_step)
            try:
                subprocess_schema = CreateProcess.objects.get(subprocess_UID=next_step, organization=organization_id,
                                                              parent_process=process_id)
                print("subprocess_schema", subprocess_schema)

            except CreateProcess.DoesNotExist:
                logger.error("Subprocess not found for Subprocess_uid=%s, organization_id=%s, processId=%s", next_step,
                             organization_id, process_id)
                subprocess_schema = None
                # return Response(
                #     {"error": f"Subprocess with ID {next_step} does not exist."},
                #     status=status.HTTP_404_NOT_FOUND,
                # )

            rule = None
            form_json_schema = None
            form_rule_schema = None
            process_codeblock_schema = None

            try:
                form_json_schema = FormDataInfo.objects.get(
                    Form_uid=next_step,
                    organization=organization_id,
                    processId=process_id
                )

                try:
                    rule = Rule.objects.get(
                        form=form_json_schema,
                        organization=organization_id,
                        processId=process_id
                    )
                    form_rule_schema = rule.form_rule_schema or ''
                    process_codeblock_schema = rule.process_codeblock_schema or ''

                except Rule.DoesNotExist:
                    logger.error("Rule not found for form=%s, organization_id=%s, processId=%s",
                                 form_json_schema, organization_id, process_id)

            except FormDataInfo.DoesNotExist:
                logger.error("FormDataInfo not found for Form_uid=%s, organization_id=%s, processId=%s",
                             next_step, organization_id, process_id)

            try:
                ocr_data = Ocr.objects.get(
                    ocr_uid=next_step, organization=organization_id, flow_id=process_id)
            except Ocr.DoesNotExist:
                ocr_data = None

            try:

                rule_schema = Rule.objects.get(ruleId=next_step, organization=organization_id,
                                               processId=process_id)
                return self.handle_case_step(request, pk)

            except Rule.DoesNotExist:
                rule_schema = None

            try:
                notifction_schema = NotificationBotSchema.objects.get(notification_uid=next_step)
                return self.handle_case_step(request, pk)

            except NotificationBotSchema.DoesNotExist:
                notifction_schema = None

            try:
                emd_element_data = EndElement.objects.get(
                    element_uid=next_step, organization=organization_id, process=process_id)
                return self.handle_case_step(request, pk)
            except EndElement.DoesNotExist:
                emd_element_data = None

            try:

                api_schema = Integration.objects.get(Integration_uid=next_step, organization=organization_id,
                                                     flow_id=process_id)
                return self.handle_case_step(request, pk)

            except Integration.DoesNotExist:
                api_schema = None

            try:

                bot_schema_123 = BotSchema.objects.get(bot__bot_uid=next_step, organization=organization_id,
                                                       flow_id=process_id)

                return self.handle_case_step(request, pk)

            except BotSchema.DoesNotExist:
                bot_schema_123 = None

            # Initialize response data with case information
            response_data = {
                'caseid': case.id,
                'createdby': case.created_by,
                'createdon': case.created_on,
                'updatedon': case.updated_on,
                'updatedby': case.updated_by,
                'status': case.status,
                'stages': case.stages,
                'process_name': process.process_name,
                'process_stages': process.process_stages,
                'process_table_configuration': process.process_table_configuration,
                "parent_case_data_schema": process.parent_case_data_schema,
                # 04-08-2025 By Harish for parent case id
                # "parent_process_id" : parent_process_id

            }

            # Include OCR data if it exists
            if ocr_data:
                ocr_data_list = Ocr.objects.filter(
                    ocr_uid=next_step, organization=organization_id, flow_id=process_id)
                serializer = OcrSerializer(ocr_data_list, many=True)
                # Assuming only one OCR schema is needed
                response_data['ocr_schema'] = serializer.data[0]

            # Include form data if it exists
            elif form_json_schema:
                logger.info("Fetching FormDataInfo with Form_uid=%s, organization_id=%s, processId=%s", next_step,
                            organization_id, process_id)
                form_json_schema = FormDataInfo.objects.get(Form_uid=next_step, organization=organization_id,
                                                            processId=process_id)

                form_user_groups = form_json_schema.user_groups.all() if hasattr(form_json_schema,
                                                                                 'user_groups') else []  # Assuming a
                rule = None
                try:
                    rule = Rule.objects.get(
                        form=form_json_schema, organization=organization_id, processId=process_id)
                    form_rule_schema = rule.form_rule_schema or ''
                except Rule.DoesNotExist:
                    logger.error("Rule not found for form=%s, organization_id=%s, processId=%s", form_json_schema,
                                 organization_id, process_id)
                    form_rule_schema = None

                # ManyToMany or related field
                user_groups_data = [
                    {
                        "id": user_group.id,
                        "name": user_group.group_name,
                    }
                    for user_group in form_user_groups
                ]

                # response_data = {

                #
                process = CreateProcess.objects.get(
                    id=process_id, organization=organization_id)
                # response_data['process_name'] = process.process_name,
                # response_data['process_stages'] = process.process_stages,
                response_data['form_schema'] = form_json_schema.form_json_schema
                response_data['form_style_schema'] = form_json_schema.form_style_schema
                # to filter the form
                response_data['form_filter_schema'] = form_json_schema.form_filter_schema
                response_data['form_name'] = form_json_schema.form_name
                response_data['form_rule_schema'] = form_rule_schema
                response_data['case_initator'] = 'dsfsdafadsfd'
                # print("response_data", response_data)

            elif bot_schema_123:
                response_data['step_type'] = 'bot'
                response_data['bot_schema'] = bot_schema_123.bot_schema_json
                response_data['form_filter_schema'] = bot_schema_123.bot_element_permission
                print("bot_schema", response_data)

            elif subprocess_schema:
                response_data = {
                    "subprocess_schema": {
                        "id": subprocess_schema.id,
                        "name": subprocess_schema.process_name,
                        "description": subprocess_schema.process_description,
                        "subprocess_UID": subprocess_schema.subprocess_UID,
                        "parent_process": subprocess_schema.parent_process.id,
                        # "steps": subprocess_data.steps,  # Adjust this field based on your model
                    }
                }
                # response_data['subprocess_schema'] =

            # If neither OCR nor form data is present, include form and bot data if available
            else:
                print("###3333333333333")
                cs_id = case.id
                form_schema22 = FilledFormData.objects.filter(caseId=cs_id)

                bot_data = BotData.objects.filter(case_id=cs_id)
                # bot_names = [bot_data.bot.bot_name for bot_data in bot_data]
                bot_names = [bot_data.bot.bot_name if bot_data.bot and bot_data.bot.bot_name else '' for bot_data in
                             bot_data]
                integration_data = IntegrationDetails.objects.filter(
                    case_id=cs_id)
                integration_names = [integration_data.integration.integration_type for integration_data in
                                     integration_data]
                ocr_data = Ocr_Details.objects.filter(case_id=cs_id)
                print("ocr_data", ocr_data)
                ocr_names = [ocr_data.data_schema for ocr_data in
                             ocr_data]
                print("ocr_names", ocr_names)
                dms_data_qs = Dms_data.objects.filter(case_id=cs_id)
                dms_names = [
                    dms.dms.drive_types for dms in dms_data_qs if dms.dms is not None]

                serialized_bot_data = BotDataSerializer(
                    bot_data, many=True).data
                serialized_integration_data = IntegrationDetailsSerializer(
                    integration_data, many=True).data
                serialized_dms_data = DmsDataSerializer(
                    dms_data_qs, many=True).data
                serialized_ocr_data = Ocr_DetailsSerializer(
                    ocr_data, many=True).data

                form_data_list = []
                form_schemas = []
                bot_schema = []
                form_style_schema = []
                form_filter_schema = []  # to filter the form
                for form_data_id in form_schema22:
                    f_id = form_data_id.formId
                    form_data = FormDataInfo.objects.filter(
                        Form_uid=f_id).first()
                    if form_data:
                        serializer = FormDataInfoSerializer(form_data)
                        form_data_list.append(serializer.data)
                    form_schemas.append(form_data_id)
                process = CreateProcess.objects.get(
                    id=process_id, organization=organization_id)
                if form_schemas:
                    serializer_data = FilledDataInfoSerializer(
                        form_schemas, many=True)

                    response_data.update({
                        'form_schema': form_json_schema,
                        'form_style_schema': form_style_schema,
                        'form_filter_schema': form_filter_schema,  # to filter the form
                        # 'form_name': form_json_schema.form_name,

                        'process_name': process.process_name,
                        'process_stages': process.process_stages,  # Assuming it's a JSONField or List
                        'process_table_configuration': process.process_table_configuration,
                        'parent_case_data_schema': process.parent_case_data_schema,
                        # 'process_name': process_id.process_name,
                        # 'process_stages': process_id.process_stages,
                        # 'data_schema': data_schema,
                        'form_data_list': form_data_list,
                        'bot_data': serialized_bot_data,
                        'integration_data': serialized_integration_data,
                        'dms_data': serialized_dms_data,
                        'ocr_data': serialized_ocr_data,

                    })
                else:
                    return Response({'error': 'No form data found for this case'}, status=404)

            return Response(response_data)

    def post(self, request, pk=None):
        """
            Initiates the process or subprocess execution starting from the given case ID (pk).

            :param request: The HTTP request object.
            :param pk: The primary key of the case to start execution.
            :return: Response object with execution status.
            """
        if pk is None:
            return Response({"error": "Case ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Call the handle_case_step function to process the case
        return self.handle_case_step(request, pk, parent_case_id=None)

    # Function to update user case history
    def update_user_case_history(self, userId, created_on, step_name):
        """Returns the updated user_case_history list."""
        user_case_history = []
        logger.info("UserId %s", userId)
        # Replace `UserData` with your user model
        user = UserData.objects.filter(id=userId).first()
        if user is not None:
            try:
                # Append history entry if all required fields exist
                if userId and created_on and step_name:
                    user_case_history.append({
                        'userId': str(userId),
                        # 'executed_on': str(created_on),
                        'executed_on': str(datetime.utcnow().isoformat()),
                        'step_name': str(step_name),
                        'user_name': str(user.user_name),
                        'user_profile_pic': str(user.profile_pic)

                    })
            except Exception as e:
                print("Error updating user_case_history:", e)
        else:
            logger.info("User not found: %s", userId)
            user_case_history.append({
                'userId': "Admin",
                'executed_on': str(datetime.utcnow().isoformat()),
                'step_name': str(step_name),
                'user_name': "Admin",
                'user_profile_pic': "Admin"
            })

        return user_case_history

    def get_user_id_list(self, process_id):
        '''
        Author: Paramesh
        Desc: Get the List of user ids base On Process id
        Usage: Send Mail to the List of Users Assigned to the Process
        return: int[]
        '''
        user_id_list = []
        user_groups = CreateProcess.objects.filter(
            id=process_id).values('user_group')

        if user_groups:
            for user_group in user_groups:
                if user_group['user_group']:
                    users = UserData.objects.filter(
                        usergroup_id=user_group['user_group']).values_list('id', flat=True)
                    if users:
                        user_id_list.extend(users)

        return user_id_list

    def get_form_user_id_list(self, step_id, organization_id, process_id):
        '''
        Author: Paramesh
        Desc: Get the List of user ids base On Step id
        Usage: Send Mail to the List of Users Assigned to the Step
        return: int[]
        '''
        try:
            next_step_schema = FormDataInfo.objects.get(
                Form_uid=step_id, organization=organization_id, processId=process_id
            )
        except FormDataInfo.DoesNotExist:
            return []

        form_write_user_group_ids = FormPermission.objects.filter(
            form=next_step_schema,
            write=True
        ).values_list('user_group__id', flat=True)

        list_userGroupIds = list(form_write_user_group_ids)

        if not list_userGroupIds:
            return []

        userIds = list(UserData.objects.filter(
            usergroup__id__in=list_userGroupIds
        ).values_list('id', flat=True))

        return userIds

    def get_stage_name(self, process_stages, step_id):
        """
        function to return the Process stages name
        """

        if not process_stages:  # Check if process_stages is empty or None
            return None
        for stage, stage_data in process_stages.items():
            for step in stage_data.get("Steps", []):
                if step.get("stepId") == step_id:
                    return stage_data.get("StageName")
        return None  # Return None if step_id is not found

    def inject_parent_case_data(self, process_id, case_id, data_json):
        """

        :param process_id:
        :param case_id:
        :return:
        :rtype: list[Any]
        """
        process = get_object_or_404(CreateProcess, id=process_id)
        case = get_object_or_404(Case, id=case_id)

        parent_schema_raw = process.parent_case_data_schema or []

        # Flatten in case there's a nested list
        case_previos_global_data = case.parent_case_data or []
        previous_data_map = {item.get("field_id"): item.get("value") for item in case_previos_global_data if
                             isinstance(item, dict)}
        parent_schema = []
        for item in parent_schema_raw:
            if isinstance(item, list):
                parent_schema.extend(item)
            elif isinstance(item, dict):
                parent_schema.append(item)
            else:
                continue  # skip invalid items

        result = []

        for schema in parent_schema:
            field_id = schema.get("field_id")
            form_id = schema.get("form_id")
            label = schema.get("label")

            value = ""
            if data_json:
                # if filled_data and filled_data.data_json:
                #     data_json = filled_data.data_json

                if isinstance(data_json, dict):
                    value = data_json.get(field_id, "")
                elif isinstance(data_json, list):
                    # Try to extract from a list of dicts if a format is [{"field_id": ..., "value": ...}, ...]
                    for entry in data_json:
                        if isinstance(entry, dict) and entry.get("field_id") == field_id:
                            value = entry.get("value", "")
                            break

            if value == "":
                value = previous_data_map.get(field_id, "")

            result.append({
                "label": label,
                "field_id": field_id,
                "value": value
            })

        case.parent_case_data = result
        case.save()

        return result

    ############ Extracting Receiver Mail for the Notification Bot Starts ######################
    def extract_receiver_email(self, receiver_type, receiver_mail, all_data):
        if receiver_type == "value":
            if isinstance(receiver_mail, str) and "@" in receiver_mail:
                return receiver_mail
            else:
                raise ReceiverEmailResolutionError(
                    f"Invalid email value provided: '{receiver_mail}'"
                )

        elif receiver_type == "field_ref":
            for sublist in reversed(all_data):
                for item in sublist:
                    if isinstance(item, dict) and item.get('field_id') == receiver_mail:
                        email = item.get('value')
                        if isinstance(email, str) and "@" in email:
                            return email
                        else:
                            raise ReceiverEmailResolutionError(
                                f"Resolved value from field '{receiver_mail}' is not a valid email: {email}"
                            )

            raise ReceiverEmailResolutionError(
                f"Field ID '{receiver_mail}' not found in any data item."
            )

        #
        else:
            raise ReceiverEmailResolutionError(
                f"Unsupported receiver_type '{receiver_type}'. Expected 'value' or 'field_ref'."
            )

    ############ Extracting Receiver Mail for the Notification Bot Ends ######################

    ############ Mail Subject Concatenation for Notification Bot in Process STARTS #################

    def resolve_mail_subject(self, mail_content, all_data):

        subject_data = mail_content.get('mailSubject', {})
        subject_field_id = subject_data.get('subject_field_id', '')
        subject_text = subject_data.get('subject_text', '')
        subject_value = ''

        # Flatten all_data if it's a list of list of dicts
        flattened_data = []
        for group in all_data:
            if isinstance(group, list):
                flattened_data.extend(group)
            elif isinstance(group, dict):
                flattened_data.append(group)

        # Try to find value from flattened_data
        if subject_field_id:
            for item in flattened_data:
                if isinstance(item, dict) and item.get('field_id') == subject_field_id:
                    subject_value = item.get('value', '')
                    # If the value is a list (like in the table), try to extract it
                    if isinstance(subject_value, list):
                        # Join all non-empty values
                        subject_value = ', '.join(
                            str(v) for v in subject_value if v
                        )
                    break

        # Final subject
        if isinstance(subject_value, str) and subject_value.strip():
            mail_subject = f"{subject_value} {subject_text}"
        else:
            mail_subject = subject_text

        return mail_subject

    ############ Mail Subject Concatenation for Notification Bot in Process ENDS #################

    # 30-08-2025 By Harish
    def create_notification_data(self, case_id, mail_data_ids, all_data, mail_title, approved_id, process_id,
                                 organization_id):
        try:
            logger.info('Inside create_notification_data')
            field_values = {}
            # field_labels = {}
            for submission in reversed(all_data):
                for data_item in submission:
                    if not isinstance(data_item, dict):
                        continue

                    current_field_id = data_item.get("field_id")
                    value = data_item.get("value")
                    label = data_item.get("label")
                    if current_field_id in mail_data_ids and label not in field_values:

                        if isinstance(value, list) and all(
                                isinstance(v, dict) and "label" in v and "value" in v for v in value
                        ):
                            field_values[label] = value
                        else:
                            field_values[label] = value

            case_obj = Case.objects.get(id=case_id)
            # org_obj = Organization.objects.get(id=organization_id)
            # process_obj = CreateProcess.objects.get(id=process_id)

            # Create and return the NotificationData entry
            notification = NotificationData.objects.create(
                case_id=case_obj,
                mail_data=field_values,
                submitted=False,
                mail_title=mail_title,
                approved_id=approved_id,
                #
                # organization=org_obj,
                # process=process_obj,
            )
            return notification

        except Exception as e:
            logger.error("Error creating NotificationData: %s", str(e))
            return None

    def handle_case_completion(self, case):
        if case.status != "Completed":
            return False
        logger.info("sibling_cases: %s", case)
        if case.parent_case:
            parent_case = case.parent_case
            sibling_cases = Case.objects.filter(parent_case=parent_case)

            if all(sibling.status == "Completed" for sibling in sibling_cases):
                # parent_case.status = "Completed"
                # parent_case.save()

                # # Recursively continue up the chain
                # self.handle_case_completion(parent_case)
                return True

        return False

    def create_case_instance_from_sla(self, next_step_id, upcoming_next_step, case_id):

        sla_instance = SlaConfig.objects.filter(sla_uid=next_step_id).first()
        # return {'status': False, 'message': 'SLA not found for provided step ID'}
        if not sla_instance:
            sla_instance = SlaConfig.objects.filter(sla_uid=upcoming_next_step).first()
        if not sla_instance:
            return {'status': False, 'message': 'SLA not found for provided step ID'}
        # Get Case
        case = Case.objects.filter(id=case_id).first()

        if not case:
            return {'status': False, 'message': 'Case not found for provided case ID'}
        existing = SlaCaseInstance.objects.filter(case_id=case_id, sla_id=sla_instance.id, is_completed=False).first()
        if existing:
            return {"message": "SLA case instance already exists"}
        # Create CaseInstance (customize fields as needed)
        SlaCaseInstance.objects.create(
            case_id=case,
            sla_id=sla_instance,
            is_completed=False

        )

        return {'status': True, 'message': 'CaseInstance created successfully'}

    def handle_case_step(self, request, pk, parent_case_id=None):
        """
        Handle execution of a process or subprocess steps.
        If the current step is a subprocess, recursively execute it.

        :param request: HTTP request object.
        :param pk: Case ID of the current process or subprocess.
        :param parent_case_id: ID of the parent case (if any).
        """
        global responses, dms_data, code_block_config, created
        try:
            # 08-09-2025 By Harish
            user_id = request.data.get('userId', None)
            user_data_id = None
            if user_id:
                try:
                    user_data_id = UserData.objects.get(id=user_id)
                except UserData.DoesNotExist:
                    print(f"UserData with id {user_id} does not exist.")
                except Exception as e:
                    print("Unexpected error while fetching UserData:", e)
            else:
                print("userId not provided in request.")
            print(" ----------------- userId handle_case_step ----------------- : ", user_data_id)
            logger.info("Inside handle_case_step")
            case = Case.objects.get(pk=pk)
            process_id = case.processId
            case_id = case.id
            organization_name = case.organization
            organization_id = organization_name.id

            parent_case_id = case.parent_case or None

            responses = []
            try:
                sla_next_step = request.data.get('action') or None
                if sla_next_step:
                    cs_next_step = sla_next_step
                    case.next_step = cs_next_step
                    case.save()

                else:
                    cs_next_step = case.next_step
                # continue with processing steps...

            except Exception as e:
                # Collect error info — optional
                responses.append({"error": f"Exception occurred: {str(e)}"})
                logger.error(f"Exception occurred: {str(e)}")

            logger.info(
                "cs_next_step $$$$$$$$$$$$$$$$$$$$$$$$$$$$ : %s", cs_next_step)

            #################### to get the case history of the User #########

            process_data = CreateProcess.objects.get(pk=process_id.pk)
            participants_data = process_data.participants
            # added process_stages to get stages schema
            process_stages = process_data.process_stages or {}
            # parsed_data = json.loads(participants_data)
            process_table_configuration = process_data.process_table_configuration or []
            parent_case_data_schema = process_data.parent_case_data_schema,
            execution_flow = participants_data.get('executionFlow', [])
            steps = {flow['currentStepId']: flow for flow in execution_flow.values()}

            # Load JSON data

            # Get the first key in the executionFlow dictionary
            first_key = next(iter(participants_data["executionFlow"]))

            flows = []
            # Iterate over the executionFlow to get currentStepId and nextStepId
            for flow_key, flow_value in participants_data["executionFlow"].items():

                if cs_next_step.strip() == flow_value.get("currentStepId"):
                    start_form_id = flow_value.get("currentStepId")
                    end_form_id = flow_value.get("nextStepId")
                    if start_form_id and end_form_id:
                        flows.append(
                            {"start": start_form_id, "end": end_form_id})

                    # start_form_id = flow_value["currentStepId"]
                    # end_form_id = flow_value["nextStepId"]
                    # flows.append({"start": start_form_id, "end": end_form_id})

            if not flows:
                return Response({"message": "No flows found for the given next step"},
                                status=status.HTTP_400_BAD_REQUEST)

            current_step_id = flows[0]['start']
            next_step_id = flows[0]['end']

            # Changes made by Harish to check all the steps of SLA -[26.08.25] Starts
            upcoming_next_step = None
            upcoming_next_step_list = []
            for flow_key, flow_value in participants_data["executionFlow"].items():
                if current_step_id.strip() == flow_value.get("currentStepId"):
                    upcoming_next_step_list.append(flow_value.get("nextStepId"))
            for flow_key, flow_value in participants_data["executionFlow"].items():
                if flow_value.get("currentStepId") in upcoming_next_step_list:
                    upcoming_next_step = flow_value.get("nextStepId")

            sla_instance = SlaConfig.objects.filter(sla_uid=next_step_id).first() or None
            if not sla_instance:
                sla_instance = SlaConfig.objects.filter(sla_uid=upcoming_next_step).first() or None

            if sla_instance:
                existing = SlaCaseInstance.objects.filter(case_id=case_id, sla_id=sla_instance.id,
                                                          is_completed=False).first()
                if not existing:
                    result = self.create_case_instance_from_sla(next_step_id, upcoming_next_step, case_id)
                else:
                    print("SLA case instance already exists. Skipping creation.")

            # Changes made by Harish to check all the steps of SLA -[26.08.25] ENDS
            # result = self.create_case_instance_from_sla(next_step_id, case_id)
            # print(result)

            ############ execution flow modified according to case[starts] by Praba###############

            responses = []  # List to store responses by Praba
            while current_step_id and current_step_id != "null":
                current_step = steps.get(current_step_id)
                if not current_step:
                    break

                subprocess = CreateProcess.objects.filter(
                    subprocess_UID=current_step_id).first()

                # Check if current step ID corresponds to a bot or integration
                bot = Bot.objects.filter(bot_uid=current_step_id).first()
                integrations = Integration.objects.filter(
                    Integration_uid=current_step_id)

                # Check if current step ID corresponds to a form or rule
                form = FormDataInfo.objects.filter(
                    Form_uid=current_step_id).first()
                # form = FormDataInfo.objects.filter(Form_uid=current_step_id).first()

                notification_bot = NotificationBotSchema.objects.filter(
                    notification_uid=current_step_id).first()
                # Check if current step ID corresponds to a rule
                code_block_config = None  # default to None
                rule = None
                rule_block = Rule.objects.filter(
                    ruleId=current_step_id).first()

                if rule_block:
                    rule = rule_block.rule_json_schema
                    code_block_config = rule_block.process_codeblock_schema
                    # logger.info("code block %s", code_block_config)

                # Check if current step ID corresponds to a OCR
                ocr = Ocr.objects.filter(ocr_uid=current_step_id).first()
                is_sla = SlaConfig.objects.filter(sla_uid=current_step_id).first()

                # Check if the current step ID corresponds to a Notification
                ##### Need to check if end element {}
                end_element_config = None
                end_element = EndElement.objects.filter(element_uid=current_step_id).first() or ''

                if end_element:
                    element_uid = end_element.element_uid
                    end_element_config = end_element

                    # -------- Auto update case as Completed or configured status --------
                    try:
                        with transaction.atomic():
                            case_data = Case.objects.select_for_update().get(pk=case.id)

                        organization_id = case_data.organization_id

                        # Fetch the end element schema details
                        configured_status = end_element_config.element_name or "Completed"
                        end_element_schema_data = end_element_config.end_element_schema
                        # Update case
                        case_data.status = "Completed"
                        case_data.stages = configured_status
                        case_data.save()
                        # Optional: handle parent case hierarchy
                        self.inject_parent_case_data(process_id.id, case_id, data_json=[])
                        # return Response({
                        #     "message": f"Case marked as {configured_status}",
                        #     "end_element_schema": end_element_schema_data
                        # }, status=status.HTTP_200_OK)

                        logger.info("Case marked as Completed")
                        # subprocess_case_complete = self.handle_case_completion(case_data)

                        # if subprocess_case_complete:
                        #     print("subprocess case marked as completed.")
                        #     # -- working
                        #     url = f"{settings.BASE_URL}/process_related_cases/{case_data.parent_case.id}/"
                        #     logger.info("url %s",url)
                        #     try:
                        #         response = requests.post(
                        #             url,
                        #             data={
                        #                 "data_json": '{"subprocess": "Subprocess Completed Successfully"}',  # send JSON string
                        #                 "organization": case_data.organization.id,
                        #
                        #             }
                        #         )
                        #
                        #         if response.status_code == 200:
                        #             logger.info("Related case API response: %s", response.json())
                        #         else:
                        #             logger.error("Related case API failed with status: %s", response)
                        #
                        #     except Exception as e:
                        #             print("Error calling related case API:", str(e))

                    except Exception as e:
                        logger.error(f"Error completing case: {e}")
                        print("Failed to complete case")
                        return Response({"error": "Failed to complete case"},
                                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                from_mail_flag = None
                mail_token = ''

                # # print("iiiii555555555555",request.data)
                from_mail_flag = request.data.get('from_mail') or None
                mail_token = request.data.get('mail_token') or ''

                # if mail_token and not notification_bot and is_from_approval_mail:
                #         print("rrrrrrrrrrrrrrr")
                #         return Response({"Message": "Notification Bad request"}, status=status.HTTP_400_BAD_REQUEST)

                if bot:
                    # Assuming using the first one
                    bot_schema = get_object_or_404(BotSchema, bot=bot)
                    bot_type = bot.bot_name
                    bot_id_ref = bot.id
                    bot_input_data = bot_schema.bot_schema_json
                    bot_element_permission = bot_schema.bot_schema_json
                    # if isinstance(bot_input_data, str):
                    #     bot_input_data = json.loads(bot_input_data)  # Ensure JSON string is parsed

                    dynamic_input_data = request.data.get(current_step_id, {})
                    input_data = {**bot_input_data, **dynamic_input_data}

                    if bot_type == 'google_drive':
                        print('--- GOOGLE DRIVE --- 1')
                        print("input_data : ", input_data)
                        payload = {
                            'folder_id': input_data['folder_id'],
                            'file_type': input_data['file_type'],
                            'completed_folder_id': input_data['completed_folder_id']
                        }
                        # base URL + endpoint using reverse
                        url = settings.BASE_URL + reverse('drive_files_api')
                        print("url GOOGLE DRIVE : ", url)
                        print("payload : ", payload)

                        try:
                            # POST request with the payload as JSON data
                            response = requests.post(url, json=payload)
                            print("response GOOGLE DRIVE ", response)
                            # Raise an HTTPError if the HTTP request returned an unsuccessful status code
                            response.raise_for_status()
                        except requests.exceptions.RequestException as e:
                            print(f"HTTP Request failed: {e}")
                            responses.append(
                                {'error': 'Failed to execute Google Drive bot'})
                        else:
                            response_data = response.json()
                            # print("response_data : ",response_data)
                            # logger.info(response_data)

                            # Check if response_data is a list and process each item
                            if isinstance(response_data, list):
                                for file_data in response_data:
                                    file_name = file_data.get('file_name')
                                    file_id = file_data.get('file_id')
                                    temp_data = file_data.get('temp_data')

                                    # Check if all required fields are present
                                    if not (file_name and file_id and temp_data):
                                        print("Incomplete response data")
                                        responses.append(
                                            {'error': 'Incomplete response data from Google Drive bot'})
                                    else:
                                        print("case.id", case.id)
                                        print("flow_id", process_data.id)
                                        try:
                                            organization_instance = Organization.objects.get(
                                                id=organization_id)
                                        except Organization.DoesNotExist:
                                            # Handle the case where the organization does not exist
                                            organization_instance = None

                                        # Check if BotData exists; if not, create a new one
                                        try:
                                            bot_data, created = BotData.objects.get_or_create(
                                                case_id=case,
                                                flow_id=process_data,
                                                organization=organization_instance,
                                                defaults={'file_name': file_name,
                                                          'file_id': file_id,
                                                          'temp_data': temp_data}
                                            )
                                            # logger.info(bot_data)
                                            logger.info(
                                                f"Updated BotData entry for file: {bot_data}")
                                        except Exception as e:
                                            print(
                                                "Error during get_or_create:", e)
                                            responses.append(
                                                {'error': 'Database error during get_or_create'})
                                            return None

                                        if not created:
                                            try:
                                                bot_data.file_name = file_name
                                                bot_data.file_id = file_id
                                                bot_data.temp_data = temp_data
                                                bot_data.save()
                                                responses.append(
                                                    file_data)  # Ensure the correct object is added to the responses list

                                                logger.info(file_data)
                                            except Exception as e:
                                                print(
                                                    "Error during bot_data save:", e)
                                                responses.append(
                                                    {'error': 'Database error during save'})

                    elif bot_type == 'file_extractor':
                        print('--- FILE EXTRACTOR --- 2')
                        print("current_step_id : ", current_step_id)
                        file_extractor_bots = Bot.objects.filter(
                            bot_name='file_extractor', bot_uid=current_step_id)
                        if file_extractor_bots:
                            for file_extractor_bot in file_extractor_bots:
                                bot_schemas = BotSchema.objects.filter(
                                    bot=file_extractor_bot)

                                if bot_schemas:
                                    for bot_schema in bot_schemas:
                                        file_extractor_input_data = bot_schema.bot_schema_json
                                        # if isinstance(file_extractor_input_data, str):
                                        #     file_extractor_input_data = json.loads(file_extractor_input_data)
                                        file_name = file_extractor_input_data['file_name']
                                        print("file_name : ", file_name)
                                        print("case_id : ", case_id)
                                        print("process_data : ", process_data.id)
                                        print("organization_id : ", organization_id)
                                        # Fetch the file from the database
                                        try:
                                            bot_data_entry = BotData.objects.get(file_name=f'{file_name}.xlsx',
                                                                                 case_id=case_id,
                                                                                 flow_id=process_data.id,
                                                                                 organization=organization_id)
                                            print("bot_data_entry : ", bot_data_entry)

                                        except BotData.DoesNotExist:
                                            logger.error(
                                                f'File not found in the database: {file_name}')
                                            return JsonResponse(
                                                {"error": f"File not found in the database: {file_name}"}, status=404)

                                        # Construct the file path
                                        file_path = os.path.join(
                                            settings.MEDIA_ROOT, bot_data_entry.temp_data.name)

                                        # Debug statement
                                        logger.debug(f"File path: {file_path}")

                                        if not os.path.exists(file_path):
                                            logger.error(
                                                f'File path does not exist: {file_path}')
                                            return JsonResponse({"error": f"File path does not exist: {file_path}"},
                                                                status=404)

                                        # Merge dynamic input data
                                        dynamic_input_data = request.data.get(
                                            current_step_id, {})

                                        file_extractor_input_data1 = {
                                            **file_extractor_input_data, **dynamic_input_data}


                                        payload = {
                                            'file_name': file_extractor_input_data1['file_name'],
                                            'sheet_name': file_extractor_input_data1.get('sheet_name'),
                                            'column_definitions': file_extractor_input_data1['column_definitions'],
                                            'file_path': file_path

                                        }

                                        url = settings.BASE_URL + \
                                              reverse('convert_excel_to_json')

                                        response = requests.post(
                                            url, json=payload)

                                        if response.status_code == 200:

                                            response_json = response.json()  # Get the JSON response
                                            # Extract 'data' from the response
                                            data = response_json.get('data')
                                            bot_data = get_object_or_404(BotData,
                                                                         id=bot_data_entry.id)  # Replace with the correct identifier

                                            bot_data.data_schema = data  # Update the data_schema with the new data
                                            # bot_data.case_id = case  # Update the case_id
                                            bot_data.bot_id = bot_id_ref  # Update the bot_id
                                            bot_data.save()  # Save the updated BotData instance
                                            # Store the response
                                            responses.append(response_json)


                                        else:
                                            response = {"error": response.text}

                                            logger.info(response)

                                            # print("Failed to get response from convert_excel_to_json function:",
                                            #       response.text)
                                else:
                                    response = {"error": file_extractor_bot}
                                    print(
                                        "Failed to get response from convert_excel_to_json function:", response)

                                    # print('Bot schema not found for file extractor bot:', file_extractor_bot)
                        else:
                            response = {"error": current_step_id}
                            print(
                                "Failed to get response from convert_excel_to_json function:", response)

                            # print('File extractor bot not found with UID:', current_step_id)

                        # return responses

                    elif bot_type == 'screen_scraping':
                        print('--- SCREEN SCRAPING --- 4')

                        screen_scraping_bot = get_object_or_404(
                            Bot, bot_uid=current_step_id)

                        # api_config = screen_scraping_bot.bot_schema_json
                        # print('api_config---', api_config)

                        bot_schema = get_object_or_404(
                            BotSchema, bot=screen_scraping_bot)

                        schema_config = bot_schema.bot_schema_json

                        # Initialize combined_data as an empty dictionary
                        try:
                            bot_data_entries = BotData.objects.filter(
                                case_id=pk)
                            input_data_bot = {}
                            if bot_data_entries.exists():
                                for entry in bot_data_entries:
                                    data_schema = entry.data_schema
                                    print("data_schema:", data_schema)
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_data_bot.update(
                                                    {item['field_id']: item['value']})
                                            else:
                                                print(
                                                    f"Warning: Non-dictionary item in data_schema list: {item}")
                                    elif isinstance(data_schema, dict):
                                        input_data_bot.update(
                                            {data_schema['field_id']: data_schema['value']})
                                    else:
                                        print(
                                            f"Warning: BotData entry {entry.id} has a non-list, non-dict data_schema: {data_schema} (type: {type(data_schema)})")
                            print("input_data_bot:", input_data_bot)

                            logger.info("input_data_form %s", input_data_bot)
                        except BotData.DoesNotExist:
                            print(f"No BotData found for case_id {pk}")
                            input_data_bot = {}

                            # Attempt to fetch IntegrationDetails, handle if not found
                        try:
                            integration_data_entries = IntegrationDetails.objects.filter(
                                case_id=pk)
                            input_data_api = {}
                            if integration_data_entries.exists():
                                for entry in integration_data_entries:
                                    data_schema = entry.data_schema
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_data_api.update(
                                                    {item['field_id']: item['value']})
                                            else:
                                                print(
                                                    f"Warning: Non-dictionary item in data_schema list: {item}")
                                    else:
                                        print(
                                            f"Warning: IntegrationDetails entry {entry.id} has a non-list data_schema: {data_schema} (type: {type(data_schema)})")
                            print("input_data_api:", input_data_api)
                        except IntegrationDetails.DoesNotExist:
                            print(
                                f"No IntegrationDetails found for case_id {pk}")
                            input_data_api = {}
                        logger.info(input_data_api)
                        # if it is form filled data
                        try:
                            form_filled_entries = FilledFormData.objects.filter(
                                caseId=pk)
                            input_data_form = {}
                            if form_filled_entries.exists():
                                for entry in form_filled_entries:
                                    data_schema = entry.data_json
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_data_form.update(
                                                    {item['field_id']: item['value']})
                                            else:
                                                print(
                                                    f"Warning: Non-dictionary item in data_schema list: {item}")
                                    else:
                                        print(
                                            f"Warning: FilledFormDetails entry {entry.id} has a non-list data_schema: {data_schema} (type: {type(data_schema)})")
                            print("input_data_form:", input_data_form)
                        except FilledFormData.DoesNotExist:
                            print(
                                f"No FilledFormDetails found for case_id {pk}")
                            input_data_form = {}

                        logger.info(input_data_form)
                        logger.info("input_data_form %s", input_data_form)

                        # Convert combined_data list to the desired list format
                        # Initialize an empty dictionary to hold the combined data
                        combined_data = {}

                        # Add data from each source if it exists
                        if input_data_bot:
                            combined_data.update(input_data_bot)
                        if input_data_api:
                            combined_data.update(input_data_api)
                        if input_data_form:
                            combined_data.update(input_data_form)

                        logger.info("input_data_form %s", combined_data)

                        # If all data sources are empty, combined_data will remain empty
                        # You can decide if you want it to be explicitly set to None in that case
                        if not combined_data:
                            combined_data = None

                        payload = {
                            'schema_config': [schema_config],
                            'input_data': [combined_data] if combined_data else None,
                        }
                        # payload_json_bytes = json.dumps(payload)
                        # print("payload_json_bytes", payload_json_bytes)

                        url = settings.BASE_URL + reverse('screen_scraping')
                        response = requests.post(url, json=payload)
                        print("response", response)

                        if response.status_code == 200:
                            response_json = response.json()
                            # Extract 'data' from the response
                            botdata = response_json.get('data')
                            try:
                                organization_instance = Organization.objects.get(
                                    id=organization_id)
                            except Organization.DoesNotExist:
                                # Handle the case where the organization does not exist
                                organization_instance = None
                            try:
                                bot_data, created = BotData.objects.get_or_create(
                                    bot=bot,
                                    case_id=case,
                                    flow_id=process_data,
                                    organization=organization_instance,
                                    defaults={'data_schema': botdata}
                                )
                                print(" botdata:", botdata)
                                print("created:", created)
                            except Exception as e:
                                print("Error during get_or_create:", e)

                            if bot_data is None:
                                print("response_data is None")
                            else:
                                print(
                                    f"response_data details: {bot_data.__dict__}")

                                # If BotData was found, update the data_schema field
                            if not created:
                                try:
                                    bot_data.data_schema = bot_data
                                    bot_data.save()  # Ensure you call save on the correct object
                                    print("Updated integration_data successfully")
                                except Exception as e:
                                    print(
                                        "Error during integration_data save:", e)

                            responses.append(response_json)

                            # responses.append(
                            #     {"bot": bot.bot_name,
                            #      "message": "Screen scraping executed"})  # Store the required message
                        else:
                            response_json = response.json()

                            response = {"error": response_json}
                            print("Failed to execute Screen Scraping bot:", response)
                            responses.append(
                                {'error': 'Failed to execute Screen Scraping bot'})

                        print(' ---- screen_scraping_executed ---')

                    elif bot_type == 'Prompt Bot':
                        print("prompt_bot calling")
                        prompt_bot = get_object_or_404(Bot, bot_uid=current_step_id)
                        prompt_bot_schema = get_object_or_404(BotSchema, bot=prompt_bot)
                        schema_config = prompt_bot_schema.bot_schema_json

                        print("BOT DATA calling")

                        # --- BOT DATA ---
                        try:
                            bot_data_entries = BotData.objects.filter(case_id=pk)
                            input_data_bot = {}
                            if bot_data_entries.exists():
                                for entry in bot_data_entries:
                                    data_schema = entry.data_schema
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_data_bot[item['field_id']] = item['value']
                                            else:
                                                print(f"Warning: Non-dictionary item in data_schema list: {item}")
                                    elif isinstance(data_schema, dict):
                                        input_data_bot[data_schema['field_id']] = data_schema['value']
                                    else:
                                        print(f"Warning: BotData entry {entry.id} invalid data_schema: {type(data_schema)}")
                        except BotData.DoesNotExist:
                            print(f"No BotData found for case_id {pk}")
                            input_data_bot = {}

                        print("INTEGRATION DATA calling")

                        # --- INTEGRATION DATA ---
                        try:
                            integration_data_entries = IntegrationDetails.objects.filter(case_id=pk)
                            input_data_api = {}
                            if integration_data_entries.exists():
                                for entry in integration_data_entries:
                                    data_schema = entry.data_schema
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_data_api[item['field_id']] = item['value']
                                            else:
                                                print(f"Warning: Non-dict item in data_schema list: {item}")
                                    else:
                                        print(f"Warning: IntegrationDetails entry {entry.id} invalid data_schema: {type(data_schema)}")
                        except IntegrationDetails.DoesNotExist:
                            print(f"No IntegrationDetails found for case_id {pk}")
                            input_data_api = {}

                        logger.info(input_data_api)

                        print("FILLED FORM DATA calling")

                        # --- FILLED FORM DATA ---
                        try:
                            form_filled_entries = FilledFormData.objects.filter(caseId=pk)
                            input_data_form = {}
                            if form_filled_entries.exists():
                                for entry in form_filled_entries:
                                    data_schema = entry.data_json
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_data_form[item['field_id']] = item['value']
                                            else:
                                                print(f"Warning: Non-dict item in data_schema list: {item}")
                                    else:
                                        print(f"Warning: FilledFormData entry {entry.id} invalid data_schema: {type(data_schema)}")
                        except FilledFormData.DoesNotExist:
                            print(f"No FilledFormData found for case_id {pk}")
                            input_data_form = {}

                        print("NOTIFICATION DATA calling")

                        # --- NOTIFICATION DATA ---
                        try:
                            notify_data_entries = NotificationData.objects.filter(case_id=pk)
                            input_notify_data = {}
                            print("notify_data_entries.exists() : ",notify_data_entries.exists())
                            if notify_data_entries.exists():
                                for entry in notify_data_entries:
                                    data_schema = entry.data_json
                                    if isinstance(data_schema, list):
                                        for item in data_schema:
                                            if isinstance(item, dict):
                                                input_notify_data[item['field_id']] = item['value']
                                            else:
                                                print(f"Warning: Non-dict item in data_schema list: {item}")
                                    else:
                                        print(f"Warning: NotificationData entry {entry.id} invalid data_schema: {type(data_schema)}")
                        except NotificationData.DoesNotExist:
                            print(f"No NotificationData found for case_id {pk}")
                            input_notify_data = {}

                        print("COMBINE ALL DATA calling")
                        # --- COMBINE ALL DATA ---
                        combined_data = {}
                        if input_data_bot:
                            combined_data.update(input_data_bot)
                        if input_data_api:
                            combined_data.update(input_data_api)
                        if input_data_form:
                            combined_data.update(input_data_form)
                        if input_notify_data:
                            combined_data.update(input_notify_data)

                        logger.info("combined_data %s", combined_data)
                        if not combined_data:
                            combined_data = None

                        print("combined_data : ",combined_data)

                        # --- Replace {{field_id}} placeholders in schema_config['prompt'] ---
                        if schema_config and isinstance(schema_config, dict):
                            prompt_text = schema_config.get("prompt", "")
                            if prompt_text and combined_data:
                                for key, value in combined_data.items():
                                    placeholder = "{{" + key + "}}"
                                    # Replace placeholder with actual value (convert non-str to str)
                                    prompt_text = prompt_text.replace(placeholder, str(value))
                                schema_config["prompt"] = prompt_text  # update with replaced values

                        print("Updated schema_config with actual values:", schema_config)

                        payload = {
                            'prompt': schema_config['prompt'],
                            'model': schema_config['model'],
                            'output_keys': schema_config['output_keys']
                        }

                        url = settings.BASE_URL + reverse('prompt-bot')
                        response = requests.post(url, json=payload)
                        print("response", response)

                        if response.status_code == 200:
                            response_json = response.json()
                            botdata = response_json.get('data')

                            try:
                                organization_instance = Organization.objects.get(id=organization_id)
                            except Organization.DoesNotExist:
                                organization_instance = None

                            try:
                                bot_data_obj, created = BotData.objects.get_or_create(
                                    bot=prompt_bot,
                                    case_id=case,
                                    flow_id=process_data,
                                    organization=organization_instance,
                                    defaults={'data_schema': botdata}
                                )
                                print("botdata:", botdata)
                                print("created:", created)
                            except Exception as e:
                                print("Error during get_or_create:", e)
                                bot_data_obj = None

                            if bot_data_obj:
                                # Update if already existed
                                if not created:
                                    try:
                                        bot_data_obj.data_schema = botdata
                                        bot_data_obj.save()
                                        print("Updated BotData successfully")
                                    except Exception as e:
                                        print("Error during BotData save:", e)

                                print(f"response_data details: {bot_data_obj.__dict__}")

                            responses.append(response_json)

                    elif bot_type == 'Doc Builder':
                        print('--- Doc Builder --- ')
                        invoice_generator_bots = Bot.objects.filter(
                            bot_name='Doc Builder', bot_uid=current_step_id)

                        if invoice_generator_bots:
                            for invoice_generator_bot in invoice_generator_bots:
                                bot_schemas = BotSchema.objects.filter(
                                    bot=invoice_generator_bot)
                                if isinstance(process_data, CreateProcess):
                                    process_id = process_data.id
                                else:
                                    print(
                                        "process_data is not an instance of CreateProcess")
                                if bot_schemas:
                                    invoice_extractor_input_data = bot_schema.bot_schema_json
                                    logger.info(
                                        "invoice_extractor_input_data %s", invoice_extractor_input_data)

                                    response_data = {
                                        'caseid': case.id,
                                        'processId': process_id,
                                        'organization': organization_id,
                                        'createdby': case.created_by,
                                        'createdon': case.created_on,
                                        'updatedon': case.updated_on,
                                        'updatedby': case.updated_by,
                                        'bot_type': 'Doc Builder',
                                        'bot_schema': invoice_extractor_input_data,
                                        'form_filter_schema': bot_schema.bot_element_permission or [],
                                        'status': case.status,
                                        'assigned_users': []
                                    }
                                    data_json = None  # Initialize data_json with a default value
                                    if 'file' in request.FILES:
                                        print("request.data", request.data)

                                        # Handle file upload
                                        # Get the file from request.FILES
                                        uploaded_file = request.FILES['file']

                                        # If the file contains JSON data, read and parse it
                                        if uploaded_file.content_type == "application/json":
                                            file_content = uploaded_file.read().decode(
                                                'utf-8')  # Read file and decode to string
                                            try:
                                                data_json = json.loads(
                                                    file_content)  # Parse JSON data

                                            except json.JSONDecodeError as e:
                                                print(
                                                    "Error parsing JSON from file:", str(e))
                                        else:
                                            print(
                                                "Uploaded file is not a JSON file.")

                                    # Handle organization_id and data_json if provided separately
                                    if 'organization' in request.data:
                                        organization_id_value = request.data['organization']

                                        file = None
                                        for field_name, uploaded_file in request.FILES.items():
                                            file = uploaded_file

                                            break  # Assuming only one file is expected; remove break if multiple files need handling

                                        if file:
                                            # Ensure data_json is set to a string representation, even if it is None
                                            data_json_str = str(
                                                data_json) if data_json else "{}"

                                            # Fetch drive types and configurations for the specific organization
                                            dms_entries = Dms.objects.filter(
                                                organization=organization_id, flow_id=process_id) # By Harish 31.10.25
                                            drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}

                                            configurations = dms_entries.first().config_details_schema

                                            configurations['drive_types'] = drive_types
                                            # configurations['s3_bucket_metadata'] = drive_types

                                            metadata = {'case_id': str(case.id),
                                                        'organization_id': str(organization_id),
                                                        'data_json': data_json_str}
                                            configurations['metadata'] = json.dumps(
                                                metadata)

                                            files = {
                                                'files': (file.name, file.file, file.content_type)}
                                            # files = {'files': (file.name, file, 'application/octet-stream')}

                                            # external_api_url = 'http://192.168.0.106:8000/custom_components/FileUploadView/'
                                            external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                                            response = requests.post(
                                                external_api_url, data=configurations, files=files)

                                            if response.status_code == 200:
                                                # responses.append(response.json())  # Store the response
                                                response_json = response.json()

                                                file_name = response_json.get(
                                                    'file_name')
                                                # download_link = response_json.get('download_link')
                                                download_link = response_json.get(
                                                    'download_link')

                                                file_id = response_json.get(
                                                    'file', {}).get('id')

                                                try:
                                                    organization_instance = Organization.objects.get(
                                                        id=organization_id)
                                                except Organization.DoesNotExist:
                                                    # Handle the case where the organization does not exist
                                                    organization_instance = None
                                                try:
                                                    dms_instance = Dms.objects.get(
                                                        id=organization_id, flow_id=process_id) # By Harish 31.10.25
                                                except Dms.DoesNotExist:
                                                    # Handle the case where the dms_instance does not exist
                                                    dms_instance = None
                                                ####### Saving the file Details in bot data by Praba on 25-9-25[STARTS]
                                                try:
                                                    bot_data, created = BotData.objects.update_or_create(
                                                        bot=bot,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        organization=organization_instance,
                                                        defaults={
                                                            "data_schema": {
                                                                "metadata": configurations.get("metadata", {}),
                                                                "file_id": file_id,
                                                                "filename": file_name,
                                                                "download_link": download_link,
                                                                "user": user_data_id.id if user_data_id else None,

                                                            }
                                                        }
                                                    )

                                                    if created:
                                                        print(" Created new bot_data:", bot_data)
                                                    else:
                                                        print(" Updated existing bot_data:", bot_data)

                                                    # Debugging details
                                                    print("bot_data details:", bot_data.__dict__)

                                                except Exception as e:
                                                    print(" Error during update_or_create:", e)

                                                ####### Saving the file Details in bot data by Praba on 25-9-25[ENDS]
                                                dms_data = None
                                                created = False

                                                try:
                                                    dms_data, created = Dms_data.objects.get_or_create(
                                                        folder_id=file_id,
                                                        filename=file_name,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        dms=dms_instance,
                                                        download_link=download_link,
                                                        user=user_data_id,
                                                        organization=organization_instance,
                                                        defaults={
                                                            'meta_data': configurations['metadata']}
                                                    )

                                                except Exception as e:
                                                    print(
                                                        "Error during get_or_create:", e)

                                                    # Print details of integration_data to see if it is None or has unexpected # values
                                                if dms_data is None:
                                                    print("dms_data is None")
                                                else:
                                                    print(
                                                        f"dms_data details: {dms_data.__dict__}")

                                                    # If BotData was found, update the data_schema field
                                                if dms_data and not created:
                                                    try:
                                                        dms_data.meta_data = configurations['metadata']
                                                        dms_data.save()  # Ensure you call save on the correct object

                                                    except Exception as e:
                                                        print(
                                                            "Error during integration_data save:", e)

                                                responses.append(response_json)

                                            else:

                                                return Response(
                                                    {
                                                        "error": f"Failed to send {dms_data}. Response: {response.text}"
                                                    },
                                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                                                )

                                            # Update the case with the next step and save
                                            with transaction.atomic():
                                                case_data = Case.objects.select_for_update().get(pk=case.id)
                                            data_json_content = json.loads(
                                                case_data.data_json or '[]')

                                            # Append next_step
                                            data_json_content.append(
                                                case_data.next_step)

                                            # Convert back to JSON string
                                            case_data.data_json = json.dumps(
                                                data_json_content)
                                            if isinstance(case_data.user_case_history, str):
                                                case_data.user_case_history = json.loads(
                                                    case_data.user_case_history or "[]")
                                            elif not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []
                                            # step_id = next_step_id
                                            # process_stages = {}
                                            step_id = current_step_id
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            # step_name = 'Doc Builder'
                                            created_on = case.created_on
                                            # Get updated user case history
                                            userId = request.data.get(
                                                'userId', None)
                                            new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                                  stage_name)

                                            # Ensure user_case_history is a valid list in case_data
                                            if not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []

                                            # Append new history
                                            case_data.user_case_history.extend(
                                                new_user_case_history)
                                            # case_data.data_json = json.dumps(
                                            #     json.loads(case_data.data_json) + [case_data.next_step])
                                            case_data.status = "Doc Builder"
                                            case_data.stages = "Doc Builder"
                                            if not isinstance(case_data.path_json, list):
                                                case_data.path_json = []
                                            # Append next_step to path_json
                                            case_data.path_json.append(
                                                case_data.next_step)
                                            case_data.save()

                                            # Assuming next_step_id is determined elsewhere
                                            case_data.next_step = next_step_id
                                            case_data.save()

                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id
                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            case_data.status = stage_name or 'Doc Builder'
                                            case_data.stages = stage_name or 'Doc Builder'
                                            case_data.save()  # saving the case stages

                                            # sending Mail
                                            user_id_list = self.get_form_user_id_list(next_step_id, organization_id,
                                                                                      process_id)
                                            if user_id_list is not None and len(user_id_list) > 0:
                                                send_email(organization_id, user_id_list, "ACTION_TWO",
                                                           {"org_id": organization_id, "case_id": case_id})

                                            if next_step_id.lower() == "null" or cs_next_step == "null":
                                                case_data.status = "Completed"
                                                case_data.save()
                                                #  send mail --
                                                responses.append(
                                                    case_data.status)
                                                # if the case completes it will save the case important data which is configured in process
                                                # parent_case_data = self.inject_parent_case_data(process_id,
                                                #                                                 case_id)  # need to add the important case data inject function.
                                                # logger.info(
                                                #     "parent_case_data %s", parent_case_data)

                                                print(
                                                    'Sending Mail After Form Cases Completed==================')
                                                user_id_list = self.get_user_id_list(
                                                    process_id)
                                                send_email(organization_id, user_id_list, "ACTION_ONE",
                                                           {"org_id": organization_id, "case_id": case_id})

                                            responses.append(response_data)

                                            return Response(response_data,
                                                            status=status.HTTP_201_CREATED)  # Return the response

                                    else:
                                        return Response(response_data,
                                                        status=status.HTTP_200_OK)  # Make sure to return a response
                    ########## function to execute Invoice Generation Bot ######################

                    elif bot_type == 'PDF Generator':
                        print('--- PDF Generator --- ')
                        print("current_step_id", current_step_id)
                        invoice_generator_bots = Bot.objects.filter(
                            bot_name='PDF Generator', bot_uid=current_step_id)

                        if invoice_generator_bots:
                            for invoice_generator_bot in invoice_generator_bots:
                                bot_schemas = BotSchema.objects.filter(
                                    bot=invoice_generator_bot)
                                if isinstance(process_data, CreateProcess):
                                    process_id = process_data.id
                                else:
                                    print(
                                        "process_data is not an instance of CreateProcess")
                                if bot_schemas:
                                    invoice_extractor_input_data = bot_schema.bot_schema_json
                                    bot_element_permission = bot_schema.bot_element_permission

                                    logger.info(
                                        "invoice_extractor_input_data %s", invoice_extractor_input_data)

                                    response_data = {
                                        'caseid': case.id,
                                        'processId': process_id,
                                        'organization': organization_id,
                                        'createdby': case.created_by,
                                        'createdon': case.created_on,
                                        'updatedon': case.updated_on,
                                        'updatedby': case.updated_by,
                                        'bot_type': 'PDF Generator',
                                        'bot_schema': invoice_extractor_input_data,
                                        'bot_element_permission': bot_element_permission,
                                        'status': case.status,
                                        'assigned_users': []
                                    }
                                    data_json = None  # Initialize data_json with a default value
                                    if 'file' in request.FILES:

                                        # Handle file upload
                                        # Get the file from request.FILES
                                        uploaded_file = request.FILES['file']
                                        print("File Name:", uploaded_file.name)
                                        print("File Type:",
                                              uploaded_file.content_type)

                                        # If the file contains JSON data, read and parse it
                                        if uploaded_file.content_type == "application/json":
                                            file_content = uploaded_file.read().decode(
                                                'utf-8')  # Read file and decode to string
                                            try:
                                                data_json = json.loads(
                                                    file_content)  # Parse JSON data
                                                print(
                                                    "Parsed JSON Data:", data_json)
                                            except json.JSONDecodeError as e:
                                                print(
                                                    "Error parsing JSON from file:", str(e))
                                        else:
                                            print(
                                                "Uploaded file is not a JSON file.")

                                    # Handle organization_id and data_json if provided separately
                                    if 'organization' in request.data:
                                        organization_id_value = request.data['organization']

                                        file = None
                                        for field_name, uploaded_file in request.FILES.items():
                                            file = uploaded_file
                                            print("file", type(file))
                                            break  # Assuming only one file is expected; remove break if multiple files need handling

                                        if file:
                                            # Ensure data_json is set to a string representation, even if it is None
                                            data_json_str = str(
                                                data_json) if data_json else "{}"

                                            # Fetch drive types and configurations for the specific organization
                                            dms_entries = Dms.objects.filter(
                                                organization=organization_id, flow_id=process_id) # By Harish 31.10.25
                                            drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}

                                            configurations = dms_entries.first().config_details_schema

                                            configurations['drive_types'] = drive_types
                                            # configurations['s3_bucket_metadata'] = drive_types

                                            metadata = {'case_id': str(case.id),
                                                        'organization_id': str(organization_id),
                                                        'data_json': data_json_str}
                                            configurations['metadata'] = json.dumps(
                                                metadata)

                                            files = {
                                                'files': (file.name, file.file, file.content_type)}
                                            # files = {'files': (file.name, file, 'application/octet-stream')}
                                            print("inside file", files)
                                            # external_api_url = 'http://192.168.0.106:8000/custom_components/FileUploadView/'
                                            external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                                            response = requests.post(
                                                external_api_url, data=configurations, files=files)

                                            if response.status_code == 200:
                                                # responses.append(response.json())  # Store the response
                                                response_json = response.json()
                                                print(
                                                    "response_json-----------------------", response_json)

                                                file_name = response_json.get(
                                                    'file_name')
                                                # download_link = response_json.get('download_link')
                                                download_link = response_json.get(
                                                    'download_link')

                                                file_id = response_json.get(
                                                    'file', {}).get('id')

                                                print("File Name:", file_name)
                                                print("File ID:", file_id)
                                                print(
                                                    "download_linkdddddddddddd", download_link)
                                                try:
                                                    organization_instance = Organization.objects.get(
                                                        id=organization_id)
                                                except Organization.DoesNotExist:
                                                    # Handle the case where the organization does not exist
                                                    organization_instance = None
                                                try:
                                                    dms_instance = Dms.objects.get(
                                                        id=organization_id, flow_id=process_id) # By Harish 31.10.25
                                                except Dms.DoesNotExist:
                                                    # Handle the case where the dms_instance does not exist
                                                    dms_instance = None
                                                ####### Saving the file Details in bot data by Praba on 25-9-25[STARTS]
                                                try:
                                                    bot_data, created = BotData.objects.update_or_create(
                                                        bot=bot,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        organization=organization_instance,
                                                        defaults={
                                                            "data_schema": {
                                                                "metadata": configurations.get("metadata", {}),
                                                                "file_id": file_id,
                                                                "filename": file_name,
                                                                "download_link": download_link,
                                                                "user": user_data_id.id if user_data_id else None,

                                                            }
                                                        }
                                                    )

                                                    if created:
                                                        print(" Created new bot_data:", bot_data)
                                                    else:
                                                        print(" Updated existing bot_data:", bot_data)

                                                    # Debugging details
                                                    print("bot_data details:", bot_data.__dict__)

                                                except Exception as e:
                                                    print(" Error during update_or_create:", e)
                                                ####### Saving the file Details in bot data by Praba on 25-9-25[ENDS]
                                                dms_data = None
                                                created = False
                                                print("userId Dms_data Creation -3 : ", user_data_id)
                                                try:
                                                    dms_data, created = Dms_data.objects.get_or_create(
                                                        folder_id=file_id,
                                                        filename=file_name,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        dms=dms_instance,
                                                        download_link=download_link,
                                                        user=user_data_id,
                                                        organization=organization_instance,
                                                        defaults={
                                                            'meta_data': configurations['metadata']}
                                                    )

                                                except Exception as e:
                                                    print(
                                                        "Error during get_or_create:", e)

                                                    # Print details of integration_data to see if it is None or has unexpected # values
                                                if dms_data is None:
                                                    print("dms_data is None")
                                                else:
                                                    print(
                                                        f"dms_data details: {dms_data.__dict__}")

                                                    # If BotData was found, update the data_schema field
                                                if dms_data and not created:
                                                    try:
                                                        dms_data.meta_data = configurations['metadata']
                                                        dms_data.save()  # Ensure you call save on the correct object

                                                    except Exception as e:
                                                        print(
                                                            "Error during integration_data save:", e)

                                                responses.append(response_json)

                                            else:
                                                print(
                                                    "Failed to Save DMS Data:", response.text)
                                                return Response(
                                                    {
                                                        "error": f"Failed to send {dms_data}. Response: {response.text}"
                                                    },
                                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                                                )

                                            # Update the case with the next step and save
                                            with transaction.atomic():
                                                case_data = Case.objects.select_for_update().get(pk=case.id)
                                            data_json_content = json.loads(
                                                case_data.data_json or '[]')

                                            # Append next_step
                                            data_json_content.append(
                                                case_data.next_step)

                                            # Convert back to JSON string
                                            case_data.data_json = json.dumps(
                                                data_json_content)
                                            if isinstance(case_data.user_case_history, str):
                                                case_data.user_case_history = json.loads(
                                                    case_data.user_case_history or "[]")
                                            elif not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []
                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id

                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            # step_name = 'PDF Generator'
                                            created_on = case.created_on
                                            # Get updated user case history
                                            userId = request.data.get(
                                                'userId', None)
                                            new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                                  stage_name)

                                            # Ensure user_case_history is a valid list in case_data
                                            if not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []

                                            # Append new history
                                            case_data.user_case_history.extend(
                                                new_user_case_history)
                                            # case_data.data_json = json.dumps(
                                            #     json.loads(case_data.data_json) + [case_data.next_step])
                                            case_data.status = "PDF Generator"
                                            case_data.stages = "PDF Generator"
                                            if not isinstance(case_data.path_json, list):
                                                case_data.path_json = []
                                            # Append next_step to path_json
                                            case_data.path_json.append(
                                                case_data.next_step)
                                            case_data.save()

                                            # Assuming next_step_id is determined elsewhere
                                            case_data.next_step = next_step_id
                                            case_data.save()

                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id

                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            case_data.status = stage_name or 'PDF Generator'
                                            case_data.stages = stage_name or 'PDF Generator'
                                            case_data.save()  # saving the case stages

                                            # sending Mail
                                            user_id_list = self.get_form_user_id_list(next_step_id, organization_id,
                                                                                      process_id)
                                            if user_id_list is not None and len(user_id_list) > 0:
                                                send_email(organization_id, user_id_list, "ACTION_TWO",
                                                           {"org_id": organization_id, "case_id": case_id})

                                            if next_step_id.lower() == "null" or cs_next_step == "null":
                                                case_data.status = "Completed"
                                                case_data.save()
                                                #  send mail --
                                                responses.append(
                                                    case_data.status)
                                                # if the case completes it will save the case important data which is configured in process
                                                # parent_case_data = self.inject_parent_case_data(process_id,
                                                #                                                 case_id)  # need to add the important case data inject function.
                                                # logger.info(
                                                #     "parent_case_data %s", parent_case_data)

                                                print(
                                                    'Sending Mail After Form Cases Completed==================')
                                                user_id_list = self.get_user_id_list(
                                                    process_id)
                                                send_email(organization_id, user_id_list, "ACTION_ONE",
                                                           {"org_id": organization_id, "case_id": case_id})
                                                print(
                                                    'Mail are Send Success Fully ================')

                                            responses.append(response_data)
                                            print(
                                                "Returning successful response")
                                            return Response(response_data,
                                                            status=status.HTTP_201_CREATED)  # Return the response

                                    else:
                                        return Response(response_data,
                                                        status=status.HTTP_200_OK)  # Make sure to return a response

                    ########## function to execute Invoice Generation Bot ENDS ######################

                    ########## function to execute Document Generation Bot Starts ######################

                    elif bot_type == 'Doc Generator':

                        print('--- Doc Generator --- ')
                        doc_generator_bots = Bot.objects.filter(
                            bot_name='Doc Generator', bot_uid=current_step_id)
                        print("doc_generator_bots", doc_generator_bots)
                        if doc_generator_bots:
                            for doc_generator_bot in doc_generator_bots:
                                bot_schemas = BotSchema.objects.filter(
                                    bot=doc_generator_bot)
                                if isinstance(process_data, CreateProcess):
                                    process_id = process_data.id
                                    print("Extracted process_id:", process_id)
                                else:
                                    print(
                                        "process_data is not an instance of CreateProcess")
                                if bot_schemas:

                                    doc_extractor_input_data = bot_schema.bot_schema_json

                                    logger.info(
                                        "doc_extractor_input_data %s", doc_extractor_input_data)
                                    print("doc_extractor_input_data_schema:",
                                          doc_extractor_input_data)
                                    response_data = {
                                        'caseid': case.id,
                                        'processId': process_id,
                                        'organization': organization_id,
                                        'createdby': case.created_by,
                                        'createdon': case.created_on,
                                        'updatedon': case.updated_on,
                                        'updatedby': case.updated_by,
                                        'bot_type': 'Doc Generator',
                                        'bot_schema': doc_extractor_input_data,
                                        'status': case.status,
                                        'assigned_users': []
                                    }

                                    data_json = None
                                    # file_field_id = None
                                    # for item in data_json:
                                    #     if item.get('field_id') and item.get('value'):
                                    #         file_field_id = item['field_id']
                                    #         break
                                    # Assign userId from request or default to 'admin' to
                                    # file = None
                                    # for field_name, uploaded_file in request.FILES.items():
                                    #     file = uploaded_file
                                    #     print("file", type(file))
                                    #     break  # Assuming only one file is expected; remove break if multiple files need handling

                                    if 'file' in request.FILES:

                                        # Handle file upload
                                        # Get the file from request.FILES
                                        uploaded_file = request.FILES['file']
                                        print("File Name:", uploaded_file.name)
                                        print("File Type:",
                                              uploaded_file.content_type)

                                        # If the file contains JSON data, read and parse it
                                        if uploaded_file.content_type == "application/json":
                                            file_content = uploaded_file.read().decode(
                                                'utf-8')  # Read file and decode to string
                                            try:
                                                data_json = json.loads(
                                                    file_content)  # Parse JSON data
                                                print(
                                                    "Parsed JSON Data:", data_json)
                                            except json.JSONDecodeError as e:
                                                print(
                                                    "Error parsing JSON from file:", str(e))
                                        else:
                                            print(
                                                "Uploaded file is not a JSON file.")

                                    # Handle organization_id and data_json if provided separately
                                    if 'organization' in request.data:
                                        organization_id_value = request.data['organization']

                                        file = None
                                        if file:
                                            # Ensure data_json is set to a string representation, even if it is None
                                            data_json_str = str(
                                                data_json) if data_json else "{}"

                                            # Fetch drive types and configurations for the specific organization
                                            dms_entries = Dms.objects.filter(
                                                organization=organization_id, flow_id=process_id) # By Harish 31.10.25
                                            drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}

                                            configurations = dms_entries.first().config_details_schema

                                            configurations['drive_types'] = drive_types
                                            # configurations['s3_bucket_metadata'] = drive_types

                                            metadata = {'case_id': str(case.id),
                                                        'organization_id': str(organization_id),
                                                        'data_json': data_json_str}
                                            configurations['metadata'] = json.dumps(
                                                metadata)

                                            files = {
                                                'files': (file.name, file.file, file.content_type)}
                                            # files = {'files': (file.name, file, 'application/octet-stream')}

                                            # external_api_url = 'http://192.168.0.106:8000/custom_components/FileUploadView/'
                                            external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                                            response = requests.post(
                                                external_api_url, data=configurations, files=files)

                                            if response.status_code == 200:
                                                # responses.append(response.json())  # Store the response
                                                response_json = response.json()
                                                print(
                                                    "response_json-----------------------", response_json)

                                                file_name = response_json.get(
                                                    'file_name')
                                                # download_link = response_json.get('download_link')
                                                download_link = response_json.get(
                                                    'download_link')

                                                file_id = response_json.get(
                                                    'file', {}).get('id')

                                                print("File Name:", file_name)
                                                print("File ID:", file_id)
                                                print(
                                                    "download_linkdddddddddddd", download_link)
                                                try:
                                                    organization_instance = Organization.objects.get(
                                                        id=organization_id)
                                                except Organization.DoesNotExist:
                                                    # Handle the case where the organization does not exist
                                                    organization_instance = None
                                                try:
                                                    dms_instance = Dms.objects.get(
                                                        id=organization_id, flow_id=process_id) # By Harish 31.10.25
                                                except Dms.DoesNotExist:
                                                    # Handle the case where the dms_instance does not exist
                                                    dms_instance = None
                                                # Check if there are any Dms entries
                                                ####### Saving the file Details in bot data by Praba on 25-9-25[STARTS]
                                                try:
                                                    bot_data, created = BotData.objects.update_or_create(
                                                        bot=bot,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        organization=organization_instance,
                                                        defaults={
                                                            "data_schema": {
                                                                "metadata": configurations.get("metadata", {}),
                                                                "file_id": file_id,
                                                                "filename": file_name,
                                                                "download_link": download_link,
                                                                "user": user_data_id.id if user_data_id else None,

                                                            }
                                                        }
                                                    )

                                                    if created:
                                                        print(" Created new bot_data:", bot_data)
                                                    else:
                                                        print(" Updated existing bot_data:", bot_data)

                                                    # Debugging details
                                                    print("bot_data details:", bot_data.__dict__)

                                                except Exception as e:
                                                    print(" Error during update_or_create:", e)
                                                ####### Saving the file Details in bot data by Praba on 25-9-25[ENDS]
                                                dms_data = None
                                                created = False
                                                print("userId Dms_data Creation -4 : ", user_data_id)
                                                try:
                                                    dms_data, created = Dms_data.objects.get_or_create(
                                                        folder_id=file_id,
                                                        filename=file_name,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        dms=dms_instance,
                                                        download_link=download_link,
                                                        user=user_data_id,
                                                        organization=organization_instance,
                                                        defaults={
                                                            'meta_data': configurations['metadata']}
                                                    )

                                                except Exception as e:
                                                    print(
                                                        "Error during get_or_create:", e)

                                                    # Print details of integration_data to see if it is None or has unexpected # values
                                                if dms_data is None:
                                                    print("dms_data is None")
                                                else:
                                                    print(
                                                        f"dms_data details: {dms_data.__dict__}")

                                                    # If BotData was found, update the data_schema field
                                                if dms_data and not created:
                                                    try:
                                                        dms_data.meta_data = configurations['metadata']
                                                        dms_data.save()  # Ensure you call save on the correct object

                                                    except Exception as e:
                                                        print(
                                                            "Error during integration_data save:", e)

                                                responses.append(response_json)

                                            else:
                                                print(
                                                    "Failed to Save DMS Data:", response.text)
                                                return Response(
                                                    {
                                                        "error": f"Failed to send {dms_data}. Response: {response.text}"
                                                    },
                                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                                                )

                                            # Update the case with the next step and save
                                            with transaction.atomic():
                                                case_data = Case.objects.select_for_update().get(pk=case.id)
                                            data_json_content = json.loads(
                                                case_data.data_json or '[]')

                                            # Append next_step
                                            data_json_content.append(
                                                case_data.next_step)

                                            # Convert back to JSON string
                                            case_data.data_json = json.dumps(
                                                data_json_content)
                                            if isinstance(case_data.user_case_history, str):
                                                case_data.user_case_history = json.loads(
                                                    case_data.user_case_history or "[]")
                                            elif not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []
                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id
                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            step_name = "Doc Generator"
                                            created_on = case.created_on
                                            # Get updated user case history
                                            userId = request.data.get(
                                                'userId', None)
                                            new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                                  stage_name)

                                            # Ensure user_case_history is a valid list in case_data
                                            if not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []

                                            # Append new history
                                            case_data.user_case_history.extend(
                                                new_user_case_history)

                                            # case_data.data_json = json.dumps(
                                            #     json.loads(case_data.data_json) + [case_data.next_step])
                                            case_data.status = "Doc Generator"
                                            case_data.stages = "Doc Generator"
                                            if not isinstance(case_data.path_json, list):
                                                case_data.path_json = []
                                            # Append next_step to path_json
                                            case_data.path_json.append(
                                                case_data.next_step)
                                            case_data.save()

                                            # Assuming next_step_id is determined elsewhere
                                            case_data.next_step = next_step_id
                                            case_data.save()

                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id
                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            case_data.status = stage_name or 'Doc Generator'
                                            case_data.stages = stage_name or 'Doc Generator'
                                            ##### add case.stage = stage_name or 'Doc Generator'
                                            case_data.save()  # saving the case stages
                                            print("************",
                                                  stage_name)  #

                                            # sending Mail
                                            user_id_list = self.get_form_user_id_list(next_step_id, organization_id,
                                                                                      process_id)
                                            if user_id_list is not None and len(user_id_list) > 0:
                                                send_email(organization_id, user_id_list, "ACTION_TWO",
                                                           {"org_id": organization_id, "case_id": case_id})

                                            if next_step_id.lower() == "null" or cs_next_step == "null":
                                                case_data.status = "Completed"
                                                case_data.save()
                                                responses.append(
                                                    case_data.status)
                                                # if the case completes it will save the case important data which is configured in process
                                                # parent_case_data = self.inject_parent_case_data(process_id,
                                                #                                                 case_id)  # need to add the important case data inject function.
                                                # logger.info(
                                                #     "parent_case_data %s", parent_case_data)
                                                print(
                                                    'Sending Mail After Form Cases Completed==================')
                                                user_id_list = self.get_user_id_list(
                                                    process_id)
                                                send_email(organization_id, user_id_list, "ACTION_ONE",
                                                           {"org_id": organization_id, "case_id": case_id})
                                                print(
                                                    'Mail are Send Success Fully ================')

                                            responses.append(response_data)
                                            print(
                                                "Returning successful response")
                                            return Response(response_data,
                                                            status=status.HTTP_201_CREATED)  # Return the response

                                    else:
                                        return Response(response_data,
                                                        status=status.HTTP_200_OK)  # Make sure to return a response
                                    ########## function to execute Document Generation Bot Ends ######################

                    elif bot_type == 'QR Generator':
                        print('--- QR Generator --- ')
                        print("current_step_id", current_step_id)
                        qr_generator_bots = Bot.objects.filter(
                            bot_name='QR Generator', bot_uid=current_step_id)
                        print("invoice_generator_bots", qr_generator_bots)

                        if qr_generator_bots:
                            for qr_generator_bots in qr_generator_bots:
                                bot_schemas = BotSchema.objects.filter(
                                    bot=qr_generator_bots)
                                if isinstance(process_data, CreateProcess):
                                    process_id = process_data.id
                                    logger.info(
                                        "Extracted process_id %s:", process_id)
                                else:
                                    logger.info(
                                        "process_data is not an instance of CreateProcess")
                                if bot_schemas:

                                    qr_automation_input_data = bot_schema.bot_schema_json

                                    logger.info(
                                        "QR_generator_input_data %s", qr_automation_input_data)

                                    response_data = {
                                        'caseid': case.id,
                                        'processId': process_id,
                                        'organization': organization_id,
                                        'createdby': case.created_by,
                                        'createdon': case.created_on,
                                        'updatedon': case.updated_on,
                                        'updatedby': case.updated_by,
                                        'bot_type': 'QR Generator',
                                        'bot_schema': qr_automation_input_data,
                                        'status': case.status,
                                        'assigned_users': []
                                    }

                                    data_json = None
                                    # file_field_id = None
                                    # for item in data_json:
                                    #     if item.get('field_id') and item.get('value'):
                                    #         file_field_id = item['field_id']
                                    #         break
                                    if 'file' in request.FILES:
                                        print("request.data", request.data)

                                        # Handle file upload
                                        # Get the file from request.FILES
                                        uploaded_file = request.FILES['file']
                                        print("File Name:", uploaded_file.name)
                                        print("File Type:",
                                              uploaded_file.content_type)

                                        # If the file contains JSON data, read and parse it
                                        if uploaded_file.content_type == "application/json":
                                            file_content = uploaded_file.read().decode(
                                                'utf-8')  # Read file and decode to string
                                            try:
                                                data_json = json.loads(
                                                    file_content)  # Parse JSON data
                                                print(
                                                    "Parsed JSON Data:", data_json)
                                            except json.JSONDecodeError as e:
                                                print(
                                                    "Error parsing JSON from file:", str(e))
                                        else:
                                            print(
                                                "Uploaded file is not a JSON file.")

                                    # Handle organization_id and data_json if provided separately
                                    if 'organization' in request.data:
                                        organization_id_value = request.data['organization']
                                        print("Organization ID:",
                                              organization_id_value)

                                        file = None
                                        for field_name, uploaded_file in request.FILES.items():
                                            file = uploaded_file
                                            print("file", type(file))
                                            break  # Assuming only one file is expected; remove break if multiple files need handling

                                        if file:
                                            # Ensure data_json is set to a string representation, even if it is None
                                            data_json_str = str(
                                                data_json) if data_json else "{}"

                                            # Fetch drive types and configurations for the specific organization
                                            dms_entries = Dms.objects.filter(
                                                organization=organization_id, flow_id=process_id) # By Harish 31.10.25
                                            drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}

                                            configurations = dms_entries.first().config_details_schema
                                            print("configurations type",
                                                  type(configurations))
                                            configurations['drive_types'] = drive_types
                                            # configurations['s3_bucket_metadata'] = drive_types
                                            print("configurations",
                                                  configurations)

                                            metadata = {'case_id': str(case.id),
                                                        'organization_id': str(organization_id),
                                                        'data_json': data_json_str}
                                            configurations['metadata'] = json.dumps(
                                                metadata)
                                            print("configurations",
                                                  configurations)
                                            files = {
                                                'files': (file.name, file.file, file.content_type)}
                                            # files = {'files': (file.name, file, 'application/octet-stream')}
                                            print("inside file", files)
                                            # external_api_url = 'http://192.168.0.106:8000/custom_components/FileUploadView/'
                                            external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                                            response = requests.post(
                                                external_api_url, data=configurations, files=files)
                                            print("response.status_code",
                                                  response.status_code)
                                            if response.status_code == 200:
                                                # responses.append(response.json())  # Store the response
                                                response_json = response.json()
                                                print(
                                                    "response_json-----------------------", response_json)

                                                file_name = response_json.get(
                                                    'file_name')
                                                # download_link = response_json.get('download_link')
                                                download_link = response_json.get(
                                                    'download_link')
                                                print(download_link)

                                                file_id = response_json.get(
                                                    'file', {}).get('id')

                                                print("File Name:", file_name)
                                                print("File ID:", file_id)
                                                print(
                                                    "download_linkdddddddddddd", download_link)
                                                try:
                                                    organization_instance = Organization.objects.get(
                                                        id=organization_id)
                                                except Organization.DoesNotExist:
                                                    # Handle the case where the organization does not exist
                                                    organization_instance = None
                                                try:
                                                    dms_instance = Dms.objects.get(
                                                        id=organization_id, flow_id=process_id) # By Harish 31.10.25
                                                except Dms.DoesNotExist:
                                                    # Handle the case where the dms_instance does not exist
                                                    dms_instance = None
                                                ####### Saving the file Details in bot data by Praba on 25-9-25[STARTS]
                                                try:
                                                    bot_data, created = BotData.objects.update_or_create(
                                                        bot=bot,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        organization=organization_instance,
                                                        defaults={
                                                            "data_schema": {
                                                                "metadata": configurations.get("metadata", {}),
                                                                "file_id": file_id,
                                                                "filename": file_name,
                                                                "download_link": download_link,
                                                                "user": user_data_id.id if user_data_id else None,

                                                            }
                                                        }
                                                    )

                                                    if created:
                                                        print(" Created new bot_data:", bot_data)
                                                    else:
                                                        print(" Updated existing bot_data:", bot_data)

                                                    # Debugging details
                                                    print("bot_data details:", bot_data.__dict__)

                                                except Exception as e:
                                                    print(" Error during update_or_create:", e)

                                                ####### Saving the file Details in bot data by Praba on 25-9-25[ENDS]
                                                dms_data = None
                                                created = False
                                                print("userId Dms_data Creation -5 : ", user_data_id)
                                                try:
                                                    dms_data, created = Dms_data.objects.get_or_create(
                                                        folder_id=file_id,
                                                        filename=file_name,
                                                        case_id=case,
                                                        flow_id=process_data,
                                                        dms=dms_instance,
                                                        download_link=download_link,
                                                        user=user_data_id,
                                                        organization=organization_instance,
                                                        defaults={
                                                            'meta_data': configurations['metadata']}
                                                    )

                                                except Exception as e:
                                                    print(
                                                        "Error during get_or_create:", e)

                                                    # Print details of integration_data to see if it is None or has unexpected # values
                                                if dms_data is None:
                                                    print("dms_data is None")
                                                else:
                                                    print(
                                                        f"dms_data details: {dms_data.__dict__}")

                                                    # If BotData was found, update the data_schema field
                                                if dms_data and not created:
                                                    try:
                                                        dms_data.meta_data = configurations['metadata']
                                                        dms_data.save()  # Ensure you call save on the correct object

                                                    except Exception as e:
                                                        print(
                                                            "Error during integration_data save:", e)

                                                responses.append(response_json)

                                            else:
                                                print(
                                                    "Failed to Save DMS Data:", response.text)
                                                return Response(
                                                    {
                                                        "error": f"Failed to send {dms_data}. Response: {response.text}"
                                                    },
                                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                                                )

                                            print("next_step_id", next_step_id)

                                            # Update the case with the next step and save
                                            with transaction.atomic():
                                                case_data = Case.objects.select_for_update().get(pk=case.id)
                                            data_json_content = json.loads(
                                                case_data.data_json or '[]')

                                            # Append next_step
                                            data_json_content.append(
                                                case_data.next_step)

                                            # Convert back to JSON string
                                            case_data.data_json = json.dumps(
                                                data_json_content)

                                            # Convert back to JSON string
                                            if isinstance(case_data.user_case_history, str):
                                                case_data.user_case_history = json.loads(
                                                    case_data.user_case_history or "[]")
                                            elif not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []
                                            # case_data.data_json = json.dumps(data_json_content)
                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id
                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            # step_name = "QR Generator"
                                            created_on = case.created_on
                                            userId = request.data.get(
                                                'userId', None)
                                            # Get updated user case history
                                            new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                                  stage_name)

                                            # Ensure user_case_history is a valid list in case_data
                                            if not isinstance(case_data.user_case_history, list):
                                                case_data.user_case_history = []

                                            # Append new history
                                            case_data.user_case_history.extend(
                                                new_user_case_history)

                                            # case_data.data_json = json.dumps(
                                            #     json.loads(case_data.data_json) + [case_data.next_step])
                                            case_data.status = "QR Generator"
                                            case_data.stages = "QR Generatpr"
                                            if not isinstance(case_data.path_json, list):
                                                case_data.path_json = []
                                            # Append next_step to path_json
                                            case_data.path_json.append(
                                                case_data.next_step)
                                            case_data.save()

                                            # Assuming next_step_id is determined elsewhere
                                            case_data.next_step = next_step_id
                                            case_data.save()

                                            # Updated the case stages with process stages by Praba on 20.3.25
                                            # step_id = next_step_id
                                            step_id = current_step_id
                                            # process_stages = {}
                                            stage_name = self.get_stage_name(
                                                process_stages, step_id)
                                            case_data.status = stage_name or 'QR Generator'
                                            case_data.stages = stage_name or 'QR Generator'
                                            case_data.save()  # saving the case stages
                                            print("************",
                                                  stage_name)  #

                                            # sending Mail
                                            user_id_list = self.get_form_user_id_list(next_step_id, organization_id,
                                                                                      process_id)
                                            if user_id_list is not None and len(user_id_list) > 0:
                                                send_email(organization_id, user_id_list, "ACTION_TWO",
                                                           {"org_id": organization_id, "case_id": case_id})

                                            if next_step_id.lower() == "null" or cs_next_step == "null":
                                                case_data.status = "Completed"
                                                case_data.save()

                                                responses.append(
                                                    case_data.status)
                                                # if the case completes it will save the case important data which is configured in process
                                                # parent_case_data = self.inject_parent_case_data(process_id,
                                                #                                                 case_id)  # need to add the important case data inject function.
                                                # logger.info(
                                                #     "parent_case_data %s", parent_case_data)
                                                print(
                                                    'Sending Mail After Form Cases Completed==================')
                                                user_id_list = self.get_user_id_list(
                                                    process_id)
                                                send_email(organization_id, user_id_list, "ACTION_ONE",
                                                           {"org_id": organization_id, "case_id": case_id})
                                                print(
                                                    'Mail are Send Success Fully ================')

                                            responses.append(response_data)
                                            print(
                                                "Returning successful response")
                                            return Response(response_data,
                                                            status=status.HTTP_201_CREATED)  # Return the response

                                    else:
                                        return Response(response_data,
                                                        status=status.HTTP_200_OK)  # Make sure to return a response
                                    # return Response(response_data,
                                    #                 status=status.HTTP_201_CREATED)

                    ########## function to execute Desktop Automation Starts by Mohan ######################
                    elif bot_type == 'Desktop Automation':

                        print('--- Desktop Automation --- ')
                        desktop_automation_bots = Bot.objects.filter(bot_name='Desktop Automation',
                                                                     bot_uid=current_step_id)
                        logger.info("Desktop Automationbots %s",
                                    desktop_automation_bots)
                        if desktop_automation_bots:
                            for desktop_automation_bot in desktop_automation_bots:
                                bot_schemas = BotSchema.objects.filter(
                                    bot=desktop_automation_bot)
                                if isinstance(process_data, CreateProcess):
                                    process_id = process_data.id
                                    logger.info(
                                        "Extracted process_id %s:", process_id)
                                else:
                                    logger.info(
                                        "process_data is not an instance of CreateProcess")
                                if bot_schemas:

                                    desktop_automation_input_data = bot_schema.bot_schema_json

                                    logger.info(
                                        "desktop_automation_input_data %s", desktop_automation_input_data)

                                    response_data = {
                                        'caseid': case.id,
                                        'processId': process_id,
                                        'organization': organization_id,
                                        'createdby': case.created_by,
                                        'createdon': case.created_on,
                                        'updatedon': case.updated_on,
                                        'updatedby': case.updated_by,
                                        'bot_type': 'Desktop Automation',
                                        'bot_schema': desktop_automation_input_data,
                                        'status': case.status,
                                        'assigned_users': []
                                    }

                                    data_json = None
                                    # return Response(response_data,
                                    #                 status=status.HTTP_201_CREATED)
                                    if 'data_json' in request.data and request.data['data_json']:
                                        data_json_str = request.data['data_json']
                                        logger.info(
                                            "data_json_str %s", data_json_str)
                                        # Update the case with the next step and save
                                        with transaction.atomic():
                                            case_data = Case.objects.select_for_update().get(pk=case.id)
                                        data_json_content = json.loads(
                                            case_data.data_json or '[]')

                                        # Append next_step
                                        data_json_content.append(
                                            case_data.next_step)

                                        # Convert back to JSON string
                                        if isinstance(case_data.user_case_history, str):
                                            case_data.user_case_history = json.loads(
                                                case_data.user_case_history or "[]")
                                        elif not isinstance(case_data.user_case_history, list):
                                            case_data.user_case_history = []
                                        case_data.data_json = json.dumps(
                                            data_json_content)

                                        # Updated the case stages with process stages by Praba on 20.3.25
                                        # step_id = next_step_id
                                        # process_stages = {}
                                        step_id = current_step_id
                                        stage_name = self.get_stage_name(
                                            process_stages, step_id)
                                        # step_name = "Desktop Automation"
                                        created_on = case.created_on
                                        userId = request.data.get(
                                            'userId', None)
                                        # Get updated user case history
                                        new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                              stage_name)

                                        # Ensure user_case_history is a valid list in case_data
                                        if not isinstance(case_data.user_case_history, list):
                                            case_data.user_case_history = []

                                        # Append new history
                                        case_data.user_case_history.extend(
                                            new_user_case_history)

                                        # case_data.data_json = json.dumps(
                                        #     json.loads(case_data.data_json) + [case_data.next_step])
                                        case_data.status = "QR Generator"
                                        case_data.stages = "QR Generator"
                                        if not isinstance(case_data.path_json, list):
                                            case_data.path_json = []
                                        # Append next_step to path_json
                                        case_data.path_json.append(
                                            case_data.next_step)
                                        case_data.save()

                                        # Assuming next_step_id is determined elsewhere
                                        case_data.next_step = next_step_id
                                        case_data.save()

                                        # Updated the case stages with process stages by Praba on 20.3.25
                                        # step_id = next_step_id
                                        step_id = current_step_id
                                        # process_stages = {}
                                        stage_name = self.get_stage_name(
                                            process_stages, step_id)
                                        case_data.status = stage_name or 'QR Generator'
                                        case_data.stages = stage_name or 'QR Generator'
                                        case_data.save()  # saving the case stages
                                        print("************", stage_name)  #

                                        # sending Mail
                                        user_id_list = self.get_form_user_id_list(next_step_id, organization_id,
                                                                                  process_id)
                                        if user_id_list is not None and len(user_id_list) > 0:
                                            send_email(organization_id, user_id_list, "ACTION_TWO",
                                                       {"org_id": organization_id, "case_id": case_id})

                                        if next_step_id.lower() == "null" or cs_next_step == "null":
                                            case_data.status = "Completed"
                                            case_data.save()
                                            responses.append(case_data.status)
                                            # if the case completes it will save the case important data which is configured in process
                                            # parent_case_data = self.inject_parent_case_data(process_id,
                                            #                                                     case_id)  # need to add the important case data inject function.
                                            # logger.info(
                                            #     "parent_case_data %s", parent_case_data)
                                            print(
                                                'Sending Mail After Form Cases Completed==================')
                                            user_id_list = self.get_user_id_list(
                                                process_id)
                                            send_email(organization_id, user_id_list, "ACTION_ONE",
                                                       {"org_id": organization_id, "case_id": case_id})
                                            print(
                                                'Mail are Send Success Fully ================')

                                        responses.append(response_data)
                                        print("Returning successful response")
                                        return Response(response_data,
                                                        status=status.HTTP_201_CREATED)  # Return the response

                                    else:
                                        return Response(response_data,
                                                        status=status.HTTP_200_OK)

                    ########## function to execute Desktop Automation Ends by Mohan ######################

                    else:
                        return Response({"error": f"Unsupported bot type: {bot_type}"},
                                        status=status.HTTP_400_BAD_REQUEST)

                elif subprocess:
                    if 'data_json' in request.data and request.data['data_json']:
                        data_json_str = request.data['data_json']
                        # Update the case with the next step and save
                        with transaction.atomic():
                            case_data = Case.objects.select_for_update().get(pk=case.id)
                        data_json_content = json.loads(
                            case_data.data_json or '[]')

                        # Append next_step
                        data_json_content.append(case_data.next_step)

                        # Convert back to JSON string
                        case_data.data_json = json.dumps(data_json_content)

                        # Get updated user case history
                        userId = request.data.get('userId', None)
                        user = None
                        if userId:
                            user = UserData.objects.filter(
                                id=userId).first()  # Replace `UserData` with your user model
                        if user:
                            created_by = user.user_name

                        else:
                            created_by = "Admin"
                            print("User not found", "Admin")
                        # step_name = "subprocess"
                        # step_id = next_step_id
                        step_id = current_step_id
                        stage_name = self.get_stage_name(
                            process_stages, step_id)
                        created_on = case.created_on

                        if isinstance(case_data.user_case_history, str):
                            case_data.user_case_history = json.loads(
                                case_data.user_case_history or "[]")
                        elif not isinstance(case_data.user_case_history, list):
                            case_data.user_case_history = []
                        # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                        new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                              stage_name)

                        # Ensure new_user_case_history is a dictionary and not a list
                        if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                            new_user_case_history = new_user_case_history[
                                0]  # Extract first dictionary if it's a list
                        # Append new history
                        if isinstance(new_user_case_history, dict):  # Ensure it's not a list
                            case_data.user_case_history.append(
                                new_user_case_history)
                        else:
                            print(
                                "Warning: new_user_case_history is not a dictionary!")

                        # Append new history
                        case_data.user_case_history = json.dumps(
                            case_data.user_case_history)
                        # case_data.data_json = json.dumps(
                        #     json.loads(case_data.data_json) + [case_data.next_step])

                        if case_data.assigned_users is not None:
                            case_data.assigned_users.clear()  # Clear all assigned users
                        else:
                            print(
                                "Warning: assigned_user is None. Skipping clear operation.")

                        # case_data.status = "subprocess"
                        if not isinstance(case_data.path_json, list):
                            case_data.path_json = []
                        # Append next_step to path_json
                        case_data.path_json.append(case_data.next_step)
                        case_data.save()

                        # Assuming next_step_id is determined elsewhere
                        case_data.next_step = next_step_id
                        case_data.save()

                        # Updated the case stages with process stages by Praba on 20.3.25
                        # step_id = next_step_id
                        step_id = current_step_id
                        process_stages = {}
                        stage_name = self.get_stage_name(
                            process_stages, step_id)
                        case_data.status = stage_name or 'subprocess'
                        case_data.stages = stage_name or 'subprocess'
                        case_data.save()  # saving the case stages
                        print("************", stage_name)  #

                        # sending Mail
                        user_id_list = self.get_form_user_id_list(
                            next_step_id, organization_id, process_id)
                        if user_id_list is not None and len(user_id_list) > 0:
                            send_email(organization_id, user_id_list, "ACTION_TWO",
                                       {"org_id": organization_id, "case_id": case_id})

                        if next_step_id.lower() == "null" or cs_next_step == "null":
                            case_data.status = "Completed"
                            case_data.save()
                            responses.append(case_data.status)
                            # if the case completes it will save the case important data which is configured in process
                            # parent_case_data = self.inject_parent_case_data(process_id,
                            #                                                                     case_id)  # need to add the important case data inject function.
                            # logger.info("parent_case_data %s",
                            #             parent_case_data)
                            print(
                                'Sending Mail After Form Cases Completed==================')
                            user_id_list = self.get_user_id_list(process_id)
                            send_email(organization_id, user_id_list, "ACTION_ONE",
                                       {"org_id": organization_id, "case_id": case_id})
                            print('Mail are Send Success Fully ================')

                        # responses.append(response_data)
                        print("Returning successful response")
                        # return Response(responses,
                        #                 status=status.HTTP_201_CREATED)  # Return the response

                    else:
                        return Response(responses,
                                        status=status.HTTP_200_OK)

                elif integrations:
                    for integration in integrations:
                        integration_type = integration.integration_type

                        integration_id_ref = integration.id

                        integration_input_data = integration.integration_schema

                        if isinstance(integration_input_data, str):
                            integration_input_data = json.loads(
                                integration_input_data)  # Ensure JSON string is parsed

                        dynamic_input_data = request.data.get(
                            current_step_id, {})

                        # input_data = {**integration_input_data, **dynamic_input_data}
                        # print("input_data", input_data)
                        if integration_type == 'api':
                            print('--- API INTEGRATION --- 3')

                            integration_obj = get_object_or_404(Integration,
                                                                Integration_uid=integration.Integration_uid)
                            integration_schema = integration_obj.integration_schema

                            try:
                                bot_data_entries = BotData.objects.filter(
                                    case_id=pk)
                                input_data_bot = {}
                                if bot_data_entries.exists():
                                    for entry in bot_data_entries:
                                        data_schema = entry.data_schema

                                        if isinstance(data_schema, list):
                                            for item in data_schema:
                                                if isinstance(item, dict):
                                                    input_data_bot.update(
                                                        {item['field_id']: item['value']})
                                                else:
                                                    print(
                                                        f"Warning: Non-dictionary item in data_schema list: {item}")
                                        else:
                                            print(
                                                f"Warning: BotData entry {entry.id} has a non-list data_schema: {data_schema} (type: {type(data_schema)})")
                                print("input_data_bot:", input_data_bot)
                            except BotData.DoesNotExist:
                                print(f"No BotData found for case_id {pk}")
                                input_data_bot = {}

                            # Attempt to fetch IntegrationDetails, handle if not found
                            try:
                                integration_data_entries = IntegrationDetails.objects.filter(
                                    case_id=pk)
                                input_data_api = {}
                                if integration_data_entries.exists():
                                    for entry in integration_data_entries:
                                        data_schema = entry.data_schema
                                        if isinstance(data_schema, list):
                                            for item in data_schema:
                                                if isinstance(item, dict):
                                                    input_data_api.update(
                                                        {item['field_id']: item['value']})
                                                else:
                                                    print(
                                                        f"Warning: Non-dictionary item in data_schema list: {item}")
                                        else:
                                            print(
                                                f"Warning: IntegrationDetails entry {entry.id} has a non-list "
                                                f"data_schema: {data_schema} (type: {type(data_schema)})")
                                print("input_data_api:", input_data_api)
                            except IntegrationDetails.DoesNotExist:
                                print(
                                    f"No IntegrationDetails found for case_id {pk}")
                                input_data_api = {}

                            try:
                                form_filled_entries = FilledFormData.objects.filter(
                                    caseId=pk)
                                input_data_form = {}
                                if form_filled_entries.exists():
                                    for entry in form_filled_entries:
                                        data_schema = entry.data_json
                                        if isinstance(data_schema, list):
                                            for item in data_schema:
                                                if isinstance(item, dict):
                                                    input_data_form.update(
                                                        {item['field_id']: item['value']})
                                                else:
                                                    print(
                                                        f"Warning: Non-dictionary item in data_schema list: {item}")
                                        else:
                                            print(
                                                f"Warning: FilledFormDetails entry {entry.id} has a non-list data_schema: {data_schema} (type: {type(data_schema)})")
                                print("input_data_form:", input_data_form)
                            except FilledFormData.DoesNotExist:
                                print(
                                    f"No FilledFormDetails found for case_id {pk}")
                                input_data_form = {}

                            logger.info("input_data_form %s", input_data_form)

                            combined_data = {}

                            # Add data from each source if it exists
                            if input_data_bot:
                                combined_data.update(input_data_bot)
                            if input_data_api:
                                combined_data.update(input_data_api)
                            if input_data_form:
                                combined_data.update(input_data_form)

                            # If all data sources are empty, combined_data will remain empty
                            # You can decide if you want it to be explicitly set to None in that case
                            if not combined_data:
                                combined_data = None

                            # Log the combined data for debugging
                            logger.info(f"Combined Data: {combined_data}")
                            input_data_dict = {
                                "input_data": [combined_data] if combined_data else None,
                                "schema_config": integration_schema,

                            }

                            url = settings.BASE_URL + reverse('execute-api')
                            logger.info("input_data_dict %s", input_data_dict)
                            logger.info("url %s", url)
                            payload = input_data_dict

                            # payload_json_bytes = json.dumps(payload)
                            # print("payload_json_bytes", payload_json_bytes)

                            # print("payload_json_bytes##############################", response)
                            response = requests.post(
                                url, json=payload)  # api call
                            print("response", response)
                            if response.status_code == 200:
                                # responses.append(response.json())  # Store the response
                                response_json = response.json()
                                logger.info("response_json %s", response_json)

                                # Extract 'data' from the response
                                integrationdata = response_json.get(
                                    'api_response_data')

                                try:
                                    organization_instance = Organization.objects.get(
                                        id=organization_id)
                                except Organization.DoesNotExist:
                                    # Handle the case where the organization does not exist
                                    organization_instance = None
                                # Check if BotData exists, if not create a new one
                                try:
                                    integration_data, created = IntegrationDetails.objects.get_or_create(
                                        integration_id=integration_obj.id,
                                        case_id=case,
                                        flow_id=process_data,
                                        organization=organization_instance,
                                        defaults={
                                            'data_schema': integrationdata}
                                    )

                                except Exception as e:
                                    print("Error during get_or_create:", e)

                                    # Print details of integration_data to see if it is None or has unexpected values
                                if integration_data is None:
                                    print("integration_data is None")
                                else:
                                    print(
                                        f"integration_data details: {integration_data.__dict__}")

                                    # If BotData was found, update the data_schema field
                                if not created:
                                    try:
                                        integration_data.data_schema = integrationdata
                                        integration_data.save()  # Ensure you call save on the correct object

                                    except Exception as e:
                                        print(
                                            "Error during integration_data save:", e)

                                responses.append(response_json)
                                print("API Integration successful")
                            else:
                                print(
                                    "Failed to execute API integration:", response.text)
                                return response.append(
                                    {
                                        "error": f"Failed to execute {integration_type} integration. Response: {response.text}"},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)



                elif form:

                    logger.info("Activity starts")
                    print("Form activity starts")

                    # Convert the form UID to string
                    form_id_ref = str(form.Form_uid)

                    # ---------------- FIX START ----------------
                    # If this is a submission from mail, ensure we only process the intended form
                    if from_mail_flag:
                        submitted_form_id = request.data.get('Form_uid')
                        if submitted_form_id and submitted_form_id != form_id_ref:
                            logger.info(
                                f"Skipping unrelated form. Submitted form_id={submitted_form_id}, current form_id_ref={form_id_ref}")
                            continue  # skip to next form in the loop
                    # ---------------- FIX END ------------------

                    # Attempt to retrieve the form JSON schema using the form UID
                    try:
                        form_json_schema = FormDataInfo.objects.get(
                            Form_uid=form_id_ref)

                    except FormDataInfo.DoesNotExist:
                        form_json_schema = None
                    if isinstance(process_data, CreateProcess):
                        process_id = process_data.id
                    else:
                        print("process_data is not an instance of CreateProcess")

                    if form_json_schema:
                        form_schema = form_json_schema.form_json_schema
                        form_style_schema = form_json_schema.form_style_schema or []
                        form_filter_schema = form_json_schema.form_filter_schema or []  # to filter the form
                        response_data = {
                            'caseid': case.id,
                            'processId': process_id,
                            'organization': organization_id,
                            'createdby': case.created_by,
                            'createdon': case.created_on,
                            'updatedon': case.updated_on,
                            'updatedby': case.updated_by,
                            'form_schema': form_schema,
                            'form_style_schema': form_style_schema,
                            'form_filter_schema': form_filter_schema,  # to filter the form
                            'status': case.status,
                            'assigned_users': []
                        }

                        ######## sending form in mail #######3
                        try:
                            if getattr(form_json_schema, "form_send_mail", False):
                                # Only send invite mail if this isn't the mail link submission
                                if not from_mail_flag:
                                    send_form_mail_with_token(
                                        case.id,
                                        process_id,
                                        organization_id,
                                        form_json_schema,
                                        form_id_ref
                                    )
                                else:
                                    logger.info(
                                        "From mail link submission - skipping re-sending invitation mail for case %s",
                                        case.id)
                        except Exception as e:
                            logger.exception("Error sending form mail for case %s: %s", case.id, str(e))

                        if 'data_json' in request.data and request.data['data_json']:
                            data_json_str = request.data['data_json']
                            organization_id_value = request.data['organization']

                            data_json = json.loads(data_json_str)

                            # ============= Sequence starts =============
                            generated_ids = generate_sequence_ids(form_schema, organization_id_value) or []
                            if len(generated_ids) > 0 and isinstance(data_json, list):
                                data_json.extend(generated_ids)

                            # ============== Sequence ends ==============

                            uploaded_files = request.FILES.getlist(
                                'files')  # Use the key used in the form
                            for file in uploaded_files:
                                print("Received file:", file.name)

                            if request.FILES:
                                # Handle files if present in request.FILES
                                files = []
                                files_with_ids = []  # added to store multiple file names
                                for field_name_id, uploaded_file in request.FILES.items():
                                    file_field_id = field_name_id.split('[')[0]
                                    files_with_ids.append({
                                        "field_id": file_field_id,
                                        "file_tuple": (
                                            'files',  # field name for requests
                                            (uploaded_file.name, uploaded_file.file, uploaded_file.content_type)
                                        )
                                    })
                                    # files.append(
                                    #     ('files', (uploaded_file.name,
                                    #                uploaded_file.file, uploaded_file.content_type))
                                    # )

                                dms_entries = Dms.objects.filter(
                                    organization=organization_id, flow_id=process_id) # By Harish 31.10.25
                                if not dms_entries.exists():
                                    return JsonResponse({'error': 'DMS configuration not found for the organization'},
                                                        status=status.HTTP_404_NOT_FOUND)

                                drive_types = dms_entries.first().drive_types
                                configurations = dms_entries.first().config_details_schema or {}

                                # Add drive types to the config
                                configurations['drive_types'] = drive_types
                                # only_values = [{'v': item['value']} for item in data_json] # reduce the size of the data_json
                                if isinstance(data_json, list):
                                    only_values = [{'v': item.get('value')} for item in data_json if
                                                   isinstance(item, dict) and 'value' in item]
                                else:
                                    only_values = []
                                string_only_values = json.dumps(only_values)
                                data_json_size = len(string_only_values.encode('utf-8'))
                                if data_json_size > 1900:
                                    logger.warning("data_json too large (%d bytes), trimming to empty list",
                                                   data_json_size)
                                    string_only_values = "[]"
                                # Prepare metadata
                                metadata = {
                                    'form_id': form_id_ref,
                                    'organization_id': str(organization_id),
                                    'data_json': string_only_values
                                }
                                configurations['metadata'] = json.dumps(
                                    metadata)

                                external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'

                                # for field_name, uploaded_file in request.FILES.items():
                                for file_info in files_with_ids:
                                    current_file_field_id = file_info["field_id"]  # ✅ Correct field ID
                                    field_name, (filename, fileobj, content_type) = file_info["file_tuple"]
                                    f = {
                                        field_name: (filename, fileobj, content_type)
                                    }
                                    # files = {
                                    #     'files': (uploaded_file.name, uploaded_file.file, uploaded_file.content_type)
                                    # }
                                    try:
                                        response = requests.post(
                                            external_api_url,
                                            data=configurations,
                                            files=f
                                        )
                                        response.raise_for_status()

                                        if response.status_code == 200:
                                            # responses.append(response.json())  # Store the response
                                            response_json = response.json()

                                            file_name = response_json.get(
                                                'file_name')
                                            # download_link = response_json.get('download_link')
                                            download_link = response_json.get(
                                                'download_link')

                                            file_id = response_json.get(
                                                'file', {}).get('id')
                                            if not file_id:
                                                file_id = response_json.get('file_id')

                                            download_link = response_json.get(
                                                'download_link')
                                            try:
                                                organization_instance = Organization.objects.get(
                                                    id=organization_id)
                                            except Organization.DoesNotExist:
                                                # Handle the case where the organization does not exist
                                                organization_instance = None
                                            try:
                                                dms_instance = Dms.objects.get(
                                                    id=organization_id, flow_id=process_id) # By Harish 31.10.25
                                            except Dms.DoesNotExist:
                                                # Handle the case where the dms_instance does not exist
                                                dms_instance = None
                                            print("userId Dms_data Creation -6 : ", user_data_id)
                                            try:
                                                dms_data, created = Dms_data.objects.get_or_create(
                                                    folder_id=file_id,
                                                    filename=file_name,
                                                    case_id=case,
                                                    flow_id=process_data,
                                                    dms=dms_instance,
                                                    download_link=download_link,
                                                    field_id=current_file_field_id,
                                                    user=user_data_id,
                                                    organization=organization_instance,
                                                    defaults={
                                                        'meta_data': configurations['metadata']}
                                                )

                                            except Exception as e:
                                                print(
                                                    "Error during get_or_create:", e)

                                                # Print details of integration_data to see if it is None or has unexpected # values
                                            if dms_data is None:
                                                print("dms_data is None")
                                            else:
                                                print(
                                                    f"dms_data details: {dms_data.__dict__}")

                                                # If BotData was found, update the data_schema field
                                            if not created:
                                                try:
                                                    dms_data.meta_data = dms_data
                                                    dms_data.save()  # Ensure you call save on the correct object

                                                except Exception as e:
                                                    print(
                                                        "Error during integration_data save:", e)

                                            responses.append(response_json)

                                        else:
                                            print(
                                                "Failed to Save DMS Data:", response.text)
                                            return response.append(
                                                {
                                                    "error": f"Failed to send {dms_data} . Response: {response.text}"},
                                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                                    except requests.RequestException as e:
                                        return JsonResponse(
                                            {'error': f'Error uploading file {uploaded_file.name}: {str(e)}'},
                                            status=status.HTTP_500_INTERNAL_SERVER_ERROR
                                        )

                            form_status = "In Progress"
                            caseId = case.id  # Assuming case.id is available

                            Filled_data_json = {
                                'formId': form_id_ref,
                                'processId': process_id,
                                'organization': organization_id_value,
                                'data_json': data_json,
                                'caseId': caseId,
                                'status': form_status
                            }

                            # Serialize and save the filled form data
                            serializer = FilledDataInfoSerializer(
                                data=Filled_data_json)

                            if serializer.is_valid():
                                instance = serializer.save()

                                # Prepare the response data with the filled form details
                                response_data.update({
                                    'filled_form_data': serializer.data
                                })
                                # -- working now --

                                parent_case_data = self.inject_parent_case_data(process_id,
                                                                                case_id,
                                                                                data_json)  # need to add the important case data inject function.

                                # Assign userId from request or default to 'admin' to
                                userId = request.data.get('userId', None)
                                logger.info("created_by %s", userId)
                                user = None
                                if userId:
                                    user = UserData.objects.filter(
                                        id=userId).first()  # Replace `UserData` with your user model
                                    logger.info("user %s", user)
                                if user:
                                    created_by = user.user_name
                                    logger.info("User found: %s",
                                                user.user_name)
                                else:
                                    created_by = "Admin"
                                    logger.info("User not found", "Admin")
                                # Update the case with the next step and save
                                with transaction.atomic():
                                    case_data = Case.objects.select_for_update().get(pk=case.id)
                                data_json_content = json.loads(
                                    case_data.data_json or '[]')

                                # Append next_step
                                data_json_content.append(case_data.next_step)

                                # Convert back to JSON string
                                case_data.data_json = json.dumps(
                                    data_json_content)

                                step_name = form_json_schema.form_name or 'form'
                                created_on = case.created_on

                                # Updated the case stages with process stages by Praba on 20.3.25
                                # step_id = next_step_id
                                step_id = current_step_id
                                # process_stages = {}
                                stage_name = self.get_stage_name(
                                    process_stages, step_id)
                                #                                                     step_name)
                                # Ensure user_case_history is a valid list
                                # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                                if isinstance(case_data.user_case_history, str):
                                    case_data.user_case_history = json.loads(
                                        case_data.user_case_history or "[]")
                                elif not isinstance(case_data.user_case_history, list):
                                    case_data.user_case_history = []
                                # Get updated user case history
                                new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                      stage_name)

                                # Ensure new_user_case_history is a dictionary and not a list
                                if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                                    new_user_case_history = new_user_case_history[
                                        0]  # Extract first dictionary if it's a list

                                # Append new history
                                # Ensure it's not a list
                                if isinstance(new_user_case_history, dict):
                                    case_data.user_case_history.append(
                                        new_user_case_history)
                                else:
                                    print(
                                        "Warning: new_user_case_history is not a dictionary!")

                                # Convert back to JSON string and save
                                case_data.user_case_history = json.dumps(
                                    case_data.user_case_history)
                                case_data.save()

                                # Remove the assigned user (assuming field is 'assigned_user')
                                # case_data.assigned_user = None  # or use `delattr(case_data, 'assigned_user')` if applicable
                                if case_data.assigned_users is not None:
                                    case_data.assigned_users.clear()  # Clear all assigned users
                                else:
                                    print(
                                        "Warning: assigned_user is None. Skipping clear operation.")

                                # Save the case again to reflect the change
                                case_data.save()

                                # Refresh from DB to verify changes
                                case_data.refresh_from_db()
                                logger.info("Updated Case Data: %s %s", case_data.user_case_history,
                                            case_data.assigned_users)
                                # case_data.data_json = json.dumps(
                                #     json.loads(case_data.data_json) + [case_data.next_step])

                                case_data.status = "In Progress"
                                case_data.stages = "In Progress"
                                if not isinstance(case_data.path_json, list):
                                    case_data.path_json = []
                                # Append next_step to path_json
                                case_data.path_json.append(case_data.next_step)
                                case_data.save()

                                # Assuming next_step_id is determined elsewhere
                                case_data.next_step = next_step_id
                                case_data.save()

                                # Updated the case stages with process stages by Praba on 20.3.25
                                # step_id = next_step_id
                                step_id = current_step_id
                                # process_stages = {}
                                stage_name = self.get_stage_name(
                                    process_stages, step_id)
                                case_data.status = stage_name or 'In Progress'
                                case_data.stages = stage_name or 'In Progress'
                                case_data.save()  # saving the case stages

                                # sending Mail
                                user_id_list = self.get_form_user_id_list(
                                    next_step_id, organization_id, process_id)
                                if user_id_list is not None and len(user_id_list) > 0:
                                    send_email(organization_id, user_id_list, "ACTION_TWO",
                                               {"org_id": organization_id, "case_id": case_id})

                                if next_step_id.lower() == "null" or cs_next_step == "null":
                                    case_data.status = "Completed"
                                    case_data.save()
                                    responses.append(case_data.status)
                                    #### if case completes:check all the subprocess cases and redirect it

                                    # subprocess_case_complete = self.handle_case_completion(case_data)
                                    # if subprocess_case_complete:
                                    #     print("subprocess case marked as completed.")
                                    #     url = f"{settings.BASE_URL}/process_related_cases/{case_data.parent_case.id}/"
                                    #     try:
                                    #         response = requests.get(url)
                                    #         if response.status_code == 200:
                                    #             print("Related case API response:", response.json())
                                    #         else:
                                    #             print("Related case API failed with status:", response.status_code)
                                    #     except Exception as e:
                                    #         print("Error calling related case API:", str(e))

                                    # if the case completes, it will save the case important data which is configured in process
                                    # parent_case_data = self.inject_parent_case_data(process_id,
                                    #                                                             case_id)  # need to add the important case data inject function.
                                    # logger.info(
                                    #     "parent_case_data %s", parent_case_data)
                                    print(
                                        'Sending Mail After Form Cases Completed==================')
                                    user_id_list = self.get_user_id_list(
                                        process_id)
                                    send_email(organization_id, user_id_list, "ACTION_ONE",
                                               {"org_id": organization_id, "case_id": case_id})
                                    print(
                                        'Mail are Send Success Fully ================')

                                # responses.append(response_data)


                            else:
                                # Return error response if serializer is not valid
                                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                        else:
                            # Make sure to return a response
                            return Response(response_data, status=status.HTTP_200_OK)
                    else:
                        return Response({"error": "Form schema not found."},
                                        status=status.HTTP_404_NOT_FOUND)  # Handle case when form_json_schema is not found

                elif code_block_config:
                    logger.info("Code block starts")
                    code_block_id_ref = rule_block.id
                    logger.info("code_block_id_ref: %s", code_block_id_ref)

                    code_block_input_data = rule_block.process_codeblock_schema
                    # logger.info("code_block_input_data: %s",
                    #             code_block_input_data)

                    # Step 1: Extract all field_ids from variablesList
                    field_ids = [var['field_id'] for var in code_block_input_data.get(
                        'variablesList', []) if 'field_id' in var]
                    # logger.info("field_ids: %s", field_ids)
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

                    except Exception as e:
                        logger.error(
                            f"Error filtering IntegrationDetails: {e}")
                        traceback.print_exc()

                    try:
                        filtered_bot_table = BotData.objects.filter(
                            case_id=case_id)

                    except Exception as e:
                        logger.error(f"Error filtering BotData: {e}")
                        traceback.print_exc()

                    form_user_eg_data = []

                    # Load JSON data_json
                    for form in filtered_filled_form_table:
                        try:
                            json_data = json.loads(form.data_json) if isinstance(form.data_json,
                                                                                 str) else form.data_json
                            form_user_eg_data.append(json_data)
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

                    for item in filtered_integration_details:
                        try:
                            json_data = json.loads(item.data_schema) if isinstance(item.data_schema,
                                                                                   str) else item.data_schema
                            all_data.append(json_data)
                        except Exception as e:
                            logger.error(
                                f"Error processing integration details: {e}")
                            traceback.print_exc()
                    logger.info('case Global instance started ')
                    # working -on this
                    case_global_data = case.parent_case_data or []

                    valid_case_global_data = [
                        item for item in case_global_data
                        if item.get('value') not in [None, '', [], {}, ()]
                    ]

                    all_data.append(valid_case_global_data)
                    # logger.info("all_data %s", all_data)
                    # Step 3: Flatten the data first
                    # If you're dynamically generating field_ids from all_data
                    # Normalize all_data so every element becomes a dict entry or list of dicts
                    flat_data = []
                    for entry in all_data:
                        if isinstance(entry, dict):
                            # a single dict (e.g. {'subprocess': '...'} or a field dict)
                            flat_data.append(entry)
                        elif isinstance(entry, list):
                            # extend with items (only include dict items)
                            for item in entry:
                                if isinstance(item, dict):
                                    flat_data.append(item)
                        else:
                            # ignore unexpected types (strings, None, etc.)
                            logger.debug("Ignoring non-dict/non-list entry in all_data: %r", entry)

                    # flat_data = [
                    #     item for sublist in all_data for item in sublist]
                    # field_ids = [item.get('field_id')
                    #                       for item in flat_data if 'field_id' in item]
                    field_ids = [item.get('field_id') for item in flat_data if
                                 isinstance(item, dict) and 'field_id' in item]

                    # Step 3: Extract values for the field_ids
                    extracted_values = {}
                    for field_id in field_ids:
                        for data_dict in reversed(flat_data):
                            # skip non-dict entries just in case
                            if not isinstance(data_dict, dict):
                                continue
                            if data_dict.get('field_id') == field_id:
                                extracted_values[field_id] = data_dict.get(
                                    'value')
                                break

                    logger.info("Extracted Values: %s", extracted_values)

                    # Step 4: Call the external code block API
                    try:

                        codeblock_url = f'{settings.BASE_URL}/custom_components/execute-code-block/'

                        # logger.info("INSTANCE_PARENT_CASE_ID %s", parent_case_id.id)

                        if parent_case_id:
                            parent_case_id = parent_case_id.id

                        codeblock_payload = {
                            "variablesList": code_block_input_data.get('variablesList', []),
                            "encodedScript": code_block_input_data.get('encodedScript', ''),
                            # "filledData": extracted_values
                            "organization_id": organization_id,
                            "filledData": {**extracted_values, 'INSTANCE_CASE_ID': case_id,
                                           'BASE_URL': settings.BASE_URL, 'INSTANCE_PARENT_CASE_ID': parent_case_id},
                        }

                        response = requests.post(
                            codeblock_url, json=codeblock_payload)
                        response.raise_for_status()

                    except Exception as e:
                        logger.error(f"Error calling code block API: {e}")
                        traceback.print_exc()

                    with transaction.atomic():
                        case_data = Case.objects.select_for_update().get(pk=case.id)
                    data_json_content = json.loads(
                        case_data.data_json or '[]')

                    # Append next_step
                    data_json_content.append(case_data.next_step)

                    # Convert back to JSON string
                    case_data.data_json = json.dumps(data_json_content)

                    # case_data.data_json = json.dumps(
                    #     json.loads(case_data.data_json or '[]') + [case_data.next_step])
                    case_data.status = "In Progress"
                    case_data.stages = "None"
                    if not isinstance(case_data.path_json, list):
                        case_data.path_json = []
                    # Append next_step to path_json

                    case_data.path_json.append(case_data.next_step)

                    # try:
                    #     notification = NotificationData.objects.get(mail_token_id=mail_token)
                    # except Notification.DoesNotExist:
                    #     raise ValidationError({'mail_token': 'Invalid mail token'})

                    # step_name = 'Process Block' or 'Code Block Execution'
                    created_on = case.created_on
                    userId = request.data.get('userId', None)

                    # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                    if isinstance(case_data.user_case_history, str):
                        case_data.user_case_history = json.loads(
                            case_data.user_case_history or "[]")
                    elif not isinstance(case_data.user_case_history, list):
                        case_data.user_case_history = []

                    # Updated the case stages with process stages by Praba on 20.3.25
                    # step_id = next_step_id
                    step_id = current_step_id
                    # process_stages = {}
                    stage_name = self.get_stage_name(
                        process_stages, step_id)
                    # Get updated user case history
                    new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                          stage_name)
                    #    Ensure new_user_case_history is a dictionary and not a list
                    if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                        new_user_case_history = new_user_case_history[
                            0]  # Extract first dictionary if it's a list

                    # Append new history
                    if isinstance(new_user_case_history, dict):  # Ensure it's not a list
                        case_data.user_case_history.append(
                            new_user_case_history)
                    else:
                        print(
                            "Warning: new_user_case_history is not a dictionary!")

                    # Convert back to JSON string and save
                    case_data.user_case_history = json.dumps(
                        case_data.user_case_history)
                    # Assuming next_step_id is determined elsewhere
                    case_data.next_step = next_step_id
                    case_data.save()
                    logger.info("case saved")

                    # Updated the case stages with process stages by Praba on 20.3.25
                    # step_id = next_step_id
                    step_id = current_step_id
                    # process_stages = {}
                    stage_name = self.get_stage_name(
                        process_stages, step_id)
                    case_data.status = stage_name or 'Code Block'
                    case_data.stages = stage_name or 'Code Block'
                    case_data.save()  # saving the case stages

                    # sending Mail
                    user_id_list = self.get_form_user_id_list(
                        next_step_id, organization_id, process_id)
                    if user_id_list is not None and len(user_id_list) > 0:
                        send_email(organization_id, user_id_list, "ACTION_TWO",
                                   {"org_id": organization_id, "case_id": case_id})

                    # if the case completes it will save the case important data which is configured in process
                    parent_case_data = self.inject_parent_case_data(process_id.id,
                                                                    case_id,
                                                                    data_json=[])  # need to add the important case data inject function.

                    if next_step_id.lower() == "null" or cs_next_step == "null":
                        case_data.status = "Completed"
                        case_data.save()
                        responses.append(case_data.status)
                        # if the case completes it will save the case important data which is configured in process
                        # parent_case_data = self.inject_parent_case_data(process_id,
                        #                                                 case_id)  # need to add the important case data inject function.
                        # logger.info("parent_case_data %s",
                        #             parent_case_data)
                        print(
                            'Sending Mail After Form Cases Completed==================')
                        user_id_list = self.get_user_id_list(process_id)
                        send_email(organization_id, user_id_list, "ACTION_ONE",
                                   {"org_id": organization_id, "case_id": case_id})
                        print('Mail are Send Success Fully ================')
                    # responses.append(response_data)
                    print("Returning successful response")

                    # self.handle_case_step(request=request,pk=case_id)
                    # Return the response
                    # return Response({"Message:Code Block  Executed Successfully"}, status=status.HTTP_200_OK)

                elif notification_bot:
                    print("inside notification bot")
                    mail_token = request.data.get('mail_token')

                    if mail_token:
                        try:
                            notification = NotificationData.objects.get(
                                mail_token_id=mail_token)
                        except Notification.DoesNotExist:
                            raise ValidationError(
                                {'mail_token': 'Invalid mail token'})

                        if notification.submitted:
                            raise ValidationError(
                                {'detail': 'Notification already submitted'})

                        if 'data_json' in request.data:
                            data_json = request.data.get('data_json', None)
                            # data_json_str = request.data['data_json']
                            # Flatten the data_json structure
                            # flattened_data_json = {}
                            # for file_name, content_list in data_json.items():
                            #     for index, item in enumerate(content_list, start=1):
                            #         flattened_data_json[f"{file_name}_data_{index}"] = item

                            caseId = case.id  # Assuming case.id is available

                            # Step 1: Get the existing instance
                            existing_notification = NotificationData.objects.get(
                                mail_token_id=mail_token)

                            # Step 2: Prepare the data to update
                            notification_data = {
                                # This should be formatted properly (list, dict, etc.)
                                'data_json': data_json,
                                'case_id': caseId,
                                'submitted': True,
                            }

                            # Step 3: Update the instance with the new data
                            serializer = NotificationDataSerializer(existing_notification, data=notification_data,
                                                                    partial=True)

                            if serializer.is_valid():
                                instance = serializer.save()

                                with transaction.atomic():
                                    case_data = Case.objects.select_for_update().get(pk=case.id)
                                data_json_content = json.loads(
                                    case_data.data_json or '[]')

                                # Append next_step
                                data_json_content.append(case_data.next_step)

                                # Convert back to JSON string
                                case_data.data_json = json.dumps(
                                    data_json_content)

                                # parent_case_data = self.inject_parent_case_data(process_id.id,
                                #                                                 case_id)  # need to add the important case data inject function.
                                # logger.info(
                                #     "parent_case_data %s", parent_case_data)
                                # case_data.data_json = json.dumps(
                                #     json.loads(case_data.data_json or '[]') + [case_data.next_step])
                                case_data.status = "In Progress"
                                case_data.stages = "None"
                                if not isinstance(case_data.path_json, list):
                                    case_data.path_json = []
                                # Append next_step to path_json
                                case_data.path_json.append(case_data.next_step)
                                try:
                                    notification = NotificationData.objects.get(
                                        mail_token_id=mail_token)
                                except Notification.DoesNotExist:
                                    raise ValidationError(
                                        {'mail_token': 'Invalid mail token'})

                                step_name = notification.mail_title or 'Approval Notification (Mail)'

                                # Updated the case stages with process stages by Praba on 20.3.25
                                # step_id = next_step_id
                                step_id = current_step_id
                                # process_stages = {}
                                stage_name = self.get_stage_name(
                                    process_stages, step_id)
                                created_on = case.created_on
                                userId = request.data.get('userId', None)

                                # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                                if isinstance(case_data.user_case_history, str):
                                    case_data.user_case_history = json.loads(
                                        case_data.user_case_history or "[]")
                                elif not isinstance(case_data.user_case_history, list):
                                    case_data.user_case_history = []

                                # Get updated user case history
                                new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                      stage_name)
                                #    Ensure new_user_case_history is a dictionary and not a list
                                if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                                    new_user_case_history = new_user_case_history[
                                        0]  # Extract first dictionary if it's a list

                                # Append new history
                                # Ensure it's not a list
                                if isinstance(new_user_case_history, dict):
                                    case_data.user_case_history.append(
                                        new_user_case_history)
                                else:
                                    print(
                                        "Warning: new_user_case_history is not a dictionary!")

                                    # Convert back to JSON string and save
                                case_data.user_case_history = json.dumps(
                                    case_data.user_case_history)

                                # Assuming next_step_id is determined elsewhere
                                case_data.next_step = next_step_id
                                case_data.save()

                                # Updated the case stages with process stages by Praba on 20.3.25
                                # step_id = next_step_id
                                step_id = current_step_id
                                # process_stages = {}
                                stage_name = self.get_stage_name(
                                    process_stages, step_id)
                                case_data.status = stage_name or 'Mail Approval'
                                case_data.stages = stage_name or 'Mail Approval'
                                case_data.save()  # saving the case stages

                                # sending Mail
                                user_id_list = self.get_form_user_id_list(
                                    next_step_id, organization_id, process_id)
                                if user_id_list is not None and len(user_id_list) > 0:
                                    send_email(organization_id, user_id_list, "ACTION_TWO",
                                               {"org_id": organization_id, "case_id": case_id})

                                if next_step_id.lower() == "null" or cs_next_step == "null":
                                    case_data.status = "Completed"
                                    case_data.save()
                                    responses.append(case_data.status)
                                    # if the case completes it will save the case important data which is configured in process
                                    # parent_case_data = self.inject_parent_case_data(process_id.id,
                                    #                                                 case_id)  # need to add the important case data inject function.
                                    # logger.info(
                                    #     "parent_case_data %s", parent_case_data)

                                    user_id_list = self.get_user_id_list(
                                        process_id)
                                    send_email(organization_id, user_id_list, "ACTION_ONE",
                                               {"org_id": organization_id, "case_id": case_id})

                                    return Response({"Message:Notification Mail send Successfully"},
                                                    status=status.HTTP_201_CREATED)
                                # responses.append(response_data)

                                self.handle_case_step(request, pk=case_id)

                                # self.handle_case_step(request=new_request, pk=case_id)

                            else:
                                # Return error response if serializer is not valid
                                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                        # return Response(responses, status=status.HTTP_200_OK)

                    logger.info("Notification Sends Automatically ")
                    # Convert the form UID to string

                    # Step 1: Extract all notification details
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

                    if NotificationData.objects.filter(case_id=case_id, approved_id=approved_id).exists():
                        return Response(
                            {"message": "Mail has been send already",
                             "step_type": "approve_mail",
                             "case_id": case_id,
                             "mail_title": mail_title
                             },
                            status=status.HTTP_200_OK
                        )

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

                    except Exception as e:
                        logger.error(
                            f"Error filtering IntegrationDetails: {e}")
                        traceback.print_exc()
                    try:

                        filterd_notification_table = NotificationData.objects.filter(case_id=case_id)

                    except Exception as e:
                        print(f"Error filtering NotificationData: {e}")
                        traceback.print_exc()
                    try:
                        filtered_bot_table = BotData.objects.filter(
                            case_id=case_id)

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

                    ######## added global data filter - 23.07.2025
                    logger.info('case Global instance started ')
                    # workign -on this
                    case_global_data = case.parent_case_data or []

                    valid_case_global_data = [
                        item for item in case_global_data
                        if item.get('value') not in [None, '', [], {}, ()]
                    ]

                    all_data.append(valid_case_global_data)

                    # (Optional) Gather field values for use in the mail – customize this to your use case
                    field_values = {}  # A dict like {'field1': 'value1', ...}
                    # Usually the same as mail_fields if you want to populate those
                    mail_data_ids = mail_fields
                    field_labels = {}
                    for submission in reversed(all_data):
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
                    # assuming all_data is a list containing a list of field dicts
                    #                     for submission in reversed(all_data):
                    #                         for data_item in submission:
                    #                         # for data_item in all_data[0]:
                    #                             if isinstance(data_item, dict):
                    #                                 current_field_id = data_item.get("field_id")
                    #                                 if current_field_id in mail_data_ids:
                    #                                     value = data_item.get("value")
                    #                                     label = data_item.get("label")
                    #                                     # Handle a special case like data table with a list of dicts
                    #                                     if isinstance(value, list) and all(
                    #                                             isinstance(v, dict) and "label" in v and "value" in v for v in value):
                    #                                         field_values[current_field_id] = value
                    #                                         field_labels[current_field_id] = label
                    #                                     else:
                    #                                         field_values[current_field_id] = value
                    #                                         field_labels[current_field_id] = label
                    #                         if field_values:
                    #                             break  # Stop after the first valid (latest) submission with match

                    ########## Receiver mail Extraction from filled data STARTS ###################
                    try:
                        receiver_email_extracted = self.extract_receiver_email(
                            receiver_type, receiver_mail, all_data)
                        logger.info("receiver_email_+extracted %s",
                                    receiver_email_extracted)
                    except ReceiverEmailResolutionError as e:
                        logger.error(f"Receiver email error: {e.message}")
                        return Response({"error": e.message}, status=400)
                    ########## Receiver mail Extraction from filled data ENDS ###################
                    # sending mail Subject with field_id concate with subject text
                    mail_subject = self.resolve_mail_subject(
                        mail_content, all_data)

                    logger.info('Notification started')
                    # Step 2: If type is 'notify', generate mail
                    if notification_type == "notify":
                        logging.info("Generate Notify Mail")
                        html_content = generate_notification_email_template(
                            mail_title=mail_title,
                            mail_body_text=mail_body,
                            mail_footer=mail_footer,
                            mail_data_ids=mail_data_ids,
                            field_values=field_values,
                            field_labels=field_labels,
                            primary_color=primary_color,
                            secondary_color=secondary_color,
                            url='https://example.com/approve',
                            type_=notification_type
                        )
                        logger.info("html content rendered")
                        send_notification_email(to_email=receiver_email_extracted,
                                                subject=mail_subject,
                                                html_body=html_content,
                                                organization_id=organization_id  # Make sure you pass it
                                                )
                        logger.info('Mail sent successfully')

                        with transaction.atomic():
                            case_data = Case.objects.select_for_update().get(pk=case.id)
                        data_json_content = json.loads(
                            case_data.data_json or '[]')

                        # Append next_step
                        data_json_content.append(case_data.next_step)

                        # Convert back to JSON string
                        case_data.data_json = json.dumps(data_json_content)

                        # case_data.data_json = json.dumps(
                        #     json.loads(case_data.data_json or '[]') + [case_data.next_step])
                        case_data.status = "In Progress"
                        case_data.stages = "None"
                        if not isinstance(case_data.path_json, list):
                            case_data.path_json = []
                        # Append next_step to path_json

                        case_data.path_json.append(case_data.next_step)

                        # try:
                        #     notification = NotificationData.objects.get(mail_token_id=mail_token)
                        # except Notification.DoesNotExist:
                        #     raise ValidationError({'mail_token': 'Invalid mail token'})

                        step_name = mail_title or 'Approval Notification (Mail)'
                        created_on = case.created_on
                        userId = request.data.get('userId', None)
                        # Updated the case stages with process stages by Praba on 20.3.25
                        # step_id = next_step_id
                        step_id = current_step_id
                        # process_stages = {}
                        stage_name = self.get_stage_name(
                            process_stages, step_id)
                        # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                        if isinstance(case_data.user_case_history, str):
                            case_data.user_case_history = json.loads(
                                case_data.user_case_history or "[]")
                        elif not isinstance(case_data.user_case_history, list):
                            case_data.user_case_history = []

                        # Get updated user case history
                        new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                              stage_name)
                        #    Ensure new_user_case_history is a dictionary and not a list
                        if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                            new_user_case_history = new_user_case_history[
                                0]  # Extract first dictionary if it's a list

                        # Append new history
                        if isinstance(new_user_case_history, dict):  # Ensure it's not a list
                            case_data.user_case_history.append(
                                new_user_case_history)
                        else:
                            print(
                                "Warning: new_user_case_history is not a dictionary!")

                            # Convert back to JSON string and save
                        case_data.user_case_history = json.dumps(
                            case_data.user_case_history)

                        # Assuming next_step_id is determined elsewhere
                        case_data.next_step = next_step_id
                        case_data.save()
                        logger.info("case saved")

                        # Updated the case stages with process stages by Praba on 20.3.25
                        # step_id = next_step_id
                        step_id = current_step_id
                        # process_stages = {}
                        stage_name = self.get_stage_name(
                            process_stages, step_id)
                        case_data.status = stage_name or 'Mail Approval'
                        case_data.stages = stage_name or 'Mail Approval'
                        case_data.save()  # saving the case stages
                        #

                        # sending Mail
                        user_id_list = self.get_form_user_id_list(
                            next_step_id, organization_id, process_id.id)
                        if user_id_list is not None and len(user_id_list) > 0:
                            send_email(organization_id, user_id_list, "ACTION_TWO",
                                       {"org_id": organization_id, "case_id": case_id})

                        # if the case completes it will save the case important data which is configured in process
                        # parent_case_data = self.inject_parent_case_data(process_id.id,
                        #                                                 case_id)  # need to add the important case data inject function.
                        # logger.info("parent_case_data %s",
                        #             parent_case_data)
                        if next_step_id.lower() == "null" or cs_next_step == "null":
                            case_data.status = "Completed"
                            case_data.save()
                            responses.append(case_data.status)
                            # if the case completes it will save the case important data which is configured in process
                            # parent_case_data = self.inject_parent_case_data(process_id.id,
                            #                                                 case_id)  # need to add the important case data inject function.
                            # logger.info("parent_case_data %s",
                            #             parent_case_data)
                            print(
                                'Sending Mail After Form Cases Completed==================')
                            user_id_list = self.get_user_id_list(process_id.id)
                            send_email(organization_id, user_id_list, "ACTION_ONE",
                                       {"org_id": organization_id, "case_id": case_id})
                            print('Mail are Send Success Fully ================')
                        # responses.append(response_data)
                        print("Returning successful response")
                        # Return the response
                        return Response({"Message:Notification Mail send Successfully"}, status=status.HTTP_201_CREATED)

                    elif notification_type == "approve":
                        print("Generate Approve Notification")
                        logger.info("Generate Approve Notification")
                        ######
                        case_id = case_id
                        # Usually the same as mail_fields if you want to populate those
                        mail_data_ids = mail_fields

                        # case_id = case.id
                        process_id = case.processId
                        organization_name = case.organization
                        organization_id = case.organization.id
                        # case.organization.id

                        if NotificationData.objects.filter(case_id=case_id, approved_id=approved_id).exists():
                            return Response(
                                {"message": "Mail already sent successfully"},
                                status=status.HTTP_200_OK
                            )

                        logger.info('11111111111')

                        # if case_id  and approved_id exsits
                        #      return Response({"Message:Mail Already send Successfully"}, status=status.HTTP_200_OK)
                        #
                        logger.info("all_data befor sending %s", all_data)

                        notification = self.create_notification_data(
                            case_id, mail_data_ids, all_data, mail_title, approved_id, process_id, organization_id)
                        logger.info('222 notification data is %s (type: %s)', notification, type(notification))

                        try:
                            mail_token_id = notification.mail_token_id
                        except Exception as e:
                            logger.warning("mail_token_id not found, using notification itself. Error: %s", str(e))
                            mail_token_id = notification

                        logger.info('333333333333333')
                        logger.info("mail token id", mail_token_id)  # Print generated UID

                        url = f"{settings.SITE_URL}/approve-mail/{case_id}/{mail_token_id}"
                        html_content = generate_notification_email_template(
                            mail_title=mail_title,
                            mail_body_text=mail_body,
                            mail_footer=mail_footer,
                            mail_data_ids=mail_data_ids,
                            field_values=field_values,
                            field_labels=field_labels,
                            primary_color=primary_color,
                            secondary_color=secondary_color,
                            url=url,
                            type_=notification_type
                        )
                        logger.info('Content is redy to send')
                        send_notification_email(to_email=receiver_email_extracted,
                                                subject=mail_subject,
                                                html_body=html_content,
                                                organization_id=organization_id  # Make sure you pass it
                                                )

                        logger.info('Notification Mail send Successfully')
                        print("Notification Mail send Successfully")
                        ################ changed to check next step update after approval

                        return Response({"Message:Notification Mail send Successfully"},
                                        status=status.HTTP_200_OK)  # Return the response



                elif rule:
                    logger.info("Inside rule block")

                    # Define a dictionary to map operator strings to functions
                    operator_map = {
                        '>': operator.gt,
                        '<': operator.lt,
                        '>=': operator.ge,
                        '<=': operator.le,
                        '==': operator.eq,
                        '!=': operator.ne
                    }

                    # Function to evaluate rules
                    def evaluate_rules(rules, extracted_data):
                        actions = []

                        for rule in rules:
                            source = rule['source']
                            field_id = rule['field_id']
                            op_str = rule['operator']
                            comparison_type = rule['comparison']['type']
                            comparison_value = rule['comparison']['value']
                            # value_source = rule['comparison']['value_source']
                            action = rule['comparison']['action']

                            field_value = None

                            try:
                                # Find field_value for field_id
                                for data_group in reversed(extracted_data):
                                    for field in data_group:
                                        if isinstance(field, dict) and 'field_id' in field and field[
                                            'field_id'] == field_id:
                                            field_value = field['value']
                                            break
                                        elif field_id in field:  # Handle cases where field_id is a key directly
                                            field_value = field[field_id]
                                            break

                                    if field_value is not None:
                                        break

                                if field_value is None:
                                    print(f"Field value is None for field_id: {field_id}. Skipping rule evaluation.")
                                    continue

                                print(f"Found field value: {field_value} for field_id: {field_id}")

                                # Handle comparison_value based on comparison_type
                                if comparison_type == 'field_id':
                                    comparison_field_id = comparison_value
                                    comparison_value = None

                                    for data_group in extracted_data:
                                        for field in data_group:
                                            if isinstance(field, dict) and 'field_id' in field and field[
                                                'field_id'] == comparison_field_id:
                                                comparison_value = field['value']
                                                break
                                            elif comparison_field_id in field:  # Handle cases where
                                                # comparison_field_id is a key directly
                                                comparison_value = field[comparison_field_id]
                                                break

                                        if comparison_value is not None:
                                            break

                                    if comparison_value is None:
                                        print(
                                            f"Comparison value is None for comparison_field_id: {comparison_field_id}. Skipping rule evaluation.")
                                        continue

                                    print(
                                        f"Found comparison value: {comparison_value} for comparison_field_id: {comparison_field_id}")

                                # Convert values to float for comparison
                                # Convert values for proper comparison
                                try:
                                    # Convert only if both are numeric (either int/float or numeric string)
                                    if isinstance(field_value, (int, float)) and isinstance(comparison_value,
                                                                                            (int, float)):
                                        field_value = float(field_value)
                                        comparison_value = float(comparison_value)
                                    elif isinstance(field_value, str) and field_value.replace('.', '', 1).isdigit():
                                        field_value = float(field_value)
                                    elif isinstance(comparison_value, str) and comparison_value.replace('.', '',
                                                                                                        1).isdigit():
                                        comparison_value = float(comparison_value)
                                    else:
                                        # Ensure proper string comparison
                                        field_value = str(field_value).strip()
                                        comparison_value = str(comparison_value).strip()
                                except ValueError as ve:
                                    print(f"Error converting values: {ve}")
                                    continue

                                print(
                                    f"Comparing field value: {field_value} with comparison value: {comparison_value} using operator: {op_str}")

                                # Evaluate the rule using the specified operator
                                try:
                                    if operator_map[op_str](field_value, comparison_value):
                                        actions.append(action)
                                except KeyError as ke:
                                    print(f"Unrecognized operator: {op_str}")

                            except Exception as e:
                                print(f"Error evaluating rule: {e}")
                                continue

                        return actions

                    print('--- Rule starts --- 1')
                    logger.info("Activity startsssssssssssssssssss")
                    rule_id_ref = rule_block.id

                    rule_input_data = rule_block.rule_json_schema

                    # Extract sources and value_sources into sets
                    sources = set()

                    value_sources = set()

                    for item in rule_input_data:
                        sources.add(item['source'])

                        # Check if 'comparison' exists and if 'value_source' exists within 'comparison'
                        if 'comparison' in item and 'value_source' in item['comparison']:
                            if item['comparison']['value_source']:
                                value_sources.add(item['comparison']['value_source'])

                    filterd_notification_table = []
                    if value_sources:
                        all_ids = sources.union(value_sources)
                    else:
                        all_ids = sources

                    # all_ids = sources.union(value_sources)

                    # Query all models with the single filter for all_ids and the additional case_id filter
                    try:
                        filtered_filled_form_table = FilledFormData.objects.filter(formId__in=all_ids, caseId=case_id)
                    except Exception as e:
                        print(f"Error filtering FilledFormData: {e}")
                        traceback.print_exc()

                    try:
                        filterd_notification_table = NotificationData.objects.filter(case_id=case_id)
                    except Exception as e:
                        print(f"Error filtering NotificationData: {e}")
                        traceback.print_exc()

                    try:
                        filtered_integration_details = IntegrationDetails.objects.filter(
                            integration__Integration_uid__in=all_ids, case_id=case_id)
                    except Exception as e:
                        print(f"Error filtering IntegrationDetails: {e}")
                        traceback.print_exc()

                    try:
                        filtered_bot_table = BotData.objects.filter(bot__bot_uid__in=all_ids, case_id=case_id)
                    except Exception as e:
                        print(f"Error filtering BotData: {e}")
                        traceback.print_exc()

                    # try:
                    #     filtered_rule_table = Rule.objects.filter(ruleId__in=all_ids, case_id=case_id)
                    # except Exception as e:
                    #     print(f"Error filtering Rule: {e}")
                    #     traceback.print_exc()

                    # Print results

                    # Extract data from all relevant tables
                    extracted_data = []

                    # Extract the data JSON from the filtered queryset
                    for form in filtered_filled_form_table:
                        try:
                            extracted_data.append(
                                json.loads(form.data_json) if isinstance(form.data_json, str) else form.data_json)
                        except Exception as e:
                            print(f"Error processing filled form data: {e}")
                            traceback.print_exc()
                    print("extracted_data", extracted_data)

                    for notification in filterd_notification_table:
                        try:
                            extracted_data.append(
                                json.loads(notification.data_json) if isinstance(notification.data_json,
                                                                                 str) else notification.data_json)
                        except Exception as e:
                            print(f"Error processing notification data: {e}")
                            traceback.print_exc()

                    for item in filtered_bot_table:
                        try:
                            extracted_data.append(
                                json.loads(item.data_schema) if isinstance(item.data_schema, str) else item.data_schema)
                        except Exception as e:
                            print(f"Error processing bot data: {e}")
                            traceback.print_exc()

                    for item in filtered_integration_details:
                        try:
                            extracted_data.append(
                                json.loads(item.data_schema) if isinstance(item.data_schema, str) else item.data_schema)
                        except Exception as e:
                            print(f"Error processing integration details: {e}")
                            traceback.print_exc()

                    logger.info('case Global instance started ')
                    # working -on this
                    case_global_data = case.parent_case_data or []

                    valid_case_global_data = [
                        item for item in case_global_data
                        if item.get('value') not in [None, '', [], {}, ()]
                    ]

                    extracted_data.append(valid_case_global_data)
                    # updated_data = extracted_data + valid_case_global_data
                    try:
                        actions = evaluate_rules(rule_input_data, extracted_data)
                        # Print the actions to be taken
                        logger.info("Actions to be taken %s:", actions)
                        if actions == [None] or not actions:  # if action is None
                            cs_next_step = "null"
                        final_flow_key = []
                        final_flow_start = []
                        if actions:
                            next_step_id = actions[0]  # Assuming the first action is the next step

                            final_flow_start = []
                            final_flow_key = []

                            # Initialize variables for case update
                            cs_next_step = None

                            # Check for next_step_id in participants_data["executionFlow"]
                            if next_step_id in participants_data["executionFlow"]:
                                flow = participants_data["executionFlow"][next_step_id]

                                # Iterate over the flows and find matches
                                for flow_item in flows:
                                    if flow_item['start'] == flow['currentStepId'] or flow_item['end'] == flow[
                                        'nextStepId']:
                                        print(f"Processing flow: {flow_item}")
                                        start = flow_item['start']

                                        end = flow_item['end']

                                        # Update the end key with the nextStepId
                                        flow_item['end'] = flow['nextStepId']

                                        # Set the case_next_step to the updated end value
                                        cs_next_step = flow_item['end']
                                        cs_current_step = flow_item['start']

                                cs_current_step = None
                                if cs_next_step:
                                    # Update the case with the next step and save
                                    with transaction.atomic():
                                        case_instance = Case.objects.select_for_update().get(pk=case.id)
                                    case_instance.nextstep = cs_next_step  # Update with the new end value

                                    ##### Updated the case stages with process stages by Praba on 20.3.25
                                    # step_id = next_step_id
                                    # step_id = current_step_id
                                    step_id = cs_next_step
                                    process_stages = process_data.process_stages or {}
                                    # process_stages = {}
                                    stage_name = self.get_stage_name(process_stages, step_id)
                                    case_instance.status = stage_name or 'In Progress'
                                    case_instance.stages = stage_name or 'In Progress'
                                    case_instance.save()  # saving the case stages

                                    # Ensure user_case_history is a valid list
                                    if isinstance(case_instance.user_case_history, str):
                                        case_instance.user_case_history = json.loads(
                                            case_instance.user_case_history or "[]")
                                    elif not isinstance(case_instance.user_case_history, list):
                                        case_instance.user_case_history = []
                                    # case_instance.user_case_history = json.loads(case_instance.user_case_history or "[]")
                                    # Get updated user case history
                                    userId = None
                                    # userId = request.data.get('userId', '')
                                    # step_name = "Rule"
                                    created_on = case_instance.updated_on
                                    new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                          stage_name)
                                    #    Ensure new_user_case_history is a dictionary and not a list
                                    if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                                        new_user_case_history = new_user_case_history[
                                            0]  # Extract first dictionary if it's a list

                                    # Append new history
                                    if isinstance(new_user_case_history, dict):  # Ensure it's not a list
                                        case_instance.user_case_history.append(new_user_case_history)
                                    else:
                                        logger.info("Warning: new_user_case_history is not a dictionary!")

                                    # Convert back to JSON string and save
                                    case_instance.user_case_history = json.dumps(case_instance.user_case_history)

                                    case_instance.save()

                            else:
                                print(f"No matching flow found for next_step_id: {next_step_id}")

                        else:
                            return responses.append({"error": f"No actions found for rule {rule.ruleId}"},
                                                    status=status.HTTP_400_BAD_REQUEST)
                    except Exception as e:
                        print("An error occurred:", e)

                # id the stepid is OCR

                elif ocr:
                    print('--- OCR starts --- 1')

                    ocr_id_ref = str(ocr.ocr_uid)
                    print("ocr_id_ref:", ocr_id_ref)
                    try:
                        ocr_details = Ocr.objects.get(ocr_uid=ocr_id_ref)
                        print("ocr_details:", ocr_details.ocr_type)
                    except Ocr.DoesNotExist:
                        ocr_details = None
                    if isinstance(process_data, CreateProcess):
                        process_id = process_data.id
                        print("Extracted process_id:", process_id)
                    else:
                        print("process_data is not an instance of CreateProcess")
                    # try:
                    #     ocr_schema = Ocr.objects.get(Form_uid=ocr_id_ref)
                    #     print("ocr_schema:", ocr_schema)
                    # except FormDataInfo.DoesNotExist:
                    #     form_json_schema = None

                    if 'data_json' in request.data:
                        print("^^^^^^^^^^^^^^^^^^^^^", request.data)
                        data_json = request.data.get('data_json', None)
                        # data_json_str = request.data['data_json']
                        print("data_json_str", data_json)
                        # Flatten the data_json structure
                        flattened_data_json = {}
                        for file_name, content_list in data_json.items():
                            for index, item in enumerate(content_list, start=1):
                                flattened_data_json[f"{file_name}_data_{index}"] = item

                        caseId = case.id  # Assuming case.id is available

                        process_id = process_data.id  # Assuming process_data.id is available

                        organization_id = organization_id

                        filled_ocr_data = {
                            'ocr_uid': ocr_id_ref,
                            'flow_id': process_id,
                            'organization': organization_id,
                            'data_schema': data_json,  # JSON list (need to change)
                            'case_id': caseId,
                        }

                        # Serialize and save the filled form data
                        serializer = Ocr_DetailsSerializer(data=filled_ocr_data)

                        if serializer.is_valid():
                            instance = serializer.save()
                            print("Serializer data is valid:", serializer.validated_data)
                            with transaction.atomic():
                                case_data = Case.objects.select_for_update().get(pk=case.id)
                            data_json_content = json.loads(case_data.data_json or '[]')

                            # Append next_step
                            data_json_content.append(case_data.next_step)

                            # Convert back to JSON string
                            case_data.data_json = json.dumps(data_json_content)
                            # case_data.data_json = json.dumps(
                            #     json.loads(case_data.data_json or '[]') + [case_data.next_step])
                            case_data.status = "In Progress"
                            case_data.stages = "In Progress"
                            if not isinstance(case_data.path_json, list):
                                case_data.path_json = []
                            # Append next_step to path_json
                            case_data.path_json.append(case_data.next_step)

                            step_name = ocr_details.ocr_type or 'OCR'
                            created_on = case.created_on
                            userId = request.data.get('userId', None)
                            ##### Updated the case stages with process stages by Praba on 20.3.25
                            # step_id = next_step_id
                            step_id = current_step_id
                            # process_stages = {}
                            stage_name = self.get_stage_name(process_stages, step_id)
                            # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                            if isinstance(case_data.user_case_history, str):
                                case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                            elif not isinstance(case_data.user_case_history, list):
                                case_data.user_case_history = []

                            # Get updated user case history
                            new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                                  stage_name)
                            #    Ensure new_user_case_history is a dictionary and not a list
                            if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                                new_user_case_history = new_user_case_history[
                                    0]  # Extract first dictionary if it's a list

                            # Append new history
                            if isinstance(new_user_case_history, dict):  # Ensure it's not a list
                                case_data.user_case_history.append(new_user_case_history)
                            else:
                                print("Warning: new_user_case_history is not a dictionary!")

                                # Convert back to JSON string and save
                            case_data.user_case_history = json.dumps(case_data.user_case_history)

                            case_data.next_step = next_step_id  # Assuming next_step_id is determined elsewhere
                            case_data.save()

                            ##### Updated the case stages with process stages by Praba on 20.3.25
                            # step_id = next_step_id
                            step_id = current_step_id
                            # process_stages = {}
                            stage_name = self.get_stage_name(process_stages, step_id)
                            case_data.status = stage_name or 'In Progress'
                            case_data.stages = stage_name or 'In Progress'
                            case_data.save()  # saving the case stages
                            print("************", stage_name)  #

                            # sending Mail
                            user_id_list = self.get_form_user_id_list(next_step_id, organization_id, process_id)
                            if user_id_list is not None and len(user_id_list) > 0:
                                send_email(organization_id, user_id_list, "ACTION_TWO",
                                           {"org_id": organization_id, "case_id": case_id})

                            print("next_step_idiiiiiiiiiiiiii in OCR ", next_step_id)
                            if next_step_id.lower() == "null" or cs_next_step == "null":
                                case_data.status = "Completed"
                                case_data.save()
                                responses.append(case_data.status)
                                #### if the case completes it will save the case important data which is configured in process
                                # parent_case_data = self.inject_parent_case_data(process_id,
                                #                                                                 case_id)  ########## need to add the important case data inject function.
                                # logger.info("parent_case_data %s", parent_case_data)
                                # print('Sending Mail After Form Cases Completed==================')
                                user_id_list = self.get_user_id_list(process_id)
                                send_email(organization_id, user_id_list, "ACTION_ONE",
                                           {"org_id": organization_id, "case_id": case_id})
                                print('Mail are Send Success Fully ================')
                            # responses.append(response_data)
                            print("Returning successful response")

                        else:
                            # Return error response if serializer is not valid
                            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

                    if ocr_details:

                        return self.get(request, organization_id, process_id, pk)

                    else:
                        return Response({"error": "Ocr Details not found."},
                                        status=status.HTTP_404_NOT_FOUND)  # Handle case when form_json_schema is not found





                elif is_sla:
                    logger.info("--- SLA starts ---")
                    try:
                        sla_id_ref = is_sla.id
                        sla_input_schema = is_sla.sla_json_schema
                        with transaction.atomic():
                            case_data = Case.objects.select_for_update().get(pk=case.id)

                        for condition in sla_input_schema:
                            try:
                                sla_type = condition.get("sla_type")
                                comparison = condition.get("comparison", {})
                                offset_type = comparison.get("offset_type")
                                offset_value = comparison.get("value")
                                action = comparison.get("action")
                                logger.debug(
                                    f"SLA Type: {sla_type}, Action: {action}, Offset Type: {offset_type}, Value: {offset_value}")
                                if sla_type == 'regular_step':
                                    case_data.next_step = action
                                    case_data.save()
                                    logger.info(f"Case {case.id} moved to next step: {action} by SLA rule.")

                                    try:
                                        sla_instance = SlaCaseInstance.objects.get(case_id=case.id, sla_id=is_sla.id,
                                                                                   is_completed=False)
                                        sla_instance.is_completed = True
                                        sla_instance.save()
                                        logger.info(
                                            f"SlaCaseInstance marked as completed for case {case.id} and SLA {is_sla.id}")
                                    except SlaCaseInstance.DoesNotExist:
                                        logger.warning(
                                            f"SlaCaseInstance not found for case {case.id} and SLA {is_sla.id}")

                                    return self.get(request, organization_id, process_id.id, pk)
                                # Add more SLA type handling here if needed:




                            except Exception as inner_e:
                                msg = f"Error evaluating SLA condition: {str(inner_e)}"
                                logger.error(msg)
                    except Exception as outer_e:
                        logger.error("Failed processing SLA logic: %s", str(outer_e))

                step_id_stages = steps[current_step_id]['nextStepId']
                logger.info("step_id_stages %s", step_id_stages)
                current_step_id = cs_next_step

                # Update the case data
                case_data = Case.objects.get(pk=pk)
                case_data.data_json = json.dumps(json.loads(case_data.data_json) + [case_data.next_step])

                case_data.status = 'In Progress'
                case_data.stages = 'In Progress'
                if not isinstance(case_data.path_json, list):
                    case_data.path_json = []
                # Append next_step to path_json
                case_data.path_json.append(case_data.next_step)

                bot_name = bot.bot_name if bot else ''  # Default if bot not found
                logger.info("bot_name %s", bot_name)

                if bot_name:
                    if isinstance(case_data.user_case_history, str):
                        case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                    elif not isinstance(case_data.user_case_history, list):
                        case_data.user_case_history = []
                    # case_data.user_case_history = json.loads(case_data.user_case_history or "[]")
                    # Get updated user case history
                    # step_id = current_step_id
                    step_id = step_id_stages
                    # process_stages = {}
                    stage_name = self.get_stage_name(process_stages, step_id)
                    userId = None
                    step_name = bot_name
                    created_on = case_data.updated_on
                    new_user_case_history = self.update_user_case_history(userId, created_on,
                                                                          stage_name)

                    #    Ensure new_user_case_history is a dictionary and not a list
                    if isinstance(new_user_case_history, list) and len(new_user_case_history) > 0:
                        new_user_case_history = new_user_case_history[
                            0]  # Extract first dictionary if it's a list

                    # Append new history
                    if isinstance(new_user_case_history, dict):  # Ensure it's not a list
                        case_data.user_case_history.append(new_user_case_history)
                    else:
                        print("Warning: new_user_case_history is not a dictionary!")

                    # Convert back to JSON string and save

                    case_data.user_case_history = json.dumps(case_data.user_case_history)
                    case_data.save()

                if current_step_id in [None, "None"]:
                    case_data.next_step = "null"
                    current_step_id = "null"
                    case_data.status = "Completed"
                    case_data.save()
                else:
                    case_data.next_step = current_step_id
                    case_data.save()
                # case_data.next_step = current_step_id
                # case_data.next_step = case_next_step
                case_data.save()

                ##### Updated the case stages with process stages by Praba on 20.3.25
                # step_id = current_step_id
                # # step_id = step_id_stages
                # # process_stages = {}
                # process_stages = process_data.process_stages or {}
                # stage_name = self.get_stage_name(process_stages, step_id)
                # case_data.status = stage_name or 'In Progress'
                # case_data.stages = stage_name or 'In Progress'
                # case_data.save()  # saving the case stage
                # # Check the end form id
                # print("stage_name at the end",stage_name)

                end_element_config = None
                end_element = EndElement.objects.filter(element_uid=current_step_id).first() or ''
                if end_element:
                    element_uid = end_element.element_uid
                    end_element_config = end_element
                    # -------- Auto update case as Completed or configured status --------
                    try:
                        with transaction.atomic():
                            case_data = Case.objects.select_for_update().get(pk=case.id)
                            # Fetch the end element schema details
                            configured_status = end_element_config.element_name or "Completed"
                            end_element_schema_data = end_element_config.end_element_schema
                            # Update case
                            case_data.status = "Completed"
                            case_data.stages = configured_status

                            case_data.save()
                            self.inject_parent_case_data(process_id.id, case_id, data_json=[])
                            return Response({"message": "Case marked as Completed"}, status=200)


                    except Exception as e:
                        logger.error(f"Error completing case: {e}")
                    #### if the case completes, it will save the case important data which is configured in process
                    parent_case_data = self.inject_parent_case_data(process_id.id, case_id,
                                                                    data_json=[])  ########## need to add the important case data inject function.

                if current_step_id == "null" or cs_next_step == "null":
                    case_data.status = "Completed"
                    case_data.save()
                    responses.append(case_data.status)
                    #### if the case completes, it will save the case important data which is configured in process
                    # parent_case_data = self.inject_parent_case_data(process_id.id,case_id)  ########## need to add the important case data inject function.

                    print('Sending Mail After Form Cases Completed==================')
                    # Send Mail Services Function Calling
                    user_id_list = self.get_user_id_list(process_id.id)
                    send_email(organization_id, user_id_list, "ACTION_ONE",
                               {"org_id": organization_id, "case_id": case_id})
                    print('Mail are Send Success Fully ================')

                    # break
                else:
                    # Find the next flow starting from the end of the current flow
                    final_flow_start = []
                    final_flow_key = []
                    for flow in flows:
                        for flow_key, flow_value in participants_data["executionFlow"].items():
                            print(f"Processing flow: {flow_key}:{flow_value}")
                            # for flow_key, flow_value in process_flow.items():
                            start = flow['start']
                            end = flow['end']
                            if isinstance(flow_value, dict) and flow_value.get('currentStepId') == flow['end']:
                                start_form_id = flow_value.get('currentStepId')
                                if start_form_id:
                                    final_flow_start.append(start_form_id)
                                    final_flow_key.append(flow_key)
                    if final_flow_start:
                        case_data.next_step = final_flow_start[0]

                        ############### working
                        # step_id = current_step_id
                        # step_id = step_id_stages
                        step_id = case_data.next_step
                        # process_stages = {}
                        process_stages = process_data.process_stages or {}
                        stage_name = self.get_stage_name(process_stages, step_id)
                        case_data.status = stage_name or 'In Progress'
                        case_data.stages = stage_name or 'In Progress'
                        case_data.save()  # saving the case stage
                        # Check the end form id
                        print("stage_name at the end", stage_name)

                    else:
                        return Response({"message": "No next flow found for the end flow"},
                                        status=status.HTTP_400_BAD_REQUEST)
                    case_data.save()
                    if next_step_id:
                        cleaned_data = request.data.copy()
                        cleaned_data.pop('data_json', None)
                        cleaned_data.pop('from_mail_flag', None)
                        cleaned_data.pop('from_mail', None)
                        new_request = Request(request._request)
                        new_request._full_data = cleaned_data

                        return self.handle_case_step(new_request, case_id, parent_case_id=parent_case_id)
                    else:
                        return Response(responses, status=status.HTTP_200_OK)
                    # break
                # return Response({"message": "Form schema saved successfully"}, status=status.HTTP_201_CREATED)

                return Response({"message": "Process executed successfully", "responses": responses},
                                status=status.HTTP_200_OK)
            return None
        except Case.DoesNotExist:
            return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            responses.append({"error": f"Exception occurred while executing step {current_step_id}: {str(e)}"})
            return Response(responses, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # return Response(responses, status=status.HTTP_200_OK)
        # except Case.DoesNotExist:
        #     return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)
        # except FormDataInfo.DoesNotExist:
        #     return Response({"error": "Form schema not found"}, status=status.HTTP_404_NOT_FOUND)
        # except Exception as e:
        #     return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


######################## Form Proceed Dunctionality Starts ##########################
def proceed_form_view(request, token):
    data = verify_secure_token(token)
    if not data:
        return HttpResponseBadRequest("Invalid or expired link.")

    organization_id, process_id, case_id = data.split(":")
    # Construct frontend redirect URL using SITE_URL
    redirect_url = f"{settings.SITE_URL}/form-view/{organization_id}/{process_id}/{case_id}"
    # Optional: mark the token as used (e.g., store in DB with timestamp)
    # Redirect to frontend/form with data
    return HttpResponseRedirect(redirect_url)


class FormMailSubmitView(APIView):

    def post(self, request, org_id, process_id, case_id, token, form_uid):
        try:
            # Step 1: Get Case
            case = Case.objects.get(id=case_id, organization=org_id, processId=process_id)

            # Step 2: Get expected form (e.g., next_step)
            expected_step_id = case.next_step  #
            if expected_step_id != form_uid:
                return Response({"error": "Form already submitted or step mismatch"},
                                status=status.HTTP_400_BAD_REQUEST)
                # Step 4: Call the method from another class
            case_handler = CaseRelatedFormView()
            response = case_handler.post(request, case_id)
            return response

            # return Response({"message": "Form submitted and step handled"}, status=status.HTTP_200_OK)

        except Case.DoesNotExist:
            return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            # Step 4: Call case handling function

    def get(self, request, org_id, process_id, case_id, token, form_uid):
        try:
            # Step 1: Get Case
            case = Case.objects.get(id=case_id, organization=org_id, processId=process_id)

            # Step 2: Get expected form (e.g., next_step)
            expected_step_id = case.next_step  #
            if expected_step_id != form_uid:
                return Response({"error": "Form already submitted or step mismatch"},
                                status=status.HTTP_400_BAD_REQUEST)
                # Step 4: Call the method from another class
            case_handler = CaseRelatedFormView()
            response = case_handler.get(request, org_id, process_id, case_id)

            return response


        except Case.DoesNotExist:
            return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            # Step 4: Call case handling function


############ execution flow modified according to case[ends] by Praba
# added by laxmi mam
### case_id and mailtoken and data_json,submitted -True- send - post method
############################## Mail Approve method for Notification Approve #####################
class ApproveMailView(APIView):
    def get(self, request, case_id, mail_token_id):
        try:
            notification = NotificationData.objects.get(case_id=case_id, mail_token_id=mail_token_id)
            # notification.submitted = True
            # notification.save()

            return Response({
                # "message": "Mail approved successfully",
                "case_id": case_id,
                "mail_token_id": str(mail_token_id),
                "mail_data": notification.mail_data,  # Include mail_data here,
                "submitted": notification.submitted,
                "mail_title": notification.mail_title,
                "approved_id": notification.approved_id
            }, status=status.HTTP_200_OK)

        except NotificationData.DoesNotExist:
            return Response({
                "error": "Invalid case_id or mail_token_id"
            }, status=status.HTTP_404_NOT_FOUND)


########################## API to update tha Case global Data ################################

class UpdateCaseGlobalDataView(APIView):
    def post(self, request):
        case_id = request.GET.get('case_id')
        if not case_id:
            return Response({'error': 'Missing case_id'}, status=400)

        try:
            case_id = int(case_id)
        except ValueError:
            return Response({'error': 'Invalid case_id'}, status=400)

        case = get_object_or_404(Case, id=case_id)

        global_case_data = request.data.get('data_json', [])
        if not isinstance(global_case_data, list):
            return Response({"error": "data_json must be a list."}, status=status.HTTP_400_BAD_REQUEST)

        existing_data = case.parent_case_data or []

        # Create a lookup for field_id → index in the list
        field_id_index_map = {item['field_id']: idx for idx, item in enumerate(existing_data) if 'field_id' in item}
        for new_item in global_case_data:
            field_id = new_item.get('field_id')
            new_value = new_item.get('value')
            if field_id in field_id_index_map:
                # Only update the value of existing item
                existing_data[field_id_index_map[field_id]]['value'] = new_value
            else:
                # Append the full new item
                existing_data.append(new_item)

        case.parent_case_data = existing_data
        case.save()

        return Response({"message": "global_case_data updated successfully."}, status=status.HTTP_200_OK)


####################### Case Assignment for User Starts ################################


@api_view(['POST'])
def assign_case_to_users(request, process_id, case_id):
    """
    API to assign a case to multiple users.

    URL Parameters:
    - process_id: ID of the process
    - case_id: ID of the case

    """
    try:
        case = Case.objects.get(id=case_id)  # Get the case object

        if request.method == 'GET':
            # Fetch assigned users for the case
            assigned_users = case.assigned_users.all()
            serialized_users = UserDataSerializer(assigned_users, many=True).data

            return Response({
                "case_id": case.id,
                "process_id": case.processId.id if case.processId else None,
                "org_code": case.organization.org_code if case.organization else None,
                "assigned_users": list(assigned_users.values_list('id', flat=True)),
                "assigned_user_info": serialized_users
            }, status=status.HTTP_200_OK)
        elif request.method == 'POST':
            process_id = case.processId.id

            org_code = case.organization.org_code

            assigned_user_ids = request.data.get('assigned_users', [])  # Extract user IDs from request
            print("assigned_user_ids", assigned_user_ids)
            if assigned_user_ids:
                users = UserData.objects.filter(id__in=assigned_user_ids)  # Fetch assigned users

                #### I need to send, org_id,process_id,case_id,user id,user mail id
                if not users.exists():
                    return Response({"error": "No valid users found"}, status=status.HTTP_400_BAD_REQUEST)

                case.assigned_users.set(users)  # Assign users to the case

                message = "Users assigned successfully"
            else:
                case.assigned_users.clear()  # Clear all assigned users
                message = "All users unassigned successfully"

            case.save()
            all_users_serialized = UserDataSerializer(case.assigned_users.all(), many=True).data
            organization_id = case.organization.id

            send_email(organization_id, assigned_user_ids, "ACTION_THREE",
                       {"org_id": organization_id, "case_id": case.id})

            # need to add process id under case_id
            # need to add organization code under case_id

            return Response(
                {
                    "case_id": case.id,
                    "process_id": process_id,
                    "org_code": org_code,
                    "assigned_users": list(case.assigned_users.values_list('id', flat=True)),  # Only assigned user IDs,
                    "assigned_user_info": all_users_serialized,
                    "message": "Users assigned successfully"
                },
                status=status.HTTP_200_OK
            )


    except Case.DoesNotExist:
        return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)

    # Fallback for unsupported methods (should never reach here with @api_view)
    return Response({"error": "Method not allowed"}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


####################### Case Assignment for User Ends ################################

###################### Getting case related comments [STARTS]####################################
@api_view(['GET'])
def get_case_comments(request, process_id, case_id):
    """
    API to get case_data_comments based on case_id and process_id
    """
    try:
        case = Case.objects.get(id=case_id, processId__id=process_id)

        return Response({
            "case_id": case.id,
            "process_id": case.processId.id if case.processId else None,
            "case_data_comments": case.case_data_comments or ""
        }, status=status.HTTP_200_OK)

    except Case.DoesNotExist:
        return Response(
            {"error": "Case comments not found for the given process_id and case_id"},
            status=status.HTTP_404_NOT_FOUND
        )


###################### Getting case related comments [Ends]####################################

##################### Getting case user history[Starts] ##############################################

@api_view(['GET'])
def get_user_case_history(request, process_id, case_id):
    """
    API to get case_data_comments based on case_id and process_id
    """
    try:
        case = Case.objects.get(id=case_id, processId__id=process_id)

        return Response({
            "case_id": case.id,
            "process_id": case.processId.id if case.processId else None,
            "user_case_history": case.user_case_history or None
        }, status=status.HTTP_200_OK)

    except Case.DoesNotExist:
        return Response(
            {"error": "Case history not found for the given process_id and case_id"},
            status=status.HTTP_404_NOT_FOUND
        )


##################### Getting case user history[Ends] ##############################################


################# userfilleddata based on organization and process starts ###################################
from django.db.models import Count, Q


class OrganizationCasesView(APIView):
    def get(self, request, organization_id):
        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            return Response({'error': 'Organization not found'}, status=404)

        try:
            # load all cases for org (keep original serializer usage for compatibility)
            cases_qs = Case.objects.filter(organization=organization)
            case_serializer = CaseSerializer(cases_qs, many=True)
            serialized_data = case_serializer.data

            # aggregated counts in one shot
            counts = cases_qs.aggregate(
                total_cases=Count('id'),
                completed_cases=Count('id', filter=Q(status='Completed')),
                inprogress_cases=Count('id', filter=Q(status='In Progress'))
            )

            # Collect unique identifiers needed for bulk loads
            data_json_ids_needed = set()
            next_steps = set()
            process_ids = set()

            def parse_first_data_json_id(raw):
                """Return first integer id from a string like '[12,34]' or None"""
                if not raw:
                    return None
                try:
                    parts = [p.strip() for p in raw.strip("[]").split(",")]
                    for p in parts:
                        if p.isdigit():
                            return int(p)
                except Exception:
                    return None
                return None

            for item in serialized_data:
                dj_raw = item.get('data_json')
                first_id = parse_first_data_json_id(dj_raw)
                if first_id:
                    data_json_ids_needed.add(first_id)

                ns = item.get('next_step')
                if ns:
                    next_steps.add(ns)

                pid = item.get('processId')
                # keep processId as whatever it is (int/string). Try int conversion for mapping keys.
                try:
                    pid_int = int(pid) if pid is not None else None
                except Exception:
                    pid_int = pid
                if pid_int is not None:
                    process_ids.add(pid_int)

            # Bulk load FilledFormData and pre-serialize their 'data_json' using your serializer
            filled_forms_qs = FilledFormData.objects.filter(pk__in=data_json_ids_needed)
            filled_form_map = {}
            for ff in filled_forms_qs:
                dt = FilledDataInfoSerializer(ff).data
                filled_form_map[ff.pk] = dt.get('data_json', None)

            # Bulk fetch FormDataInfo for next_steps (Form_uid) and map by Form_uid
            form_schemas_qs = FormDataInfo.objects.filter(Form_uid__in=next_steps, organization=organization_id)
            form_schema_by_uid = {fs.Form_uid: fs for fs in form_schemas_qs}

            # Bulk fetch form permissions for those forms, grouped by form id
            form_permissions_qs = FormPermission.objects.filter(form__in=form_schemas_qs).values(
                'form_id', 'user_group__id', 'read', 'write', 'edit'
            )
            form_permissions_map = {}
            for perm in form_permissions_qs:
                fid = perm['form_id']
                form_permissions_map.setdefault(fid, []).append({
                    'user_group__id': perm['user_group__id'],
                    'read': perm['read'],
                    'write': perm['write'],
                    'edit': perm['edit']
                })

            # Bulk fetch CreateProcess -> process_user_groups (id -> [user_group_ids])
            process_user_group_qs = CreateProcess.objects.filter(id__in=process_ids).values_list('id', 'user_group__id')
            process_user_groups_map = {}
            for pid, ugid in process_user_group_qs:
                process_user_groups_map.setdefault(pid, []).append(ugid)

            # Bulk fetch subprocess CreateProcess (subprocess_UID -> instance)
            subprocess_qs = CreateProcess.objects.filter(subprocess_UID__in=next_steps, organization=organization_id)
            subprocess_map = {sp.subprocess_UID: sp for sp in subprocess_qs}

            # Bulk fetch NotificationBotSchema (notification_uid -> instance)
            notification_qs = NotificationBotSchema.objects.filter(notification_uid__in=next_steps)
            notification_map = {n.notification_uid: n for n in notification_qs}

            # Bulk fetch Bots and BotSchema (bot_uid and (bot_uid, flow_id))
            bots_qs = Bot.objects.filter(bot_uid__in=next_steps)
            bots_map = {b.bot_uid: b for b in bots_qs}
            bot_schemas_qs = BotSchema.objects.filter(bot__in=bots_qs, organization=organization_id,
                                                      flow_id__in=process_ids)
            bot_schema_map = {}
            for bs in bot_schemas_qs:
                bot_schema_map[(bs.bot.bot_uid, bs.flow_id)] = bs

            # Bulk fetch EndElement (element_uid -> instance)
            end_elem_qs = EndElement.objects.filter(element_uid__in=next_steps)
            end_elem_map = {ee.element_uid: ee for ee in end_elem_qs}

            # Now one-pass through serialized_data and enrich using maps (no DB hits inside loop)
            for data_item in serialized_data:
                # ---- case_initiated_by ----
                user_case_history = data_item.get('user_case_history')
                case_initiated_by = None
                try:
                    history = json.loads(user_case_history) if user_case_history else []
                    first = history[0] if isinstance(history, list) and history else {}
                    user_id = first.get('userId') if isinstance(first, dict) else None
                    case_initiated_by = int(user_id) if user_id is not None else None
                except (json.JSONDecodeError, ValueError, TypeError):
                    case_initiated_by = None
                data_item['case_initiated_by'] = case_initiated_by

                # ---- data_json replaced with actual filled form data_json ----
                raw_data_json = data_item.get('data_json')
                data_json_id = parse_first_data_json_id(raw_data_json)
                data_item['data_json'] = filled_form_map.get(data_json_id, None)

                # ---- process_user_groups ----
                procId = data_item.get('processId')
                try:
                    procId_int = int(procId) if procId is not None else None
                except Exception:
                    procId_int = procId
                data_item['process_user_groups'] = process_user_groups_map.get(procId_int, [])

                # ---- permissions/form_filter_schema resolution (priority preserved) ----
                next_step = data_item.get('next_step')

                # sensible defaults
                data_item['permissions'] = []
                data_item['form_filter_schema'] = None
                data_item['next_step_schema'] = None

                if next_step:
                    # 1) FormDataInfo (form schema + permissions)
                    fs = form_schema_by_uid.get(next_step)
                    if fs:
                        data_item['next_step_schema'] = getattr(fs, 'form_json_schema', None)
                        data_item['form_filter_schema'] = getattr(fs, 'form_filter_schema', None)
                        perms = form_permissions_map.get(fs.id, [])
                        data_item['permissions'] = perms if perms else []

                    # 2) subprocess CreateProcess override
                    sp = subprocess_map.get(next_step)
                    if sp:
                        table_permissions = getattr(sp, 'process_table_permission', []) or []
                        data_item['permissions'] = table_permissions
                        data_item['form_filter_schema'] = table_permissions

                    # 3) NotificationBotSchema override
                    notif = notification_map.get(next_step)
                    if notif:
                        table_permissions = getattr(notif, 'notification_element_permission', []) or []
                        data_item['permissions'] = table_permissions
                        data_item['form_filter_schema'] = table_permissions

                    # 4) Bot + BotSchema override (use (bot_uid, flow_id) key)
                    bot = bots_map.get(next_step)
                    if bot:
                        key = (next_step, procId_int)
                        bs = bot_schema_map.get(key)
                        if bs:
                            table_permissions = getattr(bs, 'bot_element_permission', []) or []
                            data_item['permissions'] = table_permissions
                            data_item['form_filter_schema'] = table_permissions

                    # 5) EndElement override
                    ee = end_elem_map.get(next_step)
                    if ee:
                        table_permissions = ee.end_element_schema.get('end_element_permission', []) if getattr(ee,
                                                                                                               'end_element_schema',
                                                                                                               None) else []
                        data_item['permissions'] = table_permissions
                        data_item['form_filter_schema'] = table_permissions

            # Build response (counts from aggregated query)
            response_data = {
                'organization_id': organization.id,
                'total_cases': counts.get('total_cases', 0),
                'completed_cases': counts.get('completed_cases', 0),
                'inprogress_cases': counts.get('inprogress_cases', 0),
                'cases': serialized_data,
            }

            return Response(response_data)

        except Exception as e:
            print(f"Error retrieving cases: {str(e)}")
            return Response({'error': 'An error occurred while retrieving case data'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CoreData(APIView):
    def get(self, request):

        form_data = CreateProcess.objects.all().values('id', 'process_name')
        if form_data:
            first_id = form_data[0]['id']
        else:
            print("No records in the queryset")
        for item in form_data:
            id_value = item['id']
            print(id_value)

        # Retrieve the 'participants' field for all records
        participants_list = CreateProcess.objects.values('participants')

        formids = set()  # Use a set to ensure unique formids
        for entry in participants_list:
            for participant in entry['participants']:
                if 'formid' in participant:
                    formids.add(participant['formid'])

        # Retrieve all 'id' values from 'SaveFormData'
        save_form_data_ids = FormDataInfo.objects.values_list('id', flat=True)

        # Filter 'id' values from 'save_form_data_ids' that are not in 'formids'
        unique_ids = [id for id in save_form_data_ids if str(id) not in formids]

        # Convert the result to a list if needed
        id_list = list(unique_ids)
        print(id_list)

        # Fetch the associated FormJsonSchema objects using the 'id' values
        form_json_schemas = FormDataInfo.objects.filter(id__in=id_list)

        # Serialize the FormJsonSchema objects into a response format, assuming you have a serializer
        serializer = FormDataInfoSerializer(form_json_schemas, many=True)

        # Return the serialized data in the response
        return Response(serializer.data)


# added by laxmi mam
class CoreDataFilledForm(APIView):
    def get(self, request, pk=None):
        form_json_schema = FormDataInfo.objects.get(id=pk)
        serializer = FormDataInfoSerializer(form_json_schema)
        return Response(serializer.data)

    def post(self, request, pk):
        try:

            try:
                form_data = FormDataInfo.objects.get(id=pk)
                data_json = request.data.get('data_json')

                Filled_data_json = {
                    'formId': pk,
                    'data_json': data_json,  # json list (need to change)

                }
                serializer = FilledDataInfoSerializer(data=Filled_data_json)
                if serializer.is_valid():
                    instance = serializer.save()

                return Response(serializer.data, status=status.HTTP_200_OK)
            except FormDataInfo.DoesNotExist:
                return Response({"error": "The provided form_id does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": "An error occurred while updating the data."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            filled_data = FormDataInfo.objects.get(id=pk)
            data_json = request.data.get('data_json')

            Filled_data_json = {
                'formId': pk,
                'data_json': data_json,  # json list (need to change)

            }
            serializer = FilledDataInfoSerializer(data=Filled_data_json)
            if serializer.is_valid():
                instance = serializer.save()

            return Response(serializer.data, status=status.HTTP_200_OK)
        except FilledFormData.DoesNotExist:
            return Response({"error": "The provided formId does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": "An error occurred while updating the data."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)



############# User Profile form Creation , Updation and Deletion ######################

############# User Profile form Creation , Updation and Deletion ######################
# views.py
import logging
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404

logger = logging.getLogger(__name__)


class UserFormSchemaListCreateView(APIView):
    def get(self, request):
        try:
            organization_id = request.query_params.get('organization_id')
            if organization_id:
                schema = UserFormSchema.objects.filter(organization_id=organization_id).first()
                if schema:
                    serializer = UserFormSchemaSerializer(schema)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Schema not found for the given organization'},
                                    status=status.HTTP_404_NOT_FOUND)
            else:
                # If no org ID is provided, return all as a list
                schemas = UserFormSchema.objects.all()
                serializer = UserFormSchemaSerializer(schemas, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching UserFormSchemas: {e}")
            return Response({'error': 'Failed to retrieve schemas'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            organization_id = request.data.get('organization')
            if not organization_id:
                return Response({'error': 'Organization ID is required'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if schema already exists for the organization
            instance = UserFormSchema.objects.filter(organization_id=organization_id).first()

            if instance:
                # Update the existing schema
                serializer = UserFormSchemaSerializer(instance, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    logger.info("UserFormSchema updated successfully.")
                    return Response(serializer.data, status=status.HTTP_200_OK)
                logger.warning(f"Validation failed during update: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                # Create new schema
                serializer = UserFormSchemaSerializer(data=request.data)
                if serializer.is_valid():
                    # Generate UID for new schema
                    uid = generate_uid(UserFormSchema, prefix='UFS', organization_id=organization_id)
                
                    serializer.save(uid=uid)
                    logger.info("New UserFormSchema created successfully.")
                    return Response(serializer.data, status=status.HTTP_201_CREATED)
                logger.warning(f"Validation failed during creation: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error creating/updating UserFormSchema: {e}")
            return Response({'error': 'Failed to create or update schema'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


################################################# Create User Starts ##################################################


class UserDataView(APIView):
    def get(self, request, user_id=None, organization_id=None):
        if user_id:
            # Retrieve a single user by ID
            user_data = get_object_or_404(UserData, id=user_id)
            serializer = UserDataSerializer(user_data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        elif organization_id:
            # Filter users based on organization_id
            user_data = UserData.objects.filter(organization_id=organization_id)
            serializer = UserDataSerializer(user_data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # Retrieve all users
            user_data = UserData.objects.all()
            serializer = UserDataSerializer(user_data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)



class UserCreateView(APIView):
    # permission_classes = [IsAuthenticated]  # Ensure only admin users can access this view
    ## Vk Reason for Hide is I dont have permission as is_super_user as isLead

    def get(self, request, user_id=None, organization_id=None):
        if user_id:
            # Retrieve a single user by ID
            user_data = get_object_or_404(UserData, id=user_id)
            serializer = UserDataSerializer(user_data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        elif organization_id:
            # Filter users based on organization_id
            user_data = UserData.objects.filter(organization_id=organization_id)
            serializer = UserDataSerializer(user_data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            # Retrieve all users
            user_data = UserData.objects.all()
            serializer = UserDataSerializer(user_data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        user = request.user
        # print("request : ",request.data)
        print("request.user : ",request.user)
        print("request.user id: ",request.user.id)
        try:
            userData = UserData.objects.get(user_id=user.id)
            print("userData : ",userData)
        except UserData.DoesNotExist:
            return Response({"error": "User data not found."}, status=status.HTTP_404_NOT_FOUND)

        if not (request.user.is_superuser or userData.is_lead):
            return Response({"error": "You do not have permission to perform this action."},
                            status=status.HTTP_403_FORBIDDEN)

        serializer = UserDataSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        mail_id = serializer.validated_data.get('mail_id')
        user_name = serializer.validated_data.get('user_name')
        org_instance = serializer.validated_data.get('organization')
        org_id = org_instance.id if org_instance else None

        if UserData.objects.filter(mail_id=mail_id, organization=org_id).exists():
            return Response({"error": "Email address already in use."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                # Generate UID using the utility function
                uid = generate_uid(UserData, "USR",org_id)
                # Check if admin_set_password flag is True
                if org_instance.admin_set_password:
                    # Admin will provide password directly
                    password = request.data.get("password")
                    if not password:
                        return Response({"error": "Password required as admin set password is enabled."},
                                        status=status.HTTP_400_BAD_REQUEST)
                    send_email = False
                else:
                    # Generate temporary password and send reset email
                    password = "temporary_password"
                    send_email = True
                # --- Ensure unique username internally ---
                unique_username = f"{user_name}_{uuid.uuid4().hex[:6]}"
                mail_id_converted = mail_id.strip().lower()
                # Create user
                user = User.objects.create_user(
                    username=mail_id,
                    email=mail_id,
                    password=password
                )

                # Save UserData
                serializer.save(user_id=user.id, uid=uid)

                # Only send email if flag is disabled
                if send_email:
                    try:
                        mail_config = NotificationConfig.objects.get(organization=org_id)
                        mail_data = mail_config.config_details
                        if isinstance(mail_data, str):
                            mail_data = json.loads(mail_data)
                        self.send_password_reset_email(user, request, mail_data)
                    except NotificationConfig.DoesNotExist:
                        raise Exception("Email configuration not found for this organization.")

        except IntegrityError as e:
            logger.error(f"User creation failed: {str(e)}")
            return Response({"error": "Failed to create user due to duplicate entry."},
                            status=status.HTTP_400_BAD_REQUEST)

        message = "User created successfully."
        if send_email:
            message += " A password setup link has been sent to the registered email address."
        else:
            message += " The password was set directly by the admin."

        return Response({'status': message}, status=status.HTTP_201_CREATED)

    def put(self, request, user_id, organization_id):
        user_data = get_object_or_404(UserData, id=user_id, organization_id=organization_id)
        serializer = UserDataSerializer(user_data, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            # --- Update related User model as well ---
            if hasattr(user_data, "user"):  # If relation exists
                user = user_data.user
                # --- Update username only if provided and different ---
                if "user_name" in request.data:
                    new_username = request.data["user_name"].strip()

                    if new_username:
                        # Check if username already exists
                        # Update only in UserData table
                        user_data.user_name = new_username
                        user_data.save()


                # --- Update email only if provided and different ---
                if "mail_id" in request.data:
                    new_email = request.data["mail_id"].strip()
                    if new_email and new_email != user.email:

                        # Check if username already exists (mail_id = username)
                        if User.objects.filter(username=new_email).exclude(id=user.id).exists():
                            return Response(
                                {"error": f"Mail ID '{new_email}' already exists."},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        # Update in Django User table
                        user.email = new_email
                        user.username = new_email  # <-- IMPORTANT
                    # if new_email and new_email != user.email:
                    #     user.email = new_email
                # password update
                if "password" in request.data and request.data["password"]:
                    user.password = make_password(request.data["password"])
                user.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, user_id, organization_id):
        user_data = get_object_or_404(UserData, id=user_id, organization_id=organization_id)
        user_data.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # 22-09-2025 by Harish (Email config)[Project TI]
    def send_password_reset_email(self, user, request, mail_data):
        try:
            from_email = mail_data.get("email_host_user")
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            reset_url = reverse('password_reset', kwargs={'user_id': user.id, 'token': token})
            # reset_link = request.build_absolute_uri(reset_url)
            # Combine SITE_URL with the reset URL path to form the full URL
            reset_link = f"{settings.SITE_URL}/{user.id}/reset-continue/{token}"
            subject = 'Password Reset'
            body = f'Here is your password reset link: {reset_link}'
            # Email connection setup
            connection = get_connection(
                host=mail_data.get("email_host"),
                port=mail_data.get("email_port"),
                username=mail_data.get("email_host_user"),
                password=mail_data.get("email_host_password"),
                use_tls=mail_data.get("use_tls", True),
                use_ssl=mail_data.get("use_ssl", False),
            )

            send_mail(subject, body, from_email, [user.email], connection=connection)

            logger.info(f"Password reset email sent to {user.email}")
            return Response({"message": "Password reset email sent successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}")
            return Response({"error": "An error occurred while sending the email."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


################################################# Create User Ends ##################################################
# JWT Authentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication

class LoginView(APIView):

    permission_classes = [AllowAny]  # allow any only for login

    def post(self, request, organization_id=None, format=None):
        mail_id = request.data.get('mail_id')
        password = request.data.get('password')

        if not mail_id or not password:
            return Response({'error': 'Email and password are required.'}, status=400)

        # Normalize mail_id (make case-insensitive)
        mail_id_converted = mail_id.strip().lower()

        # Fixed user filters for login (LIVE - 24/11/2025 - Harish)
        # User filters
        user_filters = {'mail_id__iexact': mail_id_converted}
        if organization_id:
            user_filters['organization_id'] = organization_id

        # Fetch user ignoring case
        try:
            user = UserData.objects.get(**user_filters)
        except UserData.DoesNotExist:
            return Response({'error': 'Invalid email or password.'}, status=401)

        # Authenticate user
        user = authenticate(request, username=mail_id, password=password)

        # user = authenticate(request, mail_id=mail_id, password=password)

        if user is not None:

            # Get additional user data
            try:
                if organization_id is not None:
                    # Ensure the user belongs to the specified organization
                    user_data = UserData.objects.get(mail_id=mail_id_converted, organization_id=organization_id)
                else:
                    user_data = UserData.objects.get(mail_id=mail_id_converted)

                usergroup = user_data.usergroup
                usergroup_id = user_data.id
                # if mail_id == "admin@skycode.com" and password == "Skycode@123":

                if (mail_id == "admin@skycode.com" and password == "Skycode@123") or \
                        (mail_id == "admin@kodivian.com" and password == "Password@123"):
                    usergroup_name = "skycode_admin"
                    usergroup_id = usergroup.id if usergroup else None
                else:
                    usergroup_id = usergroup.id if usergroup else None
                    usergroup_name = usergroup.group_name if usergroup else "is_superuser"

                # Get organization details if present
                organization = user_data.organization
                organization_id = organization.id if organization else None
                organization_code = organization.org_code if organization else None

                token, created = Token.objects.get_or_create(user=user)

                # refresh = RefreshToken.for_user(user) # JWT Token

                response_data = {
                    # "refresh": str(refresh),
                    # "access": str(refresh.access_token),
                    "usergroup_id": usergroup_id,
                    "user_id": user_data.id,
                    "user_name": user_data.user_name,
                    "login_user": user.id,
                    "usergroup_name": usergroup_name,
                    "token": token.key,
                    "mail_id": mail_id,
                    "organization_id": organization_id,
                    "organization_code": organization_code,
                    "user_profile_pic": user_data.profile_pic,
                    "user_profile_schema": user_data.user_profile_schema or '',
                    "is_lead": user_data.is_lead
                }

                logger.info(f"User {user.id} authenticated successfully.")
                return Response(response_data, status=status.HTTP_200_OK)
            except UserData.DoesNotExist:
                logger.warning(f"User {user.id} not found in organization {organization_id}.")
                return Response({"error": "User not found in the specified organization"},
                                status=status.HTTP_401_UNAUTHORIZED)

        else:
            logger.warning(f"Authentication failed for mail_id: {mail_id}")
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


@method_decorator(csrf_exempt, name='dispatch')
class CustomPasswordResetView(APIView):
    def post(self, request, user_id, token):
        # Fetch the user by ID
        user = get_object_or_404(User, id=user_id)

        # Check if the token is valid
        if not default_token_generator.check_token(user, token):
            return Response({'error': 'Invalid token or user ID.'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate the new password data
        serializer = PasswordResetSerializer(data=request.data)

        """ Modified by Harish at 21-08-2025 (Cause : User data not found)"""
        if serializer.is_valid():
            try:
                # Set the new password
                new_password = serializer.validated_data["password"]
                user.set_password(new_password)
                user.save()

                # Update the password in the UserData model
                user_data = UserData.objects.get(user=user)
                # Store hashed password instead of plain text
                user_data.password = make_password(new_password)
                user_data.save()
            except UserData.DoesNotExist:
                return Response({'error': 'User data not found.'}, status=status.HTTP_404_NOT_FOUND)

            return Response({'success': 'Password reset successful.'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


############################## Notification configutation API starts #########################
class NotificationConfigAPI(APIView):

    def get(self, request, pk=None):
        """Retrieve all notification configurations or a specific one."""
        if pk:
            # config = get_object_or_404(NotificationConfig, pk=pk)
            config = NotificationConfig.objects.get(organization=pk)
            serializer = NotificationConfigSerializer(config)
            return Response(serializer.data, status=status.HTTP_200_OK)

        configs = NotificationConfig.objects.all()
        serializer = NotificationConfigSerializer(configs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a new notification configuration."""
        serializer = NotificationConfigSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        """Update an existing notification configuration (full update)."""
        config = get_object_or_404(NotificationConfig, pk=pk)
        serializer = NotificationConfigSerializer(config, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, pk):
        """Partially update an existing notification configuration."""
        config = get_object_or_404(NotificationConfig, pk=pk)
        serializer = NotificationConfigSerializer(config, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        """Delete a notification configuration."""
        config = get_object_or_404(NotificationConfig, pk=pk)
        config.delete()
        return Response({"message": "Deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


################################### notification configuration API ends ##########################

# ............... SLA with Cron bgn .............
# mohan
def sla_email():
    """
    Notify users
    """
    print("SLA Email +++++++++++++++")
    try:
        # get_case = Case.objects.get(pk=233)
        get_case = Case.objects.all()
        for case in get_case:
            next_step = case.next_step
            process_id = case.processId

            # Retrieve the corresponding CreateProcess object
            process_data = CreateProcess.objects.get(pk=process_id.pk)
            # print("Process Data:", process_data)
            participants_data = process_data.participants

            j_data = json.dumps(participants_data)
            data_list = json.loads(j_data)

            # get sla bgn --
            get_sla = Sla.objects.get(processId=process_id)
            sla_jsn = get_sla.sla_json_schema

            if isinstance(sla_jsn, str):
                sla_jsn = json.loads(sla_jsn)

            condition = sla_jsn.get('Condition', {})
            condition_form_id = condition.get('FormId', '')
            check_condition = condition.get('Check', '')
            # get sla end --

            flow_start = []
            for flow in data_list:  # find next start
                if "processFlow" in flow:
                    process_flow = flow["processFlow"]
                    for flow_key, flow_value in process_flow.items():

                        if flow_key == next_step:
                            # print('flow_key---', flow_key)
                            # print('next_step---', next_step)
                            current_flow_key = flow_key
                            current_flow_values = flow_value['Start']
                            flow_start.append(current_flow_values)

            if condition_form_id in flow_start:
                # find eta date bgn --
                current_flow_value = flow_start[0]
                find_eta_form = FilledFormData.objects.get(formId=current_flow_value)
                find_eta_json = find_eta_form.data_json
                data_dict = json.loads(find_eta_json)
                # ETA date
                eta_date_str = data_dict.get("ETA")
                eta_date = datetime.strptime(eta_date_str, "%Y-%m-%d").date()

                current_date = datetime.now().date()
                eta_minus_4 = eta_date - timedelta(days=4)
                # find eta date end --

                if current_date >= eta_minus_4:
                    subject = 'Form Completion Reminder'
                    message = 'You have an assigned form that needs to be completed' \
                              ' within four days. Please complete it as soon as possible.'
                    from_email = settings.EMAIL_HOST_USER
                    recipient_list = ['mohansaravanan111@gmail.com']
                    send_mail(subject, message, from_email, recipient_list)
                else:
                    print("Current date is not greater than ETA date - 4.")
            else:
                print("Condition form ID not found in flow start.")

        return HttpResponse('Email sent successfully.')  # response to indicate success
    except Case.DoesNotExist:
        return HttpResponse('Case with ID 1 does not exist.')  # response to indicate failure


######################################## User Create function starts ###################################

####################################### User Filltered according to usergroups Starts ###################

@api_view(['GET'])
def filter_users(request):
    """
        API to filter users based on user group IDs.

        Query Parameters:
    - q (string, optional): Search keyword for username or mail_id
    - page (int, optional): Page number for pagination
    - page_size (int, optional): Number of results per page

        Example Request:
        GET /users/filter/?q=1,2,3

        """
    search_query = request.GET.get('search', '').strip()  # Search keyword
    group_ids_param = request.GET.get('groupid', '').strip()
    page_size = request.GET.get('page_size', 10)  # Default to 10 per page
    users = UserData.objects.all()

    # Filter by usergroup IDs
    if group_ids_param:
        group_ids = [gid.strip() for gid in group_ids_param.split(',') if gid.strip()]
        users = users.filter(usergroup_id__in=group_ids)

    # Apply search filter if q exists
    if search_query:
        users = users.filter(
            Q(user_name__icontains=search_query) |
            Q(mail_id__icontains=search_query)
        )

    # Pagination
    paginator = PageNumberPagination()
    paginator.page_size = int(page_size)  # Use page_size from query param
    paginated_users = paginator.paginate_queryset(users, request)

    # Serialize paginated data
    serializer = UserDataListSerializer(paginated_users, many=True)

    return paginator.get_paginated_response(serializer.data)


####################################### User Filltered according to usergroups Ends ###################


########################## Email Notification To send [Starts] by Mohan on 17.2.2025 #########################################

from rest_framework.response import Response
from rest_framework import status

from django.conf import settings
from django.core.mail import send_mail
from .models import *
from django.contrib.auth.models import User

# Email templates stored in a dictionary (Can be moved to a database or JSON file)
EMAIL_TEMPLATES = {
    "ACTION_ONE": {
        "subject": "Confirmation: Process Case Completed for {org_name}",
        "message": """\
            <p>Hello {username},</p>

            <p>We are pleased to inform you that the requested process (Case ID: {case_id}) has been successfully completed for {org_name}.</p>

            <p>If you have any questions or need further assistance, please feel free to contact us.</p>

            <a href="{url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
                color: #fff; background-color: #007bff; text-decoration: none; border-radius: 5px;">
                View Details
            </a>

            <p>Best regards,<br>[{org_name}]</p>
        """
    },
    "ACTION_TWO": {
        "subject": "Important Alert: Attention Required for {org_name}",
        "message": """\
            <p>Hello {username},</p>

            <p>The case with ID {case_id} has been assigned to your user group in {org_name}.  
            Please review the details at your earliest convenience.</p>

            <p>If you need any assistance, our support team is available to help.</p>

            <a href="{url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
                color: #fff; background-color: #007bff; text-decoration: none; border-radius: 5px;">
                View Case
            </a>

            <p>Best regards,<br>[{org_name}]</p>
        """
    },
    "ACTION_THREE": {
        "subject": "Notification: Update for {org_name}",
        "message": """\
            <p>Hello {username},</p>

            <p>TWe wanted to inform you of a recent update regarding Case ID: {case_id} for your organization, {org_name}.
             Please review the update and take any necessary actions as required.</p>

            <p>For any inquiries or support, feel free to reach out.</p>

            <a href="{url}" style="display: inline-block; padding: 10px 20px; font-size: 16px; 
                color: #fff; background-color: #007bff; text-decoration: none; border-radius: 5px;">
                View Update
            </a>

            <p>Best regards,<br>[{org_name}]</p>
        """
    }
}


def send_email(organization_id, user_ids, action_type, extra_context):
    """
    Generic function to send email notifications based on a dynamic template.

    Args:
        organization_id (int): Organization ID to fetch email configuration.
        user_ids (list): List of user IDs to send the email to.
        action_type (str): Type of action (ACTION_ONE, ACTION_TWO, etc.).
        extra_context (dict): Dictionary with dynamic data (org_id, case_id, etc.).

    Returns:
        (bool, str): Success status and message.
    """
    try:
        # Fetch email configuration from database
        config_entry = NotificationConfig.objects.get(organization=organization_id)
        org_name = Organization.objects.get(id=organization_id).org_name or "Unknown Organization"
        email_config = config_entry.config_details

        if not email_config:
            return False, "Email configuration not found."

        # users = UserData.objects.filter(id__in=user_ids).values_list("mail_id", flat=True)
        users = UserData.objects.filter(id__in=user_ids).values("mail_id", "user_name")

        if not users:
            return False, "No valid users found for the given IDs."

        # Get email subject and message from template
        template = EMAIL_TEMPLATES.get(action_type)
        if not template:
            return False, f"Invalid action type: {action_type}"

        connection = get_connection(
            backend=settings.EMAIL_BACKEND,  # Ensure EMAIL_BACKEND is set in settings.py
            host=email_config["email_host"],
            port=email_config["email_port"],
            username=email_config["email_host_user"],
            password=email_config["email_host_password"],
            use_tls=email_config.get("use_tls", True),
            use_ssl=email_config.get("use_ssl", False),
        )

        for user in users:
            email_id = user["mail_id"]
            user_name = user["user_name"]

            # Format subject and message with user-specific data
            subject = template["subject"].format(org_name=org_name, **extra_context)
            message = template["message"].format(org_name=org_name, username=user_name, **extra_context)

            send_mail(
                subject=subject,
                message=message,
                from_email=config_entry.config_details["email_host_user"],
                recipient_list=[email_id],
                fail_silently=False,
                connection=connection
            )

            logger.info(f"Email sent successfully to {email_id}")

        return True, "Emails sent successfully."

    except NotificationConfig.DoesNotExist:
        return False, "No email configuration found in DB."
    except Exception as e:
        return False, str(e)


########################## Email Notification To send [Ends] by Mohan on 17.2.2025 #########################################


############################# In App Notification Starts by Mohan On 18.3.25 ##################

# Notification table access(admin only)
class NotificationAPIView(APIView):
    def get(self, request, pk=None):
        if pk:
            notification = get_object_or_404(Notification, pk=pk)
            data = {
                "id": notification.id,
                "notification_type": notification.notification_type,
                "notification_name": notification.notification_name,
                "description": notification.description,
                "notification_content": notification.notification_content,
                "created_at": notification.created_at,
                "updated_at": notification.updated_at
            }
        else:
            notifications = Notification.objects.all()
            data = [
                {
                    "id": n.id,
                    "notification_type": n.notification_type,
                    "notification_name": n.notification_name,
                    "description": n.description,
                    "notification_content": n.notification_content,
                    "created_at": n.created_at,
                    "updated_at": n.updated_at
                } for n in notifications
            ]
        return Response(data, status=status.HTTP_200_OK)

    def post(self, request):
        data = request.data
        notification = Notification.objects.create(
            notification_type=data.get("notification_type"),
            notification_name=data.get("notification_name"),
            description=data.get("description"),
            notification_content=data.get("notification_content")
        )
        return Response({"id": notification.id}, status=status.HTTP_201_CREATED)

    def put(self, request, pk):
        notification = get_object_or_404(Notification, pk=pk)
        data = request.data
        notification.notification_type = data.get("notification_type", notification.notification_type)
        notification.notification_name = data.get("notification_name", notification.notification_name)
        notification.description = data.get("description", notification.description)
        notification.notification_content = data.get("notification_content", notification.notification_content)
        notification.save()
        return Response({"message": "Updated successfully"}, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        notification = get_object_or_404(Notification, pk=pk)
        notification.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# In-App Notifications
class InAppNotificationAPIView(APIView):
    def format_notification_content(self, notification, organization, process, case, url):
        return notification.notification_content.format(
            organization_name=organization.org_name,
            process_name=process.process_name,
            case_id=case.id,
            url=url
        )

    def get(self, request, user_id):
        notifications = Notification.objects.filter(notification_type='In-App')

        try:
            # Get User Data
            user_data = UserData.objects.get(id=user_id)
            user_data_user_group = user_data.usergroup

            # get user
            get_login_user = user_data.user_id
            user = User.objects.get(id=get_login_user)

            # Check if user is a superuser or lead
            is_superuser = user.is_superuser
            is_lead = user_data.is_lead

            # If user is not a superuser/lead and has no user group, restrict access
            if not (is_superuser or is_lead) and not user_data_user_group:
                return Response({"error": "User group is not assigned"}, status=status.HTTP_403_FORBIDDEN)

            # Check user group status
            if user_data_user_group and user_data_user_group.status == "No":
                return Response({"error": "User is inactive"}, status=status.HTTP_403_FORBIDDEN)

            # Organization details
            organization = user_data.organization

            # Get all processes related to the organization
            processes = CreateProcess.objects.filter(organization_id=organization.id)

            # Get dismissed notifications for the current user, including process & case details
            dismissed_notifications = NotificationDismiss.objects.filter(
                user=user, is_dismissed=True, process__isnull=False, case__isnull=False
                ## changed to check process and case is null

            ).values_list('notification_id', 'process_id', 'case_id')

            # Convert dismissed notifications to a set for easy filtering
            dismissed_notifications_set = set(dismissed_notifications)
            # Initialize final notifications list
            final_notifications = []

            # Iterate over each process
            for process in processes:
                cases = Case.objects.filter(processId=process)

                for case in cases:
                    case_status = case.status
                    case_assigned_users = case.assigned_users
                    next_step = case.next_step

                    # Check if user is assigned to the case
                    is_user_assigned = case_assigned_users.filter(id=user.id).exists()

                    # Process each notification
                    for notification in notifications:
                        notification_type = notification.notification_type
                        notification_name = notification.notification_name

                        if notification_type == "In-App":

                            if (notification.id, process.id or None, case.id or None) in dismissed_notifications_set:
                                continue  # Skip dismissed notifications
                            base_url = settings.SITE_URL
                            url = f"{base_url}/list-process/{process.id}"

                            # Format notification content
                            formatted_content = self.format_notification_content(notification, organization, process,
                                                                                 case, url)

                            # Common notification data structure
                            notification_data = {
                                "notification_name": notification.notification_name,
                                "notification_type": notification.notification_type,
                                "description": notification.description,
                                "notification_content": formatted_content,
                                "url": url,
                                "params": {
                                    "user_id": user.id,
                                    "notification_id": notification.id,
                                    "case_id": case.id if case else None,
                                    "process_id": process.id if process else None
                                }
                            }

                            # 09-09-2025 by Harish

                            # Superusers and leads get all notifications (excluding dismissed ones)
                            # if is_superuser or is_lead:
                            #     final_notifications.append(notification_data)
                            #     continue

                            # Case Assignment Notification
                            if is_user_assigned and notification_name == "case assignment":
                                final_notifications.append(notification_data)

                            # Case Completed Notification
                            elif notification_name == "case completed" and case_status == "Completed":
                                tagged_user_groups = process.user_group.all()
                                eligible_users = UserData.objects.filter(
                                    usergroup__in=tagged_user_groups
                                ).values_list('user_id', flat=True)
                                if user.id in eligible_users:
                                    final_notifications.append(notification_data)

                            # Next Step Notification

                            elif notification_name == "next step notification":
                                # Fetch all next step forms related to the case
                                form_data_list = FormDataInfo.objects.filter(Form_uid=next_step)
                                if form_data_list.exists():
                                    for form_data in form_data_list:
                                        # Get user groups that have write access to this form
                                        user_groups_with_access = FormPermission.objects.filter(
                                            form=form_data.id, write=True
                                        ).values_list('user_group', flat=True)

                                        if user_groups_with_access:
                                            # Get users from those user groups
                                            eligible_users = UserData.objects.filter(
                                                usergroup__id__in=user_groups_with_access
                                            ).values_list('user_id', flat=True)

                                            if user.id in eligible_users:
                                                final_notifications.append(notification_data)

                        # notification = Notification.objects.get(id=notification_id)
                        # notification = Notification.objects.get(id=notification_id)
            # Set up pagination
            paginator = PageNumberPagination()
            paginator.page_size_query_param = 'page_size'
            paginator.page_size = int(request.query_params.get('page_size', 10))
            # Paginate final_notifications
            page = paginator.paginate_queryset(final_notifications, request)
            # for notification in final_notifications:
            for notification in page:
                notification_instance = Notification.objects.get(id=notification["params"]["notification_id"])
                process = CreateProcess.objects.get(id=notification["params"]["process_id"]) if notification["params"][
                    "process_id"] else None
                case = Case.objects.get(id=notification["params"]["case_id"]) if notification["params"][
                    "case_id"] else None

                NotificationDismiss.objects.update_or_create(
                    user=user,
                    notification=notification_instance,
                    process=process,
                    case=case,
                    defaults={"is_dismissed": False}
                )
            return paginator.get_paginated_response(page)
            # return Response(final_notifications, status=status.HTTP_200_OK)

        except UserData.DoesNotExist:
            return Response({"error": "User data not found"}, status=status.HTTP_404_NOT_FOUND)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)


############################# Dismiss Notification Starts - by Mohan on 18.3.25 #############
class DismissNotificationAPIView(APIView):
    """
    Allows a user to dismiss notifications for a specific process and case.
    """

    def post(self, request):
        """
        Dismiss notifications based on query parameters.
        """
        try:
            user_id = request.query_params.get("user_id")
            notification_id = request.query_params.get("notification_id")
            process_id = request.query_params.get("process_id")
            case_id = request.query_params.get("case_id")

            if not user_id:
                return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

            user_data = UserData.objects.get(id=user_id)
            user = User.objects.get(id=user_data.user_id)
            # Bulk dismiss all notifications if notification_id is not provided
            if not notification_id:
                NotificationDismiss.objects.filter(user=user).update(is_dismissed=True)
                return Response({"message": "All notifications dismissed for user"}, status=status.HTTP_200_OK)

            # Fetch specific notification
            notification = Notification.objects.get(id=notification_id)
            process = CreateProcess.objects.get(id=process_id) if process_id else None
            case = Case.objects.get(id=case_id) if case_id else None

            # Dismiss the specified notification
            NotificationDismiss.objects.update_or_create(
                user=user,
                notification=notification,
                process=process,
                case=case,
                defaults={"is_dismissed": True}
            )

            return Response({"message": "Notification dismissed successfully"}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Notification.DoesNotExist:
            return Response({"error": "Notification not found"}, status=status.HTTP_404_NOT_FOUND)
        except CreateProcess.DoesNotExist:
            return Response({"error": "Process not found"}, status=status.HTTP_404_NOT_FOUND)
        except Case.DoesNotExist:
            return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)


############################# Dismiss Notification Ends - by Mohan on 18.3.25 #############


########################### getting core data from organization[STARTS] ##############################


class CoreFormDataInfoListView(APIView):
    """
    List all core data forms for an organization
    """

    def get(self, request, organization_id, form_id=None):
        try:
            if form_id:
                # Retrieve a single core form
                try:
                    core_data = FormDataInfo.objects.get(
                        organization=organization_id,
                        id=form_id,
                        processId__isnull=True,
                        core_table=True
                    )
                except FormDataInfo.DoesNotExist:
                    return Response({"error": "Form not found"}, status=status.HTTP_404_NOT_FOUND)

                serializer = CoreDataInfoSerializer(core_data)
                data = serializer.data
                # Construct response with required fields only

                # Get related permissions
                form_permissions = FormPermission.objects.filter(
                    form_id=core_data.id
                ).values('user_group', 'read', 'write', 'edit')

                data['permissions'] = list(form_permissions)
                form_rules = Rule.objects.filter(form=core_data.id).values_list('form_rule_schema', flat=True)
                # form_data['form_rule_schema'] = list(form_rules)
                data['form_rule_schema'] = list(chain.from_iterable(item for item in form_rules if item))

                return Response(data, status=status.HTTP_200_OK)

            else:
                # List all core forms for the organization
                forms = list(FormDataInfo.objects.filter(
                    organization_id=organization_id,
                    processId__isnull=True,
                    core_table=True
                ).values('id', 'form_name', 'processId_id', 'form_description', 'form_json_schema'))

                for form in forms:
                    permissions = FormPermission.objects.filter(
                        form_id=form['id']
                    ).values('user_group', 'read', 'write', 'edit')

                    form['permissions'] = list(permissions)

                return Response(forms, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CoreFilledDataView(APIView):
    """
    1.2
    user filled data get,post,update and delete function
    """

    def get(self, request, organization_id=None, pk=None):
        """
        List all user data, retrieve particular data, or filter by organization.
        """
        permissions_list = []
        try:
            if organization_id and pk:
                filled_data = FilledFormData.objects.get(pk=pk, organization=organization_id)

                filled_data_list = [filled_data]
            elif organization_id:
                filled_data_list = FilledFormData.objects.filter(organization=organization_id, processId__isnull=True)
                # Extract form IDs from the filled form data
                form_ids = filled_data_list.values_list('formId', flat=True)

                # Filter the FormPermission table using the extracted form IDs
                form_permissions = FormPermission.objects.filter(form_id__in=form_ids).values(
                    'form_id', 'user_group__id', 'read', 'write', 'edit'
                )
                permissions_list = list(form_permissions)


            elif pk:
                filled_data = FilledFormData.objects.get(pk=pk)

                filled_data_list = [filled_data]
            else:
                filled_data_list = FilledFormData.objects.all()

            data = []
            for filled_data in filled_data_list:
                filled_data_info = FilledDataInfoSerializer(filled_data).data
                case = filled_data.caseId
                if case is not None:
                    filled_data_info['created_on'] = case.created_on
                    filled_data_info['updated_on'] = case.updated_on
                else:
                    filled_data_info['created_on'] = None
                    filled_data_info['updated_on'] = None

                filled_data_info['process_name'] = (
                    filled_data.processId.process_name if filled_data.processId else None
                )
                filled_data_info['user_groups'] = list(filled_data.user_groups.values_list('id', flat=True))
                # Add permissions to filled form data
                # Add permissions by matching form_id from permissions_list with filled_data.formId
                filled_data_info['permissions'] = [perm for perm in permissions_list if
                                                   perm['form_id'] == filled_data.formId]

                data.append(filled_data_info)

            return Response(data if len(data) > 1 else data[0])
        except FilledFormData.DoesNotExist:
            return Response({"error": "Filled form data not found."}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": "An unexpected error occurred.", "details": str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):  # store ths data in db
        """
        List all user data, retrieve particular data, or filter by organization for Process Engine.
        """
        if request.method == 'POST':
            try:
                # Extract jsonData, formId, organization
                # json_data_str = request.POST.get('jsonData', '[]')
                if 'jsonData' in request.data and request.data['jsonData']:
                    data_json_str = request.data['jsonData']
                else:
                    data_json_str = request.POST.get('jsonData', '[]')

                if isinstance(data_json_str, str):
                    json_data = json.loads(data_json_str)
                else:
                    json_data = data_json_str
                form_id = request.POST.get('formId') or request.data.get('formId')
                organization_id = request.POST.get('organization') or request.data.get('organization')
                if not form_id or not organization_id:
                    return JsonResponse({'error': 'formId and organization are required fields'},
                                        status=status.HTTP_400_BAD_REQUEST)

                # json_data = json.loads(json_data_str)

                # Validate and get organization
                try:
                    organization = Organization.objects.get(id=organization_id)
                except Organization.DoesNotExist:
                    return JsonResponse({'error': 'Organization not found'}, status=404)

                # Extract the field id for file, if present in jsonData
                file = None
                for item in json_data:
                    if item.get('field_id') and item.get('value'):
                        file_field_id = item['field_id']
                        break

                if request.FILES:  ####### modified for multiple files
                    # Handle files if present in request.FILES
                    files = []
                    for field_name, uploaded_file in request.FILES.items():
                        files.append(
                            ('files', (uploaded_file.name, uploaded_file.file, uploaded_file.content_type))
                        )
                    # Fetch drive types and configurations for the specific organization
                    dms_entries = Dms.objects.filter(organization=organization)
                    if not dms_entries.exists():
                        return JsonResponse({'error': 'DMS configuration not found for the organization'},
                                            status=status.HTTP_404_NOT_FOUND)

                    # drive_types = list(dms_entries.values_list('drive_types', flat=True))
                    drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}
                    configurations = dms_entries.first().config_details_schema
                    # configurations.update("drive_type": drive_types)
                    configurations['drive_types'] = drive_types
                    # configurations['s3_bucket_metadata'] = drive_types

                    metadata = {'form_id': form_id, 'organization_id': str(organization_id),
                                'data_json': str(json_data)}
                    configurations['metadata'] = json.dumps(metadata)

                    # Prepare the file for the request
                    files = {'files': (file.name, file.file, file.content_type)}

                    try:
                        external_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                        response = requests.post(
                            external_api_url,
                            data=configurations, files=files

                        )
                        response.raise_for_status()
                    except requests.RequestException as e:
                        return JsonResponse({'error': f'Error sending file to external API: {str(e)}'},
                                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                # Save the data to the database
                form_data = FilledFormData(
                    data_json=json_data,
                    formId=form_id,
                    organization=organization,

                )
                form_data.save()

                return JsonResponse({'status': 'success', 'form_data_id': form_data.id})
            except json.JSONDecodeError:
                return JsonResponse({'error': 'Invalid JSON format in jsonData'}, status=status.HTTP_400_BAD_REQUEST)
            except KeyError:
                return JsonResponse({'error': 'Missing required fields in data'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # return None

        #     except (json.JSONDecodeError, KeyError) as e:
        #         return JsonResponse({'error': 'Invalid data or missing fields'}, status=400)
        #
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    def put(self, request, organization_id, pk):  # edit the particular filled form
        """
            Edit all user filled data
        """
        try:
            # filled_data = FilledFormData.objects.get(pk=pk)
            filled_data = FilledFormData.objects.filter(pk=pk, organization=organization_id).first()
            if not filled_data:
                return Response({'error': 'Filled form data not found'}, status=status.HTTP_404_NOT_FOUND)
        except FilledFormData.DoesNotExist:
            return Response({'error': 'Filled form data not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error retrieving filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        serializer = FilledDataInfoSerializer(filled_data, data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(serializer.data)
            except ValidationError as e:
                return Response({'error': f'Validation error: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error': f'Error saving filled form data: {str(e)}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):  # delete the particular filled form
        try:
            filled_data = FilledFormData.objects.get(pk=pk)
        except FilledFormData.DoesNotExist:
            return Response({'error': 'Filled form data not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error retrieving filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        try:
            filled_data.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'error': f'Error deleting filled form data: {str(e)}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


########################################################################################


class CoreFilledFormDataView(APIView):
    # Cast JSONField to text for search
    def casttotext(self, field_name):
        return Func(models.F(field_name), function='CAST', template="%(expressions)s::text", output_field=TextField())

    def get(self, request, organization_id=None, form_id=None, pk=None):
        """
        List all filled forms based on organization and form ID or retrieve a specific filled form by its ID.
        Only include forms that are not tagged with a process or case.
        """
        try:
            if organization_id and form_id and pk:
                try:
                    filled_data = FilledFormData.objects.filter(pk=pk, organization=organization_id, formId=form_id,
                                                                processId__isnull=True,
                                                                caseId__isnull=True).first()
                    filled_data_list = [filled_data] if filled_data else []
                except FilledFormData.DoesNotExist:
                    return Response({"detail": "Filled form not found."}, status=status.HTTP_404_NOT_FOUND)
                filled_data_list = [filled_data]
            # Retrieve filled forms based on organization and form ID
            elif organization_id and form_id:
                filled_data_list = FilledFormData.objects.filter(organization=organization_id, formId=form_id,
                                                                 processId__isnull=True,
                                                                 caseId__isnull=True)
            # Retrieve all filled forms not tagged with a process or case
            else:
                filled_data_list = FilledFormData.objects.filter(processId__isnull=True, caseId__isnull=True)

            # --- Search ---
            # Search fix (LIVE - 24/11/2025 - Harish)
            search_query = request.query_params.get("search", None)
            if search_query:
                # Optional: sanitize search input (safe if user types special characters)
                import re
                search_query = re.sub(r'[^\w\s@.-]', '', search_query).strip()

                filled_data_list = filled_data_list.annotate(
                    data_json_text=Cast('data_json', TextField()),
                    id_text=Cast('id', TextField()),
                    updated_at_text=Cast('updated_at', TextField())
                ).filter(
                    Q(id_text__icontains=search_query) |
                    Q(data_json_text__icontains=search_query) |
                    Q(updated_at_text__icontains=search_query)
                )

            # --- Field-specific searches (dynamic) ---
            # Search fix (LIVE - 24/11/2025 - Harish)
            reserved_params = {"page", "page_size", "search", "start_date", "end_date"}
            for key, value in request.query_params.items():
                if key not in reserved_params:
                    print("key : ",key)
                    if key == "updated_at":
                        start_date, end_date = parse_date_range(value)
                        if start_date and end_date:
                            filled_data_list = filled_data_list.filter(
                                updated_at__date__range=(start_date, end_date)
                            )
                    elif key == "id":
                        print("Id : ",value)
                        filled_data_list = filled_data_list.annotate(
                            id_text=Cast('id', TextField())
                        ).filter(id_text__icontains=value)

                    else:
                        filled_data_list = filled_data_list.annotate(
                            data_json_text=Cast('data_json', TextField())
                        ).filter(data_json_text__icontains=value)

            # Filter by date range if provided
            start_date = self.request.query_params.get("start_date")
            end_date = self.request.query_params.get("end_date")
            if start_date and end_date:
                filled_data_list = filled_data_list.filter(
                    created_at__date__range=[parse_date(start_date), parse_date(end_date)]
                )
            # --- Pagination ---
            filled_data_list = filled_data_list.order_by('-updated_at')
            paginated = pk is None and organization_id and form_id
            if paginated:
                filled_data_list = filled_data_list
                page = request.query_params.get("page", 1)
                page_size = request.query_params.get("page_size", 10)  # default 10
                paginator = Paginator(filled_data_list, page_size)
                try:
                    filled_data_list = paginator.page(page)
                except PageNotAnInteger:
                    filled_data_list = paginator.page(1)
                except EmptyPage:
                    filled_data_list = paginator.page(paginator.num_pages)

            data = []
            for filled_data in filled_data_list:
                filled_data_info = {
                    'id': filled_data.id,
                    'formId': filled_data.formId,
                    'data_json': filled_data.data_json,
                    'created_at': filled_data.created_at,
                    'updated_at': filled_data.updated_at,
                    'organization': filled_data.organization.id,
                    'user_groups': list(filled_data.user_groups.values_list('id', flat=True)),
                }
                data.append(filled_data_info)

            if not data:
                if paginated:
                    return Response({
                        "count": 0,
                        "total_pages": 0,
                        "current_page": int(page),
                        "page_size": int(page_size),
                        "results": []
                    }, status=status.HTTP_200_OK)
                else:
                    return Response([], status=status.HTTP_200_OK)
            if paginated:
                return Response({
                    "count": paginator.count,
                    "total_pages": paginator.num_pages,
                    "current_page": int(page),
                    "page_size": int(page_size),
                    "results": data
                }, status=status.HTTP_200_OK)
            else:
                return Response(data, status=status.HTTP_200_OK)
            # return Response(data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"error": "Invalid ID provided or resource does not exist."},
                            status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as e:
            return Response({"error": f"Validation error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": f"An unexpected error occurred: {str(e)}"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # except Exception as e:
        #     return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# 20-09-2025 by Harish (Date search)[Project TI]

def parse_date_range(value: str):
    """
    Parse a string into (start_date, end_date) tuple.
    Supports formats: YYYY, YYYY-MM, YYYY-MM-DD.
    """
    patterns = ["%Y-%m-%d", "%Y-%m", "%Y"]
    for pattern in patterns:
        try:
            dt = datetime.strptime(value, pattern).date()
            if pattern == "%Y":
                start_date = datetime(dt.year, 1, 1).date()
                end_date = datetime(dt.year, 12, 31).date()
            elif pattern == "%Y-%m":
                last_day = calendar.monthrange(dt.year, dt.month)[1]
                start_date = datetime(dt.year, dt.month, 1).date()
                end_date = datetime(dt.year, dt.month, last_day).date()
            else:  # "%Y-%m-%d"
                start_date = end_date = dt
            return start_date, end_date
        except ValueError:
            continue
    return None, None


################################### Sequence ID Generator API ###########################

################################### Sequence ID Configuration for Organization Generator API ###########################
class SequenceIDConfigAPIView(APIView):

    def get(self, request, pk=None):
        try:
            organization_id = request.query_params.get('organization')
            if pk:
                sequence = get_object_or_404(Sequence, pk=pk)
                serializer = SequenceSerializer(sequence)
                return Response(serializer.data)
            sequences = Sequence.objects.all()
            if organization_id:
                sequences = sequences.filter(organization_id=organization_id)
            serializer = SequenceSerializer(sequences, many=True)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error in GET SequenceAPIView: {str(e)}")
            return Response({"error": "An error occurred while fetching sequences."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            # 18-09-2025 by Harish (Sequence Validation) [Product Level]
            prefix = request.data.get("prefix", "").strip()
            suffix = request.data.get("suffix", "").strip()
            organization_id = request.data.get("organization")
            access_id = request.data.get("access_id")
            # Check uniqueness of (organization, prefix, suffix)
            if Sequence.objects.filter(organization_id=organization_id, prefix=prefix, suffix=suffix).exists():
                return Response({"error": "Duplicate entry: prefix and suffix already exists for this organization."},
                                status=status.HTTP_400_BAD_REQUEST)

            if Sequence.objects.filter(access_id=access_id).exists():
                return Response({"error": "This Access ID is already in use across the system"},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer = SequenceSerializer(data=request.data)
            if serializer.is_valid():
                uid = generate_uid(Sequence, 'SQ', organization_id)
                serializer.save(uid=uid)
                logger.info("Sequence created successfully.")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            else:
                logger.warning(f"Validation error in POST SequenceAPIView: {serializer.errors}")
                return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except IntegrityError as e:
            logger.error(f"IntegrityError in POST SequenceAPIView: {str(e)}")
            return Response(
                {"error": "Duplicate entry for prefix, suffix, or access_id."},
                status=status.HTTP_400_BAD_REQUEST
            )

        except Exception as e:
            logger.error(f"Unexpected error in POST SequenceAPIView: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred while creating the sequence."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request, pk=None):
        try:
            sequence = get_object_or_404(Sequence, pk=pk)
            serializer = SequenceSerializer(sequence, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            logger.error(f"Integrity error in PUT SequenceAPIView: {str(e)}")
            return Response({"error": "Duplicate entry for prefix, suffix, or access_id."},
                            status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error in PUT SequenceAPIView: {str(e)}")
            return Response({"error": "An error occurred while updating sequence."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


############################ Sequence ID Generated API ########################

class GenerateSequenceIdView(APIView):
    def get(self, request):
        access_id = request.query_params.get('access_id')
        organization_id = request.query_params.get('organization')

        if not access_id or not organization_id:
            return Response({'error': 'Both access_id and organization are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            sequence = Sequence.objects.get(access_id=access_id, organization_id=organization_id)
        except Sequence.DoesNotExist:
            return Response({'error': 'Sequence not found for the given access_id and organization.'},
                            status=status.HTTP_404_NOT_FOUND)

        # Generate the ID
        number_part = str(sequence.counter).zfill(sequence.digit)
        generated_id = f"{sequence.prefix}{number_part}{sequence.suffix}"

        # Increment the counter and save
        # sequence.counter += 1
        # sequence.save()

        return Response({'generated_id': generated_id}, status=status.HTTP_200_OK)

    def post(self, request):
        access_id = request.query_params.get('access_id')
        organization_id = request.query_params.get('organization')

        if not access_id or not organization_id:
            return Response({'error': 'Both access_id and organization are required.'},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            sequence = Sequence.objects.get(access_id=access_id, organization_id=organization_id)
        except Sequence.DoesNotExist:
            return Response({'error': 'Sequence not found for the given access_id and organization.'},
                            status=status.HTTP_404_NOT_FOUND)

        # Increment the counter
        sequence.counter += 1
        sequence.save()

        return Response({'message': 'Counter incremented successfully.', 'new_counter': sequence.counter},
                        status=status.HTTP_200_OK)

    def generate_sequence_id(self, access_id, organization_id):
        if not access_id or not organization_id:
            return None

        try:
            sequence = Sequence.objects.get(access_id=access_id, organization_id=organization_id)
        except Sequence.DoesNotExist:
            return None

        number_part = str(sequence.counter).zfill(sequence.digit)
        generated_id = f"{sequence.prefix}{number_part}{sequence.suffix}"

        # Optional: update the counter
        sequence.counter += 1
        sequence.save()

        return generated_id


################################### Core Data filled Form Update API Starts ##################


class UpdateCoreDataView(APIView):
    def put(self, request, form_id):
        request_data_json = request.data.get("data_json", [])
        if not request_data_json:
            return Response({"error": "data_json is required in request body"}, status=status.HTTP_400_BAD_REQUEST)

        query_params = request.query_params
        # Step 1: Find all filled forms for the given core form
        filled_forms = FilledFormData.objects.filter(formId=form_id)

        for filled_form in filled_forms:
            existing_data = filled_form.data_json or []
            model_fields = model_to_dict(filled_form)
            match = True
            for key, val in query_params.items():
                found = False

                #  Check in data_json
                for item in existing_data:
                    if item.get("field_id") == key and str(item.get("value")) == val:
                        found = True
                        break

                #  Check in model fields (case-insensitive keys)
                if not found:
                    for field_name, field_value in model_fields.items():
                        if field_name.lower() == key.lower() and str(field_value) == val:
                            found = True
                            break

                if not found:
                    match = False
                    break
            if match:
                # Update fields in data_json
                updated = False
                for update_item in request_data_json:
                    field_id = update_item.get("field_id")
                    new_value = update_item.get("value")
                    if not field_id:
                        continue
                    for item in existing_data:
                        if item.get("field_id") == field_id:
                            item["value"] = new_value
                            updated = True
                            break
                if updated:
                    filled_form.data_json = existing_data
                    filled_form.save()
                    return Response({"message": "Data updated successfully"}, status=status.HTTP_200_OK)
                else:
                    return Response({"message": "No matching field_id found to update"},
                                    status=status.HTTP_400_BAD_REQUEST)

        return Response({"error": "No filled form matched the query parameters"}, status=status.HTTP_404_NOT_FOUND)


################################### Core Data filled Form Update API Ends ##################

################################ CaseChatHistoryAPI #######################################
class CaseChatHistoryAPI(APIView):
    def get(self, request, pk):
        try:
            case = Case.objects.get(pk=pk)
            return Response(case.case_data_comments or [], status=status.HTTP_200_OK)
        except Case.DoesNotExist:
            return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, pk):
        try:
            case = Case.objects.filter(id=pk).first()
            if not case:
                return Response({"error": "Case not found"}, status=status.HTTP_404_NOT_FOUND)
            user_id = request.data.get("user_id")
            if not user_id:
                return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = UserData.objects.get(id=user_id)
            except UserData.DoesNotExist:
                return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            new_message = {
                "id": str(uuid.uuid4()),
                "username": user.user_name,
                "user_id": user.id,
                "user_profile_pic": user.profile_pic,  # Directly insert encoded text
                "message": request.data.get("message"),
                "timestamp": now().isoformat()
            }

            # Ensure we append to the existing list
            chat = case.case_data_comments if isinstance(case.case_data_comments, list) else []
            chat.append(new_message)

            case.case_data_comments = chat
            case.save()

            # case.case_data_comments.append(new_message)
            # case.save()

            return Response({"message": "Message added to chat history"}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


################################ Subprocess List View based on organization included on 08.7.25 [Starts]##########################
class SubprocessListView(APIView):
    def get(self, request, organization_id):
        try:
            # Get subprocesses for this organization
            subprocesses = CreateProcess.objects.filter(
                organization=organization_id,
                parent_process__isnull=False
            )

            if not subprocesses.exists():
                return Response(
                    {"message": "No subprocesses found for this organization."},
                    status=status.HTTP_404_NOT_FOUND
                )

            response_data = []
            for process in subprocesses:
                # Serialize the process itself
                process_data = CreateProcessSerializer(process).data

                # Filter FormDataInfo where process_id = this process
                forms = FormDataInfo.objects.filter(processId=process.id)
                forms_data = FormDataInfoSerializer(forms, many=True).data

                # Attach forms to process
                process_data['form'] = forms_data

                response_data.append(process_data)

            return Response(response_data, status=status.HTTP_200_OK)

        except ValueError:
            return Response(
                {"error": "Invalid organization ID."},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['POST'])
def components_proxy_api(request):
    ip_entry = get_object_or_404(ConfigTab)  # Extracting IP from DB
    logger.info("ip_entry %s", ip_entry)
    BASE_URL = f"http://{ip_entry.Instance_IP}/"
    logger.info("BASE_URL %s", BASE_URL)
    # BASE_URL = "http://13.203.60.158/"
    target_endpoint = request.data.get("endpoint")  # Extract endpoint from request body

    if not target_endpoint:
        return Response({"error": "Missing 'endpoint' in request data"}, status=status.HTTP_400_BAD_REQUEST)

    url = f"{BASE_URL}{target_endpoint}"
    logger.info("Final url %s", url)
    data = {key: value for key, value in request.data.items() if key != "file"}
    files = request.FILES
    try:
        response = requests.request(
            method=request.method,
            url=url,
            data=data,
            files=files
        )

        return Response(response.json(), status=response.status_code)

    except requests.RequestException as e:
        return Response({"error": 'Contact Admin for Support'}, status=status.HTTP_502_BAD_GATEWAY)


run_time = time(1, 0, 0)


def schedule_job():
    schedule.every().day.at(run_time.strftime('%H:%M')).do(sla_email)


schedule_job()


# while True:
#     import time
#     schedule.run_pending()
#     time.sleep(1)
# -- Cron End --
# ............... SLA with Cron end .............


def generate_sequence_ids(form_schema, organization_id):
    """
    Generates sequence IDs for fields with type 'seqGen' in the form schema.
    
    Args:
        form_schema (list): List of form field dictionaries.
        organization_id (str): Organization ID used for generating sequence IDs.
        
    Returns:
        list: List of dictionaries containing field_id, value, and label.
    """
    logger.info("generate_sequence_ids")
    filtered_sequence = [x for x in form_schema if x.get("type") == "seqGen"]
    sequence_schema_with_value = []

    if filtered_sequence:
        for sequence in filtered_sequence:
            access_id = sequence.get("format")
            sequence_id_class = GenerateSequenceIdView()
            generated_id = sequence_id_class.generate_sequence_id(access_id, organization_id)
            data = {
                'field_id': sequence.get("field_id"),
                'value': generated_id,
                'label': sequence.get("label")
            }
            sequence_schema_with_value.append(data)

    return sequence_schema_with_value


# import json
#
# with open("db.json", "r", encoding="utf-8") as f:
#     data = json.load(f)
#
# dms_records = [item for item in data if item["model"] == "custom_components.dms"]
#
# with open("dms.json", "w", encoding="utf-8") as f:
#     json.dump(dms_records, f, indent=4)
#
# print(f"Extracted {len(dms_records)} DMS records to dms.json")

class CaseFinanceAmountUpdateAPIView(APIView):
    """
    Update fin_amount using entity_type + bs_code in parent_case_data.
    """

    def post(self, request, organization_id, process_id):
        updates = request.data.get("updates")

        if not updates or not isinstance(updates, list):
            return Response(
                {"error": "'updates' must be a list of objects containing 'entity_type', 'bs_code', 'fin_amount'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        success_updates = []
        failed_updates = []

        try:
            cases = Case.objects.filter(
                organization_id=organization_id,
                processId_id=process_id
            )

            if not cases.exists():
                return Response(
                    {"error": "No cases found for given organization and process."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            with transaction.atomic():

                for update_item in updates:
                    entity_type = update_item.get("entity_type")
                    bs_code = update_item.get("bs_code")
                    new_amount = update_item.get("fin_amount")

                    # Validate fields
                    if not entity_type or not bs_code or new_amount is None:
                        failed_updates.append({
                            "entity_type": entity_type,
                            "bs_code": bs_code,
                            "error": "Missing entity_type or bs_code or fin_amount"
                        })
                        continue

                    matching_case = None

                    # Find correct case
                    for case_obj in cases:
                        parent_json = case_obj.parent_case_data or []

                        if not isinstance(parent_json, list):
                            continue

                        et_field = next((f for f in parent_json if f.get("field_id") == "fin_entity_type"), None)
                        bs_field = next((f for f in parent_json if f.get("field_id") == "fin_bs_code"), None)

                        if et_field and bs_field:
                            if et_field.get("value") == entity_type and bs_field.get("value") == bs_code:
                                matching_case = case_obj
                                break

                    if not matching_case:
                        failed_updates.append({
                            "entity_type": entity_type,
                            "bs_code": bs_code,
                            "error": "No matching case found"
                        })
                        continue

                    # Update fin_amount
                    parent_json = matching_case.parent_case_data
                    updated = False

                    for field in parent_json:
                        if field.get("field_id") == "fin_amount":
                            field["value"] = new_amount
                            updated = True
                            break

                    if not updated:
                        failed_updates.append({
                            "entity_type": entity_type,
                            "bs_code": bs_code,
                            "error": "'fin_amount' field missing"
                        })
                        continue

                    matching_case.parent_case_data = parent_json
                    matching_case.save(update_fields=["parent_case_data"])

                    success_updates.append({
                        "entity_type": entity_type,
                        "bs_code": bs_code,
                        "new_amount": new_amount
                    })

            return Response(
                {
                    "message": "Update completed.",
                    "updated": success_updates,
                    "failed": failed_updates,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            # Safe generic exception (no sensitive data)
            return Response(
                {"error": "An unexpected error occurred during update.",
                 "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )





# class CaseFinanceAmountUpdateAPIView(APIView):
#     """
#     Update 'fin_amount' for one or more BS codes inside parent_case_data
#     for all cases under a given organization and process.
#     """
#
#     def put(self, request, organization_id, process_id):
#         updates = request.data.get("updates")
#
#         if not updates or not isinstance(updates, list):
#             return Response(
#                 {"error": "'updates' must be a list of objects with 'bs_code' and 'fin_amount'."},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#
#         success_updates = []
#         failed_updates = []
#
#         try:
#             cases = Case.objects.filter(
#                 organization_id=organization_id,
#                 processId_id=process_id
#             )
#
#             with transaction.atomic():
#                 for update_item in updates:
#                     bs_code = update_item.get("bs_code")
#                     new_amount = update_item.get("fin_amount")
#
#
#                     if not bs_code or new_amount is None:
#                         failed_updates.append(
#                             {"bs_code": bs_code, "error": "Missing bs_code or fin_amount"}
#                         )
#                         continue
#
#                     target_case = None
#                     for case_obj in cases:
#                         parent_json = case_obj.parent_case_data or []
#                         if not isinstance(parent_json, list):
#                             continue
#
#                         bs_field = next(
#                             (item for item in parent_json if item.get("field_id") == "fin_bs_code"),
#                             None
#                         )
#                         if bs_field and bs_field.get("value") == bs_code:
#                             target_case = case_obj
#                             break
#
#                     if not target_case:
#                         failed_updates.append(
#                             {"bs_code": bs_code, "error": "No matching case found"}
#                         )
#                         continue
#
#                     parent_json = target_case.parent_case_data
#                     updated = False
#                     for field in parent_json:
#                         if field.get("field_id") == "fin_amount":
#                             field["value"] = new_amount
#                             updated = True
#                             break
#
#                     if not updated:
#                         failed_updates.append(
#                             {"bs_code": bs_code, "error": "'fin_amount' field missing"}
#                         )
#                         continue
#
#                     target_case.parent_case_data = parent_json
#                     target_case.save(update_fields=["parent_case_data"])
#                     success_updates.append({"bs_code": bs_code, "new_amount": new_amount})
#
#             return Response(
#                 {
#                     "message": "Update completed successfully.",
#                     "updated": success_updates,
#                     "failed": failed_updates,
#                 },
#                 status=status.HTTP_200_OK,
#             )
#
#         except Exception as e:
#             return Response(
#                 {"error": f"Update failed: {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             )


# Initialize client
client = OpenAI(api_key=settings.OPENAI_API_KEY)

class ModelListView(APIView):
    """
    Returns list of supported OpenAI models.
    """
    def get(self, request):
        models = [
            {"id": "gpt-4o-mini", "name": "GPT-4o Mini "},
            {"id": "On-prem LLM", "name": "GPT-4o "}, 
        ]
        return Response({"models": models}, status=status.HTTP_200_OK)


class PromptBotView(APIView):
    def post(self, request):
        try:
            prompt_template = request.data.get("prompt", "")
            selected_model = request.data.get("model", "gpt-4o-mini") # Default Model
            output_keys = request.data.get("output_keys",[])  # output keys to extract

            if not prompt_template:
                return Response({"error": "Prompt is required"}, status=status.HTTP_400_BAD_REQUEST)
            
            if not isinstance(output_keys, list) or not output_keys:
                return Response({"error": "output_keys must be a non-empty list"}, status=status.HTTP_400_BAD_REQUEST)

            keys_str = ", ".join([f'"{key}"' for key in output_keys])
            json_instruction = f"""
                Return the result strictly in **valid JSON** format only.
                Your response must contain exactly these keys: [{keys_str}]
                For example:
                {{
                    {", ".join([f'"{key}": <{key}_value>' for key in output_keys])}
                }}
                Do not include any explanations or text outside the JSON.Values must be relevant to the prompt and value must be single value not list or object unless explicitly asked for.
                """

            final_prompt_with_json = prompt_template + "\n\n" + json_instruction

            #  Call OpenAI model
            completion = client.chat.completions.create(
                model=selected_model,
                messages=[{"role": "user", "content": final_prompt_with_json}],
                max_tokens=600,  # control output length
                temperature=0.3, # lower randomness  faster output
            )

            response_text = completion.choices[0].message.content.strip()

            # --- Clean out Markdown formatting (```json ... ``` etc.)
            response_text = re.sub(r"^```(?:json)?", "", response_text)
            response_text = re.sub(r"```$", "", response_text)
            response_text = response_text.strip()

            # --- Try parsing it as JSON if it's valid
            try:
                parsed_json = json.loads(response_text)
            except json.JSONDecodeError:
                # If not valid, just return the cleaned string
                parsed_json = response_text

            return Response({
                "prompt": prompt_template,
                "data": parsed_json,
            }, status=status.HTTP_200_OK)


        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

