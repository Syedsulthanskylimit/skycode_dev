import ast
import random
import re
import traceback
import uuid
from collections import Counter
from sqlite3 import IntegrityError
from sys import platform
from urllib import request

# authentication token based
# from rest_framework import permissions
# from rest_framework.permissions import BasePermission

from django.db import DatabaseError, IntegrityError

from django.shortcuts import get_object_or_404, get_list_or_404
from django.urls import reverse

from django_celery_beat.models import CrontabSchedule, PeriodicTask
from rest_framework.parsers import FormParser

from custom_components.utils.generate_uid import generate_uid

from .models import Bot, BotSchema, Integration, IntegrationDetails, NotificationData, Organization, UserGroup, Permission, Ocr, Dms, \
    Dashboard, Dms_data, Scheduler, SchedulerData, ReportConfig, Ocr_Details, BotData, NotificationBotSchema, Agent
from form_generator.models import ConfigTab, CreateProcess, FormDataInfo, Notification, NotificationConfig, NotificationConfig, NotificationDismiss, Rule, Case, Sequence, \
    UserData, FormPermission, UserFormSchema, FilledFormData, EndElement
from form_generator.serializer import CreateProcessSerializer, FormDataInfoSerializer, RuleSerializer, \
    FilledDataInfoSerializer, UserLoginSerializer, CreateProcessResponseSerializer, CaseSerializer, \
    CaseDashboardSerializer
from .serializer import BotSerializer, BotSchemaSerializer, BotDataSerializer, \
    IntegrationSerializer, IntegrationDetailsSerializer, OrganizationSerializer, UserGroupSerializer, \
    PasswordResetSerializer, Ocr_DetailsSerializer, OcrSerializer, DashboardSerializer, DmsSerializer, \
    DmsDataSerializer, SchedulerSerializer, ReportConfigSerializer, ScriptExecutionSerializer, \
    NotificationBotSchemaSerializer, AgentSerializer
from custom_components.utils.email_utils import send_email  # Adjust the import based on your app name
from automation.models import SlaConfig, SlaCaseInstance
from .tasks import monitor_emails_task  # imported from custom_componets
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from rest_framework.generics import RetrieveUpdateAPIView
from django.contrib.auth import views as auth_views
from django.contrib.auth.hashers import make_password
from rest_framework.exceptions import APIException
# Import for Components BGN --Fo

# Google_drive bot imports BGN

from google.oauth2 import service_account

from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload

from rest_framework.decorators import api_view
from rest_framework import generics, status, serializers

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
# Google_drive bot imports END

# api integration and screen scraping BGN
from rest_framework.response import Response

from django.core.exceptions import ValidationError

from .utils.query_parser import evaluate_conditions
from form_generator.utils.dashboard_cases_api import DashboardCasesView

# from .utils.rpa_handler import RPAHandler

"""----Screen scraping(Automation) package-----"""
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

from selenium.common.exceptions import TimeoutException, WebDriverException, StaleElementReferenceException, \
    NoSuchWindowException, NoSuchElementException, ElementNotInteractableException
from selenium.webdriver.chrome.options import Options
from time import sleep
from selenium.webdriver.common.action_chains import ActionChains

# api integration and screen scraping END

# Import for Components END --

import json
from django.http import FileResponse, Http404, JsonResponse
from rest_framework.views import APIView

from django.contrib.auth.tokens import PasswordResetTokenGenerator

from django.contrib.auth import authenticate, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# import for OCR Components starts ######################################

import pandas as pd

from requests.exceptions import RequestException, SSLError, Timeout
from requests.auth import HTTPBasicAuth
from rest_framework.exceptions import NotFound
from django.core.exceptions import ObjectDoesNotExist

from PIL import Image, ImageDraw
from datetime import datetime, timezone, date
from django.utils import timezone
from .serializer import DashboardConfigurationSerializer
from datetime import date, timedelta
from random import sample
from decimal import Decimal
from django.http import HttpResponseBadRequest
# import for OCR Components ends ######################################
from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client.file import Storage
from apiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.http import MediaIoBaseUpload
from google.oauth2.credentials import Credentials
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from oauth2client.file import Storage
from google.auth.transport.requests import Request
import base64
from selenium.webdriver.chrome.service import Service as ChromeService
from django.core.mail import get_connection, BadHeaderError
from smtplib import SMTPException

"""----------------------OneDrive-----------------------"""
from msal import ConfidentialClientApplication, SerializableTokenCache

"""----------------s3 Bucket--------------------------"""
import boto3
from botocore.exceptions import NoCredentialsError, ClientError

"""---------------Mail Monitor-----------------"""

import os
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

"""---------------Create Log file-------------------"""
import logging
import os, uuid, paramiko
from datetime import datetime
from django.conf import settings

"""------------Scheduler__________________________________"""

# logger = logging.getLogger(__name__)
User = get_user_model()
logger = logging.getLogger('custom_components')  # Replace 'myapp' with the name of your app
IGNORE_ERRORS = [
    "web view not found"
]


class ListProcessesByOrganization(APIView):
    """
    List processes by organization ID and optionally by process ID,
    along with related bots, integrations, and rules
    """

    def get(self, request, organization_id, process_id=None):
        try:
            # processes = CreateProcess.objects.filter(organization_id=organization_id)
            if process_id:
                # process = CreateProcess.objects.filter(organization_id=organization_id, id=process_id).first()
                process = CreateProcess.objects.filter(organization_id=organization_id, id=process_id,
                                                       parent_process__isnull=True).first()
                if not process:
                    return Response({"error": "Process not found."}, status=status.HTTP_404_NOT_FOUND)

                    # Return a single process as an object
                process_data = self.get_process_data(process)
                process_data['subprocess'] = self.get_subprocesses(process.id)
                process_data['dms'] = list(Dms.objects.filter(organization=organization_id, flow_id=process.id).values())
                return Response(process_data, status=status.HTTP_200_OK)
            else:
                # Retrieve all processes for the organization
                processes = CreateProcess.objects.filter(organization_id=organization_id, parent_process__isnull=True).order_by('-updated_on')
                if not processes.exists():
                    return Response({"message": "No processes found for the given organization."},
                                    status=status.HTTP_404_NOT_FOUND)
                # print("processes",processes.user)
                # Serialize the processes into an object format
                processes_data = []
                for process in processes:
                    process_data = self.get_process_data(process)
                    process_data['subprocess'] = self.get_subprocesses(process.id)
                    # processes_data[process.id] = process_data
                    processes_data.append(process_data)

                return Response(processes_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_process_data(self, process):
        """Fetch process details, including participants, forms, and user groups."""
        process_data = {
            "id": process.id,
            "process_name": process.process_name,
            "participants": self.get_participants(process),
            "process_description": process.process_description,
            "org_id": process.organization_id,
            "process_stages": process.process_stages if hasattr(process,
                                                                "process_stages") and process.process_stages else {},
            "process_table_configuration": process.process_table_configuration if hasattr(process,
                                                                                          "process_table_configuration") and process.process_table_configuration else {},
            "parent_case_data_schema": process.parent_case_data_schema if hasattr(process,
                                                                                  "parent_case_data_schema") and process.parent_case_data_schema else [],
            "process_table_permission": process.process_table_permission if hasattr(process,
                                                                                    "process_table_permission") and process.process_table_permission else [],

            # "user_groups": process.user_group
        }

        bots = BotSchema.objects.filter(flow_id=process.id).select_related('bot')
        process_data['bots'] = [{
            'id': bot.id,
            'bot_uid': bot.bot.bot_uid,
            'bot_name': bot.bot.bot_name,
            'bot_description': bot.bot.bot_description,
            'bot_schema_json': bot.bot_schema_json,
            "bot_element_permission": bot.bot_element_permission,
            'organization_id': bot.organization_id,
            'flow_id_id': bot.flow_id_id
        } for bot in bots]
        from django.db.models import F
        process_data['integrations'] = list(Integration.objects.filter(flow_id=process.id).values())
        process_data['rules'] = {'RuleConditions': list(Rule.objects.filter(processId=process.id).values())}
        process_data['ocr'] = list(Ocr.objects.filter(flow_id=process.id).values())
        process_data['scheduler'] = list(Scheduler.objects.filter(process=process.id).values())
        process_data['codeblock_config'] = list(
            Rule.objects.filter(processId=process.id).values(
                code_block_schema_json=F('process_codeblock_schema'),
                code_block_uid=F('ruleId'),
                code_block_name=F('rule_type')
            )
        )
        process_data['notification_config'] = list(NotificationBotSchema.objects.filter(process=process.id).values())
        process_data['sla'] = list(SlaConfig.objects.filter(process_id=process.id).values())
        process_data['end_element_info'] = list(EndElement.objects.filter(process=process.id).values())
        # Fetch forms and their permissions
        forms = FormDataInfo.objects.filter(processId=process.id).values()
        form_rule_schemas = []  # Collect form_rule_schema separately

        for form in forms:
            form_permissions = FormPermission.objects.filter(form_id=form['id']).values(
                'user_group', 'read', 'write', 'edit'
            )
            form['permissions'] = list(form_permissions) if form_permissions else []

            form_rule = Rule.objects.filter(form_id=form['id']).values('form_rule_schema').first()
            if form_rule:
                form['form_rule_schema'] = form_rule['form_rule_schema']  # Attach it to the form
                form_rule_schemas.append(form_rule['form_rule_schema'])  # Store separately if needed

        # form_rule_schemas.append(form_rule['form_rule_schema'])
        process_data['form'] = list(forms)
        # process_data['form_rule_schema'] = form_rule_schemas  # Sending form_rule_schema separately
        # Fetch user groups
        # user_groups = process_data['user_groups']  # Assuming user_group is already serialized as a list of IDs
        # process_data['user_group'] = UserGroup.objects.filter(id__in=user_groups).values('id', 'group_name')
        #
        # "user_group": list(process.usergroup_set.values("id", "group_name")),

        # user_groups = list(process.user_group.values("id", "group_name")),  # Use related_name

        user_groups = process.user_group.values("id", "group_name")
        process_data['user_group'] = user_groups
        # process_data["user_groups"] = user_groups  # Store the list in process_data
        # print("process_data",process_data)
        return process_data

    def get_subprocesses(self, parent_process_id):
        """Recursively fetch subprocesses and their nested subprocesses."""
        subprocesses = CreateProcess.objects.filter(parent_process_id=parent_process_id)
        subprocess_data = []

        for subprocess in subprocesses:
            data = self.get_process_data(subprocess)

            # Add the subprocess UID explicitly
            data['subprocess_UID'] = subprocess.subprocess_UID  # Assuming the field exists in your model

            # Recursively fetch nested subprocesses
            data['subprocess'] = self.get_subprocesses(subprocess.id)
            form_rule_schemas = []
            # Add form data for the subprocess
            forms = FormDataInfo.objects.filter(processId=subprocess.id).values()
            for form in forms:
                form_permissions = FormPermission.objects.filter(form_id=form['id']).values(
                    'user_group', 'read', 'write', 'edit'
                )
                form['permissions'] = list(form_permissions) if form_permissions else []
                form_rule = Rule.objects.filter(form_id=form['id']).values('form_rule_schema').first()
                if form_rule:
                    form['form_rule_schema'] = form_rule['form_rule_schema']  # Attach it to the form
                    form_rule_schemas.append(form_rule['form_rule_schema'])

            data['form'] = list(forms)
            user_groups = subprocess.user_group.values('id', 'group_name')  # Use related_name
            data['user_group'] = list(user_groups)

            # # Add user groups for the subprocess
            # user_groups = UserGroup.objects.filter(processes=subprocess).values('id', 'group_name')
            # data['user_groups'] = list(user_groups)

            subprocess_data.append(data)

        return subprocess_data

    def get_participants(self, process):
        """Directly fetch participants JSON."""
        # Retrieving  participants JSON is stored in the process object
        return process.participants


class CreateProcessView(APIView):
    """
    Create a new process
    """

    def post(self, request):
        try:
            serializer = CreateProcessSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            organization = serializer.validated_data.get("organization")
            organization_id = organization.id if organization else None

            # Generate UID using organization_id
            uid = generate_uid(
                model=CreateProcess,
                prefix="PRC",
                organization_id=organization_id
            )

            serializer.save(uid=uid)

            logger.info(f"New process created successfully: {uid}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except serializers.ValidationError as e:
            logger.warning(f"Validation error creating process: {e.detail}")
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Failed to create new process: {str(e)}", exc_info=True)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class ProcessDetailView(RetrieveUpdateAPIView):
    """
    Retrieve, update or delete a process instance.
    """
    queryset = CreateProcess.objects.all()
    serializer_class = CreateProcessSerializer


# API to create the Bot Component, List and Update  starts ############################

class BotListCreateView(generics.ListCreateAPIView):
    # queryset = BotSchema.objects.all()
    serializer_class = BotSchemaSerializer

    # List all the bots
    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        if organization_id:
            return BotSchema.objects.filter(organization=organization_id).select_related('bot')
        return BotSchema.objects.all().select_related('bot')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        response_data = []

        for botschema in queryset:
            flow_data = None
            if botschema.flow_id:  # Check if flow_id is not None
                flow_data = CreateProcessSerializer(botschema.flow_id).data
            combined_data = {
                'id': botschema.bot.id,
                'bot_schema_json': botschema.bot_schema_json,
                'flow_id': flow_data,
                'organization': botschema.organization.id,  # Assuming organization ID is enough
                'bot_name': botschema.bot.bot_name,
                'bot_description': botschema.bot.bot_description,
                'name': botschema.bot.name,
            }
            response_data.append(combined_data)

        return JsonResponse(response_data, safe=False, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        logger.info("Creating a bot")
        bot_data = request.data

        bot_name = bot_data.get('bot_name')
        name = bot_data.get('name')
        bot_description = bot_data.get('bot_description')
        bot_schema_json = bot_data.get('bot_schema_json')
        organization_id = bot_data.get('organization')

        bot_data = {
            'name': name,
            'bot_name': bot_name,
            'bot_description': bot_description,
        }
        logger.debug(f"bot_data: {bot_data}")

        bot_serializer = BotSerializer(data=bot_data)

        if bot_serializer.is_valid():
            try:
                bot_instance = bot_serializer.save()
            except Exception as e:
                logger.error(f"Error saving bot: {e}")
                raise APIException(f"An error occurred while saving the bot: {e}")
        else:
            logger.error(f"Invalid bot data: {bot_serializer.errors}")
            return Response(bot_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        flow_id = bot_data.get('flow_id', None)
        bot_schema_data = {
            'bot': bot_instance.id,
            'bot_schema_json': bot_schema_json,
            'flow_id': flow_id,  # Assuming flow_id is not provided in the input
            'organization': organization_id
        }
        logger.debug(f"bot_schema_data: {bot_schema_data}")

        bot_schema_serializer = BotSchemaSerializer(data=bot_schema_data)
        print("bot_serializer", bot_schema_data)
        if bot_schema_serializer.is_valid():
            try:
                bot_schema_instance = bot_schema_serializer.save()
                print("bot_schema_instance", bot_schema_instance)
            except Exception as e:
                logger.error(f"Error saving bot schema: {e}")
                bot_instance.delete()
                raise APIException(f"An error occurred while saving the bot schema: {e}")
        else:
            logger.error(f"Invalid bot schema data: {bot_schema_serializer.errors}")
            bot_instance.delete()
            return Response(bot_schema_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        logger.info("Successfully created bot")
        return Response({"message": "Bot created successfully"}, status=status.HTTP_201_CREATED)


class BotDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BotSerializer

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        bot_id = self.kwargs.get('id')
        return Bot.objects.filter(id=bot_id)

    def retrieve(self, request, *args, **kwargs):
        organization_id = self.kwargs.get('organization_id')
        bot_id = self.kwargs.get('id')
        try:
            bot_instance = Bot.objects.get(id=bot_id)
            bot_schema_instance = BotSchema.objects.get(bot=bot_id, organization=organization_id)
        except Bot.DoesNotExist:
            logger.error(f"Bot with id {bot_id} not found")
            return Response({"error": "Bot not found"}, status=status.HTTP_404_NOT_FOUND)
        except BotSchema.DoesNotExist:
            logger.error(f"BotSchema with bot id {bot_id} and organization {organization_id} not found")
            return Response({"error": "BotSchema not found"}, status=status.HTTP_404_NOT_FOUND)

        bot_serializer = self.get_serializer(bot_instance)
        bot_schema_json = bot_schema_instance.bot_schema_json  # Get only bot_schema_json

        response_data = bot_serializer.data
        response_data['bot_schema_json'] = bot_schema_json

        return Response(response_data)

    def update(self, request, *args, **kwargs):
        bot_id = self.kwargs.get('id')
        try:
            bot_instance = Bot.objects.get(id=bot_id)
        except Bot.DoesNotExist:
            logger.error(f"Bot with id {bot_id} not found")
            return Response({"error": "Bot not found"}, status=status.HTTP_404_NOT_FOUND)

        bot_data = request.data
        bot_schema_json = bot_data.get('bot_schema_json')
        organization_id = bot_data.get('organization')  # For bot schema

        bot_serializer = BotSerializer(bot_instance, data=bot_data, partial=True)
        if bot_serializer.is_valid():
            try:
                bot_instance = bot_serializer.save()
            except Exception as e:
                logger.error(f"Error updating bot: {e}")
                raise APIException(f"An error occurred while updating the bot: {e}")
        else:
            logger.error(f"Invalid bot data: {bot_serializer.errors}")
            return Response(bot_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if bot_schema_json is not None:
            try:
                bot_schema_instance = BotSchema.objects.get(bot=bot_instance.id, organization=organization_id)
                bot_schema_serializer = BotSchemaSerializer(bot_schema_instance,
                                                            data={'bot_schema_json': bot_schema_json}, partial=True)
                if bot_schema_serializer.is_valid():
                    bot_schema_instance = bot_schema_serializer.save()
                else:
                    logger.error(f"Invalid bot schema data: {bot_schema_serializer.errors}")
                    return Response(bot_schema_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            except BotSchema.DoesNotExist:
                logger.error("Bot schema does not exist")
                return Response({"error": "Bot schema does not exist"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                logger.error(f"Error updating bot schema: {e}")
                raise APIException(f"An error occurred while updating the bot schema: {e}")

        logger.info("Successfully updated bot")
        return Response({"message": "Bot updated successfully"}, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        bot_id = self.kwargs.get('id')
        try:
            bot_instance = Bot.objects.get(id=bot_id)
        except Bot.DoesNotExist:
            logger.error(f"Bot with id {bot_id} not found")
            return Response({"error": "Bot not found"}, status=status.HTTP_404_NOT_FOUND)

        bot_instance.delete()
        logger.info(f"Successfully deleted bot with id: {bot_instance.id}")
        return Response({"message": "Bot deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


# API to create the Bot Component, List and Update  ends #############################


# API to create the Integration starts ##############################

class IntegrationListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = IntegrationSerializer

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        if organization_id:
            return Integration.objects.filter(organization_id=organization_id)
        return Integration.objects.none()

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            logger.info(f"Integration created: {serializer.data}")
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Failed to create integration: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class IntegrationDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Integration.objects.all()
    serializer_class = IntegrationSerializer


# API to create the Integration ends ###############################

# API to create OCR components Starts ##############################

class OcrListCreateView(generics.ListCreateAPIView):
    serializer_class = OcrSerializer

    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        if organization_id:
            return Ocr.objects.filter(organization_id=organization_id)
        return Ocr.objects.all()

    def create(self, request, *args, **kwargs):
        request.data['organization'] = self.kwargs.get('organization_id')
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class OcrDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = OcrSerializer

    # permission_classes = [IsAuthenticated]

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        return Ocr.objects.filter(organization_id=organization_id)


# API to create OCR components Ends ##############################


# API to create Dashboard Starts #################################

class DashboardListCreateView(generics.ListCreateAPIView):
    serializer_class = DashboardSerializer

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        print("organization_id", organization_id)
        return Dashboard.objects.filter(organization_id=organization_id)

    def perform_create(self, serializer):
        organization_id = self.kwargs.get('organization_id')
        try:
            uid = generate_uid(
                model=Dashboard,
                prefix='DB',
                organization_id=organization_id
            )
            serializer.save(organization_id=organization_id, uid=uid)
        except ValidationError as e:
            logger.error(f"Validation error while creating dashboard: {e.detail}")
            raise e
        except Exception as e:
            logger.error(f"Unexpected error while creating dashboard: {e}")
            raise ValidationError("An unexpected error occurred while creating the dashboard.")

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except ValidationError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DashboardRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DashboardSerializer
    queryset = Dashboard.objects.all()

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        usergroup = self.kwargs.get('usergroup')
        if usergroup is not None:
            return Dashboard.objects.filter(organization_id=organization_id, usergroup=usergroup)
        else:
            return Dashboard.objects.filter(organization_id=organization_id)
        # return Dashboard.objects.filter(organization_id=organization_id, usergroup=usergroup)

    def get_object(self):
        organization_id = self.kwargs.get('organization_id')
        usergroup = self.kwargs.get('usergroup')
        pk = self.kwargs.get('pk')

        if pk is not None:  # Handling case where dashboard ID is provided
            filter_kwargs = {
                'id': pk,
                'organization_id': organization_id
            }
        elif usergroup is not None:  # Handling case where usergroup is provided
            filter_kwargs = {
                'organization_id': organization_id,
                'usergroup': usergroup
            }
        else:
            raise ValidationError("Invalid parameters provided")

        obj = get_object_or_404(Dashboard.objects.all(), **filter_kwargs)
        return obj

        # queryset = self.get_queryset()
        # filter_kwargs = {
        #     'organization_id': self.kwargs.get('organization_id'),
        #     'usergroup': self.kwargs.get('usergroup')
        # }
        # obj = get_object_or_404(queryset, **filter_kwargs)
        # return obj

    def perform_update(self, serializer):
        try:
            serializer.save()
        except ValidationError as e:
            logger.error(f"Validation error while updating dashboard: {e.detail}")
            raise e
        except Exception as e:
            logger.error(f"Unexpected error while updating dashboard: {e}")
            raise ValidationError("An unexpected error occurred while updating the dashboard.")

    def update(self, request, *args, **kwargs):
        try:
            return super().update(request, *args, **kwargs)
        except ValidationError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# API to create Dashboard Ends #################################

# API to create DMS Starts #####################################
class DmsListCreateView(generics.ListCreateAPIView):
    serializer_class = DmsSerializer

    def get_queryset(self):
        organization_id = self.kwargs['organization_id']
        return Dms.objects.filter(organization_id=organization_id)

    def perform_create(self, serializer):
        organization_id = self.kwargs['organization_id']
        try:
            organization = Organization.objects.get(id=organization_id)
            serializer.save(organization=organization)
        except Organization.DoesNotExist:
            raise ValidationError({"organization_id": "Invalid organization ID."})
        except IntegrityError as e:
            logger.error(f"IntegrityError: {e}")
            raise ValidationError({"detail": str(e)})

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except IntegrityError as e:
            logger.error(f"IntegrityError in create: {e}")
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# class DmsListCreateView(generics.ListCreateAPIView):
#     serializer_class = DmsDataSerializer
#
#     # permission_classes = [IsAuthenticated]
#
#     def get_queryset(self):
#         organization_id = self.kwargs['organization_id']
#         return Dms.objects.filter(organization_id=organization_id)
#
#     def perform_create(self, serializer):
#         organization_id = self.kwargs['organization_id']
#         # Retrieve the Organization instance using the provided organization_id
#         # organization = Organization.objects.get(id=organization_id)
#         # serializer.save(organization_id=organization_id)
#         try:
#             organization = Organization.objects.get(id=organization_id)
#             serializer.save(organization=organization)
#         except Organization.DoesNotExist:
#             raise ValidationError({"organization_id": "Invalid organization ID."})
#
#     def create(self, request, *args, **kwargs):
#         try:
#             return super().create(request, *args, **kwargs)
#         except IntegrityError as e:
#             return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class DmsRetrieveUpdateView(generics.RetrieveUpdateAPIView):
    # serializer_class = DmsDataSerializer
    serializer_class = DmsSerializer
    # permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        organization_id = self.kwargs['organization_id']
        return Dms.objects.filter(organization_id=organization_id)


# class DmsDataListView(generics.ListAPIView):
#     queryset = Dms_data.objects.all()
#     serializer_class = DmsDataSerializer

class DmsDataListView(generics.ListAPIView):
    serializer_class = DmsDataSerializer

    def get_queryset(self):
        organization_id = self.kwargs.get('organization_id')
        queryset = Dms_data.objects.filter(organization_id=organization_id).order_by('-id')
        print("Files found:", queryset.count())  # Debug
        return queryset
        # return Dms_data.objects.filter(organization_id=organization_id)


class DMSAPIView(APIView):
    def post(self, request, *args, **kwargs):
        # Extract filename from request data
        filename = request.data.get('filename')
        organization_id = request.data.get('organization_id')

        if not filename:
            return Response({"error": "Filename not provided."}, status=status.HTTP_400_BAD_REQUEST)

        if not organization_id:
            return Response({"error": "Organization ID not provided."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the Dms instance associated with the given organization ID
        try:
            dms_instance = Dms.objects.get(organization=organization_id)
        except Dms.DoesNotExist:
            return Response({"error": "DMS entry not found for the given organization."},
                            status=status.HTTP_404_NOT_FOUND)

        # Get the additional details from the Dms instance
        drive_types = dms_instance.drive_types
        config_details_schema = dms_instance.config_details_schema
        config_details_schema['drive_types'] = drive_types
        config_details_schema['filename'] = filename

        print("config_details_schema", config_details_schema)

        # Send the filename and additional data to another API
        self.send_filename_to_api(config_details_schema)

        return Response({"message": "Filename and details are downloaded ."}, status=status.HTTP_200_OK)

    def send_filename_to_api(self, config_details_schema):
        # external_api_url = 'http://192.168.0.106:8000/custom_components/FileDownloadView/'
        external_api_url = f'{settings.BASE_URL}/custom_components/FileDownloadView/'
        # Separate config_details_schema from the other data
        # Prepare the data for the request
        # data_to_send = {
        #     'filename': data['filename'],
        #     'drive_types': data['drive_types'],
        #     'config_details_schema': json.dumps(data['config_details_schema'])  # JSON stringify the config details
        # }
        print("config_details_schema", config_details_schema)
        response = requests.post(
            external_api_url,
            data=config_details_schema
        )
        if response.status_code != 200:
            raise Exception(f"Failed to send data to external API: {response.text}")


# API to create DMS Ends #####################################


class ProcessBuilder(APIView):
    """
    overall process created from here and this api will store all schemas to the particular tables.
    """

    def handle_subprocess_creation(self, subprocess_schema, organization_id, parent_process=None):
        """
        Handles the creation or update of subprocesses based on the provided schema and organization ID.

        Args:
            subprocess_schema (dict): The data for the subprocess to be created or updated.
            organization_id (int): The ID of the organization associated with the subprocess.

        Returns:
            str: A log message indicating success or failure.
        """

        try:

            # Fetch parent process ID if available
            parent_process_id = parent_process.id if parent_process else subprocess_schema.get('parent_process_id')
            if not parent_process_id:
                return "parent_process_id is missing in subprocess schema."

            # Fetch parent process instance if not already provided
            if not parent_process:
                parent_process = CreateProcess.objects.get(id=parent_process_id)

            # Fetch other data from the schema
            subprocess_name = subprocess_schema.get("process_name")
            subprocess_UID = subprocess_schema.get("subprocess_UID")
            subprocess_participants = subprocess_schema.get("participants")

            subprocess_process_description = subprocess_schema.get("process_description")
            user_groups = subprocess_schema.get("user_groups")
            subprocess_stages = subprocess_schema.get("process_stages") or {}

            subprocess_table_configure = subprocess_schema.get("process_table_configuration") or []
            parent_case_data_schema = subprocess_schema.get("parent_case_data_schema") or []
            process_table_permission = subprocess_schema.get("process_table_permission") or []
            # Fetch organization instance
            organization_instance = Organization.objects.get(id=organization_id)
            print("organization_instance", organization_instance)

            # Create or update subprocess
            subprocess, created = CreateProcess.objects.update_or_create(
                parent_process=parent_process,
                organization=organization_instance,
                subprocess_UID=subprocess_UID,
                defaults={
                    'process_name': subprocess_name,
                    'participants': subprocess_participants,
                    'process_description': subprocess_process_description,
                    'process_stages': subprocess_stages,
                    'process_table_configuration': subprocess_table_configure,
                    'parent_case_data_schema': parent_case_data_schema,
                    'process_table_permission': process_table_permission
                }
            )

            # Set user groups if provided
            if user_groups is not None:
                subprocess.user_group.set(user_groups)  # user_groups should be a list of IDs

            # Process related entities
            self._process_bots(subprocess_schema.get('bots', []), subprocess.id, organization_id)
            self._process_integrations(subprocess_schema.get('integrations', []), subprocess.id, organization_id)
            self._process_form_data_info(subprocess_schema.get('form_data_info', []), subprocess.id, organization_id)
            self._process_end_element_info(subprocess_schema.get('end_element_info', []), subprocess,
                                           organization_instance)
            self._process_rules(subprocess_schema.get('rules', {}), subprocess.id, organization_id)
            self._process_ocr(subprocess_schema.get('ocr', []), subprocess.id, organization_id)
            self._process_dms(subprocess_schema.get('dms', []), subprocess.id, organization_id)
            # self._process_scheduler(subprocess_schema.get('scheduler', {}), subprocess.id, organization_id)
            self._code_block_config(subprocess_schema.get('codeblock_config', []), subprocess.id, organization_id)
            self._notification_config(subprocess_schema.get('notification_config', []), subprocess.id, organization_id)
            self._process_sla(subprocess_schema.get('sla', {}), subprocess.id, organization_id)
            self._process_scheduler(request, subprocess_schema.get('scheduler_data', {}), subprocess.id,
                                    organization_id)
            # self._process_scheduler(request, scheduler_data, process_id, organization_id)
            subprocess.save()

            # Log creation or update
            logger.info(f"{'Created' if created else 'Updated'} subprocess with ID: {subprocess.id}")

            # Recursively handle nested subprocesses
            nested_subprocesses = subprocess_schema.get("subprocess", [])
            for nested_data in nested_subprocesses:
                self.handle_subprocess_creation(nested_data, organization_id, parent_process=subprocess)

            return subprocess

        except CreateProcess.DoesNotExist:
            logger.error("Parent process not found for ID: %s", parent_process_id)
            return f"Parent process with ID {parent_process_id} not found."

        except Organization.DoesNotExist:
            logger.error("Organization not found for ID: %s", organization_id)
            return f"Organization with ID {organization_id} not found."

        except Exception as e:
            logger.error("Error handling subprocess: %s", str(e))
            return f"Error: {str(e)}"

    # ************************************** process builder Updated with subprocess starts *************************

    def post(self, request):
        # Extract the incoming data from the request
        data = request.data

        # Retrieve process and organization details from the request
        process_id = data.get("id")
        organization_id = data.get("org_id")
        participants = data.get("participants")
        user_groups = data.get("user_groups")
        process_stages = data.get("process_stages", {})
        process_table_configure = data.get("process_table_configuration", [])
        parent_case_data_schema = data.get("parent_case_data_schema", [])
        process_table_permission = data.get("process_table_permission", [])  # Table Permission for subprocess

        try:
            # Attempt to retrieve the process by ID and update its details
            process = CreateProcess.objects.get(id=process_id)
            process.participants = participants
            process.process_stages = process_stages  # added in 14.3.25 to save process stages.
            # Step 1: Ensure all user groups exist (update or create)
            process.process_table_configuration = process_table_configure
            process.parent_case_data_schema = parent_case_data_schema
            process.process_table_permission = process_table_permission
            organization = Organization.objects.get(id=organization_id)
            updated_user_groups = []

            for group in user_groups:

                if isinstance(group, dict):  # Case 1: Group is a dictionary
                    user_group, _ = UserGroup.objects.update_or_create(
                        id=group['id'],  # Extract ID
                        defaults={'group_name': group.get('group_name', '')}  # Update name if available
                    )
                else:  # Case 2: Group is just an ID
                    user_group = UserGroup.objects.get(id=group)

                # print("user_group", user_group)
                updated_user_groups.append(user_group)

            # Step 3: Update many-to-many relationship with the updated user groups
            process.user_group.set(updated_user_groups)
            process.save()
        except CreateProcess.DoesNotExist:
            # Handle case where the process does not exist
            logger.error("Process not found: %s", process_id)
            return JsonResponse({"error": "Process not found"}, status=404)
        except Exception as e:
            # Log and handle generic errors
            logger.error("Error updating process: %s", str(e))
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Process any associated subprocess schemas
        parent_process = process
        subprocess_schema = data.get('subprocess', [])

        for schema in subprocess_schema:
            if isinstance(schema, dict):
                # Handle each subprocess schema dictionary
                result = self.handle_subprocess_creation(schema, organization_id, parent_process=parent_process)

            else:
                # Log invalid schema format
                logger.error("Invalid schema format inside subprocess_schema list. Expected a dictionary.")

        # Process related entities: bots, integrations, forms, rules, OCR data, DMS, and scheduler
        self._process_bots(data.get('bots', []), process_id, organization_id)
        self._process_integrations(data.get('integrations', []), process_id, organization_id)
        self._process_form_data_info(data.get('form_data_info', []), process_id, organization_id)
        self._process_end_element_info(data.get('end_element_info', []), process,
                                       organization)  ### added to get end element

        self._process_rules(data.get('rules', {}), process_id, organization_id)
        self._process_ocr(data.get('ocr', []), process_id, organization_id)
        self._process_dms(data.get('dms', []), process_id, organization_id)
        self._code_block_config(data.get('codeblock_config', []), process_id, organization_id)
        self._notification_config(data.get('notification_config', []), process_id, organization_id)
        # self._process_scheduler(data.get('scheduler_data', {}), process_id, organization_id)
        self._process_sla(data.get('sla', {}), process_id, organization_id)
        self._process_scheduler(request, data.get('scheduler_data', {}), process_id, organization_id)

        return Response({"message": "Data processed successfully"}, status=status.HTTP_200_OK)

    # Helper methods for processing data

    def _process_bots(self, bots_data, process_id, organization_id):
        # Log the received bots data

        for bot_data in bots_data:
            try:
                # Retrieve or create a bot instance
                bot_instance = self._get_or_create_bot(bot_data)
                bot_schema_data = {
                    'bot': bot_instance.id,
                    'bot_schema_json': bot_data.get('bot_schema_json'),
                    'bot_element_permission': bot_data.get('bot_element_permission'),
                    'flow_id': process_id,
                    'organization': organization_id,
                }
                # Retrieve or create the bot schema associated with the bot instance
                self._get_or_create_bot_schema(bot_instance, process_id, bot_schema_data)
            except Exception as e:
                # Log errors during bot processing
                logger.error("Error processing Bot: %s", str(e))
                raise

    def _get_or_create_bot(self, bot_data):
        # Retrieve or create a bot based on its unique identifier (bot_uid)
        bot_uid = bot_data.get('bot_uid')
        try:
            bot_instance = Bot.objects.get(bot_uid=bot_uid)
            # Update existing bot instance details
            bot_instance.bot_name = bot_data.get('bot_name')
            bot_instance.bot_description = bot_data.get('bot_description')
            bot_instance.bot_element_permission = bot_data.get('bot_element_permission')
            bot_instance.save()
        except Bot.DoesNotExist:
            # Create a new bot instance if it does not exist
            bot_serializer = BotSerializer(data=bot_data)
            if bot_serializer.is_valid():
                bot_instance = bot_serializer.save()
            else:
                # Raise an error if the serializer validation fails
                raise ValueError(bot_serializer.errors)
        return bot_instance

    def _get_or_create_bot_schema(self, bot_instance, process_id, bot_schema_data):
        # Retrieve or create a bot schema associated with the bot instance
        try:
            bot_schema_instance = BotSchema.objects.get(bot=bot_instance.id, flow_id=process_id)
            # Update the existing bot schema details
            bot_schema_instance.bot_schema_json = bot_schema_data['bot_schema_json']
            bot_schema_instance.bot_element_permission = bot_schema_data['bot_element_permission']
            bot_schema_instance.save()
        except BotSchema.DoesNotExist:
            # Create a new bot schema if it does not exist
            bot_schema_serializer = BotSchemaSerializer(data=bot_schema_data)
            if bot_schema_serializer.is_valid():
                bot_schema_serializer.save()
            else:
                # Raise an error if the serializer validation fails
                raise ValueError(bot_schema_serializer.errors)

    def _process_integrations(self, integrations_data, process_id, organization_id):
        # Log the received integrations data

        for integration_data in integrations_data:
            try:
                # Update or create integration records
                Integration.objects.update_or_create(
                    Integration_uid=integration_data.get('Integration_uid'),
                    flow_id_id=process_id,
                    organization_id=organization_id,
                    defaults={
                        'integration_type': integration_data.get('integration_type'),
                        'integration_schema': integration_data.get('integration_schema')
                    }
                )
            except Exception as e:
                # Log errors during integration processing
                logger.error("Error processing integration: %s", str(e))
                raise

    def _process_form_data_info(self, form_data_info_data, process_id, organization_id):
        # Log the received form data info

        for form_data in form_data_info_data:
            # Update or create form data info records
            form_data_instance, created = FormDataInfo.objects.update_or_create(
                Form_uid=form_data.get('Form_uid'),
                organization_id=organization_id,
                processId_id=process_id,
                defaults={
                    'form_name': form_data.get('form_name'),
                    'form_json_schema': form_data.get('form_json_schema'),
                    'form_style_schema': form_data.get('form_style_schema'),
                    'form_filter_schema': form_data.get('form_filter_schema'),  # to filter
                    'form_description': form_data.get('form_description'),
                    'form_send_mail': form_data.get('form_send_mail', False),
                    'form_send_mail_schema': form_data.get('form_send_mail_schema', {}),
                }
            )
            # Process form rule schema
            process = CreateProcess.objects.get(id=process_id)
            organization = Organization.objects.get(id=organization_id)
            form_rule_schema = form_data.get('form_rule_schema', {})
            if form_rule_schema:
                rule_instance, rule_created = Rule.objects.update_or_create(
                    form=form_data_instance,
                    processId=process,
                    organization=organization,
                    defaults={
                        'form_rule_schema': form_rule_schema,
                    }
                )

            # Process associated permissions for the form data
            self._process_form_permissions(form_data_instance, form_data.get('permissions', []))

    def _process_form_permissions(self, form_data_instance, permissions):
        if permissions:
            # Clear existing permissions and create new ones
            FormPermission.objects.filter(form=form_data_instance).delete()
            for permission in permissions:
                user_group = UserGroup.objects.get(id=permission['user_group'])
                FormPermission.objects.create(
                    form=form_data_instance,
                    user_group=user_group,
                    read=permission['read'],
                    write=permission['write'],
                    edit=permission['edit']
                )

    def _process_rules(self, rules_data, process_id, organization_id):
        # Log the received rules data
        for rule_data in rules_data.get('RuleConditions', []):
            try:
                # Update or create rule records
                rule_instance, created = Rule.objects.update_or_create(
                    ruleId=rule_data.get('rule_uid'),
                    organization_id=organization_id,
                    processId_id=process_id,
                    defaults={
                        'rule_json_schema': rule_data.get('conditions')
                    }
                )
            except Exception as e:
                # Log errors during rule processing
                logger.error("Error processing rule: %s", str(e))
                raise

    ############ process rule block
    def _code_block_config(self, code_block_data_list, process_id, organization_id):

        for code_block_data in code_block_data_list:
            try:
                rule_id = code_block_data.get('code_block_uid', '')
                if not rule_id:
                    logger.warning("Skipping code block with empty code_block_uid.")
                    continue  # Skip this iteration if rule_id is empty

                Rule.objects.update_or_create(
                    ruleId=rule_id,
                    defaults={
                        'organization_id': organization_id,
                        'processId_id': process_id,
                        'process_codeblock_schema': code_block_data.get('code_block_schema_json', {}),
                        'rule_type': code_block_data.get('code_block_name', '')
                    }
                )
            except Exception as e:
                logger.error("Error processing code_block_data: %s", str(e))
                raise

    ########## Notification Configuration save in process on 29.5.2025 #######################
    def _notification_config(self, notification_data_list, process_id, organization_id):

        # Get actual model instances
        organization = Organization.objects.get(id=organization_id)
        process = CreateProcess.objects.get(id=process_id)
        for notification_data in notification_data_list:
            try:
                notification_uid = notification_data.get('notification_uid', '')
                if not notification_uid:
                    logger.warning("Skipping notification config with empty notification_uid.")
                    continue  # Skip this iteration if notification_uid is missing

                try:
                    obj = NotificationBotSchema.objects.get(notification_uid=notification_uid)
                    logger.info("Updating existing NotificationBotSchema for UID: %s", notification_uid)
                except ObjectDoesNotExist:
                    obj = NotificationBotSchema(notification_uid=notification_uid)
                    logger.info("Creating new NotificationBotSchema for UID: %s", notification_uid)

                # Assign/update all fields
                obj.notification_name = notification_data.get('notification_name', '')
                obj.type = notification_data.get('type', 'notify')
                obj.notification_field_id = notification_data.get('notification_field_id', '')
                obj.receiver_type = notification_data.get('receiver_type', 'value')
                obj.receiver_mail = notification_data.get('receiver_mail', [])
                obj.mail_content = notification_data.get('mail_content', {})  # JSON content
                obj.notification_element_permission = notification_data.get('notification_element_permission', [])
                obj.organization = organization
                obj.process = process

                # Save to DB (create or update)
                obj.save()
                logger.info("NotificationBotSchema saved: %s", obj.id)

            except Exception as e:

                logger.error("Error processing notification_data: %s", str(e))
                raise

    #
    def _process_ocr(self, ocr_data_list, process_id, organization_id):
        # Log the received OCR data
        for ocr_data in ocr_data_list:
            try:
                # Update or create OCR records
                Ocr.objects.update_or_create(
                    ocr_uid=ocr_data.get('ocr_uid'),
                    organization_id=organization_id,
                    flow_id_id=process_id,
                    defaults={
                        'name': ocr_data.get('name'),
                        'description': ocr_data.get('description'),
                        'ocr_type': ocr_data.get('ocr_type')
                    }
                )
            except Exception as e:
                # Log errors during OCR processing
                logger.error("Error processing OCR: %s", str(e))
                raise

    def _process_dms(self, dms_data, process_id, organization_id):

        try:
            organization_instance = Organization.objects.get(id=organization_id)
            process_instance = CreateProcess.objects.get(id=process_id)  # Get the process instance

            dms_instances = []  # List to store valid DMS instances
            print("dms_data *********** : ",dms_data)

            for dms_entry in dms_data:
                dms_uid = dms_entry.get('dms_uid')
                dms_id = dms_entry.get('id')

                # Fetch existing DMS instance
                dms_instance = Dms.objects.filter(id=dms_id, organization=organization_instance).first()

                if dms_instance:
                    print("Updating --> ")
                    dms_instance.flow_id = process_instance
                    dms_instance.save()
                    dms_instances.append(dms_instance)

            if dms_instances:
                process_instance.dms.add(*dms_instances)  # Add DMS instances to ManyToManyField
                process_instance.save()

            return Response({"message": "DMS tagged to process successfully"})

        except Exception as e:
            logger.error("Error processing DMS: %s", str(e))
            return Response({"error": "Failed to tag DMS to process"}, status=400)

    def _process_sla(self, sla, process_id, organization_id):
        # Log the received OCR data
        organization_instance = Organization.objects.get(id=organization_id)
        process_instance = CreateProcess.objects.get(id=process_id)  # Get the process instance

        for sla_data in sla:
            try:
                # Update or create OCR records
                SlaConfig.objects.update_or_create(
                    sla_uid=sla_data.get('sla_uid'),
                    organization=organization_instance,
                    process_id=process_instance,
                    defaults={
                        'sla_name': sla_data.get('sla_name'),
                        # 'description': sla_data.get('description'),
                        'sla_json_schema': sla_data.get('sla_json_schema')
                    }
                )
            except Exception as e:
                # Log errors during OCR processing
                logger.error("Error processing sla: %s", str(e))
                raise

    from django.urls import reverse
    def _process_scheduler(self, request, scheduler_data, process_id, organization_id):
        """Handles scheduler creation and updating for a given process and organization."""

        if not scheduler_data:
            logger.info("No scheduler_data provided; skipping scheduler creation.")
            return

        # Construct API URL
        relative_url = reverse('create_scheduler',
                               kwargs={'process_id': process_id, 'organization_id': organization_id})
        full_url = request.build_absolute_uri(relative_url)

        # First, check if a scheduler already exists
        get_response = requests.get(full_url)

        if get_response.status_code == 200:
            logger.info("Existing scheduler found. Updating scheduler...")
            response = requests.put(full_url, json=scheduler_data)  # Update existing scheduler
        else:
            logger.info("No existing scheduler found. Creating new scheduler...")
            response = requests.post(full_url, json=scheduler_data)  # Create new scheduler

        # Log response
        if response.status_code in [200, 201]:  # Handle both update and create success cases
            logger.info("Scheduler processed successfully with data: %s", scheduler_data)
        else:
            logger.error("Scheduler processing failed with status: %s, response: %s", response.status_code,
                         response.text)

    def _process_end_element_info(self, end_element_info, process_id, organization_id):
        try:

            for end_element_schema in end_element_info:
                try:
                    element_uid = end_element_schema.get('element_uid')
                    element_type = end_element_schema.get('element_type')
                    element_name = end_element_schema.get('element_name')
                    end_element_schema = end_element_schema.get('end_element_schema')

                    if not element_uid:
                        logger.warning("Missing element_uid in schema: %s", end_element_schema)
                        continue  # Skip invalid entry

                    obj, created = EndElement.objects.update_or_create(
                        element_uid=element_uid,
                        organization=organization_id,
                        process=process_id,
                        defaults={
                            'element_type': element_type,
                            'element_name': element_name,
                            'end_element_schema': end_element_schema,
                        }
                    )
                    action = "Created" if created else "Updated"
                    logger.info("EndElement %s: %s", action, element_uid)

                except (IntegrityError, ValidationError) as e:
                    logger.error("Error saving EndElement %s: %s", end_element_schema.get('element_uid'), str(e))
                except Exception as e:
                    logger.exception("Unexpected error processing end element schema: %s", end_element_schema)

        except Exception as e:
            logger.exception("Unexpected error in _process_end_element_info: %s", str(e))


############################## Google Drive Extraction Bot Functionality ######################################

# to store the log details of the extractions
logger = logging.getLogger(__name__)


# This function gets the Google Drive service file and authenticate to access the file service account key file is
# integrated in settings.py
# def get_google_drive_service():
#     try:
#         creds = service_account.Credentials.from_service_account_file(
#             settings.SERVICE_ACCOUNT_KEY_FILE,
#             scopes=['https://www.googleapis.com/auth/drive']
#         )
#         print("creds",creds)
#         # Log credentials validity and token refresh
#         if not creds.valid:
#             print("creds is valid",creds.valid)
#             if creds.expired and creds.refresh_token:
#                 print("creds is valid", creds.expired)
#                 print("creds is valid", creds.refresh_token)
#                 logging.debug("Refreshing expired credentials")
#                 creds.refresh(Request())
#             else:
#                 logging.error("Invalid credentials and no refresh token available")
#                 return None
#
#         # Build and return the Google Drive service
#         # return build('drive', 'v3', credentials=creds)
#         print("resultsaaaaaaaaaaa")
#         service = build('drive', 'v3', credentials=creds)
#         print("results", service)
#         return service
#         # try:
#         #     results = service.files().list(pageSize=10).execute()
#         #     print("results",results)
#         #     items = results.get('files', [])
#         #     if not items:
#         #         print('No files found.')
#         #     else:
#         #         print('Files:')
#         #         for item in items:
#         #             print(f"{item['name']} ({item['id']})")
#         # except Exception as e:
#         #     print(f"Error occurred: {str(e)}")
#
#     except Exception as e:
#         # logging.error(f"An error occurred while creating the Google Drive service: {str(e)}")
#         logging.error("Error creating Google Drive service", exc_info=True)
#         return None


# return build('drive', 'v3', credentials=creds)

def get_google_drive_service():
    try:
        print("settings.SERVICE_ACCOUNT_KEY_FILE : ", settings.SERVICE_ACCOUNT_KEY_FILE)
        creds = service_account.Credentials.from_service_account_file(
            settings.SERVICE_ACCOUNT_KEY_FILE,
            scopes=['https://www.googleapis.com/auth/drive']
        )
        if not creds.valid and creds.expired:
            logging.debug("Refreshing expired credentials")
            creds.refresh(Request())
        print("Credentials created successfully")
        return build('drive', 'v3', credentials=creds)

    except Exception as e:
        print("get_google_drive_service error : ", e)
        logging.error("Error creating Google Drive service", exc_info=True)
        return None


# Download the file from drive and store
def download_file(drive_service, file_id, file_name):
    file_metadata = drive_service.files().get(fileId=file_id, fields='mimeType').execute()
    mime_type = file_metadata.get('mimeType')
    # mime_type = file_metadata['mimeType']
    # Handle Google Docs Editors file types
    export_mime_types = {
        'application/vnd.google-apps.document': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.google-apps.spreadsheet': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.google-apps.presentation': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    }

    if mime_type in export_mime_types:
        export_mime_type = export_mime_types[mime_type]
        request = drive_service.files().export_media(fileId=file_id, mimeType=export_mime_type)
        file_extension = export_mime_type.split('/')[-1].split('.')[-1]
        file_name = f"{file_name.split('.')[0]}.{file_extension}"
    else:
        request = drive_service.files().get_media(fileId=file_id)
    temp_file_path = os.path.join(settings.MEDIA_ROOT, 'tmp', file_name)
    os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
    try:
        with io.FileIO(temp_file_path, 'wb') as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
        return temp_file_path
    except Exception as e:
        print(f"An error occurred while downloading the file: {e}")
        return {"error": f"An error occurred while downloading the file: {e}"}

    # return temp_file_path


# move the file to completed folder
def move_file(drive_service, file_id, new_parent_id):
    try:
        # 06-09-2025 by Harish
        file_info = get_file_info(drive_service, file_id)
        previous_parents = file_info.get('parents', [])

        if not previous_parents:
            print(f"No previous parents found for the file: {file_id}")
            # return {"error": f"No previous parents found for the file: {file_id}"}

        previous_parents_str = ','.join(previous_parents) if previous_parents else None

        # Move the file to the new folder by removing the old parents and adding the new parent
        drive_service.files().update(
            fileId=file_id,
            addParents=new_parent_id,
            removeParents=previous_parents_str,
            supportsAllDrives=True,
            fields='id, parents'
        ).execute()

        return True
    except HttpError as error:
        print(f"An error occurred while moving the file: {error}")
        return False


# 06-09-2025 by Harish
def get_file_info(service, file_id):
    """Retrieve file metadata, including parents, drive ID, and permissions."""
    try:
        file = service.files().get(
            fileId=file_id,
            fields='id, name, parents, driveId, permissions',
            supportsAllDrives=True
        ).execute()
        return file
    except HttpError as error:
        print(f"Error retrieving info for file {file_id}: {error}")
        raise


# To get any type of file types
def get_mime_type(file_type):
    mime_types = {
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'csv': 'text/csv',
        'txt': 'text/plain',
        'pdf': 'application/pdf',
        'jpg': 'image/jpeg',
        'png': 'image/png',
    }
    return mime_types.get(file_type, 'application/octet-stream')


# API which gets file from the Google Drive and save it in Temp folder
@api_view(['POST'])
def list_drive_files(request):
    """

    :type request: object
    """
    try:
        # request_data = json.loads(request.body.decode('utf-8'))
        request_data = request.data

    except json.JSONDecodeError:
        return Response({"error": "Invalid JSON data in request body"}, status=400)

    folder_id = request_data.get('folder_id')

    if not folder_id:
        return Response({"error": "folder_id parameter is required"}, status=400)

    file_type = request_data.get('file_type')
    completed_folder_id = request_data.get('completed_folder_id')
    print("completed_folder_id", completed_folder_id)
    # Initialize the Drive service
    drive_service = get_google_drive_service()
    print("drive_service", drive_service)

    if not drive_service:
        logging.error("Failed to create Google Drive service.")
        return Response({"error": "Failed to create Google Drive service."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        # print("Failed to create Google Drive service.")
        # return

    query = f"'{folder_id}' in parents"
    print("query", query)
    if file_type:
        mime_type = get_mime_type(file_type)
        print("mime_type", mime_type)
        query += f" and mimeType='{mime_type}'"
        print("query", query)

    try:
        results = drive_service.files().list(q=query).execute()

        print("results", results)

        logger.info(f"Extracted file: {results}")
        items = results.get('files', [])
        logger.info(f"Extracted file: {items}")

        files = []
        for item in items:
            file_id = item['id']
            file_name = item['name']
            # file_name = item[0]['name'].rsplit('.', 1)[0]
            temp_file_path = download_file(drive_service, file_id, file_name)
            if isinstance(temp_file_path, dict) and "error" in temp_file_path:
                return Response(temp_file_path, status=400)

            try:
                moved_file = move_file(drive_service, file_id, completed_folder_id)
                if not moved_file:
                    return Response({"error": f"An error occurred while moving the file: {file_name}"}, status=400)

            except HttpError as error:
                return Response({"error": f"An error occurred while moving the file: {error}"}, status=400)

            file_schema = {
                'file_name': file_name,
                'file_id': file_id,
                # 'mimeType': item['mimeType'],
                'temp_data': temp_file_path,

            }
            print("file_schema ", file_schema)
            files.append(file_schema)
            logger.info(f"Extracted file: {file_schema}")
            logger.info(f"Updated file: {files}")
        return JsonResponse(files, safe=False)
    except HttpError as error:
        logging.error(f"An error occurred while listing files: {error}")
        return Response({"error": f"An error occurred: {error}"}, status=400)


@api_view(['POST'])
def convert_excel_to_json(request):
    try:
        # Get the JSON data from the request
        input_data = json.loads(request.body.decode('utf-8'))
        input_data = request.data
        # Validate input data
        if 'file_name' not in input_data or 'column_definitions' not in input_data:
            logger.error('Missing required fields in input JSON')
            return JsonResponse({"error": "Missing required fields in input JSON"}, status=400)

        file_name = input_data['file_name']
        sheet_name = input_data.get('sheet_name')
        column_definitions = input_data['column_definitions']
        file_path = input_data['file_path']

        # Read the Excel file
        df = pd.read_excel(file_path, sheet_name=sheet_name)

        # Initialize a new dictionary to hold the final column names
        final_columns = {}
        files = []
        # Process the column definitions to map the columns
        for definition in column_definitions:
            column_key = definition['column_key']
            field_labels = definition['field_labels']

            for col in df.columns:
                if col in field_labels:
                    final_columns[col] = column_key
                    break

        # Check if all required columns are mapped
        if len(final_columns) != len(column_definitions):
            missing_columns = set([d['column_key'] for d in column_definitions]) - set(final_columns.values())
            logger.error(f'Missing columns in Excel: {missing_columns}')
            return JsonResponse({"error": f"Missing columns in Excel: {missing_columns}"}, status=400)

        # Rename the columns based on the mapping found
        df = df.rename(columns=final_columns)

        # Select only the columns specified in the final mapping
        df = df[list(final_columns.values())]

        # Convert DataFrame to JSON
        json_data = df.to_json(orient='records', date_format='iso')

        # Transform JSON data into the desired format
        transformed_data = []
        for record in json.loads(json_data):
            for key, value in record.items():
                value_type = "String"
                if isinstance(value, bool):
                    value_type = "Boolean"
                elif isinstance(value, (int, float)):
                    value_type = "Number"
                elif isinstance(value, pd.Timestamp):
                    value_type = "Date"
                transformed_data.append({
                    "field_id": key,
                    "value": value,
                    "value_type": value_type
                })

        logger.info(f"Updated BotData entry for file: {file_name}")
        # Return the JSON data
        # return JsonResponse(json.loads(json_data), safe=False)
        response_data = {
            "data": transformed_data
        }
        files.append(response_data)
        return JsonResponse(response_data, safe=False)
        # Return the JSON data
        # return JsonResponse({"files": files}, safe=False)F

    except json.JSONDecodeError as e:
        logger.error(f'Error decoding JSON: {str(e)}')
        return JsonResponse({"error": f"Error decoding JSON: {str(e)}"}, status=400)
    except Exception as e:
        logger.error(f'Unexpected error: {str(e)}')
        return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)


########################## Google Drive END ##########################
@api_view(['POST'])
def convert_excel_to_json1(request):
    try:
        # Check if a file is provided directly in the request
        uploaded_file = request.FILES.get('file', None)

        # If no file is uploaded, check for file_name in the input data
        if not uploaded_file:
            input_data = json.loads(request.body.decode('utf-8'))

            # Validate input data for file_name and column definitions
            if 'file_name' not in input_data or 'column_definitions' not in input_data:
                logger.error('Missing required fields in input JSON')
                return JsonResponse({"error": "Missing required fields in input JSON"}, status=400)

            file_name = input_data['file_name']
            sheet_name = input_data.get('sheet_name')  # Optional sheet name
            column_definitions = input_data['column_definitions']

            # Assuming the file is stored locally; update path as needed
            file_path = os.path.join('path/to/files/directory', file_name)

            # Check if the file exists
            if not os.path.exists(file_path):
                logger.error(f'File not found: {file_name}')
                return JsonResponse({"error": f"File not found: {file_name}"}, status=404)

            # Read the Excel file from the file path
            df = pd.read_excel(file_path, sheet_name=sheet_name)
        else:
            # If a file is uploaded, process it directly
            input_data = json.loads(request.body.decode('utf-8'))

            # Validate input data for column definitions
            if 'column_definitions' not in input_data:
                logger.error('Missing column_definitions in input JSON')
                return JsonResponse({"error": "Missing column_definitions in input JSON"}, status=400)

            column_definitions = input_data['column_definitions']
            sheet_name = input_data.get('sheet_name')  # Optional sheet name

            # Read the Excel file from the uploaded file
            df = pd.read_excel(uploaded_file, sheet_name=sheet_name)

        # Initialize a new dictionary to hold the final column names
        final_columns = {}
        files = []

        # Process the column definitions to map the columns
        for definition in column_definitions:
            column_key = definition['column_key']
            field_labels = definition['field_labels']

            for col in df.columns:
                if col in field_labels:
                    final_columns[col] = column_key
                    break

        # Check if all required columns are mapped
        if len(final_columns) != len(column_definitions):
            missing_columns = set([d['column_key'] for d in column_definitions]) - set(final_columns.values())
            logger.error(f'Missing columns in Excel: {missing_columns}')
            return JsonResponse({"error": f"Missing columns in Excel: {missing_columns}"}, status=400)

        # Rename the columns based on the mapping found
        df = df.rename(columns=final_columns)

        # Select only the columns specified in the final mapping
        df = df[list(final_columns.values())]

        # Convert DataFrame to JSON
        json_data = df.to_json(orient='records', date_format='iso')

        # Transform JSON data into the desired format
        transformed_data = []
        for record in json.loads(json_data):
            for key, value in record.items():
                value_type = "String"
                if isinstance(value, bool):
                    value_type = "Boolean"
                elif isinstance(value, (int, float)):
                    value_type = "Number"
                elif isinstance(value, pd.Timestamp):
                    value_type = "Date"
                transformed_data.append({
                    "field_id": key,
                    "value": value,
                    "value_type": value_type
                })

        logger.info(f"Processed file successfully")

        # Return the JSON data
        response_data = {
            "data": transformed_data
        }
        files.append(response_data)
        return JsonResponse(response_data, safe=False)

    except json.JSONDecodeError as e:
        logger.error(f'Error decoding JSON: {str(e)}')
        return JsonResponse({"error": f"Error decoding JSON: {str(e)}"}, status=400)
    except Exception as e:
        logger.error(f'Unexpected error: {str(e)}')
        return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)


##################### API Integration and screen scraping BGN #############


class Inputdata_Converter:
    @staticmethod
    def convert_to_dict(data):
        result = {}
        for item in data:
            result[item['field_id']] = item['value']
        return result


class Customize_Input:
    @staticmethod
    def customize_input_data(input_data, schema_config, view_id):
        """Customize input data based on request fields."""
        customized_data = []
        if view_id == "api":
            request_fields = schema_config.get('request', [])
            for field in request_fields:
                request_field_id = field.get('field_id')
                request_value_type = field.get('value_type')
                request_value = field.get('value')
                for item in input_data:
                    if request_value == item.get('field_id'):
                        request_value = item.get('value')
                        break
                if request_value and request_value_type == "field_id":
                    customized_data.append({
                        'field_id': request_field_id,
                        'value': request_value,
                        'value_type': request_value_type
                    })
        elif view_id == "screen_scraping":
            for form_data in schema_config:
                forms = form_data.get('forms', [])
                for form in forms:
                    form_values = form.get('form_value', [])
                    for form_value in form_values:
                        form_field_id = form_value.get('field_id')
                        form_value_type = form_value.get('value_type')
                        form_value = None
                        for item in input_data:
                            if item.get('field_id') == form_field_id:
                                form_value = item.get('value')
                                break
                        if value and form_value_type == "field_id":
                            customized_data.append({
                                'field_id': form_field_id,
                                'value': form_value,
                                'value_type': form_value_type
                            })
        return customized_data


import platform


# Modified RPA settings on 12.09.2024
class AutomationSetting:
    """This class handles the setup, navigation, and interaction with web pages using Selenium WebDriver."""
    driver = None  # Class-level variable to hold the WebDriver instance

    @staticmethod
    def capture_screenshot(step_name):
        """Capture screenshot and save it with a unique name."""
        logger.info(f"Capture screenshot and save it with a unique name.")
        screenshots_dir = os.path.join(os.getcwd(), "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        screenshot_path = os.path.join(screenshots_dir, f"{step_name}_{timestamp}.png")

        try:
            if AutomationSetting.driver:
                AutomationSetting.driver.save_screenshot(screenshot_path)
                logger.info(f"Screenshot captured and saved to {screenshot_path}")
            else:
                raise NoSuchWindowException("WebDriver instance is not available.")
        except NoSuchWindowException as nwe:
            error_message = f"Error capturing screenshot: WebDriver window is closed or not available - {nwe.msg}"
            logger.error(error_message)
            raise
        except WebDriverException as wde:
            error_message = f"Error capturing screenshot: WebDriver exception - {wde.msg}"
            logger.error(error_message)
            raise
        except Exception as e:
            error_message = f"Unexpected error capturing screenshot: {e}"
            logger.error(error_message)
            raise

        return screenshot_path

    # @staticmethod
    # def is_aws_environment():
    #     """Determine if the current environment is AWS."""
    #     # You can use different methods to check if it's an AWS environment
    #     # Here's an example using the hostname or an environment variable
    #     return os.getenv("AWS_EXECUTION_ENV") is not None or "EC2" in platform.node()

    @staticmethod
    def is_aws_environment():
        """Determine if the current environment is AWS based on hostname."""
        try:
            hostname = platform.node()
            # Check if hostname starts with 'ip-'
            if hostname.startswith('ip-'):
                return True
            return False
        except Exception as e:
            print(f"Error checking environment: {e}")
            return False

    @staticmethod
    def initialize_driver(form_status):
        """Initialize the WebDriver and store it as a class attribute."""
        if AutomationSetting.driver is None:
            try:
                logger.info("Installing ChromeDriver using ChromeDriverManager...")
                # Ensure the path is pointing to the correct executable
                driver_path = ChromeDriverManager().install()
                if not driver_path.endswith("chromedriver.exe"):
                    driver_path = driver_path.replace("THIRD_PARTY_NOTICES.chromedriver", "chromedriver.exe")
                logger.info(f"ChromeDriver installed at: {driver_path}")
                logger.info("Initializing Chrome WebDriver...")
                chrome_options = Options()
                logger.info(f"AWS hosting {platform.node()} ")

                # Set the binary location explicitly
                if AutomationSetting.is_aws_environment():
                    logger.info("Running in AWS environment")
                    chrome_options.binary_location = "/usr/bin/google-chrome"
                    # AWS-specific options
                    chrome_options.add_argument("--headless")
                else:
                    logger.info("Running in local environment")
                    # Dynamically determine the Chrome binary location for local
                    if platform.system() == "Windows":
                        chrome_path = "C:/Program Files/Google/Chrome/Application/chrome.exe"
                    elif platform.system() == "Darwin":  # macOS
                        chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
                    else:  # Assume Linux
                        chrome_path = "/usr/bin/google-chrome"

                    if os.path.exists(chrome_path):
                        chrome_options.binary_location = chrome_path
                    else:
                        raise FileNotFoundError(f"Chrome binary not found at {chrome_path}")

                # chrome_options.binary_location = "/usr/bin/google-chrome"  # Adjust the path as needed
                # Add options to run Chrome in headless mode
                # Remove headless mode if you want a graphical interface
                # chrome_options.add_argument("--headless")
                chrome_options.add_argument("--disable-gpu")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                s = Service(executable_path=driver_path)
                AutomationSetting.driver = webdriver.Chrome(service=s, options=chrome_options)
                AutomationSetting.driver.maximize_window()
                logger.info("WebDriver initialized successfully.")
                form_status['initialized'] = True  # Update form_status
            except WebDriverException as wde:
                form_status["error"] = (f"Error initializing WebDriver: {wde.msg}")
                logger.error(form_status["error"])
                raise
                # form_status['error'] = f"Error initializing WebDriver: {wde}"
                # logger.error(f"Error initializing WebDriver: {wde}")
                # raise
            except Exception as e:
                form_status['error'] = f"Error initializing WebDriver: {e}"
                logger.error(form_status["error"])
                raise

    @staticmethod
    def navigate_to(url, form_status):
        """Navigate to the specified URL."""
        try:
            if AutomationSetting.driver is not None:
                AutomationSetting.driver.get(url)
                # AutomationSetting.capture_screenshot("navigated_to_url")
                logger.info(f"Navigated to URL: {url}")
            form_status["navigated"] = True  # Update form_status

        except WebDriverException as wde:
            form_status["error"] = f"Error navigating to URL {url}: {wde.msg}"
            logger.error(form_status["error"])
            raise

    @staticmethod
    def close_driver(form_status):
        """Close the WebDriver."""
        try:
            if AutomationSetting.driver is not None:
                # AutomationSetting.capture_screenshot("before_closing_driver")
                AutomationSetting.driver.quit()
                AutomationSetting.driver = None
                logger.info("WebDriver closed successfully.")
                form_status["initialized"] = True  # Update form_status
        except NoSuchWindowException as nwe:
            form_status["error"] = (f"Error closing WebDriver: {nwe.msg}")
            logger.error(form_status["error"])
            raise
        except WebDriverException as wde:
            form_status["error"] = (f"Error closing WebDriver: {wde.msg}")
            logger.error(form_status["error"])
            raise

    @staticmethod
    def setting(url, forms, input_data, form_status):
        """Set up the WebDriver, navigate to the login URL, and fill the forms."""
        get_element_result = []
        success = False
        try:
            AutomationSetting.initialize_driver(form_status)
            AutomationSetting.navigate_to(url, form_status)
            WebDriverWait(AutomationSetting.driver, 100).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))

            processed_forms_count = 0
            for form in forms:
                try:
                    form_values = {fv['field_id']: {'value': fv['value'], 'value_type': fv.get('value_type')} for fv in
                                   form.get('form_value', [])}
                    element_details = {el['efield_id']: {'evalue': el['evalue'], 'evalue_type': el['evalue_type'],
                                                         'eaction': el['eaction'], 'ewait': el['ewait'],
                                                         'eskip': el['eskip'], **(
                            {'ewait_second': el['ewait_second']} if el['ewait'] else {})} for el in
                                       form['form_element_details']}

                    form_status, get_element_result = AutomationSetting.fill_form(form_values, element_details,
                                                                                  input_data, form_status,
                                                                                  get_element_result)
                    sleep(2)

                    processed_forms_count += 1
                    form_status["processed_forms_count"] = processed_forms_count
                    logger.info(f"Processed {processed_forms_count} forms successfully for URL: {url}")

                except KeyError as ke:
                    form_status["error"] = f"Missing key in form data: {ke}"
                    logger.error(form_status["error"])
                    raise ValidationError(form_status["error"])
                except Exception as e:
                    form_status["error"] = f"An error occurred while processing the form: {e}"
                    logger.error(form_status["error"])
                    raise ValidationError(form_status["error"])

            WebDriverWait(AutomationSetting.driver, 30).until(
                EC.presence_of_element_located((By.TAG_NAME, 'body'))
            )
            success = True
        except ValidationError as e:
            form_status["error"] = f"Validation error: {e}"
            logger.error(form_status["error"])
            raise
        except Exception as e:
            form_status["error"] = f"An error occurred during the setting process: {e.msg}"
            logger.error(form_status["error"])
            raise
        finally:
            AutomationSetting.close_driver(form_status)
            if success == True:
                form_status["error"] = False
                return {"data": get_element_result, "status": form_status}
            else:
                return {"data": get_element_result, "status": form_status}

    @staticmethod
    def fill_form(form_values, element_details, input_data, form_status, get_element_result):
        """Fill the form using the provided API configuration and input data."""
        for form_field_id, details in element_details.items():
            try:
                evalue = details["evalue"]
                evalue_type = details["evalue_type"]
                eaction = details["eaction"]
                ewait = details["ewait"]
                eskip = details["eskip"]
                print("eskip", eskip)
                ewait_second = details["ewait_second"] if ewait else 0
                locator = None
                element = None
                logger.info(f"Locating element '{form_field_id}' using {evalue_type}: {evalue}")
                retries = 3  # Number of retries for stale element
                while retries > 0:
                    try:
                        # Determine the appropriate locator based on evalue_type
                        if evalue_type == "XPATH":
                            locator = (By.XPATH, evalue)
                        elif evalue_type == "ID":
                            locator = (By.ID, evalue)
                        elif evalue_type == "CLASS_NAME":
                            locator = (By.CLASS_NAME, evalue)
                        elif evalue_type == "CSS_SELECTOR":
                            locator = (By.CSS_SELECTOR, evalue)
                        elif evalue_type == "NAME":
                            locator = (By.NAME, evalue)
                        elif evalue_type == "SWITCH_TAB":
                            if ewait and ewait_second > 0:
                                logger.info(
                                    f"Waiting for {ewait_second} seconds before performing action '{eaction}' on '{form_field_id}'")
                                sleep(ewait_second)
                                if eaction == "switch_to_tab":
                                    tab_to = AutomationSetting.driver.window_handles
                                    AutomationSetting.driver.switch_to.window(tab_to[evalue])
                                    logger.info("Switched to new tab.")
                                    break
                        elif evalue_type == "SWITCH_WINDOW":
                            if ewait and ewait_second > 0:
                                logger.info(
                                    f"Waiting for {ewait_second} seconds before performing action '{eaction}' on '{form_field_id}'")
                                sleep(ewait_second)
                                if eaction == "switch_to_window":
                                    window_to = AutomationSetting.driver.window_handles
                                    AutomationSetting.driver.switch_to.window(window_to[evalue])
                                    logger.info("Switched to new window.")
                                    break
                        elif evalue_type == "NAV_TO":
                            if ewait and ewait_second > 0:
                                logger.info(
                                    f"Waiting for {ewait_second} seconds before performing action '{eaction}' on '{form_field_id}'")
                                sleep(ewait_second)
                                if eaction == "navigate_to":
                                    AutomationSetting.navigate_to(evalue, form_status)
                        else:
                            form_status["updated"] = False
                            form_status["processed_forms_count"] += 1
                            form_status["error"] = f"Unsupported locator type '{evalue_type}' for '{form_field_id}'."
                            logger.error(form_status["error"])
                            raise ValueError(form_status["error"])

                        if locator:
                            conditions = [
                                EC.visibility_of_element_located(locator),
                                # EC.presence_of_element_located(locator),
                                # EC.presence_of_nested_elements_located_by(locator),
                                # EC.attribute_to_be((By.CSS_SELECTOR, '[data-testid="org-user-list-more-details-button"]'), "aria-expanded", "true"),
                                EC.element_to_be_clickable(locator)
                            ]
                        elements = WebDriverWait(AutomationSetting.driver, 100).until(EC.any_of(*conditions))

                        if isinstance(elements, (tuple, list)):
                            for el in elements:
                                if el.is_displayed():
                                    element = el
                                    break
                        else:
                            element = elements

                        if element:
                            if ewait and ewait_second > 0:
                                logger.info(
                                    f"Waiting for {ewait_second} seconds before performing action '{eaction}' on '{form_field_id}'")
                                sleep(ewait_second)
                            if eaction == "send_keys":
                                element.clear()
                                if form_field_id in form_values:
                                    form_value = form_values[form_field_id]
                                    value = form_value["value"]
                                    value_type = form_value["value_type"]

                                    if value_type == "value":
                                        logger.info(f"Filling value for '{form_field_id}' with value: {value}")
                                        element.send_keys(value)
                                    elif value_type == "field_id":
                                        input_field_id = value
                                        input_value = None
                                        for data in input_data:
                                            if input_field_id in data:
                                                input_value = data[input_field_id]
                                                break
                                        if input_value:
                                            logger.info(
                                                f"Filling value for '{form_field_id}' with value from input_data: {input_value}")
                                            element.send_keys(input_value)
                                        else:
                                            form_status["updated"] = False
                                            form_status["processed_forms_count"] += 1
                                            form_status[
                                                "error"] = f"No value found for '{input_field_id}' in API response."
                                            logger.error(form_status["error"])
                                            raise ValueError(form_status["error"])

                                    else:
                                        form_status["updated"] = False
                                        form_status["processed_forms_count"] += 1
                                        form_status[
                                            "error"] = f"Unsupported value type '{value_type}' for '{form_field_id}'"
                                        logger.error(form_status["error"])
                                        raise ValueError(form_status["error"])

                            elif eaction == "date_send_keys":
                                element.clear()
                                if form_field_id in form_values:
                                    form_value = form_values[form_field_id]
                                    value = form_value["value"]
                                    value_type = form_value["value_type"]

                                    if value_type == "value":
                                        logger.info(f"Filling value for '{form_field_id}' with value: {value}")
                                        element.send_keys(value)
                                    elif value_type == "field_id":
                                        input_field_id = value
                                        input_value = None
                                        for data in input_data:
                                            if input_field_id in data:
                                                input_value = data[input_field_id]
                                                break
                                        if input_value:
                                            # Convert to datetime object
                                            dt = datetime.strptime(input_value, "%Y-%m-%dT%H:%M:%S.%f")
                                            formatted_date = dt.strftime("%m-%d-%Y")
                                            logger.info(
                                                f"Filling value for '{form_field_id}' with value from input_data: {formatted_date}")
                                            element.send_keys(formatted_date)
                                        else:
                                            form_status["updated"] = False
                                            form_status["processed_forms_count"] += 1
                                            form_status[
                                                "error"] = f"No value found for '{input_field_id}' in API response."
                                            logger.error(form_status["error"])
                                            break
                                    else:
                                        form_status["updated"] = False
                                        form_status["processed_forms_count"] += 1
                                        form_status[
                                            "error"] = f"Unsupported value type '{value_type}' for '{form_field_id}'."
                                        logger.error(form_status["error"])
                                        break

                            elif eaction == "click":
                                logger.info(f"Clicking button '{form_field_id}'")
                                element.click()

                            elif eaction == "clear":
                                element.clear()
                                logger.info(f"Cleared input for '{form_field_id}'.")
                            # select
                            elif eaction == "select_by_visible_text":
                                select_box = Select(element)
                                if form_field_id in form_values:
                                    form_value = form_values[form_field_id]
                                    value = form_value["value"].strip()
                                    value_type = form_value["value_type"]
                                    select_box.select_by_visible_text(value)  # Select by visible text
                                logger.info(f"Select the value using Visible text for '{form_field_id}'.")
                            elif eaction == "select_by_index":
                                select_box = Select(element)
                                if form_field_id in form_values:
                                    form_value = form_values[form_field_id]
                                    value = int(form_value["value"])
                                    value_type = form_value["value_type"]
                                    select_box.select_by_index(value)  # Select by visible text
                                logger.info(f"Select the value using Visible text for '{form_field_id}'.")
                            elif eaction == "select_by_value":
                                select_box = Select(element)
                                if form_field_id in form_values:
                                    form_value = form_values[form_field_id]
                                    value = form_value["value"]
                                    value_type = form_value["value_type"]
                                    select_box.select_by_value(value)  # Select by visible text
                                logger.info(f"Select the value using Visible text for '{form_field_id}'.")
                            elif eaction == "switch_to_iframe":
                                AutomationSetting.driver.switch_to.frame(element)
                                logger.info(f"switch_to_iframe")
                            elif eaction == "get_element_text":
                                extracted_text = element.text
                                logger.info(f"Extracted element text '{extracted_text}'")
                                # print("get element ----*******----------",form_values)
                                if form_field_id in form_values:
                                    form_value = form_values[form_field_id]
                                    value = form_value["value"]
                                    value_type = form_value["value_type"]
                                    get_element_result.append(
                                        {"field_id": form_field_id, "value": extracted_text, "value_type": value_type})
                                    # print("get_element_result=============",get_element_result)
                                    logger.info(f"Processed text for '{form_field_id}': '{extracted_text}'")
                                else:
                                    form_status["updated"] = False
                                    form_status["processed_forms_count"] += 1
                                    form_status["error"] = f"Form values is empty"
                                    logger.error(form_status["error"])
                                    raise ValueError(form_status["error"])
                            else:
                                form_status["updated"] = False
                                form_status["processed_forms_count"] += 1
                                form_status["error"] = f"Unsupported action '{eaction}' for '{form_field_id}'. "
                                logger.error(form_status["error"])
                                raise ValueError(form_status["error"])

                            form_status["updated"] = True
                            form_status["processed_forms_count"] += 1
                            logger.info(f"Performed action '{eaction}' on element '{form_field_id}' successfully.")
                            break  # Break out of retry loop if successful
                        else:
                            # If element is not found
                            if eskip == True:
                                logger.info(f"Element '{form_field_id}' not found, skipping action.")
                                form_status["processed_forms_count"] += 1

                            else:
                                logger.error(f"Failed to locate element '{form_field_id}' after retries.")
                                form_status["error"] = f"Timeout occurred while locating element 1'{form_field_id}'"
                                raise TimeoutException(form_status["error"])

                    except StaleElementReferenceException as sere:
                        logger.warning(
                            f"StaleElementReferenceException encountered. Retrying... ({retries} retries left)")
                        retries -= 1
                        sleep(2)  # Small delay before retrying
            except TimeoutException as te:
                if eskip:
                    logger.info(f"Element '{form_field_id}' not found and 'eskip' is True. Skipping action.")
                    form_status["processed_forms_count"] += 1

                else:
                    form_status["error"] = f"Timeout occurred while locating element '{form_field_id}': {te.msg}"
                    logger.error(form_status["error"])
                    raise ValueError(form_status["error"])
            except NoSuchWindowException as nwe:
                form_status["error"] = f"NoSuchWindowException occurred: {nwe.msg}"
                logger.error(form_status["error"])
                # return form_status, get_element_result
                raise ValueError(form_status["error"])
            except NoSuchElementException as nse:
                form_status["error"] = f"NoSuchElementException occurred: {nse.msg}"
                logger.error(form_status["error"])
                # return form_status, get_element_result
                raise ValueError(form_status["error"])

            except ElementNotInteractableException as ent:
                form_status["error"] = f"ElementNotInteractableException occurred: {ent.msg}"
                logger.error(form_status["error"])
                # return form_status, get_element_result
                raise ValueError(form_status["error"])
            except WebDriverException as wde:
                form_status["error"] = (
                    f"WebDriverException occurred while processing element '{form_field_id}': {wde.msg}")
                logger.error(form_status["error"])
                # return form_status, get_element_result
                raise ValueError(form_status["error"])
            except Exception as e:
                form_status["error"] = f"An unexpected error occurred: {e}"
                logger.error(form_status["error"])
                # return form_status, get_element_result
                raise ValueError(form_status["error"])
        return form_status, get_element_result


class AutomationView(APIView):
    """This class handles sending the Requests to automate form submissions using Selenium WebDriver"""

    def post(self, request, *args, **kwargs):
        logger.info("Received a new request in AutomationView")
        form_status_view = {"error": None}
        try:
            data = request.data
            schema_config = data.get("schema_config", [])
            input_data = data.get("input_data", {})

            if not schema_config or not schema_config[0].get("form_status"):
                form_status_view["error"] = ("Invalid schema_config or form_status missing")
                logger.error(form_status_view["error"])
                raise ValidationError(form_status_view["error"])

            # Additional validation for input_data if necessary
            if not input_data:
                form_status_view["error"] = ("Input data is missing")
                logger.error(form_status_view["error"])
                raise ValidationError(form_status_view["error"])

            logger.info(f"Input data: {input_data}")

            url = schema_config[0].get("url")
            forms = schema_config[0].get("forms")
            form_status = schema_config[0].get("form_status")[0]
            logger.info(f"Form status: {form_status}")
            logger.info(f"Processing URL: {url}")

            result_setting = AutomationSetting.setting(url, forms, input_data, form_status)

            print(result_setting)
            form_error_status = result_setting.get('status', {}).get('error', None)
            if form_error_status is False:

                logger.info("Successfully processed the request")
                return Response(result_setting, status=status.HTTP_200_OK, )
            else:
                logger.error({"error": form_error_status})
                return Response({"error": form_error_status}, status=status.HTTP_400_BAD_REQUEST)


        except json.JSONDecodeError as je:
            form_status_view["error"] = f"Invalid JSON format in request body: {je}"
            logger.error(form_status_view["error"], exc_info=True)
            return Response(form_status_view, status=status.HTTP_400_BAD_REQUEST)
        except ValueError as ve:
            form_status_view["error"] = f"Value error: {ve}"
            logger.error(form_status_view["error"], exc_info=True)
            return Response(form_status_view, status=status.HTTP_400_BAD_REQUEST)
        except ValidationError as ve:
            form_status_view["error"] = f"Validation error: {ve}"
            logger.error(form_status_view["error"], exc_info=True)
            return Response(form_status_view, status=status.HTTP_400_BAD_REQUEST)

        except KeyError as e:
            form_status_view["error"] = f"{e.args[0]} is missing"
            logger.error(form_status_view["error"], exc_info=True)
            return Response(form_status_view, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            form_status_view["error"] = f"An error occurred while processing: {e}"
            logger.error(form_status_view["error"], exc_info=True)
            return Response(form_status_view, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class APISetting:
#     """This class handles the preparation, formatting, and execution of API requests, as well as the extraction and
#     comparison of JSON keys in API responses """
#
#     @staticmethod
#     def find_key_in_response(res_field_id, response_dict):
#         logger.info("find_key_in_response")
#         logger.debug(f"Finding key '{res_field_id}' in response.")
#         keys = res_field_id.split(".")
#         data = response_dict
#         try:
#             for key in keys:
#                 if isinstance(data, dict):
#                     data = data.get(key)
#                 elif isinstance(data, list):
#                     temp_data = [item.get(key) for item in data if isinstance(item, dict)]
#                     data = temp_data
#                 else:
#                     logger.warning(f"Unexpected data type encountered: {type(data)}")
#                     return None
#             if isinstance(data, list) and len(data) == 1:
#                 data = data[0]
#             if data is None:
#                 logger.warning(f"Key '{res_field_id}' not found in response.")
#             else:
#                 logger.info(f"Key '{res_field_id}' found with value: {data}")
#
#             return data
#         except Exception as e:
#             logger.error(f"Error while finding key '{res_field_id}' in response: {str(e)}")
#             return None
#
#     @staticmethod
#     def compare_json_keys_and_extract(response_data, all_responses):
#         logger.info("Comparing JSON keys and extracting values.")
#         extracted_data = []
#         for json1 in response_data:
#             if "field_id" in json1:
#                 res_field_id = json1["field_id"]
#                 print("res_field_id---", res_field_id)
#                 for response_dict in all_responses:
#                     # print("response_dict------",response_dict)
#                     if isinstance(response_dict, dict):
#                         value = APISetting.find_key_in_response(res_field_id, response_dict)
#                         # print("value---",value)
#                         if isinstance(value, list):
#                             for val in value:
#                                 extracted_item = {
#                                     "field_id": res_field_id,
#                                     "value": val,
#                                     "value_type": json1.get("value_type", "field_id")
#                                 }
#                                 extracted_data.append(extracted_item)
#                                 logger.debug(f"Extracted value '{val}' for key '{res_field_id}'.")
#                         else:
#                             json1["value"] = value
#                             extracted_data.append(json1)
#                             logger.debug(f"Extracted value '{value}' for key '{res_field_id}'.")
#                             # if value is not None:
#                             #     json1["field_id"] = json1["value"]
#                             #     json1["value"] = value
#                             #     logger.debug(f"Extracted value '{value}' for key '{res_field_id}'.")
#                             break  # Stop searching once the value is found
#         return extracted_data
#
#     @staticmethod
#     def prepare_payload(item, request_data):
#         logger.info("Preparing payload.")
#         payload = {}
#         print("prepare_payload item", item)
#         for data in request_data:
#             request_field_id = data["field_id"]
#             request_value_type = data["value_type"]
#             if request_value_type == "value":
#                 payload[request_field_id] = data["value"]
#             elif request_value_type == "field_id":
#                 payload[request_field_id] = item.get(data["value"])
#                 print("payload[request_field_id]=--------------------", request_field_id)
#                 print("item.get(data['value']-------------------------", item.get(data["value"]), )
#                 if payload[request_field_id] is None:
#                     logger.warning(f"Field '{data['value']}' not found in item. Setting payload to None.")
#         logger.debug(f"Prepared payload: {payload}")
#         print("payload---------------", payload)
#         return payload
#
#     @staticmethod
#     def format_data(payload):
#         logger.info("Formatting payload data.")
#         formatted_data = {}
#         for field_id, value in payload.items():
#             keys = field_id.split(".")
#             d = formatted_data
#             for key in keys[:-1]:
#                 if key not in d:
#                     d[key] = [{}]
#                 d = d[key][0]
#             d[keys[-1]] = value
#         json_formatted_data = json.dumps(formatted_data)
#         logger.debug(f"Formatted data: {json_formatted_data}")
#         return json_formatted_data
#
#     @staticmethod
#     def make_request(input_data, schema_config, process_status, max_retries=3):
#         logger.info("Starting request process.")
#
#         basic_url = schema_config["basic_url"]
#         endpoint_template = schema_config["end_point"]
#         headers = schema_config["header"]
#         method = schema_config["method"].lower()
#         auth_info = schema_config["auth"]
#         timeout = (10, 150)
#         request_data = schema_config["request"]
#         response_data = schema_config["response"]
#         all_responses = []
#
#         process_status = "started"  # Update status to started
#
#         try:
#             for item in input_data:
#                 print("item------", item)
#                 payload = APISetting.prepare_payload(item, request_data)
#                 formatted_data = APISetting.format_data(item)
#                 request_url = basic_url + endpoint_template
#                 for key, value in item.items():
#                     print("inside:", f"{{{key}}}", str(value))
#                     request_url = request_url.replace(f"{{{key}}}", str(value))
#
#             logger.info(f"Request URL: {request_url}")
#
#             for attempt in range(max_retries):
#                 try:
#                     auth = None
#                     if auth_info["auth_type"] == "basic":
#                         auth = HTTPBasicAuth(auth_info["username"], auth_info["password"])
#                     elif auth_info["auth_type"] in ["oauth", "bearer"]:
#                         headers["Authorization"] = f"Bearer {auth_info['authorization']}"
#                     elif auth_info["auth_type"] == "header":
#                         headers["authorization"] = auth_info["authorization"]
#
#                     response = getattr(requests, method)(request_url, headers=headers, data=payload, auth=auth,
#                                                          timeout=timeout)
#                     response.raise_for_status()
#                     print("response", response)
#                     all_responses.append(response.json())
#                     logger.info("Request successful.")
#                     logger.debug(f"Response: {response.json()}")
#                     response_data_updated = APISetting.compare_json_keys_and_extract(response_data, all_responses)
#                     logger.debug(f"Updated response fields: {response_data_updated}")
#                     process_status = "completed"  # Update status to completed
#                     return response_data_updated, process_status, all_responses
#
#                 except requests.exceptions.RequestException as e:
#                     logger.error(f"Request error on attempt '{attempt + 1}': {e}")
#                     process_status = f"retrying ({attempt + 1}/{max_retries})"
#                     if attempt < max_retries - 1:
#                         logger.info("Retrying...")
#                         sleep(2)
#                     else:
#                         if hasattr(e, "response") and e.response is not None:
#                             logger.error(f"Final request error: {e.response.status_code} {e.response.content}")
#                             process_status = f"Final request error: {e.response.status_code} {e.response.content}"
#                         else:
#                             process_status = f"Final request error: {str(e)}"
#                         return response_data, process_status, all_responses
#         except Exception as e:
#             logger.error(f"An unexpected error occurred: {e}")
#             process_status = f"error: {str(e)}"
#             return response_data, process_status, all_responses
#         return response_data, process_status, all_responses
#
#
# class APIIntegrationView(APIView):
#     """This class handles sending requests and processing responses based on the provided input data and
#     configuration. """
#
#     def post(self, request):
#         logger.info("Received a new request in APIIntegrationView")
#         try:
#             data = request.data
#             input_data = data.get("input_data", [])
#             print("input_data----------", input_data)
#             schema_config = data.get("schema_config")
#             print("schema_config----------", schema_config)
#             process_status = schema_config.get("status")
#             print("process_status----------", process_status)
#
#             # print(process_status)
#             if not input_data or not schema_config:
#                 process_status = "Invalid input data or Schema configuration."
#                 logger.warning(process_status)
#                 return Response({"error": process_status}, status=status.HTTP_400_BAD_REQUEST)
#
#             response_data, process_status, schema_config_respone = (
#                 APISetting.make_request(input_data, schema_config, process_status))
#             logger.info(schema_config_respone)
#             if process_status == "completed":
#                 return Response({"response_data": response_data, "api_response_data": schema_config_respone},
#                                 status=status.HTTP_200_OK)
#             else:
#                 return Response({"error": process_status}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except json.JSONDecodeError as e:
#             process_status = f"JSON decode error: {e}"
#             logger.error(process_status)
#             return Response({"error": process_status}, status=status.HTTP_400_BAD_REQUEST)
#         except SSLError as e:
#             process_status = f"SSL error occurred while processing the request: {e}"
#             logger.error(process_status)
#             return Response({"error": process_status}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except Timeout as e:
#             process_status = f"Request timed out: {e}"
#             logger.error(process_status)
#             return Response({"error": process_status}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except RequestException as e:
#             process_status = f"An error occurred while processing the request: {e}"
#             logger.error(process_status)
#             return Response({"error": process_status}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#         except Exception as e:
#             process_status = f"An unexpected error occurred: {e}"
#             logger.error(process_status)
#             return Response({"error": process_status}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


##################### API Integration and screen scraping END #############
@csrf_exempt
def initiate_password_reset(request):
    if request.method == 'POST':
        return auth_views.PasswordResetView.as_view()(request=request)
    return JsonResponse({'error': 'Invalid method'}, status=405)


########################## creating organization starts ##############################################
######################### organization based process alone starts ##################################

class OrganizationBasedProcess(APIView):
    """
    Organization-based Process list
    """

    def get(self, request, *args, **kwargs):
        organization_id = kwargs.get('organization_id')
        if not organization_id:
            return Response({"detail": "Organization ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            # Fetch processes tagged with the given organization but exclude those that are subprocesses of a parent process
            processes = CreateProcess.objects.filter(organization_id=organization_id,
                                                     parent_process__isnull=True)  # Filter by organization_id
            if not processes.exists():
                logger.info(f"No processes found for organization ID {organization_id}")
                return Response({"detail": "No processes found for the given organization ID."},
                                status=status.HTTP_404_NOT_FOUND)

            serializer = CreateProcessResponseSerializer(processes, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CreateProcess.DoesNotExist:
            logger.error(f"No CreateProcess objects found for organization ID {organization_id}")
            return Response({"detail": "No processes found for the given organization ID."},
                            status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error retrieving processes for organization ID {organization_id}: {str(e)}")
            return Response({"error": "Failed to retrieve processes"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OrganizationDetailsAPIView(APIView):
    """
    Organization based details starts
    """

    def get(self, request, organization_id):
        try:

            forms = FormDataInfo.objects.filter(organization=organization_id)
            dms_records = Dms.objects.filter(organization=organization_id)
            user_groups = UserGroup.objects.filter(organization=organization_id)
            bots = BotSchema.objects.filter(organization=organization_id)
            integrations = Integration.objects.filter(organization=organization_id)
            rules = Rule.objects.filter(organization=organization_id)

            # Query form permissions for the organization
            form_permissions = FormPermission.objects.filter(
                form__organization=organization_id,
                user_group__organization=organization_id,
            )

            forms_serializer = FormDataInfoSerializer(forms, many=True)
            dms_serializer = DmsSerializer(dms_records, many=True)
            user_groups_serializer = UserGroupSerializer(user_groups, many=True)
            bots_serializer = BotSchemaSerializer(bots, many=True)
            integrations_serializer = IntegrationSerializer(integrations, many=True)
            rule_serializer = RuleSerializer(rules, many=True)

            bots_data = []
            for bot in bots_serializer.data:
                bot_data = {
                    "id": bot["id"],
                    "bot_schema_json": bot["bot_schema_json"],
                    "bot_element_permission": bot["bot_element_permission"],
                    "flow_id": bot["flow_id"],
                    "organization": bot["organization"],
                }
                # bot_id = bot["bot"]
                bot_id = bot.get("bot", None)
                if bot_id:  # Check if bot_id is not None
                    try:
                        related_bot = Bot.objects.get(id=bot_id)
                        bot_data.update({
                            "name": related_bot.name,
                            "bot_name": related_bot.bot_name,
                            "bot_description": related_bot.bot_description,
                            "bot_uid": related_bot.bot_uid,
                        })
                    except Bot.DoesNotExist:
                        bot_data.update({
                            "name": "",
                            "bot_name": "",
                            "bot_description": "",
                            "bot_uid": None,
                        })
                else:
                    bot_data.update({
                        "name": "",
                        "bot_name": "",
                        "bot_description": "",
                        "bot_uid": None,
                    })
                bots_data.append(bot_data)

            # Log the bots_data for debugging purposes
            logger.debug("Bots data: %s", bots_data)

            data = {
                'forms': forms_serializer.data,
                'dms': dms_serializer.data,
                'user_groups': user_groups_serializer.data,
                # 'form_permissions': form_permissions_data, // Vk  Reson: i did not used it
                'bots': bots_data,
                'integrations': integrations_serializer.data,
                'rules': rule_serializer.data,

            }
            # print("data", data)
            return Response(data, status=status.HTTP_200_OK)
        except FormDataInfo.DoesNotExist:
            logger.error(f"FormDataInfo objects not found for organization ID {organization_id}")
            return Response({"error": "Form data not found"}, status=status.HTTP_404_NOT_FOUND)
        except Dms.DoesNotExist:
            logger.error(f"DMS records not found for organization ID {organization_id}")
            return Response({"error": "DMS data not found"}, status=status.HTTP_404_NOT_FOUND)
        except UserGroup.DoesNotExist:
            logger.error(f"UserGroup objects not found for organization ID {organization_id}")
            return Response({"error": "User groups not found"}, status=status.HTTP_404_NOT_FOUND)
        except BotSchema.DoesNotExist:
            logger.error(f"BotSchema objects not found for organization ID {organization_id}")
            return Response({"error": "Bots not found"}, status=status.HTTP_404_NOT_FOUND)
        except Integration.DoesNotExist:
            logger.error(f"Integration objects not found for organization ID {organization_id}")
            return Response({"error": "Integrations not found"}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            logger.error(f"Unexpected error retrieving details for organization ID {organization_id}: {str(e)}")
            return Response({"error": "Failed to retrieve organization details"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


############### organization based details ends #######################################


class RequestPasswordResetAPIView(APIView):

    # 22-09-2025 by Harish (Email config)[Project TI]
    def send_password_reset_email(self, user_data, request, mail_data):
        try:
            from_email = mail_data.get("email_host_user")
            user_id = getattr(user_data, "user_id", None)
            if not user_id:
                logger.error("UserData object does not contain a valid user_id.")
                return Response({"error": "Invalid user data."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                logger.error(f"User with ID {user_id} does not exist.")
                return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)

            # Email connection setup
            connection = get_connection(
                host=mail_data.get("email_host"),
                port=mail_data.get("email_port"),
                username=mail_data.get("email_host_user"),
                password=mail_data.get("email_host_password"),
                use_tls=mail_data.get("use_tls", True),
                use_ssl=mail_data.get("use_ssl", False),
            )

            # Generate password reset token
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)

            # Build reset URL
            reset_link = f"{settings.SITE_URL}/{user_id}/reset-continue/{token}"
            logger.debug(f"Generated password reset link: {reset_link}")

            subject = "Password Reset"
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
                <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <h2 style="color: #333333;">Password Reset Request</h2>
                    <p style="color: #555555; font-size: 16px;">
                        You requested to reset your password. Click the button below to create a new password:
                    </p>
                    <p style="text-align: center; margin: 30px 0;">
                        <a href="{reset_link}" style="background-color: #007bff; color: white; text-decoration: none; padding: 12px 20px; border-radius: 5px; font-weight: bold; display: inline-block;">
                            Reset Password
                        </a>
                    </p>
                    <p style="color: #888888; font-size: 14px;">
                        If you didn't request a password reset, please ignore this email.
                    </p>
                    <hr style="border: none; border-top: 1px solid #eeeeee; margin: 40px 0;">
                </div>
            </body>
            </html>
            """

            try:
                sent_count = send_mail(
                    subject,
                    body,
                    from_email,
                    [user.email],
                    html_message=body,
                    connection=connection
                )
                if sent_count:
                    logger.info(f"Password reset email sent to {user.email}")
                    return Response({"message": "Password reset email sent successfully."},
                                    status=status.HTTP_200_OK)
                else:
                    logger.warning(f"Email not sent to {user.email}")
                    return Response({"error": "Failed to send password reset email."},
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            except BadHeaderError:
                logger.error("Invalid header found in email.")
                return Response({"error": "Invalid email header."},
                                status=status.HTTP_400_BAD_REQUEST)
            except SMTPException as smtp_error:
                logger.error(f"SMTP error: {smtp_error}")
                return Response({"error": "SMTP error while sending email."},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.exception(f"Unexpected error in send_password_reset_email: {str(e)}")
            return Response({"error": "Unexpected error occurred."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # 18-09-2025 by Harish (Check email with organization)[Product Level]
    def post(self, request):
        email = request.data.get("email")
        organization_id = request.data.get("organization_id")

        if not email:
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        if not organization_id:
            return Response({"error": "Organization ID is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            organization = Organization.objects.get(id=organization_id)
            user = UserData.objects.get(mail_id=email, organization=organization)
        except Organization.DoesNotExist:
            return Response({"error": "Organization does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except UserData.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Get NotificationConfig
        try:
            mail_config = NotificationConfig.objects.get(organization=organization_id)
            mail_data = mail_config.config_details  # Assuming this is a JSONField or dict
            if isinstance(mail_data, str):
                mail_data = json.loads(mail_data)
        except NotificationConfig.DoesNotExist:
            raise Exception("Email configuration not found for this organization.")

        return self.send_password_reset_email(user, request, mail_data)


class OrganizationListCreateAPIView(generics.ListCreateAPIView):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def create(self, request, *args, **kwargs):
        try:
            # Validate the email before proceeding
            super_admin_email = request.data.get('email')
            if not super_admin_email:
                raise ValidationError("The 'email' field is required.")

            # Check if the email is already associated with a User
            if User.objects.filter(email=super_admin_email).exists():
                raise ValidationError(f"A user with the email '{super_admin_email}' already exists.")

            # Check if the email is already associated with UserData
            if UserData.objects.filter(mail_id=super_admin_email).exists():
                raise ValidationError(f"A user data entry with the email '{super_admin_email}' already exists.")

            # If email validation passes, save the organization
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            organization = serializer.save()  # Save organization if validation passes

            # Create the super admin user
            logger.info("Creating super admin user...")
            user = User.objects.create(
                email=super_admin_email,
                is_superuser=True,
                is_staff=True,
            )

            # Generate a unique username if needed
            base_username = super_admin_email.split('@')[0]
            username = base_username
            counter = 1

            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            user.username = username
            user.set_unusable_password()  # Ensures the user must set a password
            user.save()

            logger.info(f"Super admin user created with email: {super_admin_email}")

            # Create UserData entry
            user_data = UserData.objects.create(
                mail_id=super_admin_email,
                user_name=username,
                organization=organization,
                user=user
            )

            # Send password reset email
            self.send_password_reset_email(user_data)

            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

        except ValidationError as e:
            # Return specific validation error message
            # Return detailed validation error
            error_message = e.detail if hasattr(e, 'detail') else str(e)
            return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

            # return Response({'error': str(e.detail if hasattr(e, 'detail') else str(e))},
            #                 status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Error creating organization: {str(e)}")
            # Capture the specific error if possible
            error_message = str(e)
            return Response({"error": error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            # return Response({"error": "Failed to create organization"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def send_password_reset_email(self, user_data):
        try:
            user_id = user_data.user_id  # Assuming user_id is a field in UserData
            user = User.objects.get(id=user_id)

            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            # Constructing reset URL without encoding user_id
            reset_url = reverse('password_reset', kwargs={'user_id': user_id, 'token': token})
            # reset_link = self.request.build_absolute_uri(reset_url)
            # Combine SITE_URL with the reset URL path to form the full URL
            # reset_link = f"{settings.SITE_URL}{reset_url}"
            reset_link = f"{settings.SITE_URL}/{user_id}/reset-continue/{token}"
            print("reset_link", reset_link)

            subject = 'Password Reset'
            body = f'Here is your password reset link: {reset_link}'

            send_mail(subject, body, settings.EMAIL_HOST_USER, [user.email])

            logger.info(f"Password reset email sent to {user.email}")
            return Response({"message": "Password reset email sent successfully."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            logger.error(f"User with ID {user_id} does not exist.")
            return Response({"error": "User does not exist."},
                            status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error sending password reset email: {str(e)}")
            return Response({"error": "Failed to send password reset email."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error listing organizations: {str(e)}")
            return Response({"error": "Failed to list organizations"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class OrganizationRetrieveUpdateAPIView(generics.RetrieveUpdateAPIView):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer

    def get_object(self):
        lookup_url_kwarg_id = 'pk'
        lookup_url_kwarg_code = 'org_code'
        try:
            if lookup_url_kwarg_id in self.kwargs:
                return self.queryset.get(pk=self.kwargs[lookup_url_kwarg_id])
            elif lookup_url_kwarg_code in self.kwargs:
                return self.queryset.get(org_code=self.kwargs[lookup_url_kwarg_code])
            else:
                raise Organization.DoesNotExist()
        except Organization.DoesNotExist:
            logger.error(f"Organization with provided identifier not found: {self.kwargs}")
            raise

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error retrieving organization: {str(e)}")
            return Response({"error": "Failed to retrieve organization"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data)
        except Organization.DoesNotExist:
            return Response({"error": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error updating organization: {str(e)}")
            return Response({"error": "Failed to update organization"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def perform_update(self, serializer):
        try:
            organization = serializer.save()
            # Optionally send email to organization email for super admin
            # self.generate_password_link_email(organization.email)
        except Exception as e:
            logger.error(f"Error performing update on organization: {str(e)}")
            raise

    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)


class CreatePermissionsView(APIView):
    def post(self, request):
        permissions = [
            {'code': 'read', 'description': 'Read permission'},
            {'code': 'write', 'description': 'Write permission'},
            {'code': 'delete', 'description': 'Delete permission'},
            {'code': 'execute', 'description': 'Execute permission'}
        ]

        created_permissions = []
        try:
            for perm in permissions:
                permission, created = Permission.objects.get_or_create(
                    code=perm['code'], defaults={'description': perm['description']}
                )
                created_permissions.append(permission)

            return Response(
                {"created_permissions": [perm.code for perm in created_permissions]},
                status=status.HTTP_201_CREATED
            )

        except IntegrityError as e:
            # Handle cases where there might be a database integrity issue (e.g., unique constraint violation)
            return Response(
                {"error": "A database integrity error occurred.", "details": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except DatabaseError as e:
            # Handle general database errors
            return Response(
                {"error": "A database error occurred.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except Exception as e:
            # Catch any other unexpected exceptions
            return Response(
                {"error": "An unexpected error occurred.", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


###################### create user permission ends ##############################################


######################### creating UserGroups[ADD,EDIT,LIST,DELETE] BGN #############################

class UserGroupListCreateAPIView(generics.ListCreateAPIView):
    # queryset = UserGroup.objects.all()
    serializer_class = UserGroupSerializer

    def get_queryset(self):
        org_id = self.kwargs['org_id']  # Retrieve org_id from URL parameters
        # 18-09-2025 by Harish (Usergroup fixes)[Product Level]
        status = self.request.query_params.get("status")
        if org_id is None:
            return UserData.objects.none()  # Return an empty queryset if org_id is not provided
        try:
            if status == "active":
                queryset = UserGroup.objects.filter(organization_id=org_id, status=True)
            elif status == "in_active":
                queryset = UserGroup.objects.filter(organization_id=org_id, status=False)
            else:
                queryset = UserGroup.objects.filter(organization_id=org_id)
            # Check if the queryset is empty
            if not queryset.exists():
                raise NotFound(detail='No user groups found for the provided organization ID.')
            return queryset
        except ObjectDoesNotExist:
            # Handle cases where the organization does not exist
            raise NotFound(detail='The organization does not exist.')

        except Exception as e:
            # Log the exception details for debugging purposes
            print(f"Unexpected error: {str(e)}")
            # Raise a generic exception
            raise NotFound(detail='An unexpected error occurred.')

    def create(self, request, *args, **kwargs):  #### need to include for usergroup name duplication
        try:
            group_name = request.data.get("group_name")
            organization_id = request.data.get("organization")

            # Check if the same group name exists for the same organization
            if UserGroup.objects.filter(group_name__iexact=group_name, organization_id=organization_id).exists():
                return Response(
                    {"error": "A user group with this name already exists in the selected organization."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            with transaction.atomic():
                uid = generate_uid(UserGroup,'UG',organization_id) 
                mutable_data = request.data.copy()
                mutable_data["uid"] = uid

                serializer = self.get_serializer(data=mutable_data)
                serializer.is_valid(raise_exception=True)
                self.perform_create(serializer)

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except serializers.ValidationError as e:
            logger.error(f"Validation error creating user group: {str(e)}")
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error creating user group: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserGroupRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    # queryset = UserGroup.objects.all()
    serializer_class = UserGroupSerializer
    lookup_url_kwarg = 'pk'

    def get_queryset(self):
        org_id = self.kwargs['org_id']
        if org_id is None:
            # If 'org_id' is not provided, raise a validation error
            raise ValidationError('Organization ID is required.')
        try:
            # Try to filter the queryset by organization_id
            queryset = UserGroup.objects.filter(organization_id=org_id)

            # Check if the queryset is empty
            if not queryset.exists():
                raise NotFound('No user groups found for the provided organization ID.')

            return queryset

        except ObjectDoesNotExist:
            # Handle cases where the organization does not exist
            raise NotFound('The organization does not exist.')

        except Exception as e:
            # Log the exception details for debugging purposes
            print(f"Unexpected error: {str(e)}")
            # Raise a generic not found exception
            raise NotFound('An unexpected error occurred.')
        # return UserGroup.objects.filter(organization_id=org_id)

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', False)
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            return Response(serializer.data)
        except Exception as e:
            logger.error(f"Error updating user group: {str(e)}")
            return Response({"error": "Failed to update user group"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            self.perform_destroy(instance)
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting user group: {str(e)}")
            return Response({"error": "Failed to delete user group"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


######################### creating UserGroups ENDS ##################################################


########################## Password reset function ############################################
@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetConfirmView(generics.UpdateAPIView):
    serializer_class = PasswordResetSerializer

    def update(self, request, *args, **kwargs):
        try:
            user_id = kwargs.get('user_id')
            token = kwargs.get('token')
            logger.info(f"Password reset requested for user_id: {user_id} with token: {token}")

            user = get_object_or_404(User, id=user_id)
            user_data = get_object_or_404(UserData, user_id=user_id)

            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                logger.error("Invalid token provided.")
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            password = serializer.validated_data['password']

            # Set the new password in the User model
            user.set_password(password)
            user.save()
            logger.info(f"Password for user {user_id} has been reset successfully in User model.")

            # Update the password in UserData
            user_data.password = make_password(password)  # Store hashed password
            user_data.save()
            logger.info(f"Password for user {user_id} has been updated successfully in UserData model.")

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            logger.error(f"User with ID {user_id} does not exist.")
            return Response({"error": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except UserData.DoesNotExist:
            logger.error(f"UserData with user ID {user_id} does not exist.")
            return Response({"error": "UserData does not exist."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            return Response({"error": "Failed to reset password."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


########################## Password reset function ends ############################################


######################## API for DMS components starts ##################################


class GoogleDrive(APIView):

    @staticmethod
    def get_gdrive_credentials(access_token, refresh_token, client_id, client_secret, token_uri):
        """Gets valid user credentials from access token, client ID, and client secret."""
        credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri=token_uri,
            client_id=client_id,
            client_secret=client_secret
        )

        # Refresh the token if it has expired
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())

        return credentials

    @staticmethod
    def upload_to_gdrive(folder_name, file_obj, gdrive_metadata, access_token, refresh_token, client_id, client_secret,
                         token_uri):
        """Uploads the specified file object to Google Drive with a renamed file name."""
        try:
            credentials = GoogleDrive.get_gdrive_credentials(access_token, refresh_token, client_id, client_secret,
                                                             token_uri)
            service = build('drive', 'v3', credentials=credentials)

            current_date = datetime.now().strftime("%d_%b_%Y")
            current_time = datetime.now().strftime("%H_%M_%S")
            file_name, file_extension = os.path.splitext(file_obj.name)
            modified_filename = f"{file_name}_{current_date}_{current_time}{file_extension}"

            # Check if folder exists
            results = service.files().list(
                q=f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder'",
                fields="files(id, name)"
            ).execute()

            if results.get('files'):
                folder_id = results['files'][0]['id']
                logger.info(f"Found existing folder '{folder_name}' with ID {folder_id}.")
            else:
                # Create folder if it doesn't exist
                gdrive_file_metadata = {
                    'name': folder_name,
                    'mimeType': 'application/vnd.google-apps.folder',
                    'description': gdrive_metadata
                }
                folder = service.files().create(body=gdrive_file_metadata, fields='id').execute()
                folder_id = folder.get('id')
                logger.info(f"Created new folder '{folder_name}' with ID {folder_id}.")

            # Convert InMemoryUploadedFile to BytesIO
            file_stream = io.BytesIO(file_obj.read())

            # Upload file to the folder
            media = MediaIoBaseUpload(
                file_stream, mimetype=file_obj.content_type, resumable=True
            )

            gdrive_file_metadata = {
                'name': modified_filename,
                'parents': [folder_id],
                'description': gdrive_metadata
            }

            file = service.files().create(
                body=gdrive_file_metadata,
                media_body=media,
                fields='id'
            ).execute()

            file_id = file.get('id')
            logger.info(f'File "{modified_filename}" uploaded successfully to folder "{folder_name}".')

            # Generate a shareable link for the file
            download_link = GoogleDrive.generate_shareable_link(service, file_id)

            return JsonResponse({
                'file_id': file_id,
                'file_name': modified_filename,
                'download_link': download_link,
                'status': f'File "{modified_filename}" uploaded successfully to Google Drive.'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"An error occurred during upload: {e}")
            return Response({'error': f'An error occurred during upload: {e}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def generate_shareable_link(service, file_id):
        """Generates a shareable link for the file."""
        try:
            # Update the file permission to public
            permission = {
                'type': 'anyone',
                'role': 'reader'
            }
            service.permissions().create(
                fileId=file_id,
                body=permission
            ).execute()

            # # Generate a shareable link
            # file = service.files().get(fileId=file_id, fields='webViewLink').execute()
            # return file.get('webViewLink')
            # Construct the direct download link
            direct_download_link = f"https://drive.google.com/uc?export=download&id={file_id}"
            return direct_download_link

        except HttpError as error:
            logger.error(f"An error occurred during link generation: {error}")
            return None

    @staticmethod
    def download_from_gdrive(file_name, access_token, refresh_token, client_id, client_secret, token_uri):
        """Downloads the specified file from Google Drive by name."""
        credentials = GoogleDrive.get_gdrive_credentials(access_token, refresh_token, client_id, client_secret,
                                                         token_uri)
        service = build('drive', 'v3', credentials=credentials)

        try:
            # Search for file by name
            results = service.files().list(
                q=f"name='{file_name}'",
                fields="files(id, name)"
            ).execute()
            downloads_folder = os.path.join(os.path.expanduser('~'), 'Downloads')

            if results.get('files'):
                file_id = results['files'][0]['id']
                request = service.files().get_media(fileId=file_id)
                file_stream = io.BytesIO()
                downloader = MediaIoBaseDownload(file_stream, request)
                done = False

                while not done:
                    _, done = downloader.next_chunk()

                # Save the file to the specified download path
                file_stream.seek(0)
                local_file_path = os.path.join(downloads_folder, file_name)
                with open(local_file_path, 'wb') as f:
                    f.write(file_stream.read())

                logger.info(f'File "{file_name}" downloaded successfully from Google Drive.')
                return JsonResponse({'file_name': file_name,
                                     'status': f'File "{file_name}" downloaded successfully from Google Drive.'},
                                    status=status.HTTP_200_OK)
            else:
                logger.error(f"File '{file_name}' not found in Google Drive.")
                return Response({'error': f"File '{file_name}' not found in Google Drive."},
                                status=status.HTTP_404_NOT_FOUND)

        except HttpError as error:
            logger.error(f"An error occurred during download: {error}")
            return Response({'error': f'An error occurred during download: {error}'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class S3Bucket:

    @staticmethod
    def initialize_client(aws_access_key_id, aws_secret_access_key):
        try:
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            return s3_client
        except ClientError as e:
            logger.error(f'Failed to initialize S3 client: {e}')
            return None

    @staticmethod
    def upload_to_S3Bucket(files, aws_access_key_id, aws_secret_access_key, bucket_name, s3_bucket_metadata):
        s3_client = S3Bucket.initialize_client(aws_access_key_id, aws_secret_access_key)
        if not s3_client:
            return Response({'error': 'Credentials not available'}, status=status.HTTP_403_FORBIDDEN)

        try:
            # Generate a unique file ID (UUID)
            file_id = str(uuid.uuid4())
            print("***************************", file_id)

            # Create the filename with the current date, time, and UUID
            current_date = datetime.now().strftime("%d_%b_%Y")
            current_time = datetime.now().strftime("%H_%M_%S")
            # file_name, file_extension = files.name.split('.')
            if '.' in files.name:
                file_name, file_extension = files.name.rsplit('.', 1)
            else:
                file_name = files.name
                file_extension = ''

            modified_filename = f"{file_name}_{current_date}_{current_time}_{file_id}.{file_extension}" if file_extension else f"{file_name}_{current_date}_{current_time}_{file_id}"
            # modified_filename = f"{file_name}_{current_date}_{current_time}_{file_id}.{file_extension}"
            print("***************************", modified_filename)
            # Upload the file to S3
            s3_client.upload_fileobj(files, bucket_name, modified_filename, ExtraArgs={'Metadata': s3_bucket_metadata})
            logger.info('Files uploaded successfully')

            # Set the object ACL to public-read
            s3_client.put_object_acl(Bucket=bucket_name, Key=modified_filename, ACL='public-read')

            # Generate the public URL
            download_link = f"https://{bucket_name}.s3.amazonaws.com/{modified_filename}"
            print("download_link", download_link)
            return JsonResponse({
                'file_id': file_id,
                'file_name': modified_filename,
                'download_link': download_link,
                'status': f'Files {modified_filename} uploaded successfully to S3Buckets'
            }, status=status.HTTP_200_OK)

        except ClientError as e:
            logger.error(f'Failed to upload to S3: {e}')
            return Response({'error': f'Failed to upload to S3: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def download_from_S3Bucket(file_name, aws_access_key_id, aws_secret_access_key, bucket_name):
        s3_client = S3Bucket.initialize_client(aws_access_key_id, aws_secret_access_key)
        if not s3_client:
            return Response({'error': 'Credentials not available'}, status=status.HTTP_403_FORBIDDEN)

        try:
            downloads_folder = os.path.join(os.path.expanduser('~'), 'Downloads')
            local_file_path = os.path.join(downloads_folder, file_name)
            s3_client.download_file(Bucket=bucket_name, Key=file_name, Filename=local_file_path)
            logger.info(f'File {file_name} downloaded successfully')
            return JsonResponse(
                {'file_name': file_name, 'status': f'File {file_name} downloaded successfully from S3Buckets'},
                status=status.HTTP_200_OK)
        except ClientError as e:
            logger.error(f'Failed to download from S3: {e}')
            return Response({'error': f'Failed to download from S3: {e}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# 30-09-2025 by Harish [Project TI]
class LocalServerStorage:
    """
    Handles SFTP upload for Local/Server Storage
    """

    @staticmethod
    def upload_to_sftp(file_obj, host, port, username, password, remote_path, metadata=None):
        try:
            # --- Connect to SFTP ---
            transport = paramiko.Transport((host, port))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            # --- Ensure remote directory exists ---
            try:
                sftp.stat(remote_path)
            except FileNotFoundError:
                sftp.mkdir(remote_path)

            # --- Generate UUID and timestamps ---
            file_id = str(uuid.uuid4())
            now = timezone.localtime(timezone.now())  # timezone-aware local time
            current_date = now.strftime("%d_%b_%Y")
            current_time = now.strftime("%I_%M_%S_%p")  # 12-hr with AM/PM

            # --- Create modified filename ---
            if "." in file_obj.name:
                file_name, file_extension = file_obj.name.rsplit(".", 1)
                modified_filename = f"{file_name}_{current_date}_{current_time}_{file_id}.{file_extension}"
            else:
                modified_filename = f"{file_obj.name}_{current_date}_{current_time}_{file_id}"

            remote_file_path = os.path.join(remote_path, modified_filename)

            # --- Upload file ---
            sftp.putfo(file_obj.file, remote_file_path)

            # --- Close connection ---
            sftp.close()
            transport.close()
            # --- Extract organization_id from metadata ---
            org_id = None
            if metadata:
                try:
                    # metadata could be list of JSON strings or dict
                    if isinstance(metadata, list):
                        metadata_json = json.loads(metadata[0])
                    elif isinstance(metadata, str):
                        metadata_json = json.loads(metadata)
                    elif isinstance(metadata, dict):
                        metadata_json = metadata
                    else:
                        metadata_json = {}

                    org_id = metadata_json.get("organization_id")
                except Exception as e:
                    print(f"Error parsing metadata: {e}")

            # --- Build response with HTTP download link (Django API endpoint) ---
            download_link = f"{settings.BASE_URL}/custom_components/sftp_file_download/{org_id}/{modified_filename}"
            print("Success LocalServerStorage ****")
            # --- Build response (similar to S3) ---
            return JsonResponse({
                "file_id": file_id,
                "file_name": modified_filename,
                "download_link": download_link,
                "status": f"File {modified_filename} uploaded successfully to Local Storage",
                "metadata": metadata or {}
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("Error in LocalServerStorage : ", e)
            return Response(
                {"error": f"Failed to upload to Local Storage: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class FileUploadView(APIView):
    # parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):

        drive_type = request.data.get('drive_types')
        print("drive_type", drive_type)

        if drive_type == "S3 Bucket":
            bucket_name = request.data.get('bucket_name')
            print("bucket_name", bucket_name)
            aws_access_key_id = request.data.get('aws_access_key_id')
            print("aws_access_key_id", aws_access_key_id)
            aws_secret_access_key = request.data.get('aws_secret_access_key')
            print("aws_secret_access_key", aws_secret_access_key)
            # s3_bucket_metadata = json.loads(request.data.get('metadata', '{}'))
            metadata = request.data.get('metadata', '{}')
            print("metadata", metadata)

            # Check if metadata is already a dictionary to avoid re-parsing it
            if isinstance(metadata, str):
                try:
                    s3_bucket_metadata = json.loads(metadata)
                except json.JSONDecodeError:
                    s3_bucket_metadata = {}  # Or handle the error as needed
            else:
                s3_bucket_metadata = metadata  # Already a dictionary

            files = request.FILES.get('files')

            # print(type(files))

            if not (bucket_name and aws_access_key_id and aws_secret_access_key):
                logger.error("Incomplete S3 credentials")
                return Response({"error": "Incomplete S3 credentials"}, status=status.HTTP_400_BAD_REQUEST)

            if not files:
                logger.error("No files provided")
                return Response({"error": "No files provided"}, status=status.HTTP_400_BAD_REQUEST)
            return S3Bucket.upload_to_S3Bucket(files, aws_access_key_id, aws_secret_access_key, bucket_name,
                                               s3_bucket_metadata)

        elif drive_type == "Google Drive":
            access_token = request.data.get('access_token')
            refresh_token = request.data.get('refresh_token')
            client_id = request.data.get('client_id')
            client_secret = request.data.get('client_secret')
            token_uri = request.data.get('token_uri')
            folder_name = request.data.get('folder_name')

            gdrive_metadata = request.data.get('metadata')
            print("gdrive_metadata", gdrive_metadata)

            if not (access_token and refresh_token and client_id and client_secret and token_uri and folder_name):
                logger.error("Incomplete Google Drive upload data")
                return Response({"error": "Incomplete Google Drive upload data"}, status=status.HTTP_400_BAD_REQUEST)
            print("")
            files = request.FILES.get('files')

            if not files:
                logger.error("No files provided")
                return Response({"error": "No files provided"}, status=status.HTTP_400_BAD_REQUEST)
            return GoogleDrive.upload_to_gdrive(folder_name, files, gdrive_metadata, access_token, refresh_token,
                                                client_id, client_secret, token_uri)

        # 26-09-2025 by Harish [Project TI]
        elif drive_type == "SFTP Storage":
            host = request.data.get("host")
            port = int(request.data.get("port"))
            username = request.data.get("username")
            password = request.data.get("password")
            server_path = request.data.get("server_path")
            files = request.FILES.get("files")
            metadata = request.data.get("metadata", {})
            print("files in LocalServerStorage : ", files)

            if not server_path:
                return Response({"error": "Server path not provided"}, status=status.HTTP_400_BAD_REQUEST)

            if not files:
                return Response({"error": "No files provided"}, status=status.HTTP_400_BAD_REQUEST)

            return LocalServerStorage.upload_to_sftp(files, host, port, username, password, server_path, metadata)


        else:
            logger.error("Invalid drive_type")
            return Response({"error": "Invalid drive_type"}, status=status.HTTP_400_BAD_REQUEST)


# 30-09-2025 by Harish [Project TI]
class SFTPFileDownloadView(APIView):
    """
    Download a file from SFTP based on organization config.
    URL pattern example: /custom_components/download_file/<org_id>/<filename>/
    """

    def get(self, request, org_id, filename):
        try:
            # --- Get DMS configuration for the organization ---
            dms_config = Dms.objects.filter(organization=org_id).first()
            if not dms_config:
                raise Http404("Organization DMS config not found")

            config = dms_config.config_details_schema or {}
            host = config.get("host")
            port = int(config.get("port", 22))
            username = config.get("username")
            password = config.get("password")
            server_path = config.get("server_path", "/")

            if not all([host, port, username, password]):
                raise Http404("Incomplete SFTP configuration")

            remote_path = f"{server_path.rstrip('/')}/{filename}"

            # --- Connect to SFTP ---
            transport = paramiko.Transport((host, port))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            # --- Read file into memory ---
            with sftp.file(remote_path, 'rb') as remote_file:
                file_data = remote_file.read()

            # --- Close connection ---
            sftp.close()
            transport.close()

            # --- Serve file as download ---
            buffer = BytesIO(file_data)
            response = FileResponse(buffer, as_attachment=True, filename=filename)
            return response

        except Exception as e:
            print(" Download error:", e)
            raise Http404(f"File not found or SFTP error: {str(e)}")


######################## API for DMS components ends ##################################


#######################
"""---------------Mail Monitor Packages-----------------"""

from imaplib import IMAP4_SSL

from email import policy
from email.parser import BytesParser


class MailMonitorSetting:
    @staticmethod
    def authenticate_mail(imap_server, receiver_mail, receiver_password, sender_email, scheduler_id, scheduler_name,
                          attachment_dir="attachments"):
        global processId, results, results
        try:
            mail = IMAP4_SSL(imap_server)
            logger.info("Connected to IMAP server.")
            scheduler = Scheduler.objects.get(id=scheduler_id)
            logger.info(f"schedulerrrrrrrrrrrrrrrr in as {scheduler_id}.")
            scheduler_name = scheduler.scheduler_name
            logger.info(f"Logged in as {scheduler_name}.")
            process_id = scheduler.process
            logger.info(f"schedulerrrrrrrrrrrrrrrr in as {process_id}.")
            organization_id = scheduler.organization
            logger.info(f"organization_id in as {organization_id}.")
            mail.login(receiver_mail, receiver_password)
            logger.info(f"Logged in as {receiver_mail}.")
            mail.select("inbox")

            logger.info(f"Searching for emails from {sender_email}...")

            # status, messages = mail.search(None, f'(FROM "{sender_email}")')
            status, messages = mail.search(None, f'(UNSEEN FROM "{sender_email}")')
            logger.info(f"Search status: {status}, messages: {messages}")
            if status != 'OK' or not messages[0]:
                logger.error(f"No emails found from {sender_email}.")
                return {"error": f"No emails found from {sender_email}."}

            mail_ids = messages[0].split()

            if not mail_ids:
                logger.info(f"No emails found from {sender_email}.")
                return {"error": f"No emails found from {sender_email}."}

            latest_email_id = mail_ids[-1]
            result, msg_data = mail.fetch(latest_email_id, "(RFC822)")
            # Ensure msg_data is properly parsed from the fetch response
            raw_email = msg_data[0][1]

            # Parse the email using the email library
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            # Extract the email subject (for filename use)
            subject = msg['subject']
            subject_sanitized = ''.join(
                c if c.isalnum() else '_' for c in subject) if subject else 'email_without_subject'

            # Extract sender and receiver information
            from_email = msg['from']
            to_email = msg['to']

            # Initialize variables to store the email body and attachments
            email_body = ""
            html_body = ""
            attachments = []

            def process_email_parts(part):
                nonlocal email_body, html_body, attachments

                # If part is multipart, iterate through its parts
                if part.is_multipart():
                    for subpart in part.iter_parts():
                        process_email_parts(subpart)
                else:
                    content_disposition = part.get_content_disposition()
                    content_type = part.get_content_type()

                    # Handle attachments
                    if content_disposition and "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            os.makedirs(attachment_dir, exist_ok=True)
                            filepath = os.path.join(attachment_dir, filename)
                            with open(filepath, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                            logger.info(f"Saved attachment: {filepath}")
                            attachments.append(filename)
                            # Normalize the file path for cross-platform compatibility
                            filepath = os.path.normpath(filepath)



                    # Handle plain text email body
                    elif content_type == "text/plain" and not email_body:
                        email_body = part.get_payload(decode=True)
                        if isinstance(email_body, bytes):
                            email_body = email_body.decode(part.get_content_charset() or 'utf-8')

                    # Handle HTML email body
                    elif content_type == "text/html" and not html_body:
                        html_body = part.get_payload(decode=True)
                        if isinstance(html_body, bytes):
                            html_body = html_body.decode(part.get_content_charset() or 'utf-8')

            # Process all parts of the email
            process_email_parts(msg)

            # Save the plain text email body as a text file (if present)
            body_filename = None
            if email_body:
                body_filename = os.path.join(attachment_dir, f"{subject_sanitized}_body.pdf")
                with open(body_filename, 'w', encoding='utf-8') as body_file:
                    body_file.write(email_body)
                logger.info(f"Saved email body: {body_filename}")

            # Optionally save HTML body as a separate file (if present)
            html_filename = None
            if html_body:
                html_filename = os.path.join(attachment_dir, f"{subject_sanitized}_body.html")
                with open(html_filename, 'w', encoding='utf-8') as html_file:
                    html_file.write(html_body)
                logger.info(f"Saved HTML email body: {html_filename}")

            # Log the result and return a summary
            # result_info = {
            #     "email_body_saved": body_filename if email_body else None,
            #     "html_body_saved": html_filename if html_body else None,
            #     "attachments_saved": attachments if attachments else None
            # }

            def PDFSpooler(attachments, attachment_dir):
                pdf_doc = []
                for attachment_name in attachments:  # Use just the filename
                    logger.info(f"Checking for attachment_name: {attachment_name}")
                    attachment_path = os.path.join(attachment_dir, attachment_name)

                    logger.info(f"Checking for attachment: {attachment_path}")

                    if os.path.isfile(attachment_path):
                        logger.info(f"Processing attachment: {attachment_path}")

                        if attachment_path.lower().endswith(".pdf"):
                            # Call the upload function and handle the result
                            dms_response = upload_file_to_dms(attachment_path, organization_id, process_id)
                            logger.info(" dms_response %s", dms_response)
                            # Check if the result is a JsonResponse or a Dms_data object
                            if isinstance(dms_response, JsonResponse):
                                # Handle the error response if it's a JsonResponse (indicates an error)
                                return dms_response
                            elif dms_response:
                                # If successful, result is an instance of Dms_data; you can access its attributes
                                print("Upload successful!")
                                print("File ID:", dms_response.folder_id)
                                print("File Name:", dms_response.filename)
                                print("Download Link:", dms_response.download_link)
                                print("Meta Data:", dms_response.meta_data)
                                response_data = {
                                    "file_id": dms_response.folder_id,
                                    "file_name": dms_response.filename,
                                    "download_link": dms_response.download_link,
                                    "meta_data": dms_response.meta_data,
                                }
                                schedulers = Scheduler.objects.get(id=scheduler_id)
                                scheduler_ins = schedulers.id
                                logger.info(f"process_data: {scheduler_ins}")
                                # Save the model response to the OcrDetails table
                                with open(attachment_path, 'rb') as pdf_file:
                                    pdf_content = pdf_file.read()
                                    # Encode the binary content to Base64
                                    encoded_pdf = base64.b64encode(pdf_content).decode('utf-8')

                                scheduler_data = SchedulerData(
                                    filename=encoded_pdf,
                                    process=process_id,
                                    scheduler=schedulers,
                                    # caseId=caseId,
                                    status="processed",
                                    organization=organization_id,
                                    data_json=response_data,  # Adjust field name as needed
                                    # status="processed"
                                )
                                scheduler_data.save()
                                logger.info(f"DMS API response status: {pdf_doc}")
                                today = str(date.today())

                                schedulers = Scheduler.objects.get(id=scheduler_id)

                                process_ins = schedulers.process.id
                                org_ins = schedulers.organization.id
                                process_instance = CreateProcess.objects.get(id=process_ins)
                                # process_id = process_instance.id

                                organization_instance = Organization.objects.get(id=org_ins)
                                logger.info(f"process_data: {organization_instance}")

                                # # target_form_name = id_based_form_record.first_step  # Initial form
                                process_data = process_instance.participants  # get overall json participants data

                                data_json = {

                                    'processId': process_instance.id,
                                    'organization': organization_instance.id,
                                    'created_on': today,
                                    'created_by': 'admin',
                                    'status': 'In Progress',
                                    'updated_on': today,
                                    'updated_by': '',
                                    'next_step': '',
                                    'data_json': '',  # json list (need to change)
                                    'path_json': ''
                                }
                                logger.info(f"data_json: {data_json}")

                                case_serializer = CaseSerializer(data=data_json)

                                if case_serializer.is_valid():
                                    logger.info("Case Workssssssssssssssss")
                                    case_instance = case_serializer.save()

                                    case_instance.save()

                                    start = []
                                    # filled_form_data = FilledFormData.objects.filter(pk=instance.pk).first()
                                    for flow_key, flow_value in process_data["executionFlow"].items():
                                        # start_value = flow_value.get("currentStepId")
                                        # end_value = flow_value.get("nextStepId")
                                        start_value = flow_value["currentStepId"]
                                        print("start_value", start_value)
                                        end_value = flow_value["nextStepId"]

                                        print(f"--------Start: {start_value}, ---------End: {end_value}")
                                        break

                                    case_instance.next_step = end_value
                                    case_instance.save()
                                    updated_case = Case.objects.get(pk=case_instance.pk)
                                    # store case id in filled form
                                    get_case_id = case_instance.pk
                                    # model_instance = SchedulerData.objects.get(id=some_id)
                                    submitted_form_queryset = SchedulerData.objects.filter(pk=scheduler_data.pk).first()

                                    # Update the attributes of the retrieved object
                                    if submitted_form_queryset:
                                        submitted_form_queryset.case_id = case_instance
                                        submitted_form_queryset.status = "Completed"
                                        submitted_form_queryset.save()
                                        logger.info(
                                            f"SchedulerData updated with case_id: {get_case_id} and status: Completed")

                                    # submitted_form_queryset.update(case_id=get_case_id, status="Completed")
                                pdf_doc.append({
                                    "file": attachment_name,
                                    "status": "processed",
                                    "extracted_info": response_data,
                                    # "model_response": model_response.json().get("response", "")
                                })
                                logger.info(f"DMS API response status: {pdf_doc}")
                                return None

                            else:
                                pdf_doc.append({
                                    "file": attachment_name,
                                    "status": "model processing failed",
                                    # "extracted_info": response_data,
                                })
                                return None
                        else:
                            pdf_doc.append({
                                "file": attachment_name,
                                "status": "extraction failed"
                            })
                            return None
                    else:
                        # Handle the case where upload failed and returned None
                        print("Upload failed.")
                        logger.info(f"Upload failed:")
                        return None
                return None

            def process_attachments(attachments, attachment_dir):
                results = []
                for attachment_name in attachments:  # Use just the filename
                    logger.info(f"Checking for attachment_name: {attachment_name}")
                    attachment_path = os.path.join(attachment_dir, attachment_name)

                    logger.info(f"Checking for attachment: {attachment_path}")

                    if os.path.isfile(attachment_path):

                        if attachment_path.lower().endswith(".pdf"):
                            # Call the upload function and handle the result
                            dms_response = upload_file_to_dms(attachment_path, organization_id, process_id)

                            # Check if the result is a JsonResponse or a Dms_data object
                            if isinstance(dms_response, JsonResponse):
                                # Handle the error response if it's a JsonResponse (indicates an error)
                                return dms_response
                            elif dms_response:
                                # If successful, result is an instance of Dms_data; you can access its attributes
                                print("Upload successful!")
                                print("File ID:", dms_response.folder_id)
                                print("File Name:", dms_response.filename)
                                print("Download Link:", dms_response.download_link)
                            else:
                                # Handle the case where upload failed and returned None
                                print("Upload failed.")
                            logger.info("Sending PDF for model API.")
                            # Send extracted_info to the model API
                            with open(attachment_path, 'rb') as pdf_file:

                                model_response = requests.post(
                                    'http://13.203.60.158/OCRExtractionView/',
                                    # 'http://127.0.0.1:8000/components_proxy_api/',
                                    # f"{settings.BASE_URL}/",
                                    files={'file': pdf_file},
                                    data={'operation': 'InvoiceExtraction'},
                                )
                                logger.info(f"Invoice extraction response status: {model_response.status_code}")

                                model_response.raise_for_status()  # Raises an error for HTTP codes 400 or above
                                # Assuming the API returns JSON response

                                if model_response.status_code == 200:
                                    model_data = model_response.json()
                                    # content_json = json.loads(response['message']['content'])
                                    # print(content_json)

                                    schedulers = Scheduler.objects.get(id=scheduler_id)
                                    scheduler_ins = schedulers.id
                                    # Save the model response to the OcrDetails table
                                    with open(attachment_path, 'rb') as pdf_file:
                                        pdf_content = pdf_file.read()
                                        # Encode the binary content to Base64
                                        encoded_pdf = base64.b64encode(pdf_content).decode('utf-8')

                                    scheduler_data = SchedulerData(
                                        filename=encoded_pdf,
                                        process=process_id,
                                        scheduler=schedulers,
                                        # caseId=caseId,
                                        status="processed",
                                        organization=organization_id,
                                        data_json=model_data,  # Adjust field name as needed
                                        # status="processed"
                                    )
                                    scheduler_data.save()
                                    # logger.info(f"Model API response status: {results}")
                                    today = str(date.today())

                                    schedulers = Scheduler.objects.get(id=scheduler_id)

                                    process_ins = schedulers.process.id
                                    org_ins = schedulers.organization.id
                                    process_instance = CreateProcess.objects.get(id=process_ins)
                                    # process_id = process_instance.id

                                    organization_instance = Organization.objects.get(id=org_ins)

                                    # # target_form_name = id_based_form_record.first_step  # Initial form
                                    process_data = process_instance.participants  # get overall json participants data

                                    data_json = {

                                        'processId': process_instance.id,
                                        'organization': organization_instance.id,
                                        'created_on': today,
                                        'created_by': 'admin',
                                        'status': 'In Progress',
                                        'updated_on': today,
                                        'updated_by': '',
                                        'next_step': '',
                                        'data_json': '',  # json list (need to change)
                                        'path_json': '',
                                        'assigned_users': []
                                    }

                                    case_serializer = CaseSerializer(data=data_json)

                                    if case_serializer.is_valid():
                                        logger.info("Case Workssssssssssssssss")
                                        case_instance = case_serializer.save()

                                        case_instance.save()

                                        start = []
                                        # filled_form_data = FilledFormData.objects.filter(pk=instance.pk).first()
                                        for flow_key, flow_value in process_data["executionFlow"].items():
                                            # start_value = flow_value.get("currentStepId")
                                            # end_value = flow_value.get("nextStepId")
                                            start_value = flow_value["currentStepId"]
                                            print("start_value", start_value)
                                            end_value = flow_value["nextStepId"]

                                            print(f"--------Start: {start_value}, ---------End: {end_value}")
                                            break

                                        case_instance.next_step = end_value
                                        case_instance.save()
                                        updated_case = Case.objects.get(pk=case_instance.pk)
                                        # store case id in filled form
                                        get_case_id = case_instance.pk
                                        logger.info(f"get_case_id: {get_case_id}")
                                        # model_instance = SchedulerData.objects.get(id=some_id)
                                        submitted_form_queryset = SchedulerData.objects.filter(
                                            pk=scheduler_data.pk).first()
                                        logger.info(f"submitted_form_queryset: {submitted_form_queryset}")
                                        # Update the attributes of the retrieved object
                                        if submitted_form_queryset:
                                            submitted_form_queryset.case_id = case_instance
                                            submitted_form_queryset.status = "Completed"
                                            submitted_form_queryset.save()
                                            logger.info(
                                                f"SchedulerData updated with case_id: {get_case_id} and status: Completed")

                                        # submitted_form_queryset.update(case_id=get_case_id, status="Completed")
                                        results.append({
                                            "file": attachment_name,
                                            "status": "processed",
                                            # "extracted_info": extracted_info,
                                            "model_response": model_response.json().get("response", "")
                                        })
                                #

                                # Vkparamesh
                                # else:
                                #     results.append({
                                #         "file": attachment_name,
                                #         "status": "model processing failed",
                                #         "extracted_info": extracted_info
                                #     })
                                else:

                                    results.append({
                                        "file": attachment_name,
                                        "status": "extraction failed"
                                    })
                                # logger.info("Email spooler %s",case_serializer.errors)


                        else:
                            logger.info(f"Unsupported attachment type for file: {attachment_path}")
                    else:
                        logger.error(f"Attachment file not found: {attachment_path}")

                return results

            if scheduler_name == 'email spooling ':
                logger.info("UUUUUUUUUUUUUUUUUUUUUUUUU")
                results = process_attachments(attachments, attachment_dir)
            elif scheduler_name == 'PDFSpooler':
                results1 = PDFSpooler(attachments, attachment_dir)

            mail.close()
            mail.logout()
            logger.info("Logged out from the mail server.")
            return {"success": "Email processed successfully.", "details": results}

        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {"error": str(e)}


def upload_file_to_dms(filepath, organization_id, process_id):
    try:
        with open(filepath, 'rb') as file:
            # Fetch DMS entries for the organization
            dms_entries = Dms.objects.filter(organization=organization_id)
            if not dms_entries.exists():
                # Log and respond if DMS is not configured
                logger.error("DMS not configured for this organization.")
                return JsonResponse({"error": "DMS not configured"}, status=400)

            logger.info(f"Saved dms_entries: {dms_entries}")
            drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}
            logger.info(f"Saved drive_types: {drive_types}")
            configurations = dms_entries.first().config_details_schema
            configurations['drive_types'] = drive_types
            metadata = {'form_name': file.name, 'organization_id': str(organization_id)}
            configurations['metadata'] = metadata

            logger.info(f"Prepared configurations: {configurations}")
            files = {'files': (file.name, file, 'application/octet-stream')}
            logger.info(f"Prepared files: {files}")

            dms_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
            response = requests.post(dms_api_url, data=configurations, files=files)
            logger.info(f"DMS API response: {response}")

            if response.status_code == 200:
                logger.info(f"File '{file.name}' successfully sent to DMS API.")
                response_json = response.json()
                file_name = response_json.get('file_name')
                file_id = response_json.get('file', {}).get('id', response_json.get('file_id'))
                download_link = response_json.get('download_link')
                logger.info(f"organization_id '{organization_id}' .")
                # organization_instance = Organization.objects.filter(id=organization_id).first()
                organization_instance = Organization.objects.get(id=organization_id.id)
                logger.info(f"File '{organization_id}' successfully sent to DMS API %s.", organization_instance)
                if not organization_instance:
                    logger.error("Organization instance not found.")
                    return None

                dms_data, created = Dms_data.objects.get_or_create(
                    folder_id=file_id,
                    filename=file_name,
                    case_id=None,
                    flow_id=process_id,
                    download_link=download_link,
                    organization=organization_instance,
                    defaults={'meta_data': configurations['metadata']}
                )

                if not created:
                    dms_data.meta_data = configurations['metadata']
                    dms_data.save()
                    logger.info(f"Updated existing Dms_data with ID {dms_data.id}")

                return dms_data

            else:
                logger.error(f"Failed to send file '{file.name}' to DMS API. "
                             f"Status Code: {response.status_code}, Response: {response.text}")
                return JsonResponse({"error": "Failed to upload file"}, status=response.status_code)
    except Exception as e:
        logger.error(f"An error occurred during file upload to DMS: {str(e)}")
        return JsonResponse({"error": "An internal error occurred"}, status=500)


def parse_frequency_to_cron(frequency_str):
    """Parse human-readable frequency strings and convert to cron expressions."""

    # Predefined mapping for common cases
    frequency_map = {
        "hourly": "0 * * * *",
        "daily": "0 0 * * *",
        "weekly": "0 0 * * 0",
        "monthly": "0 0 1 * *"
    }

    # Direct mapping for simple frequencies
    if frequency_str.lower() in frequency_map:
        return [frequency_map[frequency_str.lower()]]

    # Every 'N' minutes pattern
    match = re.match(r"every (\d+) minutes", frequency_str.lower())
    if match:
        minutes = match.group(1)
        return [f"*/{minutes} * * * *"]

    # Every 'N' hours pattern
    match = re.match(r"every (\d+) hours", frequency_str.lower())
    if match:
        hours = match.group(1)
        return [f"0 */{hours} * * *"]

    # Twice a week pattern
    if "twice a week" in frequency_str.lower():
        return ["0 0 * * 1", "0 0 * * 4"]  # Runs on Mondays and Thursdays

    # Specific daily time pattern, e.g., "daily at 3:30 PM"
    match = re.match(r"daily at (\d{1,2}):(\d{2}) (AM|PM)", frequency_str, re.IGNORECASE)
    if match:
        hour, minute, period = match.groups()
        hour = int(hour)
        if period.lower() == "pm" and hour != 12:
            hour += 12
        elif period.lower() == "am" and hour == 12:
            hour = 0
        return [f"{minute} {hour} * * *"]

    # Unsupported frequency case
    return None


######################## Email Spooling to Extract the PDF and generate the case[STARTS]###############################


######################## Email Spooling to Extract the PDF and generate the cases[ENDS]###############################

class PDFSpooler:
    @staticmethod
    def authenticate_mail(imap_server, receiver_mail, receiver_password, sender_email, scheduler_id,
                          attachment_dir="attachments"):
        global processId
        try:
            mail = IMAP4_SSL(imap_server)
            logger.info("Connected to IMAP server.")
            scheduler = Scheduler.objects.get(id=scheduler_id)
            logger.info(f"schedulerrrrrrrrrrrrrrrr in as {scheduler_id}.")
            process_id = scheduler.process
            logger.info(f"schedulerrrrrrrrrrrrrrrr in as {process_id}.")
            organization_id = scheduler.organization
            logger.info(f"organization_id in as {organization_id}.")
            mail.login(receiver_mail, receiver_password)
            logger.info(f"Logged in as {receiver_mail}.")
            mail.select("inbox")

            logger.info(f"Searching for emails from {sender_email}...")

            # status, messages = mail.search(None, f'(FROM "{sender_email}")')
            status, messages = mail.search(None, f'(UNSEEN FROM "{sender_email}")')
            logger.info(f"Search status: {status}, messages: {messages}")
            if status != 'OK' or not messages[0]:
                logger.error(f"No emails found from {sender_email}.")
                return {"error": f"No emails found from {sender_email}."}

            mail_ids = messages[0].split()

            if not mail_ids:
                logger.info(f"No emails found from {sender_email}.")
                return {"error": f"No emails found from {sender_email}."}

            latest_email_id = mail_ids[-1]
            result, msg_data = mail.fetch(latest_email_id, "(RFC822)")
            # Ensure msg_data is properly parsed from the fetch response
            raw_email = msg_data[0][1]

            # Parse the email using the email library
            msg = BytesParser(policy=policy.default).parsebytes(raw_email)

            # Extract the email subject (for filename use)
            subject = msg['subject']
            subject_sanitized = ''.join(
                c if c.isalnum() else '_' for c in subject) if subject else 'email_without_subject'

            # Extract sender and receiver information
            from_email = msg['from']
            to_email = msg['to']

            # Initialize variables to store the email body and attachments
            email_body = ""
            html_body = ""
            attachments = []

            def process_email_parts(part):
                nonlocal email_body, html_body, attachments

                # If part is multipart, iterate through its parts
                if part.is_multipart():
                    for subpart in part.iter_parts():
                        process_email_parts(subpart)
                else:
                    content_disposition = part.get_content_disposition()
                    content_type = part.get_content_type()

                    # Handle attachments
                    if content_disposition and "attachment" in content_disposition:
                        filename = part.get_filename()
                        if filename:
                            os.makedirs(attachment_dir, exist_ok=True)
                            filepath = os.path.join(attachment_dir, filename)
                            with open(filepath, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                            logger.info(f"Saved attachment: {filepath}")
                            attachments.append(filename)
                            # Normalize the file path for cross-platform compatibility
                            filepath = os.path.normpath(filepath)
                            # Send the file to the DMS API
                            with open(filepath, 'rb') as file:
                                dms_entries = Dms.objects.filter(organization=organization_id)
                                if not dms_entries.exists():
                                    # Log and respond if DMS is not configured
                                    logger.error("DMS not configured for this organization.")
                                    return JsonResponse({"error": "DMS not configured"}, status=400)
                                logger.info(f"Saved dms_entries: {dms_entries}")
                                drive_types = dms_entries.first().drive_types if dms_entries.exists() else {}
                                logger.info(f"Saved drive_types: {drive_types}")
                                configurations = dms_entries.first().config_details_schema

                                configurations['drive_types'] = drive_types
                                # configurations['s3_bucket_metadata'] = drive_types
                                logger.info(f"Saved configurations: {configurations}")
                                metadata = {'form_name': file.name, 'organization_id': str(organization_id)}
                                configurations[
                                    'metadata'] = metadata  # Pass metadata as a dictionary if required by the API

                                logger.info(f"Prepared configurations: {configurations}")
                                # files = {'file': (file.name, file, 'application/octet-stream')}
                                # files = {'files': (file.name, file.file, file.content_type)}
                                files = {'files': (file.name, file, 'application/octet-stream')}
                                logger.info(f"Prepared files: {files}")
                                dms_api_url = f'{settings.BASE_URL}/custom_components/FileUploadView/'
                                # Send the request
                                response = requests.post(dms_api_url, data=configurations, files=files)
                                logger.info(f"DMS API response: {response}")
                                if response.status_code == 200:
                                    logger.info(f"File '{filename}' successfully sent to DMS API.")
                                    response_json = response.json()
                                    print("response_json--------------", response_json)
                                    file_name = response_json.get('file_name')
                                    file_id = response_json.get('file', {}).get('id')
                                    if not file_id:
                                        file_id = response_json.get('file_id')
                                    file_name = response_json.get('file_name')
                                    download_link = response_json.get('download_link')
                                    print("download_link ", download_link)
                                    print("File Name:", file_name)
                                    print("File ID:", file_id)
                                    print("organization_instance ID:", organization_id.id)
                                    print("organization_instance ID:", process_id.id)

                                    try:
                                        organization_instance = Organization.objects.get(id=organization_id.id)
                                    except Organization.DoesNotExist:
                                        # Handle the case where the organization does not exist
                                        organization_instance = None

                                    dms_data = None
                                    try:
                                        dms_data, created = Dms_data.objects.get_or_create(
                                            folder_id=file_id,
                                            filename=file_name,
                                            case_id=None,
                                            flow_id=process_id,
                                            download_link=download_link,

                                            organization=organization_instance,
                                            defaults={'meta_data': configurations['metadata']}
                                        )

                                    except Exception as e:
                                        print("Error during get_or_create:", e)
                                    if dms_data is None:
                                        print("dms_data is None")
                                    else:
                                        print(f"dms_data details: {dms_data.__dict__}")

                                        # If BotData was found, update the data_schema fieldF
                                    if not created:
                                        try:
                                            dms_data.meta_data = dms_data
                                            dms_data.save()  # Ensure you call save on the correct object

                                        except Exception as e:
                                            print("Error during dms data save:", e)
                                            return None
                                    return None

                                else:
                                    logger.error(f"Failed to send file '{filename}' to DMS API. "
                                                 f"Status Code: {response.status_code}, Response: {response.text}")
                                    return None
                        return None



                    # Handle plain text email body
                    elif content_type == "text/plain" and not email_body:
                        email_body = part.get_payload(decode=True)
                        if isinstance(email_body, bytes):
                            email_body = email_body.decode(part.get_content_charset() or 'utf-8')
                            return None
                        return None

                    # Handle HTML email body
                    elif content_type == "text/html" and not html_body:
                        html_body = part.get_payload(decode=True)
                        if isinstance(html_body, bytes):
                            html_body = html_body.decode(part.get_content_charset() or 'utf-8')
                            return None
                        return None
                    return None

            # Process all parts of the email
            process_email_parts(msg)

            # Save the plain text email body as a text file (if present)
            body_filename = None
            if email_body:
                body_filename = os.path.join(attachment_dir, f"{subject_sanitized}_body.pdf")
                with open(body_filename, 'w', encoding='utf-8') as body_file:
                    body_file.write(email_body)
                logger.info(f"Saved email body: {body_filename}")

            # Optionally save HTML body as a separate file (if present)
            html_filename = None
            if html_body:
                html_filename = os.path.join(attachment_dir, f"{subject_sanitized}_body.html")
                with open(html_filename, 'w', encoding='utf-8') as html_file:
                    html_file.write(html_body)
                logger.info(f"Saved HTML email body: {html_filename}")

            # Log the result and return a summary
            result_info = {
                "email_body_saved": body_filename if email_body else None,
                "html_body_saved": html_filename if html_body else None,
                "attachments_saved": attachments if attachments else None
            }
            mail.close()
            mail.logout()
            logger.info("Logged out from the mail server.")
            return {"success": "Email processed successfully.", "details": result_info}
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            return {"error": str(e)}


class SchedulerCreateAPIView(APIView):

    def get(self, request, process_id, organization_id):
        try:
            # Retrieve the scheduler objects for the given process and organization
            schedulers = Scheduler.objects.filter(
                process_id=process_id,
                organization_id=organization_id
            )
            if not schedulers.exists():
                return JsonResponse({
                    "status": "error",
                    "message": "No schedulers found for the given process and organization."
                }, status=404)

            # Serialize the scheduler data
            scheduler_data = [
                {
                    "id": scheduler.id,
                    "scheduler_name": scheduler.scheduler_name,
                    "scheduler_uid": scheduler.scheduler_uid,
                    "frequency": scheduler.frequency,
                    "scheduler_config": scheduler.scheduler_config,
                    "last_run": scheduler.last_run,
                    "next_run": scheduler.next_run,
                    "is_active": scheduler.is_active
                }
                for scheduler in schedulers
            ]

            return JsonResponse({
                "status": "success",
                "data": scheduler_data
            }, status=200)

        except Exception as e:
            logger.error(f"Error retrieving schedulers: {e}")
            return JsonResponse({
                "status": "error",
                "message": str(e)
            }, status=400)

    def post(self, request, process_id, organization_id):
        try:
            # Parse the request body (JSON input)

            # Ensure input_data is a dictionary, even if wrapped in a list
            input_data = request.data[0] if isinstance(request.data, list) else request.data

            logger.info(f"Input data %s: {input_data}")

            frequency_str = input_data.get('frequency', '')
            # Parse frequency string to cron
            cron_expressions = parse_frequency_to_cron(frequency_str)
            if not cron_expressions:
                return JsonResponse({
                    "status": "error",
                    "message": f"Invalid or unsupported frequency: {frequency_str}"
                }, status=400)

            # Retrieve the process and organization objects
            organization = get_object_or_404(Organization, id=organization_id)

            process = get_object_or_404(CreateProcess, id=process_id)

            logger.debug(f"Retrieved organization: {organization} with ID: {organization.id}")
            logger.debug(f"Retrieved process: {process} with ID: {process.id}")

            # Update or create scheduler
            scheduler, created = Scheduler.objects.update_or_create(
                scheduler_uid=input_data.get("scheduler_uid"),
                defaults={
                    "scheduler_name": input_data.get("scheduler_name"),
                    "organization": organization,
                    "process": process,
                    "frequency": frequency_str,
                    "scheduler_config": input_data,
                    "last_run": None,
                    "next_run": timezone.now(),
                    "is_active": True
                }
            )
            logger.debug(f"Created scheduler with ID: {scheduler.id}")
            logger.debug(f"{'Created' if created else 'Updated'} scheduler with ID: {scheduler.id}")

            # Delete previous periodic tasks if updating
            if not created:
                PeriodicTask.objects.filter(name__startswith=f"monitor_emails_task_{scheduler.id}_").delete()

            # Create crontab and tasks for each parsed cron expression
            for cron_expression in cron_expressions:
                minute, hour, day_of_month, month_of_year, day_of_week = cron_expression.split()

                crontab_schedule, _ = CrontabSchedule.objects.get_or_create(
                    minute=minute, hour=hour, day_of_month=day_of_month,
                    month_of_year=month_of_year, day_of_week=day_of_week
                )

                PeriodicTask.objects.create(
                    crontab=crontab_schedule,
                    name=f"monitor_emails_task_{scheduler.id}_{cron_expression}",
                    task='custom_components.tasks.monitor_emails_task',
                    args=json.dumps([scheduler.id])  # Pass scheduler_id as an argument
                )

            return JsonResponse({
                "status": "success",
                "message": "Scheduler created successfully",
                "scheduler_id": scheduler.id
            })

        except Exception as e:
            logger.error(f"Error creating scheduler: {e}")
            return JsonResponse({
                "status": "error",
                "message": str(e)
            }, status=400)

    def put(self, request, process_id, organization_id):
        try:
            # Parse input data
            input_data = request.data[0] if isinstance(request.data, list) else request.data
            logger.debug(f"Input data for update: {input_data}")

            # Retrieve the scheduler
            scheduler_id = input_data.get("scheduler_id")
            if not scheduler_id:
                return JsonResponse({
                    "status": "error",
                    "message": "Scheduler ID is required for updating."
                }, status=400)

            scheduler = get_object_or_404(
                Scheduler, id=scheduler_id, process_id=process_id, organization_id=organization_id
            )
            logger.debug(f"Retrieved scheduler with ID: {scheduler.id} for update.")

            # Update fields
            scheduler.scheduler_name = input_data.get("scheduler_name", scheduler.scheduler_name)
            scheduler.scheduler_uid = input_data.get("scheduler_uid", scheduler.scheduler_uid)
            scheduler.frequency = input_data.get("frequency", scheduler.frequency)
            scheduler.scheduler_config = input_data.get("scheduler_config", scheduler.scheduler_config)
            scheduler.is_active = input_data.get("is_active", scheduler.is_active)
            scheduler.next_run = input_data.get("next_run", scheduler.next_run)
            scheduler.save()

            logger.debug(f"Scheduler with ID: {scheduler.id} updated successfully.")

            return JsonResponse({
                "status": "success",
                "message": "Scheduler updated successfully",
                "scheduler_id": scheduler.id
            }, status=200)

        except Exception as e:
            logger.error(f"Error updating scheduler: {e}")
            return JsonResponse({
                "status": "error",
                "message": str(e)
            }, status=400)


###################### Function to activate and run the Scheduler #############################
def activate_and_run_scheduler_task(first_current_step_id):
    # Step 1: Retrieve the scheduler instance using the step ID
    scheduler = Scheduler.objects.filter(scheduler_uid=first_current_step_id).first()
    if not scheduler:
        logger.error(f"No scheduler found with step ID: {first_current_step_id}")
        return {"status": "error", "message": f"No scheduler found with step ID: {first_current_step_id}"}

    # Step 2: Get the scheduler ID
    scheduler_id = scheduler.id

    # Step 3: Locate the periodic task associated with this scheduler
    task_name = f"monitor_emails_task_{scheduler_id}_*"  # Adjust to match your naming convention
    periodic_task = PeriodicTask.objects.filter(name__startswith=task_name).first()

    if not periodic_task:
        logger.error(f"No periodic task found for scheduler with ID: {scheduler_id}")
        return {"status": "error", "message": f"No periodic task found for scheduler with ID: {scheduler_id}"}

    # Step 4: Enable the task if it's currently disabled
    if not periodic_task.enabled:
        periodic_task.enabled = True
        periodic_task.save()
        logger.info(f"Activated periodic task: {periodic_task.name}")

    # Step 5: Run the task with the scheduler ID as an argument
    logger.info(f"Triggering monitor_emails_task with scheduler ID {scheduler_id}")
    monitor_emails_task.apply_async(args=[scheduler_id])

    return {"status": "success", "message": "Scheduler task activated and triggered successfully"}


#################################### Report Generation API ##############################
class ReportConfigView(APIView):
    def get(self, request, organization_id, pk=None):
        """
        Retrieve report configurations.
        If `pk` is provided, return a specific report configuration.
        Otherwise, return all configurations for the organization.
        """
        if pk:
            try:
                report_config = ReportConfig.objects.get(pk=pk, organization_id=organization_id)
                serializer = ReportConfigSerializer(report_config)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except ReportConfig.DoesNotExist:
                return Response({"error": "Report configuration not found"}, status=status.HTTP_404_NOT_FOUND)
        else:
            report_configs = ReportConfig.objects.filter(organization_id=organization_id)
            serializer = ReportConfigSerializer(report_configs, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, organization_id):
        """
        Create a new report configuration for the given organization.
        """
        data = request.data
        data['organization'] = organization_id
        serializer = ReportConfigSerializer(data=data)
        if serializer.is_valid():
            uid = generate_uid(ReportConfig, "RC", organization_id)
            serializer.save(uid=uid)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, organization_id, pk):
        """
        Update an existing report configuration for the given organization.
        """
        try:
            report_config = ReportConfig.objects.get(pk=pk, organization_id=organization_id)
        except ReportConfig.DoesNotExist:
            return Response({"error": "Report configuration not found"}, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        data['organization'] = organization_id  # Ensure organization is not altered
        serializer = ReportConfigSerializer(report_config, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, organization_id, pk):
        """
        Delete an existing report configuration for the given organization.
        """
        try:
            report_config = ReportConfig.objects.get(pk=pk, organization_id=organization_id)
            report_config.delete()
            return Response({"message": "Report configuration deleted successfully"}, status=status.HTTP_204_NO_CONTENT)
        except ReportConfig.DoesNotExist:
            return Response({"error": "Report configuration not found"}, status=status.HTTP_404_NOT_FOUND)


class GenerateReportView(APIView):
    """
    getting case related filled form and form schema and Execute the query for the report
    """

    def get(self, request, organization_id, report_id, pk=None):
        logger.info("Case Related Reports view")

        def filter_cases_by_organization_and_process(organization_id, process_id):
            """Fetch cases based on organization and process IDs."""
            try:
                cases = Case.objects.filter(organization_id=organization_id, processId=process_id)

                return cases
            except Exception as e:
                logger.error(f"Error fetching cases for organization {organization_id} and process {process_id}: {e}")
                raise ValidationError("Error fetching cases based on organization and process")

        def serialize_queryset(queryset, serializer_class):
            """Serialize a queryset using the provided serializer."""
            try:
                serialized_data = serializer_class(queryset, many=True).data

                return serialized_data
            except Exception as e:
                logger.error(f"Error serializing data: {e}")
                raise ValidationError("Error serializing the data")

        def extract_case_ids(serialized_data):
            """Extract case IDs from serialized data."""
            try:
                case_ids = [case['id'] for case in serialized_data]
                return case_ids
            except KeyError as e:
                logger.error(f"Missing 'id' field in serialized data: {e}")
                raise ValidationError("Error extracting case IDs")

        def fetch_related_data(case_ids, related_model, serializer_class, case_field="case_id"):
            """Fetch and serialize related data."""
            try:
                filter_kwargs = {f"{case_field}__in": case_ids}
                related_data = related_model.objects.filter(**filter_kwargs)
                logger.info("Fetched %s: %s", related_model.__name__, related_data)
                return serialize_queryset(related_data, serializer_class)
            except Exception as e:
                logger.error(f"Error fetching related data for model {related_model}: {e}")
                raise ValidationError(f"Error fetching related data for {related_model.__name__}")

        def get_report_details(report_id):
            """Fetch report details including type, process/form ID, and query."""
            try:
                report_config = ReportConfig.objects.get(id=report_id)
                return report_config.report_type, report_config.data_id, report_config.query
            except ReportConfig.DoesNotExist:
                logger.error(f"ReportConfig with ID {report_id} not found.")
                raise NotFound(f"Report with ID {report_id} does not exist")
            except Exception as e:
                logger.error(f"Error fetching ReportConfig for ID {report_id}: {e}")
                raise ValidationError("Error fetching report configuration")

        try:
            # Validate organization ID
            if not Organization.objects.filter(id=organization_id).exists():
                logger.error(f"Organization with ID {organization_id} not found.")
                raise NotFound(f"Organization with ID {organization_id} does not exist")

            # Fetch report details
            report_type, data_id, report_query = get_report_details(report_id)
            # operator = report_query.get("operator", "AND")
            operator = report_query.get("operator")  # changed to get operator instead of getting by default
            conditions = report_query.get("conditions", [])

            if pk is None:
                if report_type == "process":
                    # Process-based report
                    cases = filter_cases_by_organization_and_process(organization_id, data_id)
                    serialized_cases = serialize_queryset(cases, CaseSerializer)
                    case_ids = extract_case_ids(serialized_cases)

                    # Fetch related data
                    form_data = fetch_related_data(case_ids, FilledFormData, FilledDataInfoSerializer,
                                                   case_field="caseId")
                    bot_data = fetch_related_data(case_ids, BotData, BotDataSerializer)
                    integration_data = fetch_related_data(case_ids, IntegrationDetails, IntegrationDetailsSerializer)
                    ocr_data = fetch_related_data(case_ids, Ocr_Details, Ocr_DetailsSerializer)
                    dms_data = fetch_related_data(case_ids, Dms_data, DmsDataSerializer)

                    # Combine and filter data
                    combined_data = []
                    for case in serialized_cases:
                        case_id = case['id']

                        combined_data.append({
                            "case_id": case,
                            "merged_data": {
                                "bot_data": [bot for bot in bot_data if bot['case_id'] == case_id],
                                "integration_data": [integration for integration in integration_data if
                                                     integration['case_id'] == case_id],
                                "ocr_data": [ocr for ocr in ocr_data if ocr['case_id'] == case_id],
                                "form_data": [form for form in form_data if form['caseId'] == case_id],
                            },
                            "dms_data": [dms for dms in dms_data if dms['case_id'] == case_id],
                        })
                    # filtered_cases = evaluate_and_filter_data(combined_data, conditions, operator)
                    filtered_cases = []
                    for case in combined_data:
                        result = evaluate_conditions(conditions, operator, case['merged_data'])
                        # result = evaluate_conditions(query['conditions'], query['operator'], case['merged_data'])
                        if result:
                            filtered_cases.append(case)
                    if filtered_cases:
                        response_data = {"cases": filtered_cases}
                        return Response(response_data, status=200)
                    else:
                        logger.warning("No cases matched the query conditions.")
                        return Response({"message": "Cases not found"}, status=404)


                elif report_type == "form":
                    # Form-based report
                    filled_data = FilledFormData.objects.filter(organization_id=organization_id, formId=data_id)
                    serialized_filled_data = serialize_queryset(filled_data, FilledDataInfoSerializer)
                    # filtered_cases = evaluate_and_filter_data(serialized_filled_data, conditions, operator)
                    filtered_data = []
                    for data in serialized_filled_data:
                        # result = evaluate_conditions(conditions, operator, {'form_data': serialized_filled_data})
                        result = evaluate_conditions(conditions, operator, {"form_data": [data]})
                        # result = evaluate_conditions(query['conditions'], query['operator'], case['merged_data'])
                        if result:
                            filtered_data.append(data)
                    if filtered_data:
                        response_data = {"data": filtered_data}
                        return Response(response_data, status=200)
                    else:
                        logger.warning("No Forms matched the query conditions.")
                        return Response({"message": "Forms not found"}, status=404)

                elif report_type == "core data":
                    # Form-based report
                    filled_data = FilledFormData.objects.filter(organization_id=organization_id, formId=data_id)
                    serialized_filled_data = serialize_queryset(filled_data, FilledDataInfoSerializer)
                    # filtered_cases = evaluate_and_filter_data(serialized_filled_data, conditions, operator)
                    filtered_data = []
                    for data in serialized_filled_data:
                        # result = evaluate_conditions(conditions, operator, {'form_data': serialized_filled_data})
                        result = evaluate_conditions(conditions, operator, {"form_data": [data]})
                        # result = evaluate_conditions(query['conditions'], query['operator'], case['merged_data'])
                        if result:
                            filtered_data.append(data)
                    if filtered_data:
                        response_data = {"data": filtered_data}
                        return Response(response_data, status=200)
                    else:
                        logger.warning("No Forms matched the query conditions.")
                        return Response({"message": "Forms not found"}, status=404)
                elif report_type == "subprocess":
                    # Process-based report
                    cases = filter_cases_by_organization_and_process(organization_id, data_id)
                    serialized_cases = serialize_queryset(cases, CaseSerializer)
                    case_ids = extract_case_ids(serialized_cases)

                    # Fetch related data
                    form_data = fetch_related_data(case_ids, FilledFormData, FilledDataInfoSerializer,
                                                   case_field="caseId")
                    bot_data = fetch_related_data(case_ids, BotData, BotDataSerializer)
                    integration_data = fetch_related_data(case_ids, IntegrationDetails, IntegrationDetailsSerializer)
                    ocr_data = fetch_related_data(case_ids, Ocr_Details, Ocr_DetailsSerializer)
                    dms_data = fetch_related_data(case_ids, Dms_data, DmsDataSerializer)

                    # Combine and filter data
                    combined_data = []
                    for case in serialized_cases:
                        case_id = case['id']

                        combined_data.append({
                            "case_id": case,
                            "merged_data": {
                                "bot_data": [bot for bot in bot_data if bot['case_id'] == case_id],
                                "integration_data": [integration for integration in integration_data if
                                                     integration['case_id'] == case_id],
                                "ocr_data": [ocr for ocr in ocr_data if ocr['case_id'] == case_id],
                                "form_data": [form for form in form_data if form['caseId'] == case_id],
                            },
                            "dms_data": [dms for dms in dms_data if dms['case_id'] == case_id],
                        })
                    # filtered_cases = evaluate_and_filter_data(combined_data, conditions, operator)
                    filtered_cases = []
                    for case in combined_data:
                        result = evaluate_conditions(conditions, operator, case['merged_data'])
                        # result = evaluate_conditions(query['conditions'], query['operator'], case['merged_data'])
                        if result:
                            filtered_cases.append(case)
                    # --- Search ---
                    search_query = request.query_params.get("search")
                    if filtered_cases:
                        if search_query:
                            search_query_lower = search_query.lower()
                            filtered_cases = [
                                case for case in filtered_cases
                                if search_query_lower in str(case.get('merged_data', '')).lower()
                            ]

                        # --- Pagination ---
                        page = int(request.query_params.get("page", 1))
                        page_size = int(request.query_params.get("page_size", 10))

                        paginator = Paginator(filtered_cases, page_size)

                        try:
                            paginated_cases = paginator.page(page)
                        except PageNotAnInteger:
                            paginated_cases = paginator.page(1)
                        except EmptyPage:
                            paginated_cases = paginator.page(paginator.num_pages)

                        # --- Response ---
                        response_data = {
                            "count": paginator.count,
                            "total_pages": paginator.num_pages,
                            "current_page": page,
                            "page_size": page_size,
                            "cases": paginated_cases.object_list
                        }

                        return Response(response_data, status=200)
                    # if filtered_cases:
                    #     response_data = {"cases": filtered_cases}
                    #     return Response(response_data, status=200)
                    else:
                        logger.warning("No cases matched the query conditions.")
                        return Response({"message": "Cases not found"}, status=404)
                else:
                    logger.error(f"Unsupported report type: {report_type}")
                    raise ValidationError(f"Unsupported report type: {report_type}")
            return None


        except NotFound as e:
            logger.error(f"NotFound error: {e}")
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            logger.error(f"ValidationError occurred: {e}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


############################## Reports Optimize for Report Generation modified by Harish [29.8.25] STARTS

""" Reports Optimization """
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware
from django.db.models import Prefetch, Q
import time
from form_generator.utils.log_time import log_time


class ReportBuilderView(APIView):
    """
    Optimized API endpoint to build reports with reduced DB queries and in-memory loops.
    """
    """
        Optimized API endpoint to build reports with reduced DB queries and in-memory loops.
        """

    def get(self, request, organization_id, report_id, pk=None):
        start_date_str = request.query_params.get("startDate")
        end_date_str = request.query_params.get("endDate")
        start_date, end_date = parse_date_range(start_date_str, end_date_str)

        query_ids_raw = request.query_params.get("query_ids")
        query_ids = [q.strip().lower() for q in query_ids_raw.split(",")] if query_ids_raw else []

        # page = int(request.query_params.get("page", 1))
        # page_size = int(request.query_params.get("page_size", 20))

        try:
            # 1️⃣ Validate organization
            if not Organization.objects.filter(id=organization_id).exists():
                raise NotFound(f"Organization {organization_id} does not exist")

            # 2️⃣ Cache / fetch report configuration
            start_time = time.time()
            try:
                report = ReportConfig.objects.only("id", "report_type", "data_id", "query").get(id=report_id)
                report_type, data_id, report_query = report.report_type, report.data_id, report.query
            except ReportConfig.DoesNotExist:
                raise NotFound(f"Report {report_id} does not exist")

            operator = report_query.get("operator")
            conditions = report_query.get("conditions", [])
            log_time("Get ReportConfig", start_time)

            # 3️⃣ Helper: paginate queryset efficiently
            # def paginate_queryset(qs):
            #     paginator = Paginator(qs, page_size)
            #     try:
            #         page_obj = paginator.page(page)
            #     except PageNotAnInteger:
            #         page_obj = paginator.page(1)
            #     except EmptyPage:
            #         page_obj = paginator.page(paginator.num_pages)
            #     return page_obj

            # 4️⃣ Helper: filter form/core data by query_ids
            start_time = time.time()

            def filter_by_query_ids(data_list, query_ids):
                if not query_ids:
                    return data_list

                filtered = []
                for entry in data_list:
                    fields = entry.get("data", [])
                    matching = [
                        f for f in fields
                        if any(
                            q == str(f.get("field_id", "")).lower() or
                            q == str(f.get("label", "")).lower()
                            for q in query_ids
                        )
                    ]
                    if matching:
                        new_entry = entry.copy()
                        new_entry["data"] = matching
                        filtered.append(new_entry)
                return filtered

            log_time("filter_by_query_ids", start_time)

            # 5️⃣ Process by report type
            if report_type in ["process", "subprocess"]:
                # 🔸 Prefetch related form data to avoid N+1
                start_time = time.time()
                

                # Prefetch related FilledFormData efficiently
                start_time = time.time()
                form_qs = FilledFormData.objects.only("id", "caseId", "data_json", "updated_at")
                if start_date and end_date:
                    form_qs = form_qs.filter(updated_at__range=[start_date, end_date])
                elif start_date:
                    form_qs = form_qs.filter(updated_at__gte=start_date)
                elif end_date:
                    form_qs = form_qs.filter(updated_at__lte=end_date)
                log_time("start & end date Form filter", start_time)

                start_time = time.time()
                # case_queryset = Case.objects.filter(
                #     organization_id=organization_id,
                #     processId=data_id
                # ).only("id", "stages", "status", "updated_by", "updated_on", "parent_case_data").prefetch_related(
                #     Prefetch("filledformdata_set", queryset=form_qs, to_attr="prefetched_forms")
                # )
                base_qs = Case.objects.filter(
                    organization_id=organization_id,
                    processId=data_id
                ).only("id", "stages", "status", "updated_by", "updated_on", "parent_case_data").prefetch_related(
                    Prefetch("filledformdata_set", queryset=form_qs, to_attr="prefetched_forms")
                )
                log_time("base_qs case filter", start_time)

                start_time = time.time()
                if start_date and end_date:
                    base_qs = base_qs.filter(updated_on__range=[start_date, end_date])
                elif start_date:
                    base_qs = base_qs.filter(updated_on__gte=start_date)
                elif end_date:
                    base_qs = base_qs.filter(updated_on__lte=end_date)
                log_time("start & end date Case filter", start_time)

                # paged_cases = paginate_queryset(qs)
                # --- Convert query_ids to set for O(1) lookup ---
                query_ids_set = set(q.lower() for q in query_ids)

                response_data = []
                start_time = time.time()
                for case in base_qs:
                    # Flatten parent_case_data (dict->list once)
                    parent_data = case.parent_case_data or []
                    if isinstance(parent_data, dict):
                        parent_data = [{"label": k, "field_id": k, "value": v} for k, v in parent_data.items()]

                    # Flatten only prefetched forms (already filtered in DB)
                    form_data_list = []
                    for form in getattr(case, "prefetched_forms", []):
                        data_json = form.data_json if isinstance(form.data_json, list) else json.loads(
                            form.data_json or "[]")
                        form_data_list.extend(data_json)

                    # Merge for condition evaluation
                    merged_data = {
                        "form_data": [f.__dict__ for f in getattr(case, "prefetched_forms", [])],
                        "case_id": {
                            "parent_case_data": case.parent_case_data or []
                        }
                    }
                    if not evaluate_conditions(conditions, operator, merged_data):
                        continue

                    # Filter by query_ids in Python (lightweight now)
                    combined_data = parent_data + form_data_list
                    if query_ids_set:
                        filtered_data = [
                            f for f in combined_data
                            if str(f.get("field_id", "")).lower() in query_ids_set
                               or str(f.get("label", "")).lower() in query_ids_set
                        ]
                        if not filtered_data:
                            continue
                    else:
                        filtered_data = combined_data

                    # Append final result
                    response_data.append({
                        "id": case.id,
                        "stages": case.stages,
                        "status": case.status,
                        "updated_by": case.updated_by,
                        "updated_on": case.updated_on,
                        "data": filtered_data
                    })
                log_time("case_queryset looping", start_time)

                start_time = time.time()
                filtered = filter_by_query_ids(response_data, query_ids)
                log_time("filtered cases final", start_time)
                if not filtered:
                    return Response({"message": "Cases not found"}, status=status.HTTP_404_NOT_FOUND)

                return Response(filtered, status=status.HTTP_200_OK)

            elif report_type in ["form", "core data"]:
                form_queryset = FilledFormData.objects.filter(
                    organization_id=organization_id,
                    formId=data_id
                ).only("id", "stages", "status", "updated_by", "updated_at", "data_json")

                if start_date and end_date:
                    form_queryset = form_queryset.filter(updated_at__range=[start_date, end_date])
                elif start_date:
                    form_queryset = form_queryset.filter(updated_at__gte=start_date)
                elif end_date:
                    form_queryset = form_queryset.filter(updated_at__lte=end_date)

                # paged_forms = paginate_queryset(qs)
                response_data = []

                for form in form_queryset:
                    try:
                        data_json = json.loads(form.data_json) if isinstance(form.data_json, str) else form.data_json
                    except json.JSONDecodeError:
                        data_json = []

                    if evaluate_conditions(conditions, operator, {"form_data": [form.__dict__]}):
                        response_data.append({
                            "id": form.id,
                            "stages": form.stages,
                            "status": form.status,
                            "updated_by": form.updated_by,
                            "updated_on": form.updated_at,
                            "data": data_json,
                        })

                filtered = filter_by_query_ids(response_data, query_ids)
                if not filtered:
                    return Response({"message": "Forms not found"}, status=status.HTTP_404_NOT_FOUND)

                return Response(filtered, status=status.HTTP_200_OK)

            else:
                raise ValidationError(f"Unsupported report type: {report_type}")

        except NotFound as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error in report builder: {e}", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # def get(self, request, organization_id, report_id, pk=None):
    #     """
    #     Handle GET requests to generate a report.
    #     Args:
    #         organization_id: Organization ID for data filtering
    #         report_id: Report configuration ID
    #         pk: Optional primary key (not used here)
    #     """
    #     # -------- Query Parameters -------- #


#         start_date_str = request.query_params.get("startDate")
#         end_date_str = request.query_params.get("endDate")
#         start_date, end_date = parse_date_range(start_date_str, end_date_str)
#         query_ids_raw = request.query_params.get("query_ids")
#         # page = int(request.query_params.get("page", 1))  # default page 1
#         # page_size = int(request.query_params.get("page_size", 10))  # default 10 per page
#         page = request.query_params.get("page")
#         page_size = request.query_params.get("page_size")
#
#         # start_date = parse_datetime(start_date_str) if start_date_str else None
#         # end_date = parse_datetime(end_date_str) if end_date_str else None
#         query_ids = [q.strip() for q in query_ids_raw.split(",")] if query_ids_raw else []
#
#         # ---------------- Utility Functions ---------------- #
#         def get_cases_by_org_and_process(org_id, process_id):
#             """Fetch cases for a given organization and process, with optional date filtering."""
#             try:
#                 filters = {"organization_id": org_id, "processId": process_id}
#                 qs = Case.objects.filter(**filters)
#
#                 if start_date and end_date:
#                     qs = qs.filter(updated_on__range=[start_date, end_date])
#                 elif start_date:
#                     qs = qs.filter(updated_on__gte=start_date)
#                 elif end_date:
#                     qs = qs.filter(updated_on__lte=end_date)
#
#                 return qs
#             except Exception as e:
#                 logger.error(f"Error fetching cases for org {org_id}, process {process_id}: {e}")
#                 raise ValidationError("Failed to fetch cases for organization and process")
#
#         def serialize_queryset(queryset, serializer_class):
#             """Serialize a queryset using the provided serializer class."""
#             try:
#                 return serializer_class(queryset, many=True).data
#             except Exception as e:
#                 logger.error(f"Error serializing queryset: {e}")
#                 raise ValidationError("Failed to serialize data")
#
#         def extract_case_ids(serialized_cases):
#             """Extract case IDs from serialized case data."""
#             try:
#                 return [case['id'] for case in serialized_cases]
#             except KeyError as e:
#                 logger.error(f"Missing 'id' in case data: {e}")
#                 raise ValidationError("Invalid case data: missing ID")
#
#         def fetch_and_serialize_related(case_ids, model, serializer_class, case_field="case_id"):
#             """Fetch related model data for cases and serialize, with optional date filter."""
#             try:
#                 filter_kwargs = {f"{case_field}__in": case_ids}
#                 qs = model.objects.filter(**filter_kwargs)
#
#                 if start_date and end_date:
#                     qs = qs.filter(updated_at__range=[start_date, end_date])
#                 elif start_date:
#                     qs = qs.filter(updated_at__gte=start_date)
#                 elif end_date:
#                     qs = qs.filter(updated_at__lte=end_date)
#
#                 return serialize_queryset(qs, serializer_class)
#             except Exception as e:
#                 logger.error(f"Error fetching related {model.__name__}: {e}")
#                 raise ValidationError(f"Failed to fetch related {model.__name__} data")
#
#         def get_report_configuration(report_id):
#             """Retrieve report configuration details."""
#             try:
#                 report = ReportConfig.objects.get(id=report_id)
#                 return report.report_type, report.data_id, report.query
#             except ReportConfig.DoesNotExist:
#                 logger.error(f"ReportConfig {report_id} not found")
#                 raise NotFound(f"Report {report_id} does not exist")
#             except Exception as e:
#                 logger.error(f"Error fetching ReportConfig {report_id}: {e}")
#                 raise ValidationError("Failed to fetch report configuration")
#
#         def filter_by_query_ids(data_list, query_ids):
#             """
#             Filter each entry's 'data' list by query_ids (fieldId or label).
#             Only keep matching fields (partial + case-insensitive).
#             """
#             if not query_ids:
#                 return data_list
#
#             query_ids = [q.lower() for q in query_ids]
#             filtered_entries = []
#
#             for entry in data_list:
#                 try:
#                     fields = entry.get("data", [])
#                     # Keep only fields that exactly match fieldId or label
#                     matching_fields = [
#                         field for field in fields
#                         if any(
#                             query == str(field.get("field_id", "")).lower() or
#                             query == str(field.get("label", "")).lower()
#                             for query in query_ids
#                         )
#                     ]
#                     if matching_fields:
#                         new_entry = entry.copy()
#                         new_entry["data"] = matching_fields
#                         filtered_entries.append(new_entry)
#                 except Exception as e:
#                     logger.warning(f"Invalid JSON in data_json for entry {entry.get('id')}: {e}")
#             return filtered_entries
#
#         # ---------------- Main Processing ---------------- #
#         try:
#             # Validate organization existence
#             if not Organization.objects.filter(id=organization_id).exists():
#                 logger.error(f"Organization {organization_id} not found")
#                 raise NotFound(f"Organization {organization_id} does not exist")
#
#             # Fetch report configuration
#             report_type, data_id, report_query = get_report_configuration(report_id)
#             operator = report_query.get("operator")
#             conditions = report_query.get("conditions", [])
#
#             if pk is None:
#                 logger.info(f"Generating report of type {report_type}")
#
#                 # ---------- Process/Subprocess Reports ---------- #
#                 if report_type in ["process", "subprocess"]:
#                     cases = get_cases_by_org_and_process(organization_id, data_id)
#                     serialized_cases = serialize_queryset(cases, CaseSerializer)
#                     case_ids = extract_case_ids(serialized_cases)
#
#                     # Fetch related form data
#                     form_data = fetch_and_serialize_related(case_ids, FilledFormData, FilledDataInfoSerializer,
#                                                             case_field="caseId")
#
#                     # Merge case data with related form data
#                     combined_data = []
#                     for case in serialized_cases:
#                         case_id = case['id']
#                         # Extract form data for this case
#                         case_form_data = [form for form in form_data if form['caseId'] == case_id]
#                         # Initialize data list for this case
#                         data_list = []
#                         # Add parent_case_data fields (assuming it's a list or dict convertible to label, field_id, value)
#                         parent_case_data = case.get('parent_case_data', [])
#                         if isinstance(parent_case_data, dict):
#                             # Convert dict to list of {label, field_id, value}
#                             parent_case_data = [
#                                 {"label": key, "field_id": key, "value": value} for key, value in
#                                 parent_case_data.items()
#                             ]
#                         data_list.extend(parent_case_data)
#
#                         # Add data_json fields from form data
#                         for form in case_form_data:
#                             # Parse data_json if it's a string
#                             data_json = form.get("data_json", [])
#                             if isinstance(data_json, str):
#                                 try:
#                                     data_json = json.loads(data_json)
#                                 except json.JSONDecodeError as e:
#                                     logger.warning(f"Invalid JSON in data_json for form {form.get('id')}: {e}")
#                                     data_json = []
#                             data_list.extend(data_json)
#
#                         # Combine into final case structure
#                         combined_data.append({
#                             "case": case,
#                             "form_data": {"data": data_list},
#                             "merged_data": {"form_data": [form for form in form_data if form['caseId'] == case_id]},
#                         })
#
#                     # Apply filtering
#                     filtered_cases = []
#                     for case in combined_data:
#                         if evaluate_conditions(conditions, operator, case['merged_data']):
#                             filtered_cases.append({
#                                 "id": case["case"].get("id", ""),
#                                 "stages": case["case"].get("stages", ""),
#                                 "status": case["case"].get("status", ""),
#                                 "updated_by": case["case"].get("updated_by", ""),
#                                 "updated_on": case["case"].get("updated_on", ""),
#                                 "data": case["form_data"]["data"]
#                             })
#
#                     if filtered_cases:
#                         # Filter each case's data by query_ids
#                         filtered_cases_by_query = filter_by_query_ids(filtered_cases, query_ids)
#                         # Apply pagination
#                         paginated_cases_list = paginate_list(filtered_cases_by_query, page, page_size)
#                         # Return response
#                         return Response(paginated_cases_list, status=status.HTTP_200_OK)
#
#                     logger.warning("No cases matched query conditions")
#                     return Response({"message": "Cases not found"}, status=status.HTTP_404_NOT_FOUND)
#
#                 # ---------- Form/Core Data Reports ---------- #
#                 elif report_type in ["form", "core data"]:
#                     print("data_id : ", data_id)
#                     filled_forms = FilledFormData.objects.filter(organization_id=organization_id, formId=data_id)
#
#                     if start_date and end_date:
#                         filled_forms = filled_forms.filter(updated_at__range=[start_date, end_date])
#                     elif start_date:
#                         filled_forms = filled_forms.filter(updated_at__gte=start_date)
#                     elif end_date:
#                         filled_forms = filled_forms.filter(updated_at__lte=end_date)
#
#                     serialized_forms = serialize_queryset(filled_forms, FilledDataInfoSerializer)
#
#                     filtered_data = []
#                     for form in serialized_forms:
#                         if evaluate_conditions(conditions, operator, {"form_data": [form]}):
#                             filtered_data.append({
#                                 "id": form.get("id", ""),
#                                 "stages": form.get("stages", ""),
#                                 "status": form.get("status", ""),
#                                 "updated_by": form.get("updated_by", ""),
#                                 "updated_on": form.get("updated_at", ""),
#                                 "data": json.loads(form.get("data_json", "[]")),  # parse JSON string into list
#                             })
#
#                     if filtered_data:
#                         # Filter each form/core data by query_ids
#                         filtered_data_by_query = filter_by_query_ids(filtered_data, query_ids)
#                         # Apply pagination
#                         paginated_data_list = paginate_list(filtered_data_by_query, page, page_size)
#                         # Return response
#                         return Response(paginated_data_list, status=status.HTTP_200_OK)
#                     logger.warning("No forms matched query conditions")
#                     return Response({"message": "Forms not found"}, status=status.HTTP_404_NOT_FOUND)
#
#                 # ---------- Unsupported Report Type ---------- #
#                 else:
#                     logger.error(f"Unsupported report type: {report_type}")
#                     raise ValidationError(f"Unsupported report type: {report_type}")
#
#             return None  # If pk is provided (currently unused)
#
#         # ---------------- Error Handling ---------------- #
#         except NotFound as e:
#             return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
#         except ValidationError as e:
#             return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             logger.error(f"Unexpected error: {e}", exc_info=True)
#             return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
#
#
def parse_date_range(start_date_str, end_date_str):
    """Convert date strings into datetime objects covering the full range."""
    start_date = None
    end_date = None

    if start_date_str:
        start_date = make_aware(datetime.strptime(start_date_str, "%Y-%m-%d"))
    if end_date_str:
        # include the full day by setting to 23:59:59
        end_date = make_aware(datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1))

    return start_date, end_date


def paginate_list(data_list, page=None, page_size=None):
    """
    Return a slice of data_list based on page and page_size.
    If page or page_size is not provided, return the full list.
    """
    if page is None or page_size is None:
        return data_list
    try:
        page = int(page)
        page_size = int(page_size)
    except ValueError:
        # If invalid integers are passed, return full list instead of error
        return data_list

    if page <= 0 or page_size <= 0:
        return data_list

    start = (page - 1) * page_size
    end = start + page_size
    return data_list[start:end]


################################# Report API optimized by Mohan - 7-10-25[STARTS] ########################
class ReportBuilderViewOptimized(APIView):
    """
    Optimized API endpoint to build reports with reduced DB queries and in-memory loops.
    """

    def get(self, request, organization_id, report_id, pk=None):
        start_date_str = request.query_params.get("startDate")
        end_date_str = request.query_params.get("endDate")
        start_date, end_date = parse_date_range(start_date_str, end_date_str)

        query_ids_raw = request.query_params.get("query_ids")
        query_ids = [q.strip().lower() for q in query_ids_raw.split(",")] if query_ids_raw else []

        page = int(request.query_params.get("page", 1))
        page_size = int(request.query_params.get("page_size", 20))

        try:
            # 1️⃣ Validate organization
            if not Organization.objects.filter(id=organization_id).exists():
                raise NotFound(f"Organization {organization_id} does not exist")

            # 2️⃣ Cache / fetch report configuration
            try:
                report = ReportConfig.objects.only("id", "report_type", "data_id", "query").get(id=report_id)
                report_type, data_id, report_query = report.report_type, report.data_id, report.query
            except ReportConfig.DoesNotExist:
                raise NotFound(f"Report {report_id} does not exist")

            operator = report_query.get("operator")
            conditions = report_query.get("conditions", [])

            # 3️⃣ Helper: paginate queryset efficiently
            def paginate_queryset(qs):
                paginator = Paginator(qs, page_size)
                try:
                    page_obj = paginator.page(page)
                except PageNotAnInteger:
                    page_obj = paginator.page(1)
                except EmptyPage:
                    page_obj = paginator.page(paginator.num_pages)
                return page_obj

            # 4️⃣ Helper: filter form/core data by query_ids
            def filter_by_query_ids(data_list, query_ids):
                if not query_ids:
                    return data_list

                filtered = []
                for entry in data_list:
                    fields = entry.get("data", [])
                    matching = [
                        f for f in fields
                        if any(
                            q == str(f.get("field_id", "")).lower() or
                            q == str(f.get("label", "")).lower()
                            for q in query_ids
                        )
                    ]
                    if matching:
                        new_entry = entry.copy()
                        new_entry["data"] = matching
                        filtered.append(new_entry)
                return filtered

            # 5️⃣ Process by report type
            if report_type in ["process", "subprocess"]:
                # 🔸 Prefetch related form data to avoid N+1
                base_qs = Case.objects.filter(
                    organization_id=organization_id,
                    processId=data_id
                ).only("id", "stages", "status", "updated_by", "updated_on", "parent_case_data")

                if start_date and end_date:
                    base_qs = base_qs.filter(updated_on__range=[start_date, end_date])
                elif start_date:
                    base_qs = base_qs.filter(updated_on__gte=start_date)
                elif end_date:
                    base_qs = base_qs.filter(updated_on__lte=end_date)

                # Prefetch related FilledFormData efficiently
                form_qs = FilledFormData.objects.only("id", "caseId", "data_json", "updated_at")
                if start_date and end_date:
                    form_qs = form_qs.filter(updated_at__range=[start_date, end_date])
                elif start_date:
                    form_qs = form_qs.filter(updated_at__gte=start_date)
                elif end_date:
                    form_qs = form_qs.filter(updated_at__lte=end_date)

                qs = base_qs.prefetch_related(
                    Prefetch("filledformdata_set", queryset=form_qs, to_attr="prefetched_forms")
                )

                paged_cases = paginate_queryset(qs)

                response_data = []
                for case in paged_cases:
                    # Build data list
                    data_list = []
                    parent_case_data = case.parent_case_data or []

                    if isinstance(parent_case_data, dict):
                        parent_case_data = [
                            {"label": k, "field_id": k, "value": v}
                            for k, v in parent_case_data.items()
                        ]
                    data_list.extend(parent_case_data)

                    for form in getattr(case, "prefetched_forms", []):
                        raw_json = form.data_json
                        if isinstance(raw_json, str):
                            try:
                                raw_json = json.loads(raw_json)
                            except json.JSONDecodeError:
                                raw_json = []
                        data_list.extend(raw_json)

                    merged_data = {"form_data": [f.__dict__ for f in getattr(case, "prefetched_forms", [])]}
                    if evaluate_conditions(conditions, operator, merged_data):
                        response_data.append({
                            "id": case.id,
                            "stages": case.stages,
                            "status": case.status,
                            "updated_by": case.updated_by,
                            "updated_on": case.updated_on,
                            "data": data_list
                        })

                filtered = filter_by_query_ids(response_data, query_ids)
                if not filtered:
                    return Response({"message": "Cases not found"}, status=status.HTTP_404_NOT_FOUND)

                return Response(filtered, status=status.HTTP_200_OK)

            elif report_type in ["form", "core data"]:
                qs = FilledFormData.objects.filter(
                    organization_id=organization_id,
                    formId=data_id
                ).only("id", "stages", "status", "updated_by", "updated_at", "data_json")

                if start_date and end_date:
                    qs = qs.filter(updated_at__range=[start_date, end_date])
                elif start_date:
                    qs = qs.filter(updated_at__gte=start_date)
                elif end_date:
                    qs = qs.filter(updated_at__lte=end_date)

                paged_forms = paginate_queryset(qs)
                response_data = []

                for form in paged_forms:
                    try:
                        data_json = json.loads(form.data_json) if isinstance(form.data_json, str) else form.data_json
                    except json.JSONDecodeError:
                        data_json = []

                    if evaluate_conditions(conditions, operator, {"form_data": [form.__dict__]}):
                        response_data.append({
                            "id": form.id,
                            "stages": form.stages,
                            "status": form.status,
                            "updated_by": form.updated_by,
                            "updated_on": form.updated_at,
                            "data": data_json,
                        })

                filtered = filter_by_query_ids(response_data, query_ids)
                if not filtered:
                    return Response({"message": "Forms not found"}, status=status.HTTP_404_NOT_FOUND)

                return Response(filtered, status=status.HTTP_200_OK)

            else:
                raise ValidationError(f"Unsupported report type: {report_type}")

        except NotFound as e:
            return Response({"error": str(e)}, status=status.HTTP_404_NOT_FOUND)
        except ValidationError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Unexpected error in report builder: {e}", exc_info=True)
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


################################# Report API optimized by Mohan - 7-10-25[ENDS] ########################
############################## Reports Optimize for Report Generation modified by Harish [29.8.25] ENDS
########################################## Desktop Automation [By Mohan - 21.12.2024] Starts ####################################

# class RPAHandlerView(APIView):
#     """
#     API endpoint to handle RPA tasks using RPAHandler.
#     """
#
#     def post(self, request, *args, **kwargs):
#         """
#         Handle POST requests to automate desktop applications.
#         """
#         try:
#             # Extract app_path, window_title, and actions from the request body
#             data = request.data
#             app_path = data.get("app_path")
#             window_title = data.get("window_title")  # Optional
#             actions = data.get("actions")
#
#             # Validate the input
#             if not app_path:
#                 return Response(
#                     {"error": "Missing 'app_path' in the request body."},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
#             if not isinstance(actions, list) or not actions:
#                 return Response(
#                     {"error": "Invalid 'actions'. It must be a non-empty list."},
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
#
#             # Initialize the RPA handler
#             rpa_handler = RPAHandler(app_path, window_title)
#
#             # Start the application
#             start_result = rpa_handler.start_application()
#             logger.info("RPA :** Application started successfully.")
#
#             # Perform the tasks
#             task_result = rpa_handler.perform_task(actions)
#             logger.info("RPA :** Tasks performed successfully.")
#
#             # Close the application
#             close_result = rpa_handler.close_application()
#             logger.info("RPA :** Application closed successfully.")
#
#             # Return success response
#             return Response({
#                 "message": "RPA tasks completed successfully.",
#                 "start_result": start_result,
#                 "task_result": task_result,
#                 "close_result": close_result
#             }, status=status.HTTP_200_OK)
#
#         except Exception as e:
#             logger.error(f"RPA :** An error occurred: {str(e)}")
#             return Response(
#                 {"error": f"RPA :** {str(e)}"},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


############################ API to generate the QRCODE #################################


import qrcode
from rest_framework.views import APIView
from io import BytesIO


class QRCodeGenerate(APIView):
    def post(self, request):
        try:
            # Retrieve data from the request
            data = request.data.get("data")
            if data is None:
                raise ValidationError("Missing 'data' field in the request.")

            # Convert data to JSON-compatible string if not already a string
            if not isinstance(data, str):
                try:
                    import json
                    data = json.dumps(data)
                except (TypeError, ValueError) as e:
                    raise ValidationError(f"Unable to serialize data to JSON: {e}")

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            # Save the image to a BytesIO object
            buffered = BytesIO()
            img.save(buffered, format="PNG")

            # Convert the image to a Base64 string
            img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

            # Return the Base64 string in the JSON response
            return JsonResponse({"qrcode": img_base64}, status=200)

            # response = HttpResponse(content_type="image/png")
            # img.save(response, "PNG")
            # return response

        except APIException as e:
            # Handle API-related exceptions
            return JsonResponse({"error": str(e)}, status=400)

        except Exception as e:
            # Catch unexpected exceptions
            return JsonResponse({"error": f"Unexpected error: {str(e)}"}, status=500)


################### code block API [Starts]#########################################.

import io

import base64
import re
from rest_framework.views import APIView

from django.db import connection


class CodeBlockExecutionAPIView(APIView):

    def post(self, request, *args, **kwargs):
        """Handles script execution"""
        # logger.info("Received data: %s", request.data)

        serializer = ScriptExecutionSerializer(data=request.data)
        logger.info('in the Code block')
        if serializer.is_valid():
            request_filled_data = serializer.validated_data.get("filledData", {})
            filled_data = {}
            encoded_script = serializer.validated_data.get("encodedScript", "")
            variables = serializer.validated_data.get("variablesList", [])
            organization_id = request.data.get("organization_id")
            user_schemas = []

            user_form_schema = None
            org_user_form_schema_field_ids = {}
            org_user_form_schema = UserFormSchema.objects.filter(organization=organization_id).first()
            if org_user_form_schema:
                user_form_schema = org_user_form_schema.user_form_schema.get('form_json_schema', [])
                org_user_form_schema_field_ids = {field['field_id'] for field in user_form_schema}
                # logger.info('organization_id field_ids %s', org_user_form_schema_field_ids)

            required_field_ids = org_user_form_schema_field_ids

            try:
                user_schemas = UserData.objects.filter(
                    organization=organization_id
                )
            except Exception as e:
                logger.error(f"Error in user_profiles_table: {e}")
                traceback.print_exc()

            user_profile_json_data = []
            # logger.info('user_schemas %s', user_schemas)
            for user in user_schemas:
                try:
                    raw_schema = user.user_profile_schema

                    # Check if raw_schema is a non-empty string
                    if isinstance(raw_schema, str) and raw_schema.strip():
                        json_data = json.loads(raw_schema)
                    elif isinstance(raw_schema, dict) or isinstance(raw_schema, list):
                        json_data = raw_schema
                    else:
                        logger.warning(f"Invalid or empty schema for user ID {user.id}: {raw_schema}")
                        continue

                    # Only append if json_data is a list of dicts
                    if isinstance(json_data, list) and all(isinstance(item, dict) for item in json_data):
                        user_profile_json_data.append(json_data)

                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error for user ID {user.id}: {e}")
                    traceback.print_exc()
                except Exception as e:
                    logger.error(f"Unexpected error processing user ID {user.id}: {e}")
                    traceback.print_exc()

            # logger.info("Encoded script: %s", encoded_script)
            # If filledData is empty, build it from the database using form_id
            # logger.info("user_profile_json_data %s", user_profile_json_data)
            user_combined_data = []
            combined_data_list = []

            if user_profile_json_data:
                for user_profile in user_profile_json_data:
                    if isinstance(user_profile, list):
                        # Convert list of dicts to a field_id -> value mapping for fast lookup
                        field_map = {item['field_id']: item for item in user_profile if isinstance(item, dict)}

                        for field_id in required_field_ids:
                            item = field_map.get(field_id, {
                                "field_id": field_id,
                                "value": "",
                                "label": ""  # You can fetch default label if needed
                            })
                            user_combined_data.append({
                                "field_id": item["field_id"],
                                "value": item.get("value", ""),
                                "label": item.get("label", "")
                            })
                    else:
                        logger.warning(f"Expected list, got {type(user_profile)}: {user_profile}")

            for item in user_combined_data:
                field_id = item["field_id"]
                value = item["value"]

                # If key already exists and is a list, append to it
                if field_id in filled_data:
                    # Ensure it's a list
                    if isinstance(filled_data[field_id], list):
                        # if value not in filled_data[field_id]:

                        filled_data[field_id].append(value)  # changed for duplication 
                    else:
                        # Convert existing value to list
                        filled_data[field_id] = [filled_data[field_id], value]
                else:
                    # Add new key with list
                    filled_data[field_id] = [value]

            for var in variables:
                form_id = var.get("form_id")
                field_id = var.get("field_id")
                var_name = field_id.replace("-", "_")

                # Merge all filled data for the form

                all_filled = FilledFormData.objects.filter(formId=form_id)

                # logger.info("all_filled %s", all_filled)
                for entry in all_filled:
                    data_json = entry.data_json or []
                    if isinstance(data_json, str):
                        try:
                            data_json = json.loads(data_json)
                        except json.JSONDecodeError:
                            data_json = []  # fallback if it's not valid JSON

                    for item in data_json:
                        if isinstance(item, dict) and item.get("field_id") == field_id:
                            combined_data_list.append({
                                "field_id": field_id,
                                "value": item.get("value"),
                                "label": item.get("label", "")
                            })
                            break
                    # merged_data.update(data_json)

                #       )

                #  Merge combined_data into filled_data as lists
                for item in combined_data_list:
                    field_id = item["field_id"]
                    value = item["value"]

                    # If key already exists and is a list, append to it
                    if field_id in filled_data:
                        # Ensure it's a list
                        if isinstance(filled_data[field_id], list):
                            # if value not in filled_data[field_id]:

                            filled_data[field_id].append(value)  # changed for duplication 
                        else:
                            # Convert existing value to list
                            filled_data[field_id] = [filled_data[field_id], value]
                    else:
                        # Add new key with list
                        filled_data[field_id] = [value]

            valid_request_filled_data = {
                key: value for key, value in request_filled_data.items()
                if value not in [None, '', [], {}, ()]  # You can modify this condition
            }
            filled_data.update(valid_request_filled_data)
            # Decode script
            decoded_script = self.decode_script(encoded_script)
            if isinstance(decoded_script, dict) and "error" in decoded_script:
                return Response(decoded_script, status=status.HTTP_400_BAD_REQUEST)

            # # Inject variables
            final_script = self.inject_variables(decoded_script, filled_data)

            # Execute script
            result = self.execute_script(final_script)

            return Response(result, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def decode_script(self, encoded_script):
        """Decodes base64 encoded script"""
        try:
            return base64.b64decode(encoded_script).decode("utf-8")
        except Exception as e:
            return {"error": f"Decoding failed: {str(e)}"}

    def run_dynamic_python_script(self, script_code):
        """
        Executes decoded dynamic script directly using exec.
        Note: Use only with trusted scripts.
        """
        try:
            exec_globals = {}
            exec_locals = {}
            exec(script_code, exec_globals, exec_locals)
            return {"result": exec_locals.get("data", "Executed successfully")}
        except Exception as e:
            return {"error": f"Script Execution Error: {str(e)}"}

    import re
    def inject_variables(self, script, filled_data):
        """
        Replaces placeholders with actual values from filled_data.
        Ensures for-loop variables and conditions are handled properly.
        """

        def format_value(val):
            if isinstance(val, str):
                return f'"{val}"'
            elif isinstance(val, (list, tuple, set)):
                return str(list(val))  # Convert to Python list syntax
            return str(val)

        def normalize_key(key):
            return key.replace("-", "_")

        if script is None:
            raise ValueError("Script content is None. Expected a valid string.")
        # Normalize filled_data keys for valid Python variable names
        normalized_filled_data = {normalize_key(k): v for k, v in filled_data.items()}

        ############ added for API Block #####################
        def replacer(match):
            field_id = match.group(1)
            return repr(filled_data.get(field_id, ""))  # Use repr to handle strings properly

        script = re.sub(r"\{\{\s*(\w+)\s*}}", replacer, script)
        script_lines = script.strip().splitlines()
        cleaned_lines = []

        # Extract loop variables to prevent incorrect replacements
        loop_variables = set()
        for line in script_lines:
            match = re.match(r"\s*for\s+(\w+)\s+in\s+", line)
            if match:
                loop_variables.add(match.group(1))  # Extract loop variable

        # Replace `var = None` with actual values from filled_data
        for line in script_lines:
            stripped_line = line.strip()

            replaced = False
            for key in normalized_filled_data:
                if stripped_line == f"{key} = None":
                    value = format_value(normalized_filled_data[key])
                    indent = re.match(r"^(\s*)", line).group(1)  # preserve indentation
                    cleaned_lines.append(f"{indent}{key} = {value}")
                    replaced = True
                    break  # already handled, skip to next line

            if not replaced:
                cleaned_lines.append(line)

        script = "\n".join(cleaned_lines)
        return script

        # Replace variables on RHS only (not in assignment targets)
        def replace_rhs(line):
            assign_match = re.match(r"^(\s*)(\w+)\s*=(.*)", line)
            if assign_match:
                indent, lhs, rhs = assign_match.groups()
                if lhs in normalized_filled_data:
                    lhs_replacement = lhs  # Don't replace LHS
                else:
                    lhs_replacement = lhs
                for key, val in normalized_filled_data.items():
                    if key not in loop_variables:
                        pattern = r'\b' + re.escape(key) + r'\b'
                        rhs = re.sub(pattern, format_value(val), rhs)
                return f"{indent}{lhs_replacement} = {rhs}"
            else:
                # No assignment – replace freely
                for key, val in normalized_filled_data.items():
                    if key not in loop_variables:
                        pattern = r'\b' + re.escape(key) + r'\b'
                        line = re.sub(pattern, format_value(val), line)
                return line

        # final_lines = [replace_rhs(line) for line in cleaned_lines]
        final_lines = script
        # print("final_lines",final_lines)
        # Ensure last line assigns to result
        while final_lines and final_lines[-1].strip() == "":
            final_lines.pop()
        if final_lines:
            last_line = final_lines[-1].strip()
            if (
                    not last_line.startswith("return")
                    and not last_line.startswith("result =")
                    and not last_line.startswith("raise")
                    and not last_line.startswith("print")
                    and not last_line.startswith("pass")
            ):
                final_lines[-1] = f"result = {last_line}"

        return "\n".join(final_lines)

    def execute_sql_query(self, query):
        """
        Executes an SQL query using Django's database connection.
        Returns both the executed query and its result.
        """
        try:
            with connection.cursor() as cursor:
                cursor.execute(query)

                if query.strip().upper().startswith(("SELECT", "COUNT", "SUM", "AVG", "MIN", "MAX")):
                    columns = [col[0] for col in cursor.description]  # Get column names
                    result = [dict(zip(columns, row)) for row in cursor.fetchall()]
                else:
                    result = {"message": "Query executed successfully"}

            return {"executed_query": query, "sql_result": result}
        except Exception as e:
            return {"error": f"SQL Execution Error: {str(e)}"}

    def execute_script(self, script):
        """
        Executes the given script inside a function and captures its return value.
        Handles 'return' by wrapping the script in a function scope.
        """
        try:
            local_scope = {}

            # Wrap user script inside a function
            wrapped_script = f"def user_function():\n"
            for line in script.splitlines():
                wrapped_script += "    " + line + "\n"  # Indent each line

            wrapped_script += "\nresult = user_function()"

            exec(wrapped_script, {}, local_scope)
            result = local_scope.get("result")

            # Check if result is an SQL query (including aggregate functions)
            # sql_keywords = ("SELECT", "INSERT", "UPDATE", "DELETE", "COUNT", "SUM", "AVG", "MIN", "MAX")
            # if isinstance(result, str) and result.strip().upper().startswith(sql_keywords):
            #     return self.execute_sql_query(result)
            if isinstance(result, str):
                result = result.strip().replace('"', "'")  # Convert " to ' for SQL safety

            # Check if a result is a valid SQL query
            if isinstance(result, str) and result.strip().upper().startswith(
                    ("SELECT", "INSERT", "UPDATE", "DELETE", "COUNT", "SUM", "AVG", "MIN", "MAX")):
                return self.execute_sql_query(result)

            return {"result": result}
        except Exception as e:
            return {"error": str(e)}


################### code block API [Ends]#########################################.


# Environment variables or constants (Replace with your actual values)
CLIENT_ID = '5628da5e-eeae-4061-87f2-99e8510bff35';
CLIENT_SECRET= os.getenv("CLIENT_SECRET");
SCOPE = 'https://api.businesscentral.dynamics.com/.default';
TOKEN_URL = "https://login.microsoftonline.com/7231b10c-d98a-4e28-b9b7-e0f479f06d1e/oauth2/v2.0/token"


@csrf_exempt  # Disable CSRF for simplicity (only if necessary)
def refresh_token(request):
    if request.method == 'GET':
        try:
            data = {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "client_credentials",
                "scope": SCOPE,
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            response = requests.post(TOKEN_URL, data=data, headers=headers)
            response_json = response.json()

            if response.status_code == 200:
                return JsonResponse({"access_token": response_json.get("access_token", "")}, status=200)
            else:
                return JsonResponse({"error": response_json}, status=response.status_code)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)


############################################## Execute API Newly [STARTS] #################################

import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json


def extract_from_path(data, path):
    keys = path.split(".")
    for key in keys:
        if isinstance(data, list):
            try:
                key = int(key)
                data = data[key]
            except (ValueError, IndexError):
                return None
        elif isinstance(data, dict):
            data = data.get(key)
        else:
            return None
    return data


def replace_path_params(path, path_params, input_data):
    for param in path_params:
        name = param["name"]
        source = param.get("source")
        if param.get("type") == "field_id" and param.get("fieldId"):
            value = input_data.get(param["fieldId"], f"{{{name}}}")
        else:
            value = param.get("value", f"{{{name}}}")
        path = path.replace(f"{{{name}}}", str(value))
        return path
    return None

    #     field_id = param.get("fieldId")
    #     if source == "form_id" and field_id:
    #         value = form_data.get(field_id, f"{{{name}}}")
    #         path = path.replace(f"{{{name}}}", str(value))
    # return path


def build_query_params(query_params, input_data):
    result = {}
    for param in query_params:
        key = param.get("param_key")
        if not key:
            continue

        if param.get("param_type") == "field_id" and param.get("fieldId"):
            result[key] = input_data.get(param["fieldId"], "")
        else:
            result[key] = param.get("param_value", "")
    return result


def build_headers(headers_config, input_data):
    headers = {}
    for h in headers_config:
        key = h["header_key"]
        val = h["header_value"]
        if key and val:
            headers[key] = val
    return headers


def build_payload(body_config, input_data):
    content_type = body_config.get("contentType")
    payload = {}
    # If input_data is a list (like your example), take the first item
    if isinstance(input_data, list) and len(input_data) > 0:
        input_data = input_data[-1]
    else:
        input_data = input_data
    for item in body_config.get("payload", []):
        key = item.get("request_key")
        if not key:
            continue
        request_type = item.get("request_type", "")
        request_value = item.get("request_value", "")
        if request_type == "field_ref":
            # Get the value from input_data using request_value as the key
            val = input_data.get(request_value, "")
        elif request_type == "field_id":
            # Old logic for field_id
            val = input_data.get(item.get("fieldId", ""), "")
        else:
            # Static or other types
            val = request_value

        # if item.get("type") == "field_id" and item.get("fieldId"):
        #     val = input_data.get(item["fieldId"], "")
        # else:
        #     val = item.get("request_value", "")
        payload[key] = val
    return content_type, payload


class ExecuteDynamicAPI(APIView):

    def post(self, request):
        data = request.data
        config = request.data.get("schema_config", {})
        input_data = request.data.get("input_data", {})
        try:
            # === Base URL and Path ===
            base_url_config = config.get("base_url", {})
            base = base_url_config.get("base")
            if not base:
                return Response({"error": "Missing base URL"}, status=400)

            endpoint = base_url_config.get("endpoint", {})
            query_params = base_url_config.get("queryParams", [])
            path_template = endpoint.get("path", "")
            path_params = endpoint.get("pathParams", [])

            # --- Helper to check validity ---
            def has_valid_params(params, keys):
                return any(param.get(k, "") for param in params for k in keys)

            has_path_params = has_valid_params(path_params, ["name", "fieldId"])
            has_query_params = has_valid_params(query_params, ["param_key"])

            # === Path Params Replacement ===
            if has_path_params:
                for param in path_params:
                    name = param.get("name", "")
                    field_id = param.get("fieldId", "")
                    path_type = param.get("path_type", "")
                    value = None

                    if path_type == "field_ref" and field_id:
                        for item in input_data:
                            if field_id in item:
                                value = item[field_id]
                                break
                    else:
                        value = param.get("value") or field_id

                    if name and value is not None:
                        path_template = path_template.replace(f"{{{name}}}", str(value))

            # === Query Params Replacement ===
            if has_query_params:
                for param in query_params:
                    param_key = param.get("param_key", "")
                    param_value = param.get("param_value", "")
                    param_type = param.get("param_type", "")

                    value = None
                    if param_type == "field_ref" and param_value:
                        for item in input_data:
                            if param_value in item:
                                value = item[param_value]
                                break
                    else:
                        value = param.get("value") or param_value

                    if param_key and value is not None:
                        path_template = path_template.replace(f"{{{param_key}}}", str(value))

            # === Final URL ===
            url = base + path_template
            # === Query Params ===
            query_dict = build_query_params(base_url_config.get("queryParams", []), input_data)

            # === Headers ===
            headers = {}
            for header in config.get("headers", []):
                k = header.get("header_key")
                v = header.get("header_value")
                if k and v:
                    headers[k] = v

            # === Auth ===
            auth = None
            auth_config = config.get("auth", {})
            if auth_config.get("type") == "basic":
                username = auth_config["basic"].get("username")
                password = auth_config["basic"].get("password")
                auth = (username, password)
            elif auth_config.get("type") == "bearer":
                token = auth_config["bearer"].get("token")
                headers["Authorization"] = f"Bearer {token}"
            elif auth_config.get("type") == "oauth2":
                headers["Authorization"] = "Bearer <oauth_token_here>"  # Placeholder

            # === Body ===
            body_config = config.get("body", {})
            content_type, data = build_payload(body_config, input_data)

            if content_type == "json":
                body = json.dumps(data)
                headers["Content-Type"] = "application/json"
            elif content_type == "form-data":
                body = data
            else:
                body = str(data)

            # === HTTP Method ===
            method = config.get("method", "GET").upper()

            # === Make Request ===
            response = requests.request(
                method=method,
                url=url,
                params=query_dict,
                data=body if content_type != "json" else None,
                json=data if content_type == "json" else None,
                headers=headers,
                auth=auth,
            )
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                try:
                    result_data = response.json()
                except ValueError:
                    return Response({"error": "Failed to parse JSON"}, status=400)
            else:
                result_data = {"raw_response": response.text}

            # === Response Extraction ===
            api_response_data = []
            for res in config.get("api_response", []):
                key = res["response_key"]
                path = res["access_path"]
                value = extract_from_path(result_data, path)
                api_response_data.append({
                    "field_id": key,
                    "value": value
                })

            return Response({
                "api_response_data": api_response_data,
                "api_response": result_data
            })
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


################### Notiification Bot in process Create,List and Update API [Starts]###############

class NotificationBotListCreateView(APIView):
    def get(self, request):
        try:
            notifications = NotificationBotSchema.objects.all()
            serializer = NotificationBotSchemaSerializer(notifications, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            serializer = NotificationBotSchemaSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NotificationBotDetailView(APIView):
    def get_object(self, pk):
        return get_object_or_404(NotificationBotSchema, pk=pk)

    def get(self, request, pk):
        try:
            notification = self.get_object(pk)
            serializer = NotificationBotSchemaSerializer(notification)
            return Response(serializer.data)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            notification = self.get_object(pk)
            serializer = NotificationBotSchemaSerializer(notification, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            notification = self.get_object(pk)
            notification.delete()
            return Response({"message": "Deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


################### Notiifcation Bot in process Create,List and Update API [Ends]###############

################### Client Dashboard Updated for New implementation [By Harish - updated on 20-8-25]############################

################### Client Dashboard Updated for New implementation ############################
from rest_framework.test import APIRequestFactory
from collections import defaultdict
from django.db.models import Count, Prefetch
from django.db.models import Value
from django.db.models import CharField


class ClientDashboardView(APIView):
    """
    API to retrieve client dashboard data based on organization, user group, and user ID.
    Handles fetching and processing dashboard configurations for various component types.
    """

    def get(self, request):
        """
        Handles GET requests to fetch dashboard data.
        Validates query parameters and processes dashboard configurations.
        """
        try:
            # Extract query parameters with proper naming
            organization_id = request.query_params.get('org_id')
            user_group_id = request.query_params.get('user_group_id')
            user_id = request.query_params.get('user_id')

            # Validate required parameters
            if not organization_id:
                return Response(
                    {'status': False, 'error': "Missing 'org_id' parameter."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not user_id:
                return Response(
                    {'status': False, 'error': "Missing 'user_id' parameter."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Fetch user data
            user_data = self._get_user_data(user_id)

            # Fetch dashboard records based on org and user group
            dashboard_records = self._get_dashboard_records(organization_id, user_group_id)

            if dashboard_records:
                # Serialize dashboard data
                serializer = DashboardConfigurationSerializer(dashboard_records)
                dashboards = [serializer.data]

                # Process each dashboard configuration
                result_data = self._process_dashboards(
                    dashboards, organization_id, user_id, user_group_id, user_data
                )
                return Response({"status": True, "results": result_data}, status=status.HTTP_200_OK)
            else:
                return Response({"status": False, "message": "No dashboard configuration found", "results": []},
                                status=status.HTTP_404_NOT_FOUND)


        except Exception as e:
            # Catch-all for unexpected errors
            return Response(
                {'status': False, 'error': f"Unexpected error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _get_user_data(self, user_id):
        """
        Helper method to fetch and process user data.
        Returns a dictionary of user profile schema fields.
        """
        try:
            user = UserData.objects.get(id=user_id)
            user_data_list = user.user_profile_schema or []
            return {
                data.get('field_id'): data.get('value')
                for data in user_data_list if 'field_id' in data and 'value' in data
            }
        except UserData.DoesNotExist:
            raise HttpResponseBadRequest({'error': 'User not found'})

    def _get_dashboard_records(self, organization_id, user_group_id):
        """
        Helper method to fetch dashboard records based on organization and user group.
        """
        if user_group_id:
            # Both org and user group provided
            return Dashboard.objects.filter(organization=organization_id, usergroup=user_group_id,
                                            dashboard_types="custom_dashboard").order_by('-id').first()
        else:
            # Only org provided, fetch null user groups
            return Dashboard.objects.filter(organization=organization_id, usergroup__isnull=True,
                                            dashboard_types="custom_dashboard").order_by('-id').first()

    def _process_dashboards(self, dashboards, organization_id, user_id, user_group_id, user_data):
        """
        Processes each dashboard and its configurations to compute results for components.
        """
        result_data = []

        for dashboard in dashboards:

            dashboard_config_raw = dashboard.get('dashboard_config', [])

            # Convert string to list if needed
            if isinstance(dashboard_config_raw, str):
                try:
                    dashboard_config = json.loads(dashboard_config_raw)
                except json.JSONDecodeError:
                    try:
                        dashboard_config = ast.literal_eval(dashboard_config_raw)
                    except (ValueError, SyntaxError):
                        print("Invalid dashboard_config format!")
                        dashboard_config = []
            else:
                dashboard_config = dashboard_config_raw

            config_raw = dashboard_config.get('customComponents', [])

            # Convert string to list if needed
            if isinstance(config_raw, str):
                try:
                    config_list = json.loads(config_raw)
                except json.JSONDecodeError:
                    try:
                        config_list = ast.literal_eval(config_raw)
                    except (ValueError, SyntaxError):
                        print("Invalid dashboard_config format!")
                        config_list = []
            else:
                config_list = config_raw
            # print("config_list : ",config_list)
            for config_item in config_list:
                component_id = config_item['id']
                component_type = config_item['type']
                config = config_item.get('config', {})
                # print("config : ",config)
                position = config_item.get('position', {})

                # Extract common config fields with proper naming
                source_type = config.get('sourceType')
                source_id = config.get('source_id')
                source_name = config.get('sourceName')
                condition = config.get('condition', {})
                title = config.get('title')
                text_color = config.get('textColor')
                bg_color = config.get('bgColor')

                # Extract condition fields
                status_filter = condition.get('status')
                stage_name = condition.get('stage_name')
                aggregation = condition.get('aggregation')
                # field_id = condition.get('field_id')
                # print("field_id : ",field_id)
                field_id_list = condition.get('field_id_list', [])
                # field_id = field_id_list[0] if field_id_list else None
                # 30-08-2025 By Harish
                field_id = condition.get('field_id')
                duration = condition.get('duration')
                specific_date = condition.get('specific_date')
                x_field = condition.get('x_field')
                y_field = condition.get('y_field')

                # Initialize results
                count_result = 0
                result_json_list = []

                # Dispatch to component-specific handlers
                if component_type == 'Card':
                    count_result = self._handle_card_component(
                        organization_id, user_id, user_group_id, user_data,
                        source_type, source_id, status_filter, stage_name,
                        aggregation, field_id
                    )
                elif component_type == 'Latest-Activity':
                    result_json_list = self._handle_user_activity_component(
                        organization_id, user_id, user_group_id, user_data
                    )
                elif component_type == 'Table':
                    result_json_list = self._handle_table_component(
                        organization_id, user_id, user_group_id, user_data,
                        source_type, source_id
                    )
                elif component_type in ('BarChart', 'LineChart'):
                    result_json_list = self._handle_chart_component(
                        organization_id, user_id, user_group_id, user_data,
                        component_type, source_type, source_id, duration,
                        specific_date, x_field, y_field, aggregation
                    )
                elif component_type == 'PieChart':
                    result_json_list = self._handle_piechart_component(
                        organization_id, user_id, user_group_id, user_data,
                        source_type, source_id, duration, specific_date,
                        field_id_list, aggregation
                    )

                # Append processed component to result
                result_data.append({
                    "id": component_id,
                    "component_type": component_type,
                    # "source_name": source_name,
                    "source_type": source_type,
                    "component_data": {
                        # "title": title,
                        # "textColor": text_color,
                        # "bgColor": bg_color,
                        "count": count_result,
                        "records": result_json_list
                    },
                    "config": config,
                    "position": position
                })

        return result_data

    def _handle_card_component(self, organization_id, user_id, user_group_id, user_data, source_type, source_id,
                               status_filter, stage_name, aggregation, field_id):
        """
        Handles computation for 'card' component type.
        Returns a count based on source and conditions.
        """
        count_result = 0

        try:
            if source_type == "all_process":
                cases = Case.objects.filter(organization=organization_id)

                if status_filter == 'complete':
                    cases = cases.filter(status='Completed')
                elif status_filter == 'inprogress':
                    cases = cases.exclude(status='Completed')
                elif status_filter == 'total':
                    pass  # All cases

                case_serializer = CaseDashboardSerializer(cases, many=True)
                serialized_data = case_serializer.data

                for data_item in serialized_data:
                    enrich_case_data(data_item, organization_id)

                filtered_cases = [case for case in serialized_data if
                                  general_filter_cases(case, user_id, user_group_id)]
                advanced_filtered_cases = [
                    case for case in filtered_cases if advance_case_filter(case, user_id, user_group_id, user_data)
                ]
                count_result = len(advanced_filtered_cases)

            elif source_type == "process":
                cases = Case.objects.filter(organization=organization_id, processId=source_id)

                if status_filter:
                    if status_filter == 'complete':
                        cases = cases.filter(status='Completed')
                    elif status_filter == 'inprogress':
                        cases = cases.exclude(status='Completed')
                    elif status_filter == 'total':
                        pass

                    case_serializer = CaseDashboardSerializer(cases, many=True)
                    serialized_data = case_serializer.data

                    for data_item in serialized_data:
                        enrich_case_data(data_item, organization_id)

                    filtered_cases = [case for case in serialized_data if
                                      general_filter_cases(case, user_id, user_group_id)]
                    advanced_filtered_cases = [
                        case for case in filtered_cases if advance_case_filter(case, user_id, user_group_id, user_data)
                    ]
                    count_result = len(advanced_filtered_cases)

                elif stage_name:
                    cases = cases.filter(stages=stage_name)
                    case_serializer = CaseDashboardSerializer(cases, many=True)
                    serialized_data = case_serializer.data
                    for data_item in serialized_data:
                        enrich_case_data(data_item, organization_id)

                    filtered_cases = [case for case in serialized_data if
                                      general_filter_cases(case, user_id, user_group_id)]
                    advanced_filtered_cases = [
                        case for case in filtered_cases if advance_case_filter(case, user_id, user_group_id, user_data)
                    ]

                    if aggregation == 'count':
                        count_result = len(advanced_filtered_cases)

                elif field_id:
                    case_serializer = CaseDashboardSerializer(cases, many=True)
                    serialized_data = case_serializer.data

                    for data_item in serialized_data:
                        enrich_case_data(data_item, organization_id)

                    filtered_cases = [case for case in serialized_data if
                                      general_filter_cases(case, user_id, user_group_id)]

                    advanced_filtered_cases = [
                        case for case in filtered_cases if advance_case_filter(case, user_id, user_group_id, user_data)
                    ]

                    field_values = []

                    for case in advanced_filtered_cases:
                        parent_case_data = case.get("parent_case_data")
                        for item in parent_case_data or []:
                            if item.get('field_id') == field_id:
                                field_values.append(item.get('value'))
                                break
                    numeric_field_values = extract_numeric_decimals(field_values)

                    if aggregation == 'count':
                        count_result = len(field_values)
                    elif aggregation == 'sum':
                        count_result = sum(numeric_field_values)
                    elif aggregation == 'avg':
                        count_result = sum(numeric_field_values) / len(
                            numeric_field_values) if numeric_field_values else 0

            elif source_type == 'all_form':
                count_result = FormDataInfo.objects.filter(organization=organization_id, core_table=False).count()

            elif source_type == 'form':
                if field_id:
                    field_values = get_field_values(organization_id, source_id, field_id)
                    numeric_field_values = extract_numeric_decimals(field_values)
                    if aggregation == 'count':
                        count_result = len(field_values)
                    elif aggregation == 'sum':
                        count_result = sum(numeric_field_values)
                    elif aggregation == 'avg':
                        count_result = sum(numeric_field_values) / len(
                            numeric_field_values) if numeric_field_values else 0

            elif source_type == 'all_core_data':
                count_result = FormDataInfo.objects.filter(organization=organization_id, core_table=True).count()

            elif source_type == 'core_data':
                if field_id:
                    field_values = get_field_values(organization_id, source_id, field_id)
                    numeric_field_values = extract_numeric_decimals(field_values)
                    if aggregation == 'count':
                        count_result = len(field_values)
                    elif aggregation == 'sum':
                        count_result = sum(numeric_field_values)
                    elif aggregation == 'avg':
                        count_result = sum(numeric_field_values) / len(
                            numeric_field_values) if numeric_field_values else 0

            elif source_type == "users":
                if user_group_id:
                    count_result = UserData.objects.filter(organization=organization_id,
                                                           usergroup=user_group_id).count()
                else:
                    count_result = UserData.objects.filter(organization=organization_id).count()

        except Exception as e:
            # Log or handle component-specific error if needed
            count_result = 0
        return count_result

    def _handle_user_activity_component(self, organization_id, user_id, user_group_id, user_data):
        """
        Handles computation for 'useractivity' component type.
        Returns a list of recent case activities.
        """
        result_json_list = []

        try:
            one_week_ago = timezone.now() - timedelta(days=7)

            # Fetch cases updated in the last 7 days
            cases = Case.objects.filter(organization=organization_id, updated_on__gte=one_week_ago).select_related(
                'processId').order_by('-updated_on')
            # Serialize cases
            case_serializer = CaseDashboardSerializer(cases, many=True)
            serialized_data = case_serializer.data

            # Enrich cases with additional data
            for data_item in serialized_data:
                enrich_case_data(data_item, organization_id)

            # Apply filters
            filtered_cases = [
                case for case in serialized_data
                if general_filter_cases(case, user_id, user_group_id)
            ]

            advanced_filtered_cases = [
                case for case in filtered_cases
                if advance_case_filter(case, user_id, user_group_id, user_data)
            ]
            for case in advanced_filtered_cases:
                data_json = case.get("data_json")
                try:
                    parsed_data = json.loads(data_json) if isinstance(data_json, str) else data_json
                except Exception:
                    parsed_data = data_json  # fallback if parsing fails

                result_json_list.append({
                    "process_name": case.get("process_name"),
                    "case_id": case.get("id"),
                    "data": parsed_data,
                    "updated_on": case.get("updated_on"),
                    "status": case.get("status"),
                })


        except Exception as e:
            # log the error for debugging
            print(f"[ERROR] _handle_user_activity_component: {e}")

        return result_json_list

    def _handle_table_component(self, organization_id, user_id, user_group_id, user_data, source_type, source_id):
        """
        Handles computation for 'table' component type.
        Adds support for search_query and pagination.
        Returns a paginated list of table data.
        """
        result_json_list = []
        # Get query params directly from the request
        request = self.request
        search_query = request.query_params.get("search_query", "").strip()
        page = int(request.query_params.get("page", 1))  # default page = 1
        page_size = int(request.query_params.get("page_size", 10))  # default page_size = 10

        try:
            if source_type == "process":
                cases = Case.objects.filter(organization=organization_id, processId=source_id)
                # Serialize cases
                case_serializer = CaseDashboardSerializer(cases, many=True)
                serialized_data = case_serializer.data

                # Enrich cases with additional data
                for data_item in serialized_data:
                    enrich_case_data(data_item, organization_id)

                # Apply filters
                filtered_cases = [
                    case for case in serialized_data
                    if general_filter_cases(case, user_id, user_group_id)
                ]

                advanced_filtered_cases = [
                    case for case in filtered_cases
                    if advance_case_filter(case, user_id, user_group_id, user_data)
                ]
                # Prepare final result
                for case in advanced_filtered_cases:
                    data_json = case.get("data_json")
                    try:
                        parsed_data = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except Exception:
                        parsed_data = data_json  # fallback if parsing fails

                    result_json_list.append({
                        "process_name": case.get("process_name"),
                        "case_id": case.get("id"),
                        "data": parsed_data,
                        "updated_on": case.get("updated_on"),
                        "status": case.get("status"),
                    })

                # Apply search filtering
                if search_query:
                    query = search_query.lower()
                    result_json_list = [
                        row for row in result_json_list
                        if query in str(row["process_name"]).lower()
                           or query in str(row["case_id"]).lower()
                           or query in str(row["status"]).lower()
                           or query in str(row["data"]).lower()
                    ]

                # Apply pagination
                if page and page_size:
                    try:
                        page = int(page)
                        page_size = int(page_size)
                    except Exception:
                        page, page_size = 1, 10

                    start = (page - 1) * page_size
                    end = start + page_size
                    result_json_list = result_json_list[start:end]

            elif source_type == "Reports":
                # Create a fake GET request to call GenerateReportView
                factory = APIRequestFactory()
                fake_request = factory.get(
                    f"/custom_components/report/{organization_id}/{source_id}/",
                    data={}
                )
                view = GenerateReportView.as_view()
                response = view(fake_request, organization_id=organization_id, report_id=source_id)
                if response.status_code == 200:
                    reports_data = response.data.get("cases", [])

                    # Apply search filtering BEFORE adding to result_json_list
                    if search_query:
                        query = search_query.lower()
                        # Filter the reports_data based on search query
                        filtered_reports = []
                        for report in reports_data:
                            # Convert the entire report data to string and search
                            report_str = str(report).lower()
                            if query in report_str:
                                filtered_reports.append(report)
                            else:
                                # Also search in nested data structures
                                case_data = report.get("case_id", {})
                                merged_data = report.get("merged_data", {})
                                dms_data = report.get("dms_data", [])

                                # Search in case data
                                if query in str(case_data).lower():
                                    filtered_reports.append(report)
                                    continue

                                # Search in merged data (form_data, bot_data, etc.)
                                if query in str(merged_data).lower():
                                    filtered_reports.append(report)
                                    continue

                                # Search in DMS data
                                if query in str(dms_data).lower():
                                    filtered_reports.append(report)
                                    continue

                                # Search in specific fields that might be commonly searched
                                form_data = merged_data.get("form_data", [])
                                for form in form_data:
                                    data_json = form.get("data_json", "")
                                    if query in data_json.lower():
                                        filtered_reports.append(report)
                                        break

                        reports_data = filtered_reports

                    # Add filtered data to result_json_list
                    result_json_list.append({
                        "data": reports_data,
                    })

                    # Apply pagination
                    if page and page_size:
                        try:
                            page = int(page)
                            page_size = int(page_size)
                        except Exception:
                            page, page_size = 1, 10

                        start = (page - 1) * page_size
                        end = start + page_size

                        # Apply pagination to the reports_data within the result
                        if result_json_list:
                            result_json_list[0]["data"] = result_json_list[0]["data"][start:end]

        except Exception as e:
            # Handle error, return empty list
            pass

        return result_json_list

    # 06-09-2025 By harish
    def _handle_chart_component(
            self, organization_id, user_id, user_group_id, user_data,
            component_type, source_type, source_id, duration,
            specific_date, x_field, y_field, aggregation
    ):
        """
        Handles computation for 'barchart' or 'linechart' component types.
        Returns grouped data for charts based on duration and fields.
        """
        result_json_list = []
        today = date.today()

        try:
            date_labels = []
            date_group_type = "day"

            # Determine date labels and filter based on duration
            date_labels, date_group_type, query_filter = self._get_date_filter(duration, specific_date, today)

            # Helper function to map a date to a range label for 'last_month'
            def get_range_label(case_date, date_labels, date_group_type):
                if date_group_type == "range":
                    for start, end in date_labels:
                        if start <= case_date <= end:
                            return f"{start.strftime('%d-%m-%Y')} to {end.strftime('%d-%m-%Y')}"
                    return None
                return case_date.strftime("%Y-%m" if date_group_type == "month" else "%Y-%m-%d")

            if source_type in ("all_form", "all_core_data"):
                core_query_filter = {
                    k.replace('created_on__date', 'created_at__date'): v
                    for k, v in query_filter.items()
                }  # Added to map created_on__date to created_at__date

                is_core = False if source_type == "all_form" else True

                form_data_info_list = FormDataInfo.objects.filter(organization=organization_id, core_table=is_core)

                core_data_list = FilledFormData.objects.filter(organization=organization_id, **core_query_filter)

                grouped_data = defaultdict(lambda: defaultdict(int))
                # Initialize grouped_data with date labels
                for dt in date_labels:
                    label_key = (
                        f"{dt[0].strftime('%d-%m-%Y')} to {dt[1].strftime('%d-%m-%Y')}"
                        if date_group_type == "range"
                        else dt.strftime("%Y-%m" if date_group_type == "month" else "%Y-%m-%d")
                    )
                    grouped_data[label_key]

                    # Count core_data occurrences grouped by (date, form)
                for form in form_data_info_list:
                    filter_core_data = core_data_list.filter(formId=form.id)
                    for core_data in filter_core_data:
                        created_date = core_data.created_at.date()
                        label_key = get_range_label(created_date, date_labels, date_group_type)
                        if label_key:
                            grouped_data[label_key][form.form_name] += 1

                # Convert into desired output format
                response_data = []
                for label, form_counts in grouped_data.items():
                    response_data.append({
                        "label": label,
                        "result": {
                            "x_value": {form_name: form_name for form_name in form_counts.keys()},
                            "y_value": {form_name: count for form_name, count in form_counts.items()}
                        }
                    })

                result_json_list = response_data

            elif source_type == "all_process":
                # Get all processes for the organization
                processes = CreateProcess.objects.filter(organization=organization_id)
                # Get all cases of the organization
                cases = Case.objects.filter(organization=organization_id, **query_filter)
                # Serialize cases
                case_serializer = CaseDashboardSerializer(cases, many=True)
                serialized_cases = case_serializer.data

                # Apply filters
                filtered_cases = [
                    case for case in serialized_cases
                    if general_filter_cases(case, user_id, user_group_id)
                ]

                permitted_cases = [
                    case for case in filtered_cases
                    if advance_case_filter(case, user_id, user_group_id, user_data)
                ]

                # Initialize grouped_data by dates
                grouped_data = {}
                for dt in date_labels:
                    label_key = (
                        f"{dt[0].strftime('%d-%m-%Y')} to {dt[1].strftime('%d-%m-%Y')}"
                        if date_group_type == "range"
                        else dt.strftime("%Y-%m" if date_group_type == "month" else "%Y-%m-%d")
                    )
                    grouped_data[label_key] = {"x_value": {}, "y_value": {}}

                # Count cases per process grouped by created_on date
                for case in permitted_cases:
                    case_date = datetime.strptime(case.get("created_on")[:10], "%Y-%m-%d").date()
                    label_key = get_range_label(case_date, date_labels, date_group_type)

                    for process in processes:
                        process_id = str(process.id)
                        process_name = process.process_name

                        if str(case.get("processId")) == process_id:
                            grouped_data[label_key]["x_value"][process_name] = process_name
                            grouped_data[label_key]["y_value"][process_name] = grouped_data[label_key]["y_value"].get(
                                process_name, 0) + 1

                # Convert grouped_data
                process_data = [
                    {"label": label, "result": data} for label, data in grouped_data.items()
                ]

                result_json_list = process_data

            elif source_type == "process":
                cases = Case.objects.filter(organization=organization_id, processId=source_id, **query_filter)

                # Step 1: Serialize
                case_serializer = CaseDashboardSerializer(cases, many=True)
                serialized_data = case_serializer.data

                # Step 2: Enrich serialized cases
                # for data_item in serialized_data:
                #     enrich_case_data(data_item, organization_id)

                # Step 3: Apply filters
                filtered_cases = [
                    case for case in serialized_data
                    if general_filter_cases(case, user_id, user_group_id)
                ]

                permitted_cases = [
                    case for case in filtered_cases
                    if advance_case_filter(case, user_id, user_group_id, user_data)
                ]

                # Step 4: Initialize grouped buckets
                grouped_data = {}
                for dt in date_labels:
                    label_key = (
                        f"{dt[0].strftime('%d-%m-%Y')} to {dt[1].strftime('%d-%m-%Y')}"
                        if date_group_type == "range"
                        else dt.strftime("%Y-%m" if date_group_type == "month" else "%Y-%m-%d")
                    )
                    grouped_data[label_key] = []

                # Step 5: Process permitted cases if x_field & y_field exist
                if x_field and y_field:
                    for case in permitted_cases:
                        case_x_value = next(
                            (item.get('value') for item in (case.get("parent_case_data") or [])
                             if item.get('field_id') == x_field),
                            None
                        )
                        case_y_value = next(
                            (item.get('value') for item in (case.get("parent_case_data") or [])
                             if item.get('field_id') == y_field),
                            None
                        )
                        numeric_x = extract_numeric_decimals([case_x_value])[0] if case_x_value else None
                        numeric_y = extract_numeric_decimals([case_y_value])[0] if case_y_value else None
                        case_date = datetime.strptime(case.get("created_on")[:10], "%Y-%m-%d").date()
                        label_key = get_range_label(case_date, date_labels, date_group_type)

                        grouped_data[label_key].append({
                            "x_value": numeric_x,
                            "y_value": numeric_y
                        })

                # Step 6: Aggregate final chart data
                result_json_list = self._aggregate_chart_data(grouped_data, aggregation)

            elif source_type in ("form", "core_data"):
                # Adjust query_filter for FormDataInfo and FilledFormData ***
                form_query_filter = {
                    k.replace('created_on__date', 'form_created_on'): v
                    for k, v in query_filter.items()
                }  # Added to map created_on__date to form_created_on__date
                core_query_filter = {
                    k.replace('created_on__date', 'created_at__date'): v
                    for k, v in query_filter.items()
                }  # Added to map created_on__date to created_at__date

                core_data_list = FilledFormData.objects.filter(organization=organization_id, formId=source_id,
                                                               **core_query_filter)

                # Step 4: Initialize grouped buckets
                grouped_data = {}
                for dt in date_labels:
                    label_key = (
                        f"{dt[0].strftime('%d-%m-%Y')} to {dt[1].strftime('%d-%m-%Y')}"
                        if date_group_type == "range"
                        else dt.strftime("%Y-%m" if date_group_type == "month" else "%Y-%m-%d")
                    )
                    grouped_data[label_key] = []

                if x_field and y_field:

                    for core_data in core_data_list:
                        case_x_value = next(
                            (item.get('value') for item in (core_data.data_json or [])
                             if item.get('field_id') == x_field),
                            None
                        )
                        case_y_value = next(
                            (item.get('value') for item in (core_data.data_json or [])
                             if item.get('field_id') == y_field),
                            None
                        )
                        numeric_x = extract_numeric_decimals([case_x_value])[0] if case_x_value else None
                        numeric_y = extract_numeric_decimals([case_y_value])[0] if case_y_value else None

                        created_date = core_data.created_at.date()
                        label_key = get_range_label(created_date, date_labels, date_group_type)
                        grouped_data[label_key].append({
                            "x_value": numeric_x,
                            "y_value": numeric_y
                        })
                # Step 6: Aggregate final chart data
                result_json_list = self._aggregate_chart_data(grouped_data, aggregation)

        except ValueError as e:
            # Handle date parsing errors
            pass
        except Exception as e:
            # Handle other errors, return empty list
            pass

        return result_json_list

    # 06-09-2025 By harish
    def _handle_piechart_component(
            self, organization_id, user_id, user_group_id, user_data,
            source_type, source_id, duration, specific_date=None,
            field_id_list=[], aggregation=None
    ):
        """
        Handles computation for 'piechart' component type.
        Returns aggregated data for pie charts.
        """
        result_json_list = []

        try:
            today = date.today()
            query_filter = {}
            if duration:
                _, _, query_filter = self._get_date_filter(duration, specific_date, today)

            # Adjust query_filter for FormDataInfo and FilledFormData ***
            form_query_filter = {
                k.replace('created_on__date', 'form_created_on'): v
                for k, v in query_filter.items()
            }  # Added to map created_on__date to form_created_on__date
            core_query_filter = {
                k.replace('created_on__date', 'created_at__date'): v
                for k, v in query_filter.items()
            }

            cases = Case.objects.filter(organization=organization_id, **query_filter)
            form_data_info_list = FormDataInfo.objects.filter(organization=organization_id)
            core_data_list = FilledFormData.objects.filter(organization=organization_id, **core_query_filter)

            if source_type == "all_process":
                # Serialize cases
                case_serializer = CaseDashboardSerializer(cases, many=True)
                serialized_data = case_serializer.data
                # Enrich cases with additional data
                # for data_item in serialized_data:
                #     enrich_case_data(data_item, organization_id)

                # Apply filters
                filtered_cases = [
                    case for case in serialized_data
                    if general_filter_cases(case, user_id, user_group_id)
                ]

                advanced_filtered_cases = [
                    case for case in filtered_cases
                    if advance_case_filter(case, user_id, user_group_id, user_data)
                ]

                # Count occurrences of process_name
                process_counter = Counter(case.get("process_name", "") for case in advanced_filtered_cases)

                result_json_list = [
                    {"field_id": name, "result": count}
                    for name, count in process_counter.items()
                ]

            elif source_type == "process":
                cases = cases.filter(processId=source_id)
                # Step 1: Serialize
                case_serializer = CaseDashboardSerializer(cases, many=True)
                serialized_data = case_serializer.data

                # Step 2: Enrich serialized cases
                # for data_item in serialized_data:
                #     enrich_case_data(data_item, organization_id)

                # Step 3: Apply filters
                filtered_cases = [
                    case for case in serialized_data
                    if general_filter_cases(case, user_id, user_group_id)
                ]

                permitted_cases = [
                    case for case in filtered_cases
                    if advance_case_filter(case, user_id, user_group_id, user_data)
                ]
                # print("field_id_list : ",field_id_list)
                # print("permitted_cases : ",permitted_cases)

                if field_id_list:
                    for field_id in field_id_list:
                        field_values = [
                            next(
                                (item.get('value') for item in (case.get('parent_case_data') or []) if
                                 item.get('field_id') == field_id),
                                None
                            )
                            for case in permitted_cases
                        ]
                        field_values = [v for v in field_values if v is not None]
                        numeric_field_values = extract_numeric_decimals(field_values)
                        # Convert only numeric-like values for sum/avg
                        numeric_values = extract_numeric_decimals(field_values)

                        # Count each unique field_value instead of just returning field_id
                        unique_results = {}
                        for val in field_values:
                            if aggregation == 'count':
                                unique_results[val] = unique_results.get(val, 0) + 1
                            elif aggregation == 'sum':
                                # only works if values are numeric
                                unique_results[val] = unique_results.get(val, 0) + float(val)
                            elif aggregation == 'avg':
                                # store as list first for averaging later
                                if val not in unique_results:
                                    unique_results[val] = []
                                unique_results[val].append(float(val) if str(val).replace('.', '', 1).isdigit() else 0)

                        # For avg, finalize calculation
                        if aggregation == 'avg':
                            for k, v in unique_results.items():
                                unique_results[k] = sum(v) / len(v) if v else 0

                        # Append results with field_value instead of field_id
                        for field_value, count_result in unique_results.items():
                            result_json_list.append({
                                "field_id": field_value,
                                "result": count_result
                            })

            elif source_type == "all_form":
                for form in form_data_info_list.filter(core_table=False):
                    form_counts = (
                        core_data_list.filter(formId=form.id)
                        .annotate(form_name=Value(form.form_name, output_field=CharField()))  # attach form_name
                        .values("formId", "form_name")
                        .annotate(filled_count=Count("id"))
                    )

                    # Extend result list instead of overwriting
                    result_json_list.extend(
                        {
                            "field_id": fc["form_name"],
                            "result": fc["filled_count"]
                        }
                        for fc in form_counts
                    )

            elif source_type == "all_core_data":
                for form in form_data_info_list.filter(core_table=True):
                    form_counts = (
                        core_data_list.filter(formId=form.id)
                        .annotate(form_name=Value(form.form_name, output_field=CharField()))  # attach form_name
                        .values("formId", "form_name")
                        .annotate(filled_count=Count("id"))
                    )
                    # Extend result list instead of overwriting
                    result_json_list.extend(
                        {
                            "field_id": fc["form_name"],
                            "result": fc["filled_count"]
                        }
                        for fc in form_counts
                    )

            elif source_type == "form" or source_type == "core_data":
                core_data_list = core_data_list.filter(formId=source_id)
                if field_id_list:
                    for field_id in field_id_list:
                        field_values = [
                            next(
                                (item.get('value') for item in core_data.data_json if item.get('field_id') == field_id),
                                None
                            )
                            for core_data in core_data_list
                        ]
                        field_values = [v for v in field_values if v is not None]
                        # Count each unique field_value instead of just returning field_id
                        unique_results = {}
                        for val in field_values:
                            if aggregation == 'count':
                                unique_results[val] = unique_results.get(val, 0) + 1
                            elif aggregation == 'sum':
                                # only works if values are numeric
                                unique_results[val] = unique_results.get(val, 0) + float(val)
                            elif aggregation == 'avg':
                                # store as list first for averaging later
                                if val not in unique_results:
                                    unique_results[val] = []
                                unique_results[val].append(float(val) if str(val).replace('.', '', 1).isdigit() else 0)

                        # For avg, finalize calculation
                        if aggregation == 'avg':
                            for k, v in unique_results.items():
                                unique_results[k] = sum(v) / len(v) if v else 0

                        # Append results with field_value instead of field_id
                        for field_value, count_result in unique_results.items():
                            result_json_list.append({
                                "field_id": field_value,
                                "result": count_result
                            })

        except ValueError as e:
            # Handle date parsing errors
            pass
        except Exception as e:
            # Handle other errors, return empty list
            pass

        return result_json_list

    # 06-09-2025 By harish
    def _get_date_filter(self, duration, specific_date, today):
        """
        Helper to determine date labels, group type, and query filter based on duration.
        """
        date_labels = []
        date_group_type = "day"
        query_filter = {}

        if duration == "current":
            date_labels = [today]
            query_filter = {'created_on__date': today}

        elif duration == "last_day":
            yesterday = today - timedelta(days=1)
            date_labels = [yesterday]
            query_filter = {'created_on__date': yesterday}

        # 06-09-2025 By harish
        elif duration == "last_month":
            # Get first and last day of last month
            first_day_last_month = (today.replace(day=1) - timedelta(days=1)).replace(day=1)
            last_day_last_month = today.replace(day=1) - timedelta(days=1)

            # Define 5-day intervals
            ranges = [(1, 5), (6, 10), (11, 15), (16, 20), (21, 25)]

            # Add the last interval dynamically up to the last day of month
            ranges.append((26, last_day_last_month.day))

            # Build date label ranges
            date_labels = [
                (
                    first_day_last_month.replace(day=start),
                    first_day_last_month.replace(day=min(end, last_day_last_month.day))
                )
                for start, end in ranges if start <= last_day_last_month.day
            ]

            query_filter = {'created_on__date__range': [first_day_last_month, last_day_last_month]}
            date_group_type = "range"

        elif duration == "last_year":
            first_day_last_year = date(today.year - 1, 1, 1)
            last_day_last_year = date(today.year - 1, 12, 31)
            date_group_type = "month"
            date_labels = [date(today.year - 1, m, 1) for m in range(1, 13)]
            query_filter = {'created_on__date__range': [first_day_last_year, last_day_last_year]}

        elif duration == "specific_date" and specific_date:
            specific_date_obj = date.fromisoformat(specific_date)
            date_labels = [specific_date_obj]
            query_filter = {'created_on__date': specific_date_obj}

        # Note: For forms/core data, adjust query_filter keys like 'form_created_on__date' or 'created_at__date' accordingly in callers

        return date_labels, date_group_type, query_filter

    def _aggregate_chart_data(self, grouped_data, aggregation):
        """
        Aggregates chart data based on aggregation type.
        Supports both numeric and categorical values.
        """
        result_json_list = []

        for label, entries in grouped_data.items():
            if not entries:
                agg_result = {}
            elif aggregation == 'count':
                # Count categorical values separately
                x_counter = Counter([str(e["x_value"]) for e in entries if e["x_value"] is not None])
                y_counter = Counter([str(e["y_value"]) for e in entries if e["y_value"] is not None])
                agg_result = {"x_value": dict(x_counter), "y_value": dict(y_counter)}

            elif aggregation in ('sum', 'avg'):
                # Only works if numeric
                x_vals = [float(e["x_value"]) if isinstance(e["x_value"], Decimal) else e["x_value"] for e in entries if
                          isinstance(e["x_value"], (int, float, Decimal))]
                y_vals = [float(e["y_value"]) if isinstance(e["y_value"], Decimal) else e["y_value"] for e in entries if
                          isinstance(e["y_value"], (int, float, Decimal))]

                if aggregation == 'sum':
                    agg_result = {"x_value": sum(x_vals), "y_value": sum(y_vals)}
                else:  # avg
                    agg_result = {
                        "x_value": sum(x_vals) / len(x_vals) if x_vals else 0,
                        "y_value": sum(y_vals) / len(y_vals) if y_vals else 0
                    }
            else:
                agg_result = {}

            result_json_list.append({"label": label, "result": agg_result})

        return result_json_list


def get_field_values(org_id, form_id, field_id):
    values = []

    records = FilledFormData.objects.filter(organization=org_id, formId=form_id)
    for data in records:
        for item in data.data_json:
            if item.get('field_id') == field_id:
                values.append(item.get('value'))
                break

    return values


def extract_numeric_decimals(value_list):
    """
    Returns Decimals if numeric, otherwise returns original values.
    """
    result = []
    for value in value_list:
        string_value = str(value).strip()
        if string_value.replace('.', '', 1).isdigit():
            try:
                result.append(Decimal(string_value))
            except:
                continue
        else:
            result.append(string_value)  # keep text as-is
    return result


""" ProcessCaseListApi helper functionalities """


def enrich_case_data(case, org_id):
    return DashboardCasesView().enrich_case_data(case, org_id)


def general_filter_cases(case, user_id, user_group_id):
    return DashboardCasesView().general_filter_cases(case, user_id, user_group_id)


def advance_case_filter(case_item, user_id, user_group_id, user_data):
    return DashboardCasesView().advance_case_filter(case_item, user_id, user_group_id, user_data)


def is_old_condition_format(conditions):
    return DashboardCasesView().is_old_condition_format(conditions)


def convert_old_conditions_to_group(conditions):
    return DashboardCasesView().convert_old_conditions_to_group(conditions)


def evaluate_filter_tree(node, user_data, case_item):
    return DashboardCasesView().evaluate_filter_tree(node, user_data, case_item)


def evaluate_condition(condition, user_data, case_item):
    return DashboardCasesView().evaluate_condition(condition, user_data, case_item)


# class IsOrgMember(BasePermission):
#     def has_object_permission(self, request, view, obj):
#         return obj.organization in request.user.organizations.all()


class AgentAPIView(APIView):
    """
    GET (list or by org id), POST(create), UPDATE, DELETE
    """
    # permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk=None):
        try:
            if pk:
                # Fetch single agent by ID
                agent = get_object_or_404(Agent, pk=pk)
                serializer = AgentSerializer(agent)
                return Response({
                    "status": True,
                    "message": "Agent details fetched successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)

            # Fetch org-based list
            org_id = request.query_params.get('organization')
            if not org_id:
                return Response({
                    "status": False,
                    "message": "Organization ID is required to fetch agent list"
                }, status=status.HTTP_400_BAD_REQUEST)

            agents = Agent.objects.filter(organization_id=org_id)
            serializer = AgentSerializer(agents, many=True)
            return Response({
                "status": True,
                "message": f"Agents fetched successfully for organization {org_id}",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"GET /agents error: {e}")
            return Response({
                "status": False,
                "message": "Error fetching agent(s)",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        try:
            serializer = AgentSerializer(data=request.data)
                  
            if serializer.is_valid():
                organization = serializer.validated_data.get('organization')
                organization_id = organization.id if organization else None      
                uid = generate_uid(Agent, 'AG', organization_id)
                serializer.save(uid=uid)
                return Response({
                    "status": True,
                    "message": "Agent created successfully",
                    "data": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({
                "status": False,
                "message": "Validation error",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError as e:
            logger.warning(f"Integrity error creating agent: {e}")
            return Response({
                "status": False,
                "message": "Integrity constraint failed",
                "error": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except DatabaseError as e:
            logger.error(f"Database error creating agent: {e}")
            return Response({
                "status": False,
                "message": "Database error while creating agent",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            logger.exception(f"Unexpected error creating agent: {e}")
            return Response({
                "status": False,
                "message": "Unexpected error occurred",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        try:
            agent = get_object_or_404(Agent, pk=pk)
            serializer = AgentSerializer(agent, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "status": True,
                    "message": "Agent updated successfully",
                    "data": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "status": False,
                "message": "Validation error",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"PUT /agents/{pk} error: {e}")
            return Response({
                "status": False,
                "message": "Error updating agent",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        try:
            agent = get_object_or_404(Agent, pk=pk)
            agent.delete()
            return Response({
                "status": True,
                "message": "Agent deleted successfully"
            }, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"DELETE /agents/{pk} error: {e}")
            return Response({
                "status": False,
                "message": "Error deleting agent",
                "error": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


###########################################################################
#              ORGANIZATION, PROCESS DATA IMPORT & EXPORT API
###########################################################################

from django.db import transaction
from tempfile import NamedTemporaryFile
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse
from cryptography.fernet import Fernet

class ExportOrganizationDataAPIView(APIView):
    """
    Export all data related to an organization as a downloadable JSON file.
    """

    def get(self, request, org_id):
        try:
            org = Organization.objects.get(id=org_id)
        except Organization.DoesNotExist:
            return Response({"status": False, "message": "Organization not found"}, status=status.HTTP_404_NOT_FOUND)

        data = {}

        # --- Organization ---
        data['organization'] = list(Organization.objects.filter(id=org_id).values())

        # --- User Groups & Users ---
        data['user_groups'] = list(UserGroup.objects.filter(organization=org).values())

        user_datas = []
        for user in UserData.objects.filter(organization=org):
            user_obj = user.user
            user_data_entry = {
                "user_data": {
                    "id": user.id,
                    "user_name": user.user_name,
                    "mail_id": user.mail_id,
                    "password": user.password,
                    "profile_pic": user.profile_pic,
                    "is_lead": user.is_lead,
                    "user_profile_schema": user.user_profile_schema,
                    "usergroup": user.usergroup.id if user.usergroup else None,
                    "uid":user.uid,
                },
                "user": {
                    "id": user_obj.id,
                    "password": user_obj.password,
                    "last_login": str(user_obj.last_login) if user_obj.last_login else None,
                    "is_superuser": user_obj.is_superuser,
                    "username": user_obj.username,
                    "first_name": user_obj.first_name,
                    "last_name": user_obj.last_name,
                    "email": user_obj.email,
                    "is_staff": user_obj.is_staff,
                    "is_active": user_obj.is_active,
                    "date_joined": str(user_obj.date_joined) if user_obj.date_joined else None,
                } if user_obj else None,
            }
            user_datas.append(user_data_entry)

        data["user_datas"] = user_datas


        # --- Forms ---
        form_datas = []
        for form in FormDataInfo.objects.filter(organization=org):
            form_permission = []
            for perm in FormPermission.objects.filter(form=form):
                form_permission.append({
                    "user_group_id": perm.user_group.id,
                    "read": perm.read,
                    "write": perm.write,
                    "edit": perm.edit
                })
            form_datas.append({
                "id": form.id,
                "Form_uid": form.Form_uid,
                "form_name": form.form_name,
                "form_description": form.form_description,
                "form_json_schema": form.form_json_schema,
                "form_style_schema": form.form_style_schema,
                "form_status": form.form_status,
                "form_created_by": form.form_created_by,
                "form_created_on": str(form.form_created_on),
                "organization": org_id,
                "processId": form.processId.id if form.processId else None,
                "user_groups": list(form.user_groups.values_list('id', flat=True)),
                "core_table": form.core_table,
                "form_filter_schema": form.form_filter_schema,
                "form_send_mail": form.form_send_mail,
                "form_send_mail_schema": form.form_send_mail_schema,
                "form_permission": form_permission,
            })

        data['form_datas'] = form_datas

        # --- Processes & Cases ---
        processes = []
        for proc in CreateProcess.objects.filter(organization=org):
            processes.append({
                "id": proc.id,
                "process_name": proc.process_name,
                "process_description": proc.process_description,
                "initiator_group": proc.initiator_group,
                "first_step": proc.first_step.id if proc.first_step else None,
                "participants": proc.participants,
                "organization": proc.organization.id if proc.organization else None,
                "user_group": list(proc.user_group.values_list('id', flat=True)),
                "dms": list(proc.dms.values_list('id', flat=True)),
                "parent_process": proc.parent_process.id if proc.parent_process else None,
                "subprocess_UID": proc.subprocess_UID,
                "process_stages": proc.process_stages,
                "process_table_configuration": proc.process_table_configuration,
                "parent_case_data_schema": proc.parent_case_data_schema,
                "process_table_permission": proc.process_table_permission,
                "uid": proc.uid,
            })

        data['processes'] = processes

        filled_form_datas = []
        queryset = FilledFormData.objects.filter(organization=org)

        # Filter further: only formIds that are numbers (no letters)
        queryset = queryset.filter(formId__regex=r'^\d+$')

        for ffd in queryset:
            filled_form_datas.append({
                "id": ffd.id,
                "formId": ffd.formId,
                "userId": ffd.userId.id if ffd.userId else None,
                "processId": ffd.processId.id if ffd.processId else None,
                "caseId": ffd.caseId.id if ffd.caseId else None,
                "data_json": ffd.data_json,
                "created_at": str(ffd.created_at) if ffd.created_at else None,
                "updated_at": str(ffd.updated_at) if ffd.updated_at else None,
                "organization": ffd.organization.id if ffd.organization else None,
                "status": ffd.status,
                "user_groups": list(ffd.user_groups.values_list('id', flat=True)),  # m2m
                "core_filled_data": ffd.core_filled_data,
                "is_enabled": ffd.is_enabled,
                "uid": ffd.uid
            })

        data['filled_form_datas'] = filled_form_datas

        data['cases'] = list(Case.objects.filter(organization=org).values())

        # --- SLA Config & Instances ---
        sla_configs = []
        for sla in SlaConfig.objects.filter(organization=org):
            sla_case_instance = []
            for inst in SlaCaseInstance.objects.filter(sla_id=sla):
                sla_case_instance.append({
                    "id": inst.id,
                    "case_id": inst.case_id.id,
                    "is_completed": inst.is_completed,
                    "created_at": str(inst.created_at),
                    "created_by": inst.created_by,
                    "updated_at": str(inst.updated_at),
                    "updated_by": inst.updated_by
                })
            sla_configs.append({
                "id": sla.id,
                "sla_name": sla.sla_name,
                "sla_uid": sla.sla_uid,
                "process_id": sla.process_id.id if sla.process_id else None,
                "sla_json_schema": sla.sla_json_schema,
                "created_at": str(sla.created_at),
                "created_by": sla.created_by,
                "updated_at": str(sla.updated_at),
                "updated_by": sla.updated_by,
                "sla_case_instance": sla_case_instance
            })
        
        data['sla_configs'] = sla_configs

        # --- Bots, Integrations, DMS, OCR, Scheduler, Reports, Notifications, Agents ---
        # data['filled_form_datas'] = list(FilledFormData.objects.filter(organization=org).values())
        data['bots'] = list(Bot.objects.all().values())
        data['bot_schemas'] = list(BotSchema.objects.filter(organization=org).values())
        # data['bot_data'] = list(BotData.objects.filter(organization=org).values())
        data['integrations'] = list(Integration.objects.filter(organization=org).values())
        data['integration_details'] = list(IntegrationDetails.objects.filter(organization=org).values())
        data['dms'] = list(Dms.objects.filter(organization=org).values())
        # data['dms_data'] = list(Dms_data.objects.filter(organization=org).values())
        data['ocr'] = list(Ocr.objects.filter(organization=org).values())
        data['ocr_details'] = list(Ocr_Details.objects.filter(organization=org).values())
        data['schedulers'] = list(Scheduler.objects.filter(organization=org).values())
        # data['scheduler_data'] = list(SchedulerData.objects.filter(organization=org).values())
        data['reports'] = list(ReportConfig.objects.filter(organization=org).values())
        data['notification_bot_schemas'] = list(NotificationBotSchema.objects.filter(organization=org).values())
        # data['notification_data'] = list(NotificationData.objects.filter(organization=org).values())
        data['agents'] = list(Agent.objects.filter(organization=org).values())

        data['dashboards'] = list(Dashboard.objects.filter(organization=org).values())
        data['user_form_schemas'] = list(UserFormSchema.objects.filter(organization=org).values())
        data['notification_configs'] = list(NotificationConfig.objects.filter(organization=org).values())
        data['notifications'] = list(Notification.objects.all().values())
        # data['notificatio_dismiss'] = list(NotificationDismiss.objects.all().values())
        data['end_elements'] = list(EndElement.objects.filter(organization=org).values())
        data['sequence'] = list(Sequence.objects.filter(organization=org).values())
        data['rules'] = list(Rule.objects.filter(organization=org).values())
        data['notification_config'] = list(NotificationConfig.objects.filter(organization=org).values())

        # STEP 1 — Get the secret_key
        secret_key = settings.EXPORT_IMPORT_SECRET_KEY
        fernet = Fernet(secret_key)

        # STEP 2 — Convert data → JSON → Encrypt
        json_data = json.dumps(data, cls=DjangoJSONEncoder)
        encrypted_data = fernet.encrypt(json_data.encode())

        # STEP 3 — Create encrypted export file
        file_name = f"organization_{org_id}_export.enc"

        with NamedTemporaryFile(mode="wb", delete=False, suffix=".enc") as temp_file:
            temp_file.write(encrypted_data)
            temp_file_path = temp_file.name

        # STEP 4 — Return encrypted file + key in header
        with open(temp_file_path, "rb") as f:
            response = HttpResponse(f.read(), content_type="application/octet-stream")
            response["Content-Disposition"] = f'attachment; filename="{file_name}"'

        # Delete temp file
        os.remove(temp_file_path)

        return response


class ImportOrganizationDataAPIView(APIView):
    """
    Import organization data from a JSON file.
    Safely handles missing foreign keys and maintains import order.
    """

    def post(self, request):
        logs = {"created": [],"updated": [],"skipped": [],"errors": []}
        try:
            file = request.FILES.get('file')
            if not file:
                return Response(
                    {"status": False, "message": "No file uploaded."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            secret_key = settings.EXPORT_IMPORT_SECRET_KEY
            fernet = Fernet(secret_key.encode())

            encrypted_bytes = file.read()

            try:
                decrypted_json = fernet.decrypt(encrypted_bytes)
            except Exception:
                return Response(
                    {"status": False, "message": "Invalid key or corrupted file"},
                    status=400
                )

            # Convert decrypted JSON into Python dict
            data = json.loads(decrypted_json.decode())

            # --- Organization ---
            org_data = data.get('organization', [])
            if not org_data:
                return Response(
                    {"status": False, "message": "No organization data found."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            org_info = org_data[0]
            # --- Organization --- 
            try:
                org_code = org_info.get("org_code", "")
                org, org_created = Organization.objects.update_or_create(
                    org_code=org_code,
                    defaults={
                        "org_name": org_info.get("org_name"),
                        "email": org_info.get("email", ""),
                        "org_description": org_info.get("org_description", ""),
                        "large_logo_url": org_info.get("large_logo_url", ""),
                        "small_logo_url": org_info.get("small_logo_url", ""),
                        "primary_color": org_info.get("primary_color", ""),
                        "secondary_color": org_info.get("secondary_color", ""),
                        "accent1_color": org_info.get("accent1_color", ""),
                        "accent2_color": org_info.get("accent2_color", ""),
                        "accent3_color": org_info.get("accent3_color", ""),
                        "bot": org_info.get("bot"),
                        "admin_set_password": org_info.get("admin_set_password", ""),
                    }
                )
                if org_created:
                    logs["created"].append(f"Organization created: {org_code}")
                else:
                    logs["updated"].append(f"Organization updated: {org_code}")

            except Exception as e:
                logs["errors"].append(str(e))
                return Response({
                    "status": False,
                    "message": "Import failed.",
                    "logs": logs
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # --- User Groups --- 
            user_groups_map = {}
            for group in data.get("user_groups", []):
                try:
                    uid = group.get("uid")
                    if not uid:
                        logs["skipped"].append(
                            f"UserGroup skipped: missing uid → {group}"
                        )
                        continue

                    defaults = {
                        "group_name": group.get("group_name"),
                        "group_description": group.get("group_description", ""),
                        "status": group.get("status", True),
                        "organization": org,
                    }
                    user_group_instance, created = UserGroup.objects.update_or_create(
                        uid=uid, defaults=defaults
                    )
                    # Log creation / update
                    if created:
                        logs["created"].append(f"UserGroup created: {uid}")
                    else:
                        logs["updated"].append(f"UserGroup updated: {uid}")

                    user_groups_map[group.get("id")] = user_group_instance
                except Exception as e:
                    logs["errors"].append(f"UserGroup error (uid={uid}): {e}")

            # --- Users & UserData --- 
            user_data_map = {}
            for entry in data.get("user_datas", []):
                try:
                    user_info = entry.get("user")
                    user_data_info = entry.get("user_data")

                    # Auth user
                    auth_user = None
                    try:
                        if user_info:
                            auth_user, auth_created = User.objects.get_or_create(
                                email=user_info["email"],
                                defaults={
                                    "username":user_info.get("username"),
                                    "first_name": user_info.get("first_name", ""),
                                    "last_name": user_info.get("last_name", ""),
                                    "email": user_info.get("email", ""),
                                    "password": user_info.get("password", ""),
                                    "is_superuser": user_info.get("is_superuser", False),
                                    "is_staff": user_info.get("is_staff", False),
                                    "is_active": user_info.get("is_active", True),
                                }
                            )
                            if auth_created:
                                logs["created"].append(f"AuthUser created: {auth_user.email}")
                            else:
                                logs["updated"].append(f"AuthUser updated: {auth_user.email}")
                    except Exception as e:
                        logs["errors"].append(f"AuthUser error ({user_info.get('email')}): {e}")
                        continue

                    uid = user_data_info.get("uid")
                    if not uid:
                        logs["skipped"].append(
                            f"UserData skipped: missing uid → {user_data_info.get('id')}"
                        )
                        continue

                    defaults = {
                        "user_name": user_data_info.get("user_name", ""),
                        "mail_id": user_data_info.get("mail_id", ""),
                        "password": user_data_info.get("password", ""),
                        "profile_pic": user_data_info.get("profile_pic", ""),
                        "is_lead": user_data_info.get("is_lead", False),
                        "user_profile_schema": user_data_info.get("user_profile_schema", {}),
                        "organization": org,
                        "usergroup": user_groups_map.get(user_data_info.get("usergroup")),
                        "user": auth_user,
                    }

                    user_data_instance, created = UserData.objects.update_or_create(
                        uid=uid, defaults=defaults
                    )
                    if created:
                        logs["created"].append(f"UserData created: {uid}")
                    else:
                        logs["updated"].append(f"UserData updated: {uid}")

                    user_data_map[user_data_info.get("id")] = user_data_instance

                except Exception as e:
                    logs["errors"].append(f"UserData error (uid={uid}): {e}")

            # --- CreateProcess --- 
            process_map = {}
            for process in data.get("processes", []):
                try:
                    uid = process.get("uid")
                    if not uid:
                        logs["skipped"].append(
                            f"Process skipped: missing uid → {process.get('id')}"
                        )
                        continue
                    m2m_user_group_ids = process.pop("user_group", [])
                    m2m_dms_ids = process.pop("dms", [])
                    defaults = {key: value for key, value in process.items() if key not in ["id", "organization", "uid"]}
                    defaults["organization"] = org

                    proc, created = CreateProcess.objects.update_or_create(
                        uid=uid, defaults=defaults
                    )
                    if created:
                        logs["created"].append(f"Process created: {uid}")
                    else:
                        logs["updated"].append(f"Process updated: {uid}")

                    if m2m_user_group_ids:
                        new_user_groups = [user_groups_map.get(old_id) for old_id in m2m_user_group_ids if user_groups_map.get(old_id)]
                        proc.user_group.set(new_user_groups)
                    if m2m_dms_ids:
                        new_dms_groups = [user_groups_map.get(old_id) for old_id in m2m_dms_ids if user_groups_map.get(old_id)]
                        proc.dms.set(new_dms_groups)

                    process_map[process.get("id")] = proc
                except Exception as e:
                    logs["errors"].append(f"Process error (uid={process.get('uid')}): {e}")

            # --- Forms --- 
            form_map = {}
            for form in data.get("form_datas", []):
                try:
                    old_id = form.get("id")
                    uid = form.get("Form_uid")
                    if not uid:
                        logs["skipped"].append(f"FormData skipped: missing UID (old_id={old_id})")
                        continue

                    # Resolve related process
                    process_ref = process_map.get(form.get("processId"))

                    defaults = {
                        "form_name": form.get("form_name"),
                        "form_description": form.get("form_description", ""),
                        "form_json_schema": form.get("form_json_schema", {}),
                        "form_style_schema": form.get("form_style_schema", {}),
                        "form_status": form.get("form_status", ""),
                        "form_created_by": form.get("form_created_by", ""),
                        "form_created_on": form.get("form_created_on"),
                        "organization": org,
                        "processId": process_ref,
                        "core_table": form.get("core_table", ""),
                        "form_filter_schema": form.get("form_filter_schema", {}),
                        "form_send_mail": form.get("form_send_mail", False),
                        "form_send_mail_schema": form.get("form_send_mail_schema", {}),
                    }

                    # Update existing or create new FormDataInfo record
                    form_instance, created = FormDataInfo.objects.update_or_create(
                        Form_uid=uid, defaults=defaults
                    )
                    if created:
                        logs["created"].append(f"Form created: {uid}")
                    else:
                        logs["updated"].append(f"Form updated: {uid}")

                    form_map[old_id] = form_instance

                    # --- User Groups (many-to-many) ---
                    if "user_groups" in form and isinstance(form["user_groups"], list):
                        mapped_user_groups = [
                            user_groups_map.get(old_ug_id)
                            for old_ug_id in form["user_groups"]
                            if user_groups_map.get(old_ug_id)
                        ]
                        form_instance.user_groups.set(mapped_user_groups)

                    # --- Form Permissions ---
                    for perm in form.get("form_permission", []):
                        ug_id = perm.get("user_group_id")
                        ug_ref = user_groups_map.get(ug_id)

                        if not ug_id:
                            logs["skipped"].append(
                                f"FormPermission skipped for form ID {old_id}: missing user_group_id"
                            )
                            continue

                        if not ug_ref:
                            logs["skipped"].append(
                                f"FormPermission skipped for form ID {old_id}: user_group_id {ug_id} not found"
                            )
                            continue

                        try:
                            form_perm, created = FormPermission.objects.update_or_create(
                                form=form_instance,
                                user_group=ug_ref,
                                defaults={
                                    "read": perm.get("read", False),
                                    "write": perm.get("write", False),
                                    "edit": perm.get("edit", False),
                                },
                            )
                            if created:
                                logs["created"].append(f"FormPermission created: {form_perm.form}")
                            else:
                                logs["updated"].append(f"FormPermission updated: {form_perm.form}")

                        except Exception as e:
                            logs["errors"].append(f"FormPermission error for form {uid} and user_group_id {ug_id}: {e}")

                except Exception as e:
                    logs["errors"].append(f"FormData ID {form.get('id')} failed: {e}")

            # --- FilledFormData --- 
            ffd_map = {}
            for ffd in data.get("filled_form_datas", []):
                try:
                    # Extract many-to-many user groups and remove PK/id from JSON
                    m2m_user_groups = ffd.pop("user_groups", [])
                    ffd.pop("id", None)
                    
                    uid = ffd.get('uid')
                    if not uid:
                        logs["skipped"].append(f"FilledFormData skipped: missing UID {uid})")
                        continue

                    # --- Resolve Case ---
                    # original_case_id = ffd.pop("caseId_id", None)
                    # case_ref = case_map.get(original_case_id) if original_case_id else None

                    # --- Resolve Process ---
                    original_process_id = ffd.pop("processId_id", None)
                    process_ref = process_map.get(original_process_id) if original_process_id else None

                    # --- Resolve UserData ---
                    original_user_id = ffd.get("userId_id")
                    user_ref = user_data_map.get(original_user_id)

                    # --- Resolve FormDataInfo ---
                    old_form_id = ffd.get("formId")
                    form_ref = None

                    # Process only numeric formId values
                    if not str(old_form_id).isdigit():
                        # logs["skipped"].append(f"Skipped FFD: non-numeric formId {old_form_id}")
                        continue

                    # Try numeric match
                    try:
                        old_form_id_int = int(old_form_id)
                        form_ref = form_map.get(old_form_id_int)
                    except (ValueError, TypeError):
                        pass

                    # If numeric match failed, try Form_uid match
                    if not form_ref:
                        form_ref = FormDataInfo.objects.filter(Form_uid=old_form_id).first()

                    # If after everything still no match, skip
                    if not form_ref:
                        logs["skipped"].append(f"FilledFormData skipped: form not found for formId {old_form_id}")
                        continue


                    # --- Create FilledFormData ---
                    defaults = {
                        "formId": form_ref.id,
                        "userId": user_ref,
                        "processId": process_ref,
                        # "caseId": case_ref,
                        "data_json": ffd.get("data_json", {}),
                        "organization": org,
                        "status": ffd.get("status", ""),
                        "core_filled_data": ffd.get("core_filled_data"),
                        "is_enabled": ffd.get("is_enabled", True),
                    }

                    ffd_instance, created = FilledFormData.objects.update_or_create(uid=uid, defaults=defaults)
                    if created:
                        logs["created"].append(f"FilledFormData created: uid {uid}")
                    else:
                        logs["updated"].append(f"FilledFormData updated: uid {uid}")

                    # --- Set many-to-many user groups AFTER creation ---
                    if m2m_user_groups:
                        # Map old user group IDs to actual objects
                        mapped_user_groups = [
                            user_groups_map.get(ug_id)
                            for ug_id in m2m_user_groups
                            if user_groups_map.get(ug_id)
                        ]
                        ffd_instance.user_groups.set(mapped_user_groups)

                    # Map temporary reference for later foreign keys
                    ffd_map[len(ffd_map)] = ffd_instance

                except Exception as e:
                    logs["errors"].append(f"FilledFormData uid {ffd.get('uid')} error: {str(e)}")

            # --- SLA Configs --- 
            for sla in data.get("sla_configs", []):
                try:
                    process_ref = process_map.get(sla.get("process_id"))
                    if not process_ref:
                        logs["skipped"].append(f"SLA config skipped: missing process {sla.get('process_id')}")
                        continue

                    defaults = {
                        "sla_name": sla.get("sla_name"),
                        "sla_json_schema": sla.get("sla_json_schema", {}),
                        "created_by": sla.get("created_by", ""),
                        "updated_by": sla.get("updated_by", ""),
                    }

                    sla_obj, was_created = SlaConfig.objects.update_or_create(
                        sla_uid=sla.get("sla_uid"),
                        organization=org,
                        process_id=process_ref,
                        defaults=defaults
                    )

                    if was_created:
                        logs["created"].append(f"SLA created: {sla_obj.sla_name} ({sla_obj.sla_uid})")
                    else:
                        logs["updated"].append(f"SLA updated: {sla_obj.sla_name} ({sla_obj.sla_uid})")

                    # --- SLA Case Instances ---
                    # for inst in sla.get("sla_case_instance", []):
                    #     try:
                    #         case_ref = case_map.get(inst.get("case_id"))
                    #         if not case_ref:
                    #             logs["skipped"].append(f"SLA instance skipped (missing case) for SLA {sla_obj.sla_uid}")
                    #             continue

                    #         sla_case_obj, created=SlaCaseInstance.objects.update_or_create(
                    #             sla_id=sla_obj,
                    #             case_id=case_ref,
                    #             defaults={
                    #                 "is_completed": inst.get("is_completed", False),
                    #                 "created_by": inst.get("created_by", ""),
                    #                 "updated_by": inst.get("updated_by", ""),
                    #             },
                    #         )
                    #         if created:
                    #             logs["created"].append(f"SLA instance created: {sla_obj.sla_name} ({sla_obj.sla_uid})")
                    #         else:
                    #             logs["updated"].append(f"SLA instance updated: {sla_obj.sla_name} ({sla_obj.sla_uid})")

                    #     except Exception as e_inst:
                    #         logs["errors"].append(f"SLA instance error for SLA {sla_obj.sla_uid}: {str(e_inst)}")

                except Exception as e:
                    logs["errors"].append(f"SLA config error ({sla.get('sla_uid')}): {str(e)}")

            # --- Bots --- 
            bot_map = {}
            for bot in data.get("bots", []):
                try:
                    old_bot_id = bot.get("id")
                    bot_uid = bot.get("bot_uid")

                    if not bot_uid:
                        logs["skipped"].append(f"Bot skipped: missing UID {bot_uid})")
                        continue

                    # if not bot_uid:
                    #     # Generate one if missing in import data
                    #     bot_uid = f"AUTO_{old_bot_id}_{random.randint(100, 9999)}"

                    # # If bot_uid already exists in DB, make it unique to avoid collisions
                    # if Bot.objects.filter(bot_uid=bot_uid).exists():
                    #     random_suffix = random.randint(100, 9999)
                    #     bot_uid = f"DUP_{old_bot_id}_{random_suffix}"

                    defaults = {
                        "name": bot.get("name", ""),
                        "bot_name": bot.get("bot_name", ""),
                        "bot_description": bot.get("bot_description", ""),
                    }

                    bot_instance, created = Bot.objects.update_or_create(
                        bot_uid=bot_uid,
                        defaults=defaults
                    )

                    bot_map[old_bot_id] = bot_instance

                    if created:
                        logs["created"].append(f"Bot created: {bot_instance.name or bot_instance.bot_uid}")
                    else:
                        logs["updated"].append(f"Bot updated: {bot_instance.name or bot_instance.bot_uid}")

                except Exception as e:
                    logs["errors"].append(f"Bot ID {bot.get('id')} failed: {str(e)}")

            # --- BotSchemas --- 
            for schema in data.get("bot_schemas", []):
                try:
                    old_bot_id = schema.get("bot_id")
                    old_flow_id = schema.get("flow_id_id")

                    bot_ref = bot_map.get(old_bot_id)
                    flow_ref = process_map.get(old_flow_id)

                    if not bot_ref:
                        logs["skipped"].append(f"BotSchema skipped: missing bot reference for old bot_id={old_bot_id}")
                        continue

                    if not flow_ref:
                        logs["skipped"].append(f"BotSchema skipped: missing process reference for old flow_id={old_flow_id}")
                        continue

                    defaults = {
                        "bot_schema_json": schema.get("bot_schema_json", {}),
                        "bot_element_permission": schema.get("bot_element_permission", {}),
                    }

                    bot_schema_obj, created = BotSchema.objects.update_or_create(
                        bot=bot_ref,
                        flow_id=flow_ref,
                        organization=org,
                        defaults=defaults
                    )

                    if created:
                        logs["created"].append(f"BotSchema created for Bot UID {bot_ref.bot_uid}")
                    else:
                        logs["updated"].append(f"BotSchema updated for Bot UID {bot_ref.bot_uid}")

                except Exception as e:
                    logs["errors"].append(
                        f"Failed to create/update BotSchema for bot_id={schema.get('bot_id')} and flow_id={schema.get('flow_id_id')}: {str(e)}"
                    )

            # --- Integration --- 
            integration_map = {}
            for integ in data.get("integrations", []):
                try:
                    old_integration_id = integ.get("id")
                    old_flow_id = integ.get("flow_id_id")

                    # Resolve process reference
                    flow_ref = process_map.get(old_flow_id)
                    if not flow_ref:
                        logs["skipped"].append(
                            f"Integration ID {old_integration_id} skipped: missing flow reference (flow_id={old_flow_id})"
                        )
                        continue

                    integration_uid = integ.get("Integration_uid")

                    defaults = {
                        "integration_type": integ.get("integration_type", "api"),
                        "integration_name": integ.get("integration_name", ""),
                        "description": integ.get("description", ""),
                        "integration_schema": integ.get("integration_schema", {}),
                        "organization": org,
                        "flow_id": flow_ref,
                    }

                    # Update if Integration_uid exists, otherwise create new
                    integ_instance, created = Integration.objects.update_or_create(
                        Integration_uid=integration_uid,
                        defaults=defaults
                    )

                    integration_map[old_integration_id] = integ_instance

                    if created:
                        logs["created"].append(f"Integration created (uid={integration_uid}, flow={flow_ref.id})")
                    else:
                        logs["updated"].append(f"Integration updated (uid={integration_uid}, flow={flow_ref.id})")

                except Exception as e:
                    logs["errors"].append(f"Integration ID {integ.get('id')} failed: {str(e)}")

            # --- Dms --- 
            dms_map = {}
            for dms in data.get("dms", []):
                try:
                    old_dms_id = dms.get("id")
                    old_flow_id = dms.get("flow_id_id")

                    flow_ref = process_map.get(old_flow_id)

                    if not dms.get("dms_uid"):
                        logs["skipped"].append(f"DMS skipped (no UID): ID={old_dms_id}")
                        continue

                    defaults = {
                        "name": dms.get("name", ""),
                        "description": dms.get("description", ""),
                        "organization": org,
                        "drive_types": dms.get("drive_types", "Google Drive"),
                        "config_details_schema": dms.get("config_details_schema", {}),
                        "flow_id": flow_ref,
                    }

                    # Update if exists, else create new
                    dms_instance, created = Dms.objects.update_or_create(
                        dms_uid=dms.get("dms_uid"),
                        organization=org,
                        defaults=defaults,
                    )

                    dms_map[old_dms_id] = dms_instance

                    if created:
                        logs["created"].append(f"DMS created (UID={dms.get('dms_uid')})")
                    else:
                        logs["updated"].append(f"DMS updated (UID={dms.get('dms_uid')})")

                except Exception as e:
                    logs["errors"].append(f"DMS failed (ID={dms.get('id')}): {str(e)}")

            # --- OCR --- 
            ocr_map = {}
            for ocr in data.get("ocr", []):
                try:
                    old_ocr_id = ocr.get("id")
                    old_flow_id = ocr.get("flow_id_id")

                    flow_ref = process_map.get(old_flow_id)

                    # --- Define default fields for updates ---
                    defaults = {
                        "ocr_type": ocr.get("ocr_type", "Aadhar Card Extraction"),
                        "name": ocr.get("name", ""),
                        "description": ocr.get("description", ""),
                        "organization": org,
                        "flow_id": flow_ref,
                    }

                    # --- Update if exists, else create new ---
                    ocr_instance, created = Ocr.objects.update_or_create(
                        ocr_uid=ocr.get("ocr_uid"),
                        organization=org,
                        defaults=defaults
                    )

                    ocr_map[old_ocr_id] = ocr_instance

                    if created:
                        logs["created"].append(f"OCR created (ocr_uid={ocr.get('ocr_uid')})")
                    else:
                        logs["updated"].append(f"OCR updated (ocr_uid={ocr.get('ocr_uid')})")

                except Exception as e:
                    logs["errors"].append(f"OCR failed (ocr_id={ocr.get('id')}): {str(e)}")

            # --- Scheduler --- 
            scheduler_map = {}
            for scheduler in data.get("scheduler", []):
                try:
                    old_id = scheduler.get("id")
                    old_process_id = scheduler.get("process_id")

                    process_ref = process_map.get(old_process_id)

                    defaults = {
                        "scheduler_name": scheduler.get("scheduler_name", "email spooling"),
                        "organization": org,
                        "process": process_ref,
                        "frequency": scheduler.get("frequency", ""),
                        "scheduler_config": scheduler.get("scheduler_config", {}),
                        "last_run": scheduler.get("last_run"),
                        "next_run": scheduler.get("next_run"),
                        "is_active": scheduler.get("is_active", True),
                        "created_on": scheduler.get("created_on"),
                        "updated_on": scheduler.get("updated_on"),
                    }

                    # Upsert logic for idempotent imports
                    scheduler_instance, created = Scheduler.objects.update_or_create(
                        scheduler_uid=scheduler.get("scheduler_uid"),
                        organization=org,
                        defaults=defaults
                    )

                    # Maintain mapping for dependent imports
                    scheduler_map[old_id] = scheduler_instance

                    if created:
                        logs["created"].append(f"Scheduler created (uid={scheduler.get('scheduler_uid')})")
                    else:
                        logs["updated"].append(f"Scheduler updated (uid={scheduler.get('scheduler_uid')})")

                except Exception as e:
                    logs["errors"].append(f"Scheduler failed (id={scheduler.get('id')}): {str(e)}")

            # --- ReportConfig --- 
            for report in data.get("reports", []):
                try:
                    uid = report.get("uid")
                    report_type = report.get("report_type", "").lower()
                    data_id = report.get("data_id")
                    mapped_data_id = None

                    if report_type == "process":
                        mapped_data_id = process_map.get(data_id)
                    elif report_type == "form":
                        mapped_data_id = FormDataInfo.objects.filter(Form_uid=data_id).first()
                    elif report_type == "subprocess":
                        mapped_data_id = process_map.get(data_id)
                    elif report_type == "core data":
                        mapped_data_id = data_id

                    defaults = {
                        "name": report.get("name", ""),
                        "report_type": report.get("report_type", ""),
                        "data_id": mapped_data_id.id if hasattr(mapped_data_id, "id") else mapped_data_id,
                        "query": report.get("query", {}),
                        "query_result": report.get("query_result", {}),
                        "user_groups": report.get("user_groups", []),
                        "organization": org,
                        "chart_schema": report.get("chart_schema", {}),
                        "created_at": report.get("created_at"),
                        "updated_at": report.get("updated_at")
                    }

                    report_instance, created = ReportConfig.objects.update_or_create(uid=uid, defaults=defaults)

                    if created:
                        logs["created"].append(f"ReportConfig created: {report_instance.name or report_instance.uid}")
                    else:
                        logs["updated"].append(f"ReportConfig updated: {report_instance.name or report_instance.uid}")

                except Exception as e:
                    logs["skipped"].append(f"ReportConfig skipped: {e}")
            
            # --- NotificationBotSchema --- 
            for nbs in data.get("notification_bot_schemas", []):
                try:
                    process_ref = process_map.get(nbs.get("process"))

                    defaults = {
                        "type": nbs.get("type"),
                        "notification_name": nbs.get("notification_name"),
                        "notification_field_id": nbs.get("notification_field_id"),
                        "receiver_type": nbs.get("receiver_type"),
                        "receiver_mail": nbs.get("receiver_mail", {}),
                        "mail_content": nbs.get("mail_content", {}),
                        "notification_element_permission": nbs.get("notification_element_permission", []),
                    }
                    lookup_fields = {
                        "organization": org,
                        "process": process_ref,
                    }


                    # If notification_uid exists → use it as unique lookup
                    if nbs.get("notification_uid"):
                        lookup_fields["notification_uid"] = nbs.get("notification_uid")
                    else:
                        # fallback unique combination
                        lookup_fields["notification_name"] = nbs.get("notification_name")

                    # Perform update_or_create
                    nbs_instance, created = NotificationBotSchema.objects.update_or_create(
                        **lookup_fields,
                        defaults=defaults
                    )

                    if created:
                        logs["created"].append(f"NotificationBotSchema created (notification_name={nbs.get('notification_name')})")
                    else:
                        logs["updated"].append(f"NotificationBotSchema updated (notification_name={nbs.get('notification_name')})")

                except Exception as e:
                    logs["errors"].append(f"NotificationBotSchema skipped (notification_name={nbs.get('notification_name')}): {str(e)}")

            # --- Notification --- 
            for notif in data.get("notifications", []):
                try:
                    uid = notif.get("uid")
                    if not uid:
                        logs["skipped"].append(f"Notification skipped: missing uid")
                        continue

                    defaults = {
                        "notification_type": notif.get("notification_type", "In-App"),
                        "notification_name": notif.get("notification_name", ""),
                        "description": notif.get("description", ""),
                        "notification_content": notif.get("notification_content", ""),
                        "updated_at": notif.get("updated_at")
                    }

                    notif_instance, created = Notification.objects.update_or_create(
                        uid=uid,
                        defaults=defaults
                    )

                    if created:
                        logs["created"].append(f"Notification created: {uid}")
                    else:
                        logs["updated"].append(f"Notification updated: {uid}")

                except Exception as e:
                    logs["errors"].append(f"Notification errors (uid={uid}): {str(e)}")

            # --- Agents --- 
            for agent in data.get("agents", []):
                try:
                    uid = agent.get("uid")
                    if not uid:
                        logs["skipped"].append(f"Agent skipped uid not found")
                        continue

                    defaults = {
                        "agent_name": agent.get("agent_name"),
                        "agent_description": agent.get("agent_description", ""),
                        "agent_config_schema": agent.get("agent_config_schema", {}),
                        "is_active": agent.get("is_active", True),
                        "cron_timing": agent.get("cron_timing", ""),
                        "organization": org,
                        
                    }
                    agent_instance, created = Agent.objects.update_or_create(uid=uid, defaults=defaults)
                    if created:
                        logs["created"].append(f"Agent created: {agent_instance.agent_name or agent_instance.uid}")
                    else:
                        logs["updated"].append(f"Agent updated: {agent_instance.agent_name or agent_instance.uid}")

                except Exception as e:
                    # Catch any error and track as skipped
                    logs["errors"].append(f"Agent error (UID={agent.get('uid')}): {str(e)}")

            # --- Dashboards --- 
            for dashboard in data.get("dashboards", []):
                try:
                    uid = dashboard.get("uid")
                    if not uid:
                        logs["skipped"].append(f"Dashboard skipped uid not found")
                        continue

                    old_usergroup_id = dashboard.get("usergroup_id")
                    new_usergroup_ref = user_groups_map.get(old_usergroup_id)
                    defaults = {
                        "name": dashboard.get("name", ""),
                        "dashboard_types": dashboard.get("dashboard_types", ""),
                        "organization": org,
                        "usergroup": new_usergroup_ref,
                        "dashboard_config": dashboard.get("dashboard_config", {}),
                    }
                    dashboard_instance, created = Dashboard.objects.update_or_create(uid=uid, defaults=defaults)
                    if created:
                        logs["created"].append(f"Dashboard created: {dashboard_instance.name or dashboard_instance.uid}")
                    else:
                        logs["updated"].append(f"Dashboard updated: {dashboard_instance.name or dashboard_instance.uid}")

                except Exception as e:
                    logs["errors"].append(f"Dashboard error (UID={dashboard.get('uid')}): {str(e)}")

            # --- UserFormSchema --- 
            for ufs in data.get("user_form_schemas", []):
                try:
                    uid = ufs.get("uid")
                    if not uid:
                        logs["skipped"].append(f"UserFormSchema skipped uid not found")
                        continue

                    defaults = {
                        "organization": org,
                        "user_form_schema": ufs.get("user_form_schema", {}),
                    }
                    ufs_instance, created = UserFormSchema.objects.update_or_create(uid=uid, defaults=defaults)
                    if created:
                        logs["created"].append(f"UserFormSchema created: {ufs_instance.uid}")
                    else:
                        logs["updated"].append(f"UserFormSchema updated: {ufs_instance.uid}")

                except Exception as e:
                    logs["errors"].append(f"UserFormSchema error (UID={ufs.get('uid')}): {str(e)}")

            # --- End Elements --- 
            for end_element in data.get("end_elements", []):
                try:
                    element_uid = end_element.get("element_uid")
                    old_process_id = end_element.get("process_id")
                    process_ref = process_map.get(old_process_id)

                    if not end_element.get("element_uid"):
                        logs["skipped"].append(f"EndElement skipped: missing element_uid")
                        continue

                    # Fields that CAN be updated
                    defaults = {
                        "element_type": end_element.get("element_type", ""),
                        "element_name": end_element.get("element_name", ""),
                        "end_element_schema": end_element.get("end_element_schema", {}),
                        "organization": org,
                        "process": process_ref,
                    }

                    # Lookup fields
                    lookup = {
                        "element_uid": element_uid,
                    }

                    obj, created = EndElement.objects.update_or_create(
                        **lookup,
                        defaults=defaults
                    )

                    if created:
                        logs["created"].append(f"EndElement created: {obj.element_uid}")
                    else:
                        logs["updated"].append(f"EndElement updated: {obj.element_uid}")

                except Exception as e:
                    logs["skipped"].append(f"EndElement skipped: {str(e)}")

            # --- Sequences --- 
            for seq in data.get("sequence", []):
                try:
                    uid = seq.get("uid")
                    if not uid:
                        logs["skipped"].append("Sequence skipped: missing uid")
                        continue

                    defaults = {
                        "digit": seq.get("digit", 0),
                        "name": seq.get("name", ""),
                        "prefix": seq.get("prefix", ""),
                        "suffix": seq.get("suffix", ""),
                        "access_id": seq.get("access_id", ""),
                        "counter": seq.get("counter", 1),
                        "organization": org,
                    }

                    obj, created = Sequence.objects.update_or_create(
                        uid=uid,
                        defaults=defaults
                    )

                    if created:
                        logs["created"].append(f"Sequence created: {obj.uid}")
                    else:
                        logs["updated"].append(f"Sequence updated: {obj.uid}")

                except Exception as e:
                    logs["skipped"].append(f"Sequence skipped: {str(e)}")

            # --- Rules --- 
            for rule in data.get("rules", []):
                try:
                    ruleId = rule.get("ruleId")
                    if not ruleId:
                        logs["skipped"].append("Rule skipped: missing uid")
                        continue

                    old_process_id = rule.get("processId_id")
                    old_form_id = rule.get("form_id")
                    process_ref = process_map.get(old_process_id)
                    form_ref = form_map.get(old_form_id)

                    # Only updatable fields go into defaults
                    defaults = {
                        "rule_type": rule.get("rule_type", ""),
                        "rule_json_schema": rule.get("rule_json_schema", {}),
                        "form_rule_schema": rule.get("form_rule_schema", {}),
                        "process_codeblock_schema": rule.get("process_codeblock_schema", {}),
                        "form": form_ref,
                        "organization": org,
                        "processId": process_ref,
                    }

                    lookup = {
                        "ruleId": rule.get("ruleId", ""),
                    }

                    obj, created = Rule.objects.update_or_create(
                        **lookup,
                        defaults=defaults
                    )
                    if created:
                        logs["created"].append(f"Rule created: {obj.ruleId}")
                    else:
                        logs["updated"].append(f"Rule updated: {obj.ruleId}")

                except Exception as e:
                    logs["skipped"].append(f"Rule skipped: {str(e)}")

            # notification_config
            for notify_config in data.get("notification_config", []):
                try:
                    uid = notify_config.get("uid")
                    defaults = {
                            "config_details": notify_config.get("config_details", {}),
                            "organization": org,
                        }
                    lookup = {"uid": uid}
                    obj, created = NotificationConfig.objects.update_or_create(
                            **lookup,
                            defaults=defaults
                        )
                    if created:
                            logs["created"].append(f"NotificationConfig created: {obj.uid}")
                    else:
                        logs["updated"].append(f"NotificationConfig updated: {obj.uid}")

                except Exception as e:
                    logs["errors"].append(f"NotificationConfig errors: {str(e)}")

            # Final response
            return Response({
                "status": True,
                "message": ("Organization data imported successfully."if org_created else "Organization data updated successfully."),
                "logs": logs
            })

        except Exception as e:
            logs["errors"].append(str(e))
            return Response({
                "status": False,
                "message": "Import failed.",
                "logs": logs
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ExportProcessDataAPIView(APIView):
    """
    API endpoint to export process data for a specific organization.
    If a process ID is provided, only that process will be exported.
    Otherwise, all processes for the organization are included.
    """

    def get(self, request, organization_id, process_id=None):
        # --- Validate Organization ---
        try:
            organization = Organization.objects.get(id=organization_id)
        except Organization.DoesNotExist:
            return Response(
                {"status": False, "message": "Organization not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as error:
            return Response(
                {"status": False, "message": f"Error retrieving organization: {str(error)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # --- Fetch Process Data ---
        try:
            export_data = {}

            # Fetch either all processes or the specific one
            if process_id:
                processes = CreateProcess.objects.filter(id=process_id, organization=organization)
                if not processes.exists():
                    return Response(
                        {"status": False, "message": "Process not found for the given organization."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                file_name = f"process_export_org_{organization_id}_process_{process_id}.json"
            else:
                processes = CreateProcess.objects.filter(organization=organization)
                if not processes.exists():
                    return Response(
                        {"status": False, "message": "No processes found for this organization."},
                        status=status.HTTP_404_NOT_FOUND
                    )
                file_name = f"process_export_org_{organization_id}.json"

            # --- Processes ---
            export_data["processes"] = []
            for process in processes:
                export_data["processes"].append({
                    "id": process.id,
                    "process_name": process.process_name,
                    "process_description": process.process_description,
                    "initiator_group": process.initiator_group,
                    "first_step": process.first_step.id if process.first_step else None,
                    "participants": process.participants,
                    "organization": process.organization.id if process.organization else None,
                    "user_group": list(process.user_group.values_list("id", flat=True)),
                    "dms": list(process.dms.values_list("id", flat=True)),
                    "parent_process": process.parent_process.id if process.parent_process else None,
                    "subprocess_UID": process.subprocess_UID,
                    "process_stages": process.process_stages,
                    "process_table_configuration": process.process_table_configuration,
                    "parent_case_data_schema": process.parent_case_data_schema,
                    "process_table_permission": process.process_table_permission,
                    "uid": process.uid,
                })

                # --- Forms ---
                form_datas = []
                for form in FormDataInfo.objects.filter(organization=organization, processId=process.id):
                    form_permission = []
                    for perm in FormPermission.objects.filter(form=form):
                        form_permission.append({
                            "user_group_id": perm.user_group.id,
                            "read": perm.read,
                            "write": perm.write,
                            "edit": perm.edit
                        })
                    form_datas.append({
                        "id": form.id,
                        "Form_uid": form.Form_uid,
                        "form_name": form.form_name,
                        "form_description": form.form_description,
                        "form_json_schema": form.form_json_schema,
                        "form_style_schema": form.form_style_schema,
                        "form_status": form.form_status,
                        "form_created_by": form.form_created_by,
                        "form_created_on": str(form.form_created_on),
                        "organization": organization_id,
                        "processId": form.processId.id if form.processId else None,
                        "user_groups": list(form.user_groups.values_list('id', flat=True)),
                        "core_table": form.core_table,
                        "form_filter_schema": form.form_filter_schema,
                        "form_send_mail": form.form_send_mail,
                        "form_send_mail_schema": form.form_send_mail_schema,
                        "form_permission": form_permission,
                    })

                export_data['form_datas'] = form_datas

            if process_id:
                bot_schemas = BotSchema.objects.filter(organization=organization, flow_id=process_id)
                bot_data = BotData.objects.filter(organization=organization, flow_id=process_id)
                integrations = Integration.objects.filter(organization=organization, flow_id=process_id)
                integration_details = IntegrationDetails.objects.filter(organization=organization, flow_id=process_id)
                ocr = Ocr.objects.filter(organization=organization, flow_id=process_id)
                ocr_details = Ocr_Details.objects.filter(organization=organization, flow_id=process_id)
                schedulers = Scheduler.objects.filter(organization=organization, process=process_id)
                scheduler_data = SchedulerData.objects.filter(organization=organization, process=process_id)
                notification_bot_schemas = NotificationBotSchema.objects.filter(organization=organization, process=process_id)
                notification_data = NotificationData.objects.filter(organization=organization, process=process_id)
                notificatio_dismiss = NotificationDismiss.objects.filter(process=process_id)
                end_elements = EndElement.objects.filter(organization=organization, process=process_id)
                rules = Rule.objects.filter(organization=organization, processId=process_id)
            else:
                bot_schemas = BotSchema.objects.filter(organization=organization)
                bot_data = BotData.objects.filter(organization=organization)
                integrations = Integration.objects.filter(organization=organization)
                ocr = Ocr.objects.filter(organization=organization)
                ocr_details = Ocr_Details.objects.filter(organization=organization)
                schedulers = Scheduler.objects.filter(organization=organization)
                scheduler_data = SchedulerData.objects.filter(organization=organization)
                notification_bot_schemas = NotificationBotSchema.objects.filter(organization=organization)
                notification_data = NotificationData.objects.filter(organization=organization)
                notificatio_dismiss = NotificationDismiss.objects.all()
                end_elements = EndElement.objects.filter(organization=organization)
                rules = Rule.objects.filter(organization=organization, processId=process_id)

            export_data['bots'] = list(Bot.objects.all().values())
            export_data['bot_schemas'] = list(bot_schemas.values())
            export_data['bot_data'] = list(bot_data.values())
            export_data['integrations'] = list(integrations.values())
            export_data['integration_details'] = list(integration_details.values())
            export_data['ocr'] = list(ocr.values())
            export_data['ocr_details'] = list(ocr_details.values())
            export_data['schedulers'] = list(schedulers.values())
            export_data['scheduler_data'] = list(scheduler_data.values())
            export_data['notification_bot_schemas'] = list(notification_bot_schemas.values())
            export_data['notification_data'] = list(notification_data.values())
            export_data['notificatio_dismiss'] = list(notificatio_dismiss.values())
            export_data['end_elements'] = list(end_elements.values())
            export_data['rules'] = list(rules.values())
            export_data['notification_configs'] = list(NotificationConfig.objects.filter(organization=organization).values())

            # Create Temporary JSON File ---
            with NamedTemporaryFile(mode="w+", delete=False, suffix=".json") as temp_file:
                json.dump(export_data, temp_file, cls=DjangoJSONEncoder, indent=4)
                temp_file_path = temp_file.name
            # Prepare Download Response ---
            with open(temp_file_path, "rb") as file:
                response = HttpResponse(file.read(), content_type="application/json")
                response["Content-Disposition"] = f'attachment; filename="{file_name}"'
            # Clean Up ---
            os.remove(temp_file_path)

            return response

        except Exception as error:
            return Response(
                {"status": False, "message": f"Error exporting process data: {str(error)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ImportProcessDataAPIView(APIView):
    """
    API endpoint to import process data (single or multiple) from a JSON file.
    If `process_id` is provided, it updates that specific process.
    Otherwise, it creates new process entries.
    """

    def post(self, request):
        logs = {"skipped": [], "errors": []}

        try:
            # --- Step 1: Extract inputs ---
            uploaded_file = request.FILES.get("file")
            organization_id = request.data.get("organization_id")
            process_id = request.data.get("process_id")

            # --- Validate file ---
            if not uploaded_file:
                return Response(
                    {"status": False, "message": "No file uploaded."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # --- Validate organization ---
            try:
                organization = Organization.objects.get(id=organization_id)
            except Organization.DoesNotExist:
                return Response(
                    {"status": False, "message": "Organization not found."},
                    status=status.HTTP_404_NOT_FOUND
                )
            except Exception as error:
                return Response(
                    {"status": False, "message": f"Error retrieving organization: {str(error)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # --- Step 2: Parse JSON data ---
            try:
                process_data = json.load(uploaded_file)
            except json.JSONDecodeError:
                return Response(
                    {"status": False, "message": "Invalid JSON file format."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            processes = process_data.get("processes", [])
            if not processes:
                return Response(
                    {"status": False, "message": "No process data found in the uploaded file."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # --- Step 3: Create or update processes ---
            with transaction.atomic():
                for process_entry in processes:
                    try:
                        # Extract ManyToMany field IDs and remove from main dict
                        user_group_ids = process_entry.pop("user_group", [])
                        dms_ids = process_entry.pop("dms", [])

                        # --- Update existing process ---
                        if process_id:
                            process_instance = CreateProcess.objects.filter(
                                id=process_id, organization=organization
                            ).first()

                            if not process_instance:
                                logs["skipped"].append(f"Process ID {process_id} not found for update.")
                                continue

                            for key, value in process_entry.items():
                                setattr(process_instance, key, value)
                            process_instance.organization = organization
                            process_instance.save()

                        # --- Create new process ---
                        else:
                            process_instance = CreateProcess.objects.create(
                                **process_entry, organization=organization
                            )

                        # --- Handle ManyToMany relations ---
                        if user_group_ids:
                            user_groups = UserGroup.objects.filter(id__in=user_group_ids)
                            process_instance.user_group.set(user_groups)

                        if dms_ids:
                            dms_objects = Dms.objects.filter(id__in=dms_ids)
                            process_instance.dms.set(dms_objects)

                    except Exception as process_error:
                        logs["skipped"].append(
                            f"Error processing process '{process_entry.get('process_name', 'Unknown')}': {str(process_error)}"
                        )

            # --- Step 4: Return response ---
            return Response(
                {
                    "status": True,
                    "message": "Process data imported successfully.",
                    "logs": logs
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logs["errors"].append(str(e))
            return Response(
                {
                    "status": False,
                    "message": "Import failed due to an unexpected error.",
                    "logs": logs
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )






# case_list = Case.objects.all()

# for data in case_list:
#     value = data.parent_case_data

#     if isinstance(value, str) and value.strip():
#         # Auto-fix missing comma between objects
#         fixed = value.replace('}{', '},{')

#         try:
#             parsed = json.loads(fixed)  # Python list/dict
#             print("✓ Fixed JSON for Case", data.id)

#             # Save as **real JSON**, not string
#             data.parent_case_data = parsed
#             data.save()

#         except json.JSONDecodeError as e:
#             print(f"❌ Still invalid for Case Id {data.id} -> {e}")

#     else:
#         print("Case Id skipped", data.id)


# import json
# import re

# # Load your invalid json file
# with open("/Users/syedsulthan/Harish/Skycode-LifeCell/csvdata.json", "r") as f:
#     raw = f.read()

# # Extract all JSON arrays inside quotes
# matches = re.findall(r'"(\[.*?\])"', raw, flags=re.DOTALL)

# corrected_data = []

# for m in matches:
#     # Replace doubled double-quotes "" → "
#     cleaned = m.replace('""', '"')

#     # Convert string to valid JSON
#     parsed = json.loads(cleaned)
#     corrected_data.append(parsed)

# # Save corrected JSON
# with open("correct_json_new.json", "w") as f:
#     json.dump(corrected_data, f, indent=4)

# print("Conversion Complete → correct_json_new.json")


# import json

# case_list = list(Case.objects.all().order_by('id'))

# with open("/Users/syedsulthan/Harish/Skycode-LifeCell/formbuilder_backend/correct_json_new.json", "r") as f:
#     data = json.load(f)

# # Safety check
# if len(case_list) != len(data):
#     print("Length mismatch!", len(case_list), len(data))
# else:
#     print("Length OK:", len(case_list))

# for case, row in zip(case_list, data):
#     case.parent_case_data = row   # assign corresponding JSON entry
#     case.save()

# from django.db import transaction

# cases = Case.objects.all()
# updated_count = 0

# with transaction.atomic():
#     for case in cases:
#         if not case.parent_case_data:
#             continue
        
#         updated = False

#         # parent_case_data is a list of dicts
#         for item in case.parent_case_data:
#             if item.get("field_id") == "lab_admin_requested_date":
                
#                 # Replace label + field_id, keep same value
#                 item["label"] = "Current Year"
#                 item["field_id"] = "current_year"
                
#                 updated = True
        
#         if updated:
#             case.save()
#             updated_count += 1

# print("Total cases updated:", updated_count)



# from datetime import datetime
# from django.utils.timezone import make_aware

# case_list = Case.objects.all()
# updated_count = 0

# DATE_FORMATS = [
#     "%Y-%m-%d",
#     "%d-%m-%Y",
#     "%Y/%m/%d",
#     "%d/%m/%Y",
#     "%Y-%m-%dT%H:%M",
#     "%Y-%m-%dT%H:%M:%S",
# ]

# def parse_date(date_str):
#     """Try many date formats until one works."""
#     for fmt in DATE_FORMATS:
#         try:
#             return datetime.strptime(date_str.strip(), fmt)
#         except:
#             continue
#     return None


# for case in case_list:
#     parent_data = case.parent_case_data  # JSON list

#     if not parent_data:
#         continue

#     test_date_value = None

#     # get test_completion_date
#     for item in parent_data:
#         if item.get("field_id") == "test_completion_date":
#             test_date_value = item.get("value")
#             print("test_date_value : ",test_date_value)
#             break

#     if not test_date_value:
#         continue

#     parsed_date = parse_date(test_date_value)

#     if not parsed_date:
#         print(f"Invalid date format for Case {case.id}: {test_date_value}")
#         continue
#     print("parsed_date before: ",parsed_date)
#     parsed_date = make_aware(parsed_date)
#     print("parsed_date after: ",parsed_date)

#     Case.objects.filter(id=case.id).update(updated_on=parsed_date)
#     case.save()
#     updated_count += 1

# print("Updated Case count:", updated_count)
