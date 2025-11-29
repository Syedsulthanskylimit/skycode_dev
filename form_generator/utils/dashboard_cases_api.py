from collections import defaultdict
import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import json
# cron schedule imports end

from form_generator.models import CreateProcess, FormDataInfo, Rule, Case, UserData, FormPermission, UserFormSchema, \
    FilledFormData, EndElement
from custom_components.models import Bot, BotSchema, BotData, Integration, IntegrationDetails, Organization, UserGroup, \
    Ocr, Dms, Dms_data, Ocr_Details, Scheduler, SchedulerData, NotificationBotSchema, NotificationData
from custom_components.serializer import IntegrationDetailsSerializer, BotDataSerializer, OrganizationSerializer, \
    OcrSerializer, Ocr_DetailsSerializer, DmsDataSerializer, SchedulerDataSerializer, NotificationDataSerializer

from form_generator.serializer import CaseSerializer, FilledDataInfoSerializer, CaseDashboardSerializer, ProcessCaseListSerializer

import logging

from form_generator.utils.case_list_api import ProcessCaseListApi
from form_generator.utils.pagination import paginate_data
logger = logging.getLogger('custom_components')
from django.db.models import Count, F

# 22-09-2025 by Harish (Dashboard case) [Product Level]
class DashboardCasesView(APIView):
    def get(self, request, organization_id):
        user_id = request.query_params.get('uid',None)
        user_group_id = request.query_params.get('ug_id',None)
        user_id = None if user_id in (None, "", "null", "NULL") else int(user_id)
        user_group_id = None if user_group_id in (None, "", "null", "NULL") else user_group_id
        user_data = {}

        try:
            if user_id:
                user = UserData.objects.get(id=user_id)
                if user:
                    user_data_list = user.user_profile_schema
                    user_data = {data['field_id']: data['value'] for data in user_data_list}

            organization = Organization.objects.get(id=organization_id)
        except (UserData.DoesNotExist, Organization.DoesNotExist):
            return Response({'error': 'User or Organization not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            cases = Case.objects.filter(organization=organization)
            case_serializer = CaseDashboardSerializer(cases, many=True)
            serialized_data = case_serializer.data

            for data_item in serialized_data:
                self.enrich_case_data(data_item, organization.id)

            case_filtered = [
                case for case in serialized_data
                if self.general_filter_cases(case, user_id, user_group_id)
            ]

            case_advance_filter = [
                case for case in case_filtered
                if self.advance_case_filter(case, user_id, user_group_id, user_data)
            ]

            case_list = []
            for case in case_advance_filter:
                case_list.append(case.pop('data_json'))

            response_data = {
                'organization_id': organization.id,
                'total_cases': len(case_list),
                'completed_cases': cases.filter(status='Completed').count(),
                'inprogress_cases': cases.filter(status='In Progress').count(),
                'cases': case_advance_filter,
            }

            return Response(response_data)

        except Exception as e:
            logger.exception("Error retrieving cases")
            return Response({'error': 'An error occurred while retrieving case data'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def enrich_case_data(self, case, organization_id):
        """Enrich case with permissions, schemas, and other contextual data."""

        data_json_id = self.get_first_data_json_id(case.get('data_json'))
        case['data_json'] = self.get_filled_form_data_json(data_json_id)

        process_id = case.get('processId')
        next_step_uid = case.get('next_step')

        # Add user groups for the process
        case['process_user_groups'] = list(
            CreateProcess.objects.filter(id=process_id).values_list('user_group__id', flat=True))

        # Enrich with permissions and schemas from possible sources
        case.update(self.get_form_info(next_step_uid, organization_id))
        case.update(self.get_subprocess_info(next_step_uid, organization_id))
        case.update(self.get_notification_info(next_step_uid))
        case.update(self.get_bot_info(next_step_uid, organization_id, process_id))
        case.update(self.get_end_element_info(next_step_uid))
        case.pop('next_step', None)

    def get_first_data_json_id(self, data_json_str):
        """Extracts first numeric ID from a JSON-like string."""
        if data_json_str:
            ids = [int(id.strip()) for id in data_json_str.strip('[]').split(',') if id.strip().isdigit()]
            return ids[0] if ids else None
        return None

    def get_filled_form_data_json(self, data_id):
        """Returns the data_json from a filled form if available."""
        if not data_id:
            return None
        try:
            filled_data = FilledFormData.objects.get(pk=data_id)
            return FilledDataInfoSerializer(filled_data).data.get('data_json')
        except FilledFormData.DoesNotExist:
            return None

    def get_form_info(self, next_step, org_id):
        try:
            schema = FormDataInfo.objects.get(Form_uid=next_step, organization=org_id)
            permissions = list(
                FormPermission.objects.filter(form=schema).values('user_group__id', 'read', 'write', 'edit'))
            return {
                # 'permissions': permissions,
                # 'next_step_schema': schema.form_json_schema,
                'form_filter_schema': schema.form_filter_schema
            }
        except FormDataInfo.DoesNotExist:
            return {'form_filter_schema': []}

    def get_subprocess_info(self, next_step, org_id):
        try:
            subprocess = CreateProcess.objects.get(subprocess_UID=next_step, organization=org_id)
            permissions = subprocess.process_table_permission or []
            return {
                # 'permissions': permissions,
                'form_filter_schema': permissions
            }
        except CreateProcess.DoesNotExist:
            return {}

    def get_notification_info(self, next_step):
        schema = NotificationBotSchema.objects.filter(notification_uid=next_step).first()
        if schema:
            permissions = schema.notification_element_permission or []
            return {
                # 'permissions': permissions,
                'form_filter_schema': permissions
            }
        return {}

    def get_bot_info(self, next_step, org_id, process_id):
        try:
            bot_instance = Bot.objects.get(bot_uid=next_step)
            bot_schema = BotSchema.objects.get(bot=bot_instance, organization=org_id, flow_id=process_id)
            permissions = bot_schema.bot_element_permission or []
            return {
                # 'permissions': permissions,
                'form_filter_schema': permissions
            }
        except (Bot.DoesNotExist, BotSchema.DoesNotExist):
            return {}

    def get_end_element_info(self, next_step):
        schema = EndElement.objects.filter(element_uid=next_step).first()
        if schema:
            permissions = schema.end_element_schema.get('end_element_permission', [])
            return {
                # 'permissions': permissions,
                'form_filter_schema': permissions
            }
        return {}

    def general_filter_cases(self, case, user_id, user_group_id):
        if not user_id or not user_group_id:
            return True

        if case.get('case_initiated_by') == user_id:
            return True

        permissions = case.get('form_filter_schema')
        if not permissions or type(permissions) == list and len(permissions) == 0:
            return True

        case_permission = next(
            (
                cp for cp in permissions
                if (
                           isinstance(cp.get("user_group"), str) and cp["user_group"].isdigit()
                           and int(cp["user_group"]) == user_group_id
                   ) or cp.get("user_group") == user_group_id
            ),
            None
        )

        if not case_permission:
            return False

        if case_permission.get('read', False) or case_permission.get('write', False) or case_permission.get('edit',
                                                                                                            False):
            return True

        return False

    def advance_case_filter(self, case_item, user_id, user_group_id, user_data):
        if not user_id or not user_group_id:
            return True

        if case_item.get('case_initiated_by') == user_id:
            return True

        schema = case_item.get("form_filter_schema")
        if not schema:
            return True

        user_conditions = [
            item for item in schema
            if item.get("user_group", None) == user_group_id
        ]

        if not user_conditions:
            return True

        results = []
        for condition in user_conditions:
            raw_conditions = condition.get("filter_conditions")

            if self.is_old_condition_format(raw_conditions):
                condition_tree = self.convert_old_conditions_to_group(raw_conditions)
            else:
                condition_tree = raw_conditions

            result = self.evaluate_filter_tree(condition_tree, user_data, case_item)
            results.append(result)

        if any(results):
            return True

        return False

    def is_old_condition_format(self, conditions):
        return (
                isinstance(conditions, list) and
                all(
                    isinstance(c, dict) and
                    'global_field' in c and 'operator' in c and 'table_header' in c
                    for c in conditions
                )
        )

    def convert_old_conditions_to_group(self, conditions):
        return {
            'type': 'group',
            'logic': 'AND',
            'children': [{'type': 'condition', 'condition': c} for c in conditions],
        }

    def evaluate_condition(self, condition, user_data, case_item):

        globe_value = user_data.get(condition.get("global_field", ""), "")

        data_json = case_item.get('data_json') or []

        if isinstance(data_json, str):
            try:
                data_json = json.loads(data_json)
            except Exception as e:

                data_json = []

        table_value = next(
            (
                item.get("value", "")
                for item in data_json
                if isinstance(item, dict) and item.get("field_id") == condition.get("table_header")
            ),
            ""
        )

        # table_value = next(
        #     (item.get("value", "") for item in data_json if item.get("field_id") == condition.get("table_header")),
        #     ""
        # )

        print(table_value, globe_value)

        if condition.get("operator") == "=":
            return globe_value == table_value

        return True

    def evaluate_filter_tree(self, node, user_data, case_item):

        if node.get("type") == "condition":
            return self.evaluate_condition(node["condition"], user_data, case_item)

        logic = node.get("logic", "AND")
        children = node.get("children", [])
        results = [self.evaluate_filter_tree(child, user_data, case_item) for child in children]

        return all(results) if logic == "AND" else any(results)

# 24-09-2025 by Harish (Dashboard case) [Product Level]
# 08-10-2025 by Harish (Enhancement)[Project TI]
class DashboardDetailView(APIView):
    """
    API endpoint for fetching dashboard data for an organization.
    Includes case summary, process statistics, form statistics, and recent activity.
    """

    def get(self, request, organization_id):
        # --- Extract query params ---
        user_id = request.query_params.get("uid")
        user_group_id = request.query_params.get("ug_id")
        include_completed_param = request.query_params.get("include_completed", "true").lower()
        include_completed = include_completed_param in ("true", "1", "yes")

        # Normalize invalid user_id/user_group_id
        user_id = None if user_id in (None, "", "null", "NULL") else int(user_id)
        user_group_id = None if user_group_id in (None, "", "null", "NULL") else user_group_id
        print("user_group_id ********* : ",user_group_id)
        user_data = {}

        # --- Extract pagination params safely ---
        try:
            page = int(request.query_params.get("page", 1))
            page_size = int(request.query_params.get("page_size", 10))
        except ValueError:
            page, page_size = 1, 10

        if page <= 0:
            page = 1
        if page_size <= 0:
            page_size = 10
        
        search_query = request.query_params.get("search", "").strip().lower()
        
        start_time = time.time()

        try:
            # --- Validate user and organization ---
            if user_id:
                user = UserData.objects.get(id=user_id)
                user_profile_schema = user.user_profile_schema
                user_data = {}
                if user_profile_schema:
                    user_data = {
                        item["field_id"]: item["value"]
                        for item in user_profile_schema
                        if isinstance(item, dict) and "field_id" in item and "value" in item
                    }

            organization = Organization.objects.get(id=organization_id)

        except (UserData.DoesNotExist, Organization.DoesNotExist):
            return Response(
                {"error": "User or Organization not found"},
                status=status.HTTP_404_NOT_FOUND,
            )
        print("Fetching UserData ----> :", time.time() - start_time)

        try:
            # --- Fetch and serialize cases with prefetch/select ---
            start_time = time.time()
            # cases = Case.objects.filter(organization=organization).select_related('processId').prefetch_related('assigned_users')
            # print("Fetching cases ----> :", time.time() - start_time)
            start_time = time.time()
            cases_qs = Case.objects.filter(organization=organization).select_related('processId').prefetch_related('assigned_users')

            # 16-10-2025 By Harish (Hide completed case)[Project Lifecell]
            if not include_completed:
                cases_qs = cases_qs.exclude(status='Completed')
            
            cases_data = list(
                cases_qs.annotate(
                    process_name=F('processId__process_name')
                ).values(
                    "id",
                    "assigned_users",
                    "created_by",
                    "created_on",
                    "organization",
                    "parent_case_data",
                    "status",
                    "stages",
                    "updated_by",
                    "updated_on",
                    "next_step",
                    "user_case_history",
                    "processId",
                    "parent_case",
                )
            )
            print("Fetching cases new ----> :", time.time() - start_time)

            # start_time = time.time()
            # serialized_cases = ProcessCaseListSerializer(cases, many=True).data
            # print("Fetching serialized_cases ----> :", time.time() - start_time)

            # Precompute process dict (one query for all unique processes)
            # --- Precompute process_dict ---
            start_time = time.time()
            unique_process_ids = set(case['processId'] for case in cases_data if case['processId'])
            process_dict = {process.id: process for process in CreateProcess.objects.filter(id__in=unique_process_ids)}
            print("Precomputing process_dict ----> :", time.time() - start_time)

            # Collect all next steps for mapping
            start_time = time.time()
            next_steps = {case.get('next_step') for case in cases_data if case.get('next_step')}
            print("Fetching next_steps ----> :", time.time() - start_time)

            # Preload reusable maps
            start_time = time.time()
            process_api = ProcessCaseListApi()
            form_data_info_map = process_api.get_form_data_info_map(next_steps, organization_id)
            form_permission = process_api.get_form_permission(form_data_info_map)
            create_process_map = process_api.get_create_process_map(next_steps, organization_id)
            notification_schema_map = process_api.get_notification_schema_map(next_steps)
            end_element_map = process_api.get_end_element_map(next_steps, organization_id)
            bot_map = process_api.get_bot_map(next_steps)
            bot_schema_map = process_api.get_bot_schema_map(bot_map, organization_id)

            start_time = time.time()
            # Add case permissions and enrich cases
            for case in cases_data:
                process_api.add_case_permissions(
                    case,
                    organization_id,
                    "",
                    form_data_info_map,
                    create_process_map,
                    notification_schema_map,
                    end_element_map,
                    bot_schema_map,
                    form_permission=form_permission
                )

            # --- Apply filters ---
            start_time = time.time()
            general_filtered_cases = [case for case in cases_data if process_api.general_filter_cases(case, user_id, user_group_id)]


            start_time = time.time()
            advanced_filtered_cases = [
                case for case in general_filtered_cases
                if process_api.advance_case_filter(case, user_id, user_group_id, user_data)
            ]

            # Initialize process_counts
            process_counts = defaultdict(lambda: {"process_id": None, "process_name": "", "stages": defaultdict(int)})

            # --- Process cases and compute process_counts inline ---
            start_time = time.time()
            for case in advanced_filtered_cases:
                case_stage = case.get("stages")
                process_info = case.get("processId", {})
                # Safely extract process_id and process_name
                if isinstance(process_info, dict):
                    process_id = process_info.get("id")
                    process_name = process_info.get("process_name", "")
                else:
                    process_id = process_info
                    process_name = process_dict.get(process_id).process_name if process_dict.get(process_id) else ""

                process_data = process_dict.get(process_id)
                if process_data and case_stage:
                    stage_color = self._determine_stage_color(case_stage, process_data, organization_id)
                else:
                    stage_color = None

                # Filter permissions
                case_permissions = case.get("permissions", [])
                case["permissions"] = [
                    perm for perm in case_permissions
                    if str(perm.get("user_group")) == str(user_group_id)
                ] if user_group_id else case_permissions

                # Attach to case
                case["stage_color"] = stage_color
                case["process_name"] = process_name

                # Clean unnecessary fields
                for field in ["data_json", "user_case_history", "next_step_schema", "end_element_schema", "form_filter_schema"]:
                    case.pop(field, None)

                # Compute process_counts inline
                if process_id:
                    process_entry = process_counts[process_id]
                    process_entry.update({"process_id": process_id, "process_name": process_name})
                    process_entry["stages"][case_stage] += 1


            # --- Case summary counts ---
            start_time = time.time()
            case_summary = self._calculate_case_summary(advanced_filtered_cases)

            # --- Form statistics ---
            start_time = time.time()
            form_counts = self._calculate_form_counts(organization, user_group_id, is_core_table=False)
            print("Calc form_counts ----> :", time.time() - start_time)

            # --- Core Data statistics ---
            core_data_counts = self._calculate_form_counts(organization, user_group_id, is_core_table=True)

            # --- Recent activity (last 10 updated cases) ---
            start_time = time.time()
            recent_activity = self._get_recent_activity(advanced_filtered_cases)

            # --- Global search ---
            start_time = time.time()
            if search_query:
                advanced_filtered_cases = self._apply_global_search(advanced_filtered_cases, search_query)

            # --- Column Search (best practice) ---
            start_time = time.time()
            advanced_filtered_cases = self._apply_column_search(advanced_filtered_cases, request.query_params)

            # --- Pagination ---
            start_time = time.time()
            paginated_case = paginate_data(advanced_filtered_cases, page, page_size)

            # --- Final Response ---
            response_data = {
                "case_summary": case_summary,
                "process_counts": dict(process_counts),  # Convert to list for JSON
                "form_counts": form_counts,
                "core_data_counts": core_data_counts,
                "recent_activity": recent_activity,
                "cases": paginated_case["results"],
                "pagination": paginated_case["pagination"],
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Error retrieving dashboard data")
            return Response(
                {"error": "An unexpected error occurred while retrieving dashboard data"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        
    def _calculate_case_summary(self, cases):
        """Calculate summary statistics for cases."""
        total = len(cases)
        completed = sum(1 for case in cases if case.get("status") == "Completed")
        return {"total": total, "completed": completed, "in_progress": total - completed}
    
    def _get_recent_activity(self, cases):
        """Retrieve the 10 most recently updated cases."""
        sorted_cases = sorted(cases, key=lambda case: case.get("updated_on") or "", reverse=True)[:10]
        return [
            {
                "case_id": case.get("id"),
                "process_name": case.get("process_name", ""),
                "stages": case.get("stages", ""),
                "updated_on": case.get("updated_on", ""),
                "created_by": case.get("created_by", ""),
                "stage_color": case.get("stage_color"),
            }
            for case in sorted_cases
        ]
    
    def _calculate_form_counts(self, organization, user_group_id, is_core_table=True):
        """Calculate statistics for filled forms."""

        # Base filter for forms
        form_filters = {
            "organization": organization,
            "core_table": is_core_table,
        }

        if user_group_id:
            filter_forms = FormDataInfo.objects.filter(**form_filters, formpermission__user_group_id=user_group_id)
        else:
            filter_forms = FormDataInfo.objects.filter(**form_filters)
        
        filled_forms_qs = FilledFormData.objects.filter(organization=organization)

        # Pre-aggregate counts in ONE query
        filled_counts = dict(
            filled_forms_qs.values('formId').annotate(count=Count('id')).values_list('formId', 'count')
        )

        return [
            {
                "form_id": form.id,
                "form_name": form.form_name,
                "count": filled_counts.get(str(form.id), 0),
            }
            for form in filter_forms
        ]
    def _calculate_core_data_counts(self, organization, user_group_id):
        """Calculate statistics for filled forms."""

        # Base filter for forms
        form_filters = {
            "organization": organization,
            "core_table": True,
        }

        if user_group_id:
            filter_forms = FormDataInfo.objects.filter(**form_filters, formpermission__user_group_id=user_group_id)
            # filled_forms_qs = FilledFormData.objects.filter(organization=organization, user_groups=user_group_id)
        else:
            filter_forms = FormDataInfo.objects.filter(**form_filters)
            # filled_forms_qs = FilledFormData.objects.filter(organization=organization)
        filled_forms_qs = FilledFormData.objects.filter(organization=organization)
        # Pre-aggregate counts in ONE query
        filled_counts = dict(
            filled_forms_qs.values('formId').annotate(count=Count('id')).values_list('formId', 'count')
        )

        return [
            {
                "form_id": form.id,
                "form_name": form.form_name,

                "count": filled_counts.get(str(form.id),0),
            }
            for form in filter_forms
        ]
    def _determine_stage_color(self, case_stage, process_data, organization_id):
        """Determine the color for a given case stage."""
        if process_data and process_data.process_stages:
            for stage_info in process_data.process_stages.values():
                if stage_info.get("StageName") == case_stage:
                    return stage_info.get("StageColor")
        end_element = EndElement.objects.filter(organization=organization_id, element_name=case_stage).first()
        return end_element.end_element_schema.get("color") if end_element and end_element.end_element_schema else None

    def _apply_global_search(self, case_list, query):
        """Global search across Case ID, Process Name, Created By, Last Updated, and Status."""
        query = query.lower()
        return [
            case for case in case_list
            if (
                str(case.get("id", "")).lower().find(query) != -1
                or str(case.get("process_name", "")).lower().find(query) != -1
                or str(case.get("created_by", "")).lower().find(query) != -1
                or str(case.get("updated_on", "")).lower().find(query) != -1
                or str(case.get("stages", "")).lower().find(query) != -1
            )
        ]
    
    def _apply_column_search(self, cases, params):
        """
        Apply column-specific filters to cases.
        Best practice: use a mapping and iterate dynamically.
        """
        # Map query params -> case keys
        column_mapping = {
            "id": "id",
            "process_name": "process_name",
            "created_by": "created_by",
            "updated_on": "updated_on",
            "stages": "stages",
        }

        for param, case_field in column_mapping.items():
            value = params.get(param)
            if value:
                value = str(value).strip().lower()
                cases = [
                    case for case in cases
                    if value in str(case.get(case_field, "")).lower()
                ]

        return cases

