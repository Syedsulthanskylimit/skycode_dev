
from collections import defaultdict
import json
import logging
from rest_framework.response import Response
from rest_framework.views import APIView

from custom_components.models import (
    Bot, BotSchema,
Organization,
    NotificationBotSchema,
)

from form_generator.models import Case
from form_generator.serializer import ProcessCaseListSerializer


from form_generator.models import FilledFormData, FormDataInfo, FormPermission, EndElement, CreateProcess ,UserData,EndElement
from form_generator.serializer import FilledDataInfoSerializer,CaseSerializer
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from django.utils.dateparse import parse_datetime,parse_date
from datetime import datetime
import time
from django.db.models import Field, CharField, TextField, DateField, DateTimeField, IntegerField, FloatField

from form_generator.utils.pagination import paginate_data
from form_generator.utils.log_time import log_time
logger = logging.getLogger(__name__)

# 20-09-2025 by Harish (Case filter)[Project TI]
# 08-10-2025 by Harish (Enhancement)[Project TI]
class ProcessCaseListApi(APIView):
    """
    Fetch process case list without serializer (optimized for performance)
    """

    def get(self, request, organization_id, process_id):
        total_start_time = time.time() 
        # --- Extract pagination params safely ---
        try:
            page = int(request.query_params.get("page", 1))
            page_size = int(request.query_params.get("page_size", 10))
        except ValueError:
            page, page_size = 1, 10
        page = max(page, 1)
        page_size = max(page_size, 10)

        # --- Extract query params ---
        start_time = time.time()
        user_id_query = request.query_params.get('uid')
        user_group_id = request.query_params.get('ug_id')
        user_id_query = None if user_id_query in (None, "", "null", "NULL") else int(user_id_query)
        user_group_id = None if user_group_id in (None, "", "null", "NULL") else user_group_id
        search_terms = [search.strip().lower() for search in request.query_params.getlist('search') if search.strip()]
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")
        include_completed_param = request.query_params.get("include_completed", "true").lower()
        include_completed = include_completed_param in ("true", "1", "yes")
        log_time("Getting request",start_time)

        # --- Base queryset: select only fields we need (reduce ORM overhead) ---
        start_time = time.time()
        cases_qs = (
            Case.objects
            .filter(organization_id=organization_id, processId=process_id)
            .order_by('-updated_on')
            .only(
                "id", "created_by", "created_on", "organization", "parent_case_data",
                "status", "stages", "updated_by", "updated_on", "next_step",
                "user_case_history", "processId", "parent_case"
            )
        )

        # 16-10-2025 By Harish (Hide completed case)[Project Lifecell]
        if not include_completed:
            cases_qs = cases_qs.exclude(status='Completed')

        # Convert queryset to list of dicts (no serializer)
        case_data = list(cases_qs.values(
            "id",
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
        ))
        log_time("Case filtering",start_time)

        # --- Fetch user_data if user_id provided ---
        user_data = {}
        if user_id_query:
            try:
                user = UserData.objects.get(id=user_id_query)
                if user.user_profile_schema:  # ensure it's not None or empty
                    user_data = {
                        d["field_id"]: d["value"]
                        for d in user.user_profile_schema
                        if isinstance(d, dict) and "field_id" in d and "value" in d
                    }
                else:
                    print(f"⚠️ user_profile_schema is None or empty for user_id {user_id_query}")
                    user_data = {}
            except UserData.DoesNotExist:
                return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # --- Prefetch related metadata maps ---
        start_time = time.time()
        next_steps = {case['next_step'] for case in case_data if case['next_step']}
        form_data_info_map = self.get_form_data_info_map(next_steps, organization_id, process_id)
        form_permission = self.get_form_permission(form_data_info_map)
        create_process_map = self.get_create_process_map(next_steps, organization_id)
        notification_schema_map = self.get_notification_schema_map(next_steps)
        end_element_map = self.get_end_element_map(next_steps, organization_id, process_id)
        bot_map = self.get_bot_map(next_steps)
        bot_schema_map = self.get_bot_schema_map(bot_map, organization_id, process_id)
        log_time("Process mapping",start_time)

        # --- Apply date filters ---
        start_time = time.time()
        if start_date and end_date:
            try:
                start_dt = datetime.fromisoformat(start_date)
                end_dt = datetime.fromisoformat(end_date)
                case_data = [
                    case for case in case_data
                    if start_dt.date() <= case['updated_on'].date() <= end_dt.date()
                ]
            except ValueError:
                pass
        log_time("Start & End date filter",start_time)

        # --- Apply dynamic query filters ---
        start_time = time.time()
        model_fields = {field.name for field in Case._meta.get_fields() if isinstance(field, Field) and not field.is_relation}
        for param, value in request.query_params.items():
            if not value or param in ("start_date", "end_date"):
                continue

            if param in model_fields:
                value_lower = value.lower()
                case_data = [
                    case for case in case_data
                    if value_lower in str(case.get(param, '')).lower()
                ]
            elif param == "parent_value":
                value_lower = value.lower()
                case_data = [
                    case for case in case_data
                    if any(value_lower in str(item.get('value', '')).lower()
                           for item in (case.get('parent_case_data') or []))
                ]
        
        log_time("Dynamic query filters", start_time)

        # --- Attach next step mappings ---
        start_time = time.time()
        for case in case_data:
            self.add_case_permissions(
                case, organization_id, process_id,
                form_data_info_map, create_process_map,
                notification_schema_map, end_element_map, bot_schema_map, form_permission=form_permission
            )
        log_time("add_case_permissions",start_time)

        # --- Apply user-based filtering ---
        start_time = time.time()
        case_filtered = [
            case for case in case_data
            if self.general_filter_cases(case, user_id_query, user_group_id)
        ]
        log_time("general_filter_cases", start_time)

        start_time = time.time()
        case_advance_filter = [
            case for case in case_filtered
            if self.advance_case_filter(case, user_id_query, user_group_id, user_data)
        ]
        log_time("advance_case_filter", start_time)

        # --- Apply dynamic field_id partial search ---
        start_time = time.time()
        reserved_params = {"page", "page_size", "search", "start_date", "end_date", "uid", "ug_id", "include_completed"}
        for key, value in request.query_params.items():
            if key not in reserved_params and value:
                value_lower = value.lower()
                if key in {"created_by", "stages", "id"}:
                    case_advance_filter = [
                        case for case in case_advance_filter
                        if value_lower in str(case.get(key, '')).lower()
                    ]
                elif key == 'updated_on':
                    case_advance_filter = [
                        case for case in case_advance_filter
                        if case.get('updated_on') and value_lower in case['updated_on'].strftime("%Y-%m-%d")
                    ]
                else:
                    case_advance_filter = [
                        case for case in case_advance_filter
                        if any(
                            value_lower in str(item.get('value', '')).lower() and item.get('field_id') == key
                            for item in (case.get('parent_case_data') or [])
                        )
                    ]
        log_time("Column filter", start_time)
        # --- Minimize final case data ---
        case_minimized = [self.minimize_case_data(case) for case in case_advance_filter]

        # --- Apply search filter ---
        start_time = time.time()
        if search_terms:
            print("search_terms : ",search_terms)
            def matches_search(case):
                searchable_fields = [
                    str(value).lower()
                    for key, value in case.items()
                    if isinstance(value, (str, int, float))
                ]
                parent_values = [
                    str(item.get('value', '')).lower()
                    for item in (case.get('parent_case_data') or [])
                ]
                searchable_fields.extend(parent_values)
                return all(
                    any(term in field for field in searchable_fields)
                    for term in search_terms
                )

            case_minimized = [case for case in case_minimized if matches_search(case)]
        log_time("search_terms",start_time)
        # --- Apply pagination ---
        start_time = time.time()
        paginated_case = paginate_data(case_minimized, page, page_size)
        log_time("paginated_case", start_time)

        # --- Build final response ---
        response_data = {
            "results": paginated_case["results"],
            "pagination": paginated_case["pagination"],
        }
        # Log total execution time
        total_elapsed = time.time() - total_start_time
        print(f"{'Total execution time':<30} ----> : {total_elapsed:.3f} sec")

        return Response(response_data, status=status.HTTP_200_OK)

    def add_case_permissions(self, item, organization_id, process_id,
                         formdata_info_map, createprocess_map, notification_map,
                         end_element_map, bot_schema_map, form_permission=None):

        user_case_history = item.get('user_case_history')
        case_initiated_by = None

        try:
            history = json.loads(user_case_history) if user_case_history else []
            first_entry = history[0] if isinstance(history, list) and history else {}
            user_id = first_entry.get('userId')
            case_initiated_by = int(user_id) if user_id is not None else None
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        item['case_initiated_by'] = case_initiated_by

        next_step = item.get('next_step')
        if not next_step:
            return item

        # Check each map, only first match wins
        if next_step in formdata_info_map:
            schema = formdata_info_map[next_step]
            # perms = FormPermission.objects.filter(form=schema.id).values('user_group', 'read', 'write', 'edit')
            # item['permissions'] = list(perms)
            perms = form_permission.get(schema.id, [])
            item['permissions'] = perms
            item['next_step_schema'] = schema.form_json_schema
            item['form_filter_schema'] = schema.form_filter_schema
            return item

        if next_step in createprocess_map:
            subprocess = createprocess_map[next_step]
            perms = subprocess.process_table_permission or []
            item['permissions'] = perms
            item['form_filter_schema'] = perms
            return item

        if next_step in notification_map:
            schema = notification_map[next_step]
            perms = schema.notification_element_permission or []
            item['permissions'] = perms
            item['form_filter_schema'] = perms
            return item

        if next_step in end_element_map:
            element = end_element_map[next_step]
            schema = element.end_element_schema or {}
            perms = schema.get('end_element_permission', [])
            item['permissions'] = perms
            item['form_filter_schema'] = perms
            item['end_element_schema'] = schema
            return item

        if next_step in bot_schema_map:
            schema = bot_schema_map[next_step]
            perms = schema.bot_element_permission or []
            item['permissions'] = perms
            item['form_filter_schema'] = perms
            return item

        return item  # default fallback
    
    def general_filter_cases(self, case, user_id, user_group_id):
        if not user_id or not user_group_id:
            return True

        if case.get('case_initiated_by') == int(user_id) if user_id is not None else None:
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

        data_json = case_item.get('parent_case_data') or []

        if isinstance(data_json, str):
            try:
                data_json = json.loads(data_json)
            except Exception as e:

                data_json = []

        table_value = next(
            (item.get("value", "") for item in data_json if item.get("field_id") == condition.get("table_header")),
            ""
        )

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

    def minimize_case_data(self, case_data):
        keys_to_remove = {'user_case_history', 'next_step_schema', 'next_step'}
        return {k: v for k, v in case_data.items() if k not in keys_to_remove}
    
    # 20-09-2025 by Harish (Case filter)[Project TI]
    def get_form_data_info_map(self, next_steps, organization_id, process_id=None):
        filters = {
            "Form_uid__in": next_steps,
            "organization": organization_id,
        }
        if process_id:
            filters["processId"] = process_id

        return {
            form.Form_uid: form
            for form in FormDataInfo.objects.filter(**filters)
        }
    
    # 08-10-2025 by Harish (Enhancement)[Project TI]
    def get_form_permission(self, form_data_info_map):
        """
        Preload all FormPermission objects and return a mapping:
        {form_id: [permission_dict, ...], ...}
        """
        if not form_data_info_map:
            return {}

        form_ids = [form.id for form in form_data_info_map.values()]
        permissions = FormPermission.objects.filter(form_id__in=form_ids).values(
            'form_id', 'user_group', 'read', 'write', 'edit'
        )

        form_perm_map = defaultdict(list)
        for perm in permissions:
            form_perm_map[perm['form_id']].append(perm)

        return form_perm_map

    def get_create_process_map(self, next_steps, organization_id):
        return {
            process.subprocess_UID: process
            for process in CreateProcess.objects.filter(
                subprocess_UID__in=next_steps,
                organization=organization_id
            )
        }

    def get_notification_schema_map(self, next_steps):
        return {
            notif.notification_uid: notif
            for notif in NotificationBotSchema.objects.filter(
                notification_uid__in=next_steps
            )
        }

    def get_end_element_map(self, next_steps, organization_id, process_id=None):
        filters = {
            "element_uid__in": next_steps,
            "organization": organization_id,
        }
        if process_id:
            filters["process"] = process_id

        return {
            element.element_uid: element
            for element in EndElement.objects.filter(**filters)
        }

    def get_bot_map(self, next_steps):
        return {
            bot.bot_uid: bot
            for bot in Bot.objects.filter(bot_uid__in=next_steps)
        }

    def get_bot_schema_map(self, bot_map, organization_id, process_id=None):
        filters = {
            "bot__in": bot_map.values(),
            "organization": organization_id,
        }
        if process_id:
            filters["flow_id"] = process_id

        return {
            schema.bot.bot_uid: schema
            for schema in BotSchema.objects.filter(**filters)
        }
