"""
Script: fix_invalid_cases.py
Description: Fix rows in multiple models where case_id (or caseId) points to missing Case entries.
"""

import os
import sys
import django

# --- Add project root to Python path ---
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(PROJECT_ROOT)

# --- Setup Django environment ---
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "formbuilder_backend.settings")  # <- your settings module
django.setup()

# --- Import models ---
from custom_components.models import Dms_data, IntegrationDetails, NotificationData
from form_generator.models import CreateProcess, NotificationDismiss, FilledFormData, UserData
from automation.models import SlaCaseInstance
from form_generator.models import Case
from django.db import connection
from form_generator.models import FilledFormData, Case





def fix_invalid_rows(model_class, model_name, case_field="case_id"):
    """
    Generic bulk update function to set invalid case_field to NULL.
    Works for all models except FilledFormData.
    """
    valid_ids = set(Case.objects.values_list("id", flat=True))
    invalid_rows = model_class.objects.exclude(**{f"{case_field}__in": valid_ids}).exclude(**{case_field: None})
    count = invalid_rows.count()

    if count > 0:
        pk_name = model_class._meta.pk.name
        model_class.objects.filter(**{f"{pk_name}__in": invalid_rows.values_list(pk_name, flat=True)}).update(**{case_field: None})

    print(f"[{model_name}] Fixed {count} rows (set {case_field} to NULL instead of deleting).")

def fix_filledformdata():
    """
    Fix FilledFormData:
    1. Clean invalid userId_id foreign keys.
    2. Clean invalid caseId_id foreign keys using raw SQL (bypasses FK issues).
    """
    # --- Step 1: Fix invalid userId_id ---
    valid_user_ids = set(UserData.objects.values_list("id", flat=True))
    invalid_user_rows = FilledFormData.objects.exclude(userId_id__in=valid_user_ids).exclude(userId_id=None)
    count_user = invalid_user_rows.count()
    if count_user > 0:
        invalid_user_rows.update(userId_id=None)
    print(f"[FilledFormData] Fixed {count_user} rows (set userId_id to NULL).")

    # --- Step 2: Fix invalid processId_id ---
    valid_process_ids = set(CreateProcess.objects.values_list("id", flat=True))
    invalid_process_rows = FilledFormData.objects.exclude(processId_id__in=valid_process_ids).exclude(processId_id=None)
    count_process = invalid_process_rows.count()
    if count_process > 0:
        invalid_process_rows.update(processId_id=None)
    print(f"[FilledFormData] Fixed {count_process} rows (set processId_id to NULL).")

    # --- Step 3: Fix invalid caseId_id ---
    with connection.cursor() as cursor:
        cursor.execute("""
            UPDATE "form_generator_filledformdata"
            SET "caseId_id" = NULL
            WHERE "caseId_id" IS NOT NULL
            AND "caseId_id" NOT IN (SELECT "id" FROM "form_generator_case");
        """)
        count_case = cursor.rowcount
    print(f"[FilledFormData] Fixed {count_case} rows (set caseId_id to NULL using raw SQL).")

    # with connection.cursor() as cursor:
    #     cursor.execute("""
    #         UPDATE form_generator_filledformdata
    #         SET caseId_id = NULL
    #         WHERE caseId_id IS NOT NULL
    #         AND caseId_id NOT IN (SELECT id FROM "form_generator_case");
    #     """)
    #     count_case = cursor.rowcount
    # print(f"[FilledFormData] Fixed {count_case} rows (set caseId_id to NULL using raw SQL).")

def fix_all_models():
    """
    Run fixes for all models.
    """
    models = [
        (Dms_data, "Dms_data", "case_id"),
        (IntegrationDetails, "IntegrationDetails", "case_id"),
        (NotificationData, "NotificationData", "case_id"),
        (NotificationDismiss, "NotificationDismiss", "case_id"),
        (SlaCaseInstance, "SlaCaseInstance", "case_id"),
    ]

    for model_class, model_name, case_field in models:
        fix_invalid_rows(model_class, model_name, case_field)

    # FilledFormData handled separately with raw SQL
    fix_filledformdata()


if __name__ == "__main__":
    fix_all_models()

