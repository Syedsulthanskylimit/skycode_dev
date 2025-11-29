from django.core.management.base import BaseCommand
from custom_components.utils.generate_uid import generate_uid
from custom_components.models import *
from form_generator.models import *
from django.db.models import Q


class Command(BaseCommand):
    help = "Generate UIDs for existing records where uid/ruleId/form_uid is empty"

    TABLES = [
        {"model": CreateProcess, "prefix": "PRC"},
        {"model": UserFormSchema, "prefix": "UFS"},
        {"model": UserData, "prefix": "USR"},
        {"model": FilledFormData, "prefix": "FFD"},
        {"model": NotificationConfig, "prefix": "NTC"},
        {"model": Notification, "prefix": "NT"},
        {"model": Sequence, "prefix": "SQ"},
        {"model": UserGroup, "prefix": "UG"},
        {"model": Dashboard, "prefix": "DB"},
        {"model": ReportConfig, "prefix": "RC"},
        {"model": Agent, "prefix": "AG"},
        {"model": Rule, "prefix": "RL"},
        {"model": FormDataInfo, "prefix": "FD"},
        {"model": Dms, "prefix": "DMS"},
        {"model": Bot, "prefix": "BOT"},
    ]

    def handle(self, *args, **kwargs):
        self.stdout.write("Starting UID generation for existing records...")
        
        for table in self.TABLES:
            model = table["model"]
            prefix = table["prefix"]

            # Determine which field to use
            if model.__name__ == "Rule":
                field_name = "ruleId"
            elif model.__name__ == "FormDataInfo":
                field_name = "Form_uid"
            elif model.__name__ == "Dms":
                field_name = "dms_uid"
            elif model.__name__ == "Bot":
                field_name = "bot_uid"
            else:
                field_name = "uid"

            self.stdout.write(f"\nProcessing {model.__name__} (field: {field_name})...")

            # Filter by the correct field dynamically
            queryset = model.objects.filter(
                Q(**{f"{field_name}__isnull": True}) |
                Q(**{field_name: ""})
            )
            count = queryset.count()

            if count == 0:
                self.stdout.write(f"  All records already have {field_name}. Skipping.")
                continue

            self.stdout.write(f"  {count} records without {field_name} found. Generating...")

            for instance in queryset:
                try:
                    organization_id = getattr(instance, "organization_id", None)
                    uid = generate_uid(model=model, prefix=prefix, organization_id=organization_id, field_name=field_name)

                    setattr(instance, field_name, uid)
                    instance.save(update_fields=[field_name])

                    self.stdout.write(f"    Assigned {field_name} {uid} to {instance}")
                except Exception as e:
                    self.stdout.write(f"    Failed for {instance}: {str(e)}")

        self.stdout.write("\nUID generation completed successfully.")
