from django.core.management.base import BaseCommand
from django.db import transaction
from custom_components.utils.generate_uid import generate_uid
from custom_components.models import Agent, Dashboard, ReportConfig, UserGroup
from form_generator.models import CreateProcess, FilledFormData, UserData, UserFormSchema

class Command(BaseCommand):
    help = "Update UIDs for all existing records, ensuring uniqueness, with summary output"

    TABLES = [
        {"model": UserGroup, "prefix": "UG"},
        {"model": UserData, "prefix": "USR"},
        {"model": CreateProcess, "prefix": "PRC"},
        {"model": FilledFormData, "prefix": "FFD"},
        {"model": ReportConfig, "prefix": "RC"},
        {"model": Agent, "prefix": "AG"},
        {"model": Dashboard, "prefix": "DB"},
        {"model": UserFormSchema, "prefix": "UFS"},
    ]

    def handle(self, *args, **kwargs):
        self.stdout.write("Starting UID update for all records...\n")

        for table in self.TABLES:
            model = table["model"]
            prefix = table["prefix"]

            queryset = model.objects.all().order_by('id')
            total_count = queryset.count()
            updated_count = 0
            error_details = []

            with transaction.atomic():
                for instance in queryset:
                    try:
                        organization_id = getattr(instance, "organization_id", None)
                        uid = generate_uid(model=model, prefix=prefix, organization_id=organization_id)
                        instance.uid = uid
                        instance.save(update_fields=["uid"])
                        updated_count += 1
                    except Exception as e:
                        error_details.append(f"{instance} - {str(e)}")

            # Print summary for the model
            self.stdout.write(f"{model.__name__} - Updated: {updated_count}/{total_count}")
            if error_details:
                self.stdout.write(f"{model.__name__} - Errors:")
                for err in error_details:
                    self.stdout.write(f"    {err}")

        self.stdout.write("\nUID update process completed successfully.")
