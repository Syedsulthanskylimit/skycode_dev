from datetime import datetime
from django.db import transaction

def generate_uid(model, prefix, organization_id=None, field_name="uid"):
    """
    Generate a unique UID for the given model and field, avoiding collisions.
    
    field_name: column to store UID ('uid', 'ruleId', 'form_uid', etc.)
    
    Example:
        ORG5-UG-2025-00001-250218153045123
        UG-2025-00001-250218153045123
    """
    with transaction.atomic():
        now = datetime.now()
        year = now.year

        # Timestamp: YYMMDDHHMMSSsss (milliseconds)
        timestamp = now.strftime("%y%m%d%H%M%S") + f"{int(now.microsecond/1000):03d}"

        # UID prefix including organization and year
        if organization_id:
            uid_prefix = f"ORG{organization_id}-{prefix}-{year}-"
        else:
            uid_prefix = f"{prefix}-{year}-"

        # Fetch existing UIDs starting with this prefix
        existing_uids = (
            model.objects.select_for_update()
            .filter(**{f"{field_name}__startswith": uid_prefix})
            .values_list(field_name, flat=True)
        )

        # Extract the numeric sequence before timestamp
        existing_numbers = []
        for uid in existing_uids:
            try:
                # UID format: PREFIX-YEAR-NUMBER-TIMESTAMP
                number = int(uid.split("-")[-2])
                existing_numbers.append(number)
            except (ValueError, IndexError):
                continue

        next_number = max(existing_numbers, default=0) + 1

        # Construct final UID
        if organization_id:
            final_uid = f"ORG{organization_id}-{prefix}-{year}-{next_number:05d}-{timestamp}"
        else:
            final_uid = f"{prefix}-{year}-{next_number:05d}-{timestamp}"

        return final_uid
