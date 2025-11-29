# myapp/management/commands/create_permissions.py

from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from custom_components.models import UserGroup  # Replace 'myapp' and 'UserGroup' with your app name and model name

class Command(BaseCommand):
    help = 'Create custom permissions for UserGroup'

    def handle(self, *args, **kwargs):
        content_type = ContentType.objects.get_for_model(UserGroup)  # Use your actual model here

        permissions = [
            ('read', 'Can read user group'),
            ('write', 'Can write user group'),
            ('delete', 'Can delete user group')
        ]

        for codename, name in permissions:
            Permission.objects.get_or_create(codename=codename, name=name, content_type=content_type)
            self.stdout.write(self.style.SUCCESS(f'Successfully created permission: {codename}'))
