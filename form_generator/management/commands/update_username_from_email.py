from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = "Update username to match email for all users (username = email)"

    def handle(self, *args, **kwargs):
        User = get_user_model()
        updated = 0
        skipped = 0

        for user in User.objects.all():
            if not user.email:
                self.stdout.write(f"⚠️ Skipped (No email): User ID {user.id}")
                skipped += 1
                continue

            if user.username == user.email:
                self.stdout.write(f"✅ Already correct: {user.email}")
                skipped += 1
                continue

            # Update username = email
            old_username = user.username
            user.username = user.email
            user.save()

            self.stdout.write(f"🔁 Updated User ID {user.id}: '{old_username}' → '{user.email}'")
            updated += 1

        self.stdout.write(self.style.SUCCESS(f"\nDone ✅"))
        self.stdout.write(self.style.SUCCESS(f"Updated users: {updated}"))
        self.stdout.write(self.style.WARNING(f"Skipped (already correct/no email): {skipped}"))
