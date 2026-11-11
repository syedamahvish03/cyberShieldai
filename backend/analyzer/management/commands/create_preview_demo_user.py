import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


class Command(BaseCommand):
    help = "Create an isolated preview-only dashboard login when explicitly enabled."

    def handle(self, *args, **options):
        enabled = os.getenv("PREVIEW_DEMO_USER_ENABLED", "").strip().lower()
        if enabled != "true":
            raise CommandError(
                "Preview demo user creation is disabled. "
                "Set PREVIEW_DEMO_USER_ENABLED=true only on the temporary preview service."
            )

        email = os.getenv("PREVIEW_DEMO_USER_EMAIL", "").strip()
        password = os.getenv("PREVIEW_DEMO_USER_PASSWORD", "")

        if not email or not password:
            raise CommandError(
                "Set PREVIEW_DEMO_USER_EMAIL and PREVIEW_DEMO_USER_PASSWORD."
            )

        try:
            validate_email(email)
        except ValidationError as exc:
            raise CommandError("PREVIEW_DEMO_USER_EMAIL must be a valid email address.") from exc

        if len(password) < 16:
            raise CommandError(
                "PREVIEW_DEMO_USER_PASSWORD must be at least 16 characters long."
            )

        User = get_user_model()
        existing = User.objects.filter(email__iexact=email).first()
        if existing:
            if not existing.is_active:
                raise CommandError(
                    "An inactive account already uses this preview email. "
                    "Choose a different PREVIEW_DEMO_USER_EMAIL."
                )
            self.stdout.write(
                self.style.SUCCESS("The preview demo account already exists; no changes made.")
            )
            return

        base = email.split("@", 1)[0][:140] or "preview"
        username = base
        suffix = 1
        while User.objects.filter(username__iexact=username).exists():
            tail = f"_{suffix}"
            username = f"{base[:150 - len(tail)]}{tail}"
            suffix += 1

        User.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_active=True,
        )
        self.stdout.write(
            self.style.SUCCESS("Preview demo account created successfully.")
        )
