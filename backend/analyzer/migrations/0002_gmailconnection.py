from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("analyzer", "0001_user_email_case_insensitive_unique"),
    ]

    operations = [
        migrations.CreateModel(
            name="GmailConnection",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("gmail_email", models.EmailField(max_length=254)),
                ("encrypted_refresh_token", models.TextField()),
                ("history_id", models.CharField(max_length=64)),
                ("connected_at", models.DateTimeField(auto_now_add=True)),
                ("last_checked_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(default=True)),
                ("last_error", models.CharField(blank=True, default="", max_length=500)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="gmail_connection", to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
