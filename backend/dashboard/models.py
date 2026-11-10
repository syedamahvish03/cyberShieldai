
from django.conf import settings
from django.db import models


class ThreatHistory(models.Model):

    RESULT_CHOICES = (
        ('SAFE', 'SAFE'),
        ('PHISHING', 'PHISHING'),
    )

    # Existing legacy records may have no assigned user.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='threat_history',
    )

    source_type = models.CharField(
        max_length=50,
        default='Manual Scan'
    )

    content = models.TextField()

    result = models.CharField(
        max_length=20,
        choices=RESULT_CHOICES
    )

    phishing_probability = models.FloatField()

    tactics = models.JSONField(
        default=list,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    message_id = models.TextField(
        blank=True,
        null=True
    )

    safe_score = models.FloatField(default=0)

    def __str__(self):
        return f"{self.result} - {self.source_type}"


class ExtensionAPIToken(models.Model):
    """
    Stores one hashed API token per user.
    The original token is never stored in the database.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='extension_api_token',
    )

    token_hash = models.CharField(
        max_length=64,
        unique=True,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    def __str__(self):
        return f"Extension API token for user {self.user_id}"
