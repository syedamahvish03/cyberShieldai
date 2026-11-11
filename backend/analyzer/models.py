from django.conf import settings
from django.db import models


class GmailConnection(models.Model):
    """
    One Gmail OAuth connection per CyberShield account.
    Refresh tokens are encrypted before they are stored.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="gmail_connection",
    )
    gmail_email = models.EmailField(max_length=254)
    encrypted_refresh_token = models.TextField()
    history_id = models.CharField(max_length=64)
    connected_at = models.DateTimeField(auto_now_add=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_error = models.CharField(max_length=500, blank=True, default="")

    def __str__(self):
        return f"Gmail connection for user {self.user_id}"
