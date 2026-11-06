from django.db import models


class ThreatHistory(models.Model):

    RESULT_CHOICES = (
        ('SAFE', 'SAFE'),
        ('PHISHING', 'PHISHING'),
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