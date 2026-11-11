import base64
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail.message import BadHeaderError


class GmailAPIEmailBackend(BaseEmailBackend):
    """
    Django email backend that sends through the Gmail API over HTTPS.

    It uses a dedicated sender account and a refresh token stored only in
    deployment environment variables. No SMTP connection is attempted.
    """

    TOKEN_URL = "https://oauth2.googleapis.com/token"
    SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
    TIMEOUT_SECONDS = 15
    TOKEN_REFRESH_MARGIN_SECONDS = 60

    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently)
        self.client_id = getattr(settings, "GOOGLE_OAUTH_CLIENT_ID", "")
        self.client_secret = getattr(settings, "GOOGLE_OAUTH_CLIENT_SECRET", "")
        self.refresh_token = getattr(settings, "GOOGLE_OAUTH_REFRESH_TOKEN", "")
        self.sender_email = getattr(settings, "GOOGLE_OAUTH_SENDER_EMAIL", "")
        self._access_token = None
        self._access_token_expires_at = 0

    def _configuration_error(self):
        missing = [
            name for name, value in (
                ("GOOGLE_OAUTH_CLIENT_ID", self.client_id),
                ("GOOGLE_OAUTH_CLIENT_SECRET", self.client_secret),
                ("GOOGLE_OAUTH_REFRESH_TOKEN", self.refresh_token),
                ("GOOGLE_OAUTH_SENDER_EMAIL", self.sender_email),
            )
            if not value
        ]
        if missing:
            raise RuntimeError(
                "Gmail API email delivery is not configured. Missing: "
                + ", ".join(missing)
            )

    @staticmethod
    def _read_json_response(response):
        payload = response.read()
        if not payload:
            return {}
        return json.loads(payload.decode("utf-8"))

    def _request_json(self, request):
        try:
            with urlopen(request, timeout=self.TIMEOUT_SECONDS) as response:
                return self._read_json_response(response)
        except HTTPError as exc:
            # Do not include request headers or credentials in error messages.
            try:
                details = self._read_json_response(exc)
                reason = details.get("error", "Google API request failed")
            except (ValueError, AttributeError):
                reason = "Google API request failed"
            raise RuntimeError(
                f"Gmail API request failed (HTTP {exc.code}): {reason}"
            ) from None
        except URLError as exc:
            raise RuntimeError(
                f"Could not reach Google email service: {exc.reason}"
            ) from None

    def _get_access_token(self):
        self._configuration_error()
        if (
            self._access_token
            and time.monotonic()
            < self._access_token_expires_at - self.TOKEN_REFRESH_MARGIN_SECONDS
        ):
            return self._access_token

        body = urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
            "grant_type": "refresh_token",
        }).encode("utf-8")
        request = Request(
            self.TOKEN_URL,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        token_data = self._request_json(request)
        access_token = token_data.get("access_token")
        if not access_token:
            raise RuntimeError("Google did not return an access token.")

        expires_in = int(token_data.get("expires_in", 3600))
        self._access_token = access_token
        self._access_token_expires_at = time.monotonic() + expires_in
        return access_token

    def send_messages(self, email_messages):
        if not email_messages:
            return 0

        sent_count = 0
        for email_message in email_messages:
            if not email_message.recipients():
                continue

            try:
                if not self.sender_email:
                    self._configuration_error()
                # The authenticated sender address is authoritative.
                email_message.from_email = self.sender_email
                mime_message = email_message.message()
                raw_message = base64.urlsafe_b64encode(
                    mime_message.as_bytes()
                ).decode("ascii")
                payload = json.dumps({"raw": raw_message}).encode("utf-8")
                request = Request(
                    self.SEND_URL,
                    data=payload,
                    headers={
                        "Authorization": f"Bearer {self._get_access_token()}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                self._request_json(request)
                sent_count += 1
            except (RuntimeError, BadHeaderError, ValueError):
                if not self.fail_silently:
                    raise
        return sent_count
