import base64
from datetime import timedelta
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.utils import timezone
from django.urls import reverse

from analyzer.gmail_service import (
    GmailAPIError,
    encrypt_refresh_token,
    decrypt_refresh_token,
    scan_connection,
    extract_message,
    dashboard_gmail_data,
    purge_expired_gmail_history,
)
from analyzer.models import GmailConnection
from dashboard.models import ThreatHistory


User = get_user_model()
TEST_FERNET_KEY = Fernet.generate_key().decode("ascii")


@override_settings(
    GOOGLE_OAUTH_CLIENT_ID="test-google-client-id",
    GOOGLE_OAUTH_CLIENT_SECRET="test-google-client-secret",
    GMAIL_TOKEN_ENCRYPTION_KEY=TEST_FERNET_KEY,
    GMAIL_MONITOR_SECRET="test-monitor-secret",
)
class GmailOAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="gmail_oauth_user",
            email="gmail-owner@example.com",
            password="Strong-test-password-123!",
        )
        self.client.force_login(self.user)

    def test_refresh_token_is_encrypted_at_rest(self):
        token = "private-google-refresh-token"
        encrypted = encrypt_refresh_token(token)
        self.assertNotEqual(encrypted, token)
        self.assertEqual(decrypt_refresh_token(encrypted), token)

    def test_oauth_start_requests_readonly_scope_and_uses_state(self):
        response = self.client.post(
            reverse("gmail_oauth_start"),
            HTTP_X_FORWARDED_PROTO="https",
        )
        self.assertEqual(response.status_code, 302)
        parsed = urlparse(response.url)
        params = parse_qs(parsed.query)
        self.assertEqual(params["scope"], ["https://www.googleapis.com/auth/gmail.readonly"])
        self.assertEqual(params["access_type"], ["offline"])
        self.assertEqual(params["prompt"], ["consent"])
        self.assertTrue(params["redirect_uri"][0].startswith("https://"))
        self.assertEqual(
            self.client.session["gmail_oauth_state"],
            params["state"][0],
        )

    def test_callback_saves_encrypted_connection_and_starts_from_current_history(self):
        session = self.client.session
        session["gmail_oauth_state"] = "expected-state"
        session.save()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"emailAddress":"gmail-owner@gmail.com","historyId":"987654"}'

        with patch(
            "analyzer.gmail_views.exchange_authorization_code",
            return_value={
                "access_token": "temporary-access-token",
                "refresh_token": "private-refresh-token",
            },
        ), patch("analyzer.gmail_views.urlopen", return_value=FakeResponse()):
            response = self.client.get(
                reverse("gmail_oauth_callback"),
                {"state": "expected-state", "code": "one-time-code"},
            )

        self.assertEqual(response.status_code, 302)
        connection = GmailConnection.objects.get(user=self.user)
        self.assertEqual(connection.gmail_email, "gmail-owner@gmail.com")
        self.assertEqual(connection.history_id, "987654")
        self.assertNotEqual(connection.encrypted_refresh_token, "private-refresh-token")
        self.assertEqual(
            decrypt_refresh_token(connection.encrypted_refresh_token),
            "private-refresh-token",
        )

    def test_reconnect_same_mailbox_preserves_last_scanned_checkpoint(self):
        connection = GmailConnection.objects.create(
            user=self.user,
            gmail_email="gmail-owner@gmail.com",
            encrypted_refresh_token=encrypt_refresh_token("old-refresh-token"),
            history_id="500",
        )
        session = self.client.session
        session["gmail_oauth_state"] = "expected-state"
        session.save()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"emailAddress":"gmail-owner@gmail.com","historyId":"900"}'

        with patch(
            "analyzer.gmail_views.exchange_authorization_code",
            return_value={
                "access_token": "new-access-token",
                "refresh_token": "new-refresh-token",
            },
        ), patch("analyzer.gmail_views.urlopen", return_value=FakeResponse()):
            response = self.client.get(
                reverse("gmail_oauth_callback"),
                {"state": "expected-state", "code": "one-time-code"},
            )

        self.assertEqual(response.status_code, 302)
        connection.refresh_from_db()
        self.assertEqual(connection.history_id, "500")
        self.assertEqual(
            decrypt_refresh_token(connection.encrypted_refresh_token),
            "new-refresh-token",
        )

    def test_callback_does_not_reuse_existing_token_for_different_gmail_account(self):
        connection = GmailConnection.objects.create(
            user=self.user,
            gmail_email="first-mailbox@gmail.com",
            encrypted_refresh_token=encrypt_refresh_token("first-mailbox-token"),
            history_id="100",
        )
        session = self.client.session
        session["gmail_oauth_state"] = "expected-state"
        session.save()

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self):
                return b'{"emailAddress":"second-mailbox@gmail.com","historyId":"200"}'

        with patch(
            "analyzer.gmail_views.exchange_authorization_code",
            return_value={"access_token": "temporary-access-token"},
        ), patch("analyzer.gmail_views.urlopen", return_value=FakeResponse()):
            response = self.client.get(
                reverse("gmail_oauth_callback"),
                {"state": "expected-state", "code": "one-time-code"},
            )

        self.assertEqual(response.status_code, 302)
        connection.refresh_from_db()
        self.assertEqual(connection.gmail_email, "first-mailbox@gmail.com")
        self.assertEqual(
            decrypt_refresh_token(connection.encrypted_refresh_token),
            "first-mailbox-token",
        )

    def test_callback_rejects_invalid_state(self):
        session = self.client.session
        session["gmail_oauth_state"] = "correct-state"
        session.save()
        response = self.client.get(
            reverse("gmail_oauth_callback"),
            {"state": "wrong-state", "code": "one-time-code"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(GmailConnection.objects.exists())

    def test_disconnect_deletes_only_current_users_connection(self):
        other = User.objects.create_user(
            username="gmail_other_user",
            email="other@example.com",
            password="Strong-test-password-123!",
        )
        own_connection = GmailConnection.objects.create(
            user=self.user,
            gmail_email="gmail-owner@gmail.com",
            encrypted_refresh_token=encrypt_refresh_token("own-token"),
            history_id="100",
        )
        other_connection = GmailConnection.objects.create(
            user=other,
            gmail_email="other@gmail.com",
            encrypted_refresh_token=encrypt_refresh_token("other-token"),
            history_id="200",
        )

        with patch("analyzer.gmail_views.revoke_refresh_token", return_value=True):
            response = self.client.post(reverse("gmail_disconnect"))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(GmailConnection.objects.filter(pk=own_connection.pk).exists())
        self.assertTrue(GmailConnection.objects.filter(pk=other_connection.pk).exists())

    def test_monitor_endpoint_requires_shared_secret(self):
        response = Client().post(reverse("gmail_monitor_endpoint"))
        self.assertEqual(response.status_code, 401)

    def test_monitor_endpoint_runs_only_with_correct_secret(self):
        with patch(
            "analyzer.gmail_views.run_gmail_monitoring",
            return_value={
                "accounts_checked": 2,
                "emails_scanned": 3,
                "threats_found": 1,
                "errors": 0,
            },
        ):
            response = Client().post(
                reverse("gmail_monitor_endpoint"),
                HTTP_AUTHORIZATION="Bearer test-monitor-secret",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["emails_scanned"], 3)


@override_settings(GMAIL_TOKEN_ENCRYPTION_KEY=TEST_FERNET_KEY)
class GmailScanningTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="gmail_scan_user",
            email="scan-owner@example.com",
            password="Strong-test-password-123!",
        )
        self.connection = GmailConnection.objects.create(
            user=self.user,
            gmail_email="scan-owner@gmail.com",
            encrypted_refresh_token=encrypt_refresh_token("scan-refresh-token"),
            history_id="123",
        )

    @staticmethod
    def _message_payload(message_id="scan-owner@gmail.com:gmail-message-1", label_ids=None):
        body = (
            "Urgent security notice. Your account will be suspended unless "
            "you verify your account immediately using https://example.org/path?tracking=123#section."
        )
        encoded = base64.urlsafe_b64encode(body.encode("utf-8")).decode("ascii").rstrip("=")
        return {
            "id": message_id,
            "labelIds": label_ids if label_ids is not None else ["INBOX"],
            "payload": {
                "mimeType": "text/plain",
                "headers": [
                    {"name": "From", "value": "Security Team <alerts@example.net>"},
                    {"name": "Subject", "value": "Urgent account verification"},
                    {"name": "Date", "value": "Wed, 11 Nov 2026 10:00:00 +0000"},
                ],
                "body": {"data": encoded},
            },
        }

    def test_scans_only_new_inbox_messages_and_saves_under_owner(self):
        def fake_api_get(connection, path, params=None):
            if path == "history":
                return {
                    "historyId": "124",
                    "history": [{
                        "messagesAdded": [{"message": {"id": "gmail-message-1"}}]
                    }],
                }
            if path == "messages/gmail-message-1":
                if params and params.get("format") == "metadata":
                    return {"labelIds": ["INBOX"]}
                return self._message_payload()
            raise AssertionError(f"Unexpected Gmail API path: {path}")

        fake_analysis = {
            "prediction": 1,
            "result": "PHISHING",
            "phishing_probability": 98.5,
            "safe_score": 1.5,
            "tactics": ["Urgency Pressure", "Fear Manipulation"],
        }
        with patch("analyzer.gmail_service.gmail_api_get", side_effect=fake_api_get), patch(
            "analyzer.gmail_service.analyze_text", return_value=fake_analysis
        ), patch("analyzer.gmail_service._alert_owner"):
            result = scan_connection(self.connection)

        self.assertEqual(result["scanned"], 1)
        self.assertEqual(result["threats"], 1)
        record = ThreatHistory.objects.get(source_type="gmail")
        self.assertEqual(record.user, self.user)
        self.assertEqual(record.message_id, "scan-owner@gmail.com:gmail-message-1")
        self.assertEqual(record.result, "PHISHING")
        self.assertIn("Security Team <alerts@example.net>", record.content)
        self.assertIn("Urgent account verification", record.content)
        self.assertNotIn("Your account will be suspended", record.content)
        self.assertNotIn("verify your account immediately", record.content)
        self.assertIn("URL destinations: example.org/path", record.content)
        self.assertNotIn("tracking=123", record.content)
        self.assertNotIn("#section", record.content)
        dashboard_record = dashboard_gmail_data(self.user)["monitor_email_history"][0]
        self.assertEqual(dashboard_record["sender"], "Security Team <alerts@example.net>")
        self.assertEqual(dashboard_record["subject"], "Urgent account verification")
        self.assertNotIn("Your account will be suspended", dashboard_record["content"])
        self.connection.refresh_from_db()
        self.assertEqual(self.connection.history_id, "124")

    def test_ignores_messages_not_in_inbox(self):
        def fake_api_get(connection, path, params=None):
            if path == "history":
                return {
                    "historyId": "124",
                    "history": [{
                        "messagesAdded": [{"message": {"id": "sent-message"}}]
                    }],
                }
            if path == "messages/sent-message":
                return {"labelIds": ["SENT"]}
            raise AssertionError(f"Unexpected Gmail API path: {path}")

        with patch("analyzer.gmail_service.gmail_api_get", side_effect=fake_api_get), patch(
            "analyzer.gmail_service.analyze_text"
        ) as analyze:
            result = scan_connection(self.connection)

        self.assertEqual(result["scanned"], 0)
        analyze.assert_not_called()
        self.assertFalse(ThreatHistory.objects.filter(source_type="gmail").exists())

    def test_expired_history_checkpoint_resets_without_historical_scan(self):
        with patch(
            "analyzer.gmail_service.gmail_api_get",
            side_effect=GmailAPIError("expired", status_code=404),
        ), patch(
            "analyzer.gmail_service.get_gmail_profile",
            return_value={"historyId": "999"},
        ):
            result = scan_connection(self.connection)

        self.assertTrue(result["reset"])
        self.assertEqual(result["scanned"], 0)
        self.connection.refresh_from_db()
        self.assertEqual(self.connection.history_id, "999")
        self.assertFalse(ThreatHistory.objects.filter(source_type="gmail").exists())


    def test_attachment_parts_are_not_included_in_scanned_text(self):
        message = {
            "payload": {
                "mimeType": "multipart/mixed",
                "headers": [
                    {"name": "From", "value": "sender@example.com"},
                    {"name": "Subject", "value": "Message with attachment"},
                ],
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": base64.urlsafe_b64encode(b"Visible email text only").decode("ascii").rstrip("=")},
                    },
                    {
                        "mimeType": "text/plain",
                        "filename": "private-attachment.txt",
                        "body": {"data": base64.urlsafe_b64encode(b"SECRET ATTACHMENT CONTENT").decode("ascii").rstrip("=")},
                    },
                ],
            }
        }
        extracted = extract_message(message)
        self.assertIn("Visible email text only", extracted["content"])
        self.assertNotIn("SECRET ATTACHMENT CONTENT", extracted["content"])

    def test_dashboard_gmail_data_is_isolated_per_user(self):
        other = User.objects.create_user(
            username="gmail_scan_other",
            email="other-scan@example.com",
            password="Strong-test-password-123!",
        )
        ThreatHistory.objects.create(
            user=self.user,
            source_type="gmail",
            content="From: mine@example.com\nSubject: My message\n\nMy private content",
            result="PHISHING",
            phishing_probability=99,
            tactics=["Urgency Pressure"],
            safe_score=1,
            message_id="mine",
        )
        ThreatHistory.objects.create(
            user=other,
            source_type="gmail",
            content="From: other@example.com\nSubject: Other message\n\nOther private content",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="other",
        )
        own_data = dashboard_gmail_data(self.user)
        other_data = dashboard_gmail_data(other)
        self.assertEqual(own_data["monitor_total_scanned"], 1)
        self.assertEqual(other_data["monitor_total_scanned"], 1)
        self.assertEqual(own_data["monitor_email_history"][0]["subject"], "My message")
        self.assertEqual(other_data["monitor_email_history"][0]["subject"], "Other message")

    def test_gmail_history_cleanup_deletes_only_records_older_than_30_days(self):
        old_date = timezone.now() - timedelta(days=31)
        old_gmail = ThreatHistory.objects.create(
            user=self.user,
            source_type="gmail",
            content="From: old@example.com\\nSubject: Old Gmail alert",
            result="PHISHING",
            phishing_probability=99,
            tactics=["Urgency Pressure"],
            safe_score=1,
            message_id="old-gmail",
        )
        old_manual = ThreatHistory.objects.create(
            user=self.user,
            source_type="Manual Scan",
            content="Old manual scan content",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="old-manual",
        )
        old_manual_email = ThreatHistory.objects.create(
            user=self.user,
            source_type="email",
            content="Old manually submitted email",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="old-manual-email",
        )
        old_manual_sms = ThreatHistory.objects.create(
            user=self.user,
            source_type="sms",
            content="Old manually submitted SMS",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="old-manual-sms",
        )
        recent_gmail = ThreatHistory.objects.create(
            user=self.user,
            source_type="gmail",
            content="From: recent@example.com\\nSubject: Recent Gmail alert",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="recent-gmail",
        )
        ThreatHistory.objects.filter(pk__in=[old_gmail.pk, old_manual.pk, old_manual_email.pk, old_manual_sms.pk]).update(created_at=old_date)

        deleted = purge_expired_gmail_history()

        self.assertEqual(deleted, 1)
        self.assertFalse(ThreatHistory.objects.filter(pk=old_gmail.pk).exists())
        self.assertTrue(ThreatHistory.objects.filter(pk=old_manual.pk).exists())
        self.assertTrue(ThreatHistory.objects.filter(pk=old_manual_email.pk).exists())
        self.assertTrue(ThreatHistory.objects.filter(pk=old_manual_sms.pk).exists())
        self.assertTrue(ThreatHistory.objects.filter(pk=recent_gmail.pk).exists())

    def test_gmail_monitor_runs_retention_cleanup(self):
        old_record = ThreatHistory.objects.create(
            user=self.user,
            source_type="gmail",
            content="Expired Gmail history",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="expired",
        )
        ThreatHistory.objects.filter(pk=old_record.pk).update(
            created_at=timezone.now() - timedelta(days=31)
        )
        with patch("analyzer.gmail_service.GmailConnection.objects.filter") as connections:
            connections.return_value.select_related.return_value.iterator.return_value = []
            from analyzer.gmail_service import run_gmail_monitoring
            summary = run_gmail_monitoring()

        self.assertEqual(summary["expired_gmail_history_deleted"], 1)
        self.assertFalse(ThreatHistory.objects.filter(pk=old_record.pk).exists())

    def test_duplicate_message_is_not_scanned_twice(self):
        ThreatHistory.objects.create(
            user=self.user,
            source_type="gmail",
            content="Previously scanned message content",
            result="SAFE",
            phishing_probability=1,
            tactics=[],
            safe_score=99,
            message_id="scan-owner@gmail.com:gmail-message-1",
        )

        def fake_api_get(connection, path, params=None):
            if path == "history":
                return {
                    "historyId": "124",
                    "history": [{
                        "messagesAdded": [{"message": {"id": "gmail-message-1"}}]
                    }],
                }
            raise AssertionError("Duplicate messages should not be fetched again.")

        with patch("analyzer.gmail_service.gmail_api_get", side_effect=fake_api_get), patch(
            "analyzer.gmail_service.analyze_text"
        ) as analyze:
            result = scan_connection(self.connection)

        self.assertEqual(result["scanned"], 0)
        analyze.assert_not_called()
        self.assertEqual(ThreatHistory.objects.filter(source_type="gmail").count(), 1)
