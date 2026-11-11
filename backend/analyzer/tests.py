import json
import hashlib

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import Client, TestCase
from django.urls import reverse

from dashboard.models import ThreatHistory, ExtensionAPIToken


User = get_user_model()


class DashboardTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="cybershield_test",
            email="cybershield_test@example.com",
            password="Test-password-123!",
        )
        self.client.login(
            username="cybershield_test@example.com",
            password="Test-password-123!",
        )

    def test_dashboard_page_loads(self):
        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "index.html")

    def test_email_analysis_saves_result(self):
        response = self.client.post(
            reverse("dashboard"),
            {
                "content_type": "email",
                "email_text": (
                    "Your account requires immediate verification. "
                    "Please review this important security notification."
                ),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(ThreatHistory.objects.count(), 1)

        record = ThreatHistory.objects.first()
        self.assertEqual(record.source_type, "email")
        self.assertEqual(record.user, self.user)
        self.assertIn(record.result, ["SAFE", "PHISHING"])

    def test_sms_analysis_saves_result(self):
        response = self.client.post(
            reverse("dashboard"),
            {
                "content_type": "sms",
                "email_text": (
                    "Congratulations! You have won a free gift. "
                    "Click this link immediately to claim your prize."
                ),
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(ThreatHistory.objects.count(), 1)

        record = ThreatHistory.objects.first()
        self.assertEqual(record.source_type, "sms")
        self.assertEqual(record.user, self.user)
        self.assertIn(record.result, ["SAFE", "PHISHING"])

    def test_short_input_is_not_saved(self):
        response = self.client.post(
            reverse("dashboard"),
            {
                "content_type": "email",
                "email_text": "Hello",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(ThreatHistory.objects.count(), 0)
        self.assertContains(response, "Input too short")

    def test_email_connection_is_disabled(self):
        response = self.client.post(
            reverse("connect_email"),
            {
                "email": "test@example.com",
                "password": "dummy-test-password",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("email_password", self.client.session)

    def test_email_connection_rejects_get(self):
        response = self.client.get(reverse("connect_email"))

        self.assertEqual(response.status_code, 405)

    def test_latest_emails_endpoint_is_disabled(self):
        response = self.client.get(reverse("get_latest_emails"))

        self.assertEqual(response.status_code, 503)

    def test_disconnect_rejects_get(self):
        response = self.client.get(reverse("disconnect_email"))

        self.assertEqual(response.status_code, 405)

    def test_login_page_loads(self):
        anonymous_client = Client()
        response = anonymous_client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response,
            "registration/login.html",
        )

    def test_login_with_valid_credentials(self):
        anonymous_client = Client()

        response = anonymous_client.post(
            reverse("login"),
            {
                "username": "cybershield_test@example.com",
                "password": "Test-password-123!",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            anonymous_client.get(reverse("dashboard")).status_code == 200
        )

    def test_logout(self):
        response = self.client.post(reverse("logout"))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(
            "_auth_user_id" in self.client.session
        )



class UserHistoryIsolationTests(TestCase):

    def setUp(self):
        self.user_a = User.objects.create_user(
            username="privacy_user_a",
            password="Test-password-123!",
        )

        self.user_b = User.objects.create_user(
            username="privacy_user_b",
            password="Test-password-123!",
        )

        self.admin = User.objects.create_superuser(
            username="privacy_admin",
            email="privacy_admin@example.com",
            password="Test-password-123!",
        )

        self.scan_a = ThreatHistory.objects.create(
            user=self.user_a,
            source_type="email",
            content="Private test message belonging to user A",
            result="PHISHING",
            phishing_probability=0.95,
            tactics=["Urgency Pressure"],
            safe_score=0.05,
        )

        self.scan_b = ThreatHistory.objects.create(
            user=self.user_b,
            source_type="sms",
            content="Private test message belonging to user B",
            result="PHISHING",
            phishing_probability=0.90,
            tactics=["Suspicious Link"],
            safe_score=0.10,

        )

    def test_user_can_clear_only_own_history(self):
        # Create an unassigned legacy record.
        legacy_record = ThreatHistory.objects.create(
            user=None,
            source_type="email",
            content="Unassigned legacy test record",
            result="SAFE",
            phishing_probability=0.10,
            tactics=[],
            safe_score=0.90,
        )

        # Log in as user A and clear their history.
        self.client.force_login(self.user_a)

        response = self.client.post(reverse("clear_history"))

        self.assertEqual(response.status_code, 302)

        # User A's record should be deleted.
        self.assertFalse(
            ThreatHistory.objects.filter(
                pk=self.scan_a.pk
            ).exists()
        )

        # User B's record must remain.
        self.assertTrue(
            ThreatHistory.objects.filter(
                pk=self.scan_b.pk
            ).exists()
        )

        # Unassigned legacy record must remain.
        self.assertTrue(
            ThreatHistory.objects.filter(
                pk=legacy_record.pk
            ).exists()
        )

    def test_clear_history_rejects_get(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("clear_history"))

        self.assertEqual(response.status_code, 405)

        # GET must not delete any records.
        self.assertTrue(
            ThreatHistory.objects.filter(
                pk=self.scan_a.pk
            ).exists()
        )

        self.assertTrue(
            ThreatHistory.objects.filter(
                pk=self.scan_b.pk
            ).exists()
        )


    def test_user_can_see_own_history(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["email_scanned"], 1)

        visible_ids = list(
            response.context["history_items"].values_list(
                "id", flat=True
            )
        )

        self.assertEqual(visible_ids, [self.scan_a.id])

    def test_users_cannot_see_each_others_history(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("dashboard"))

        visible_ids = list(
            response.context["history_items"].values_list(
                "id", flat=True
            )
        )

        self.assertIn(self.scan_a.id, visible_ids)
        self.assertNotIn(self.scan_b.id, visible_ids)

        self.client.force_login(self.user_b)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["email_scanned"], 1)

        visible_ids = list(
            response.context["history_items"].values_list(
                "id", flat=True
            )
        )

        self.assertIn(self.scan_b.id, visible_ids)
        self.assertNotIn(self.scan_a.id, visible_ids)

    def test_dashboard_does_not_render_another_users_private_scan_content(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Private test message belonging to user A")
        self.assertNotContains(response, "Private test message belonging to user B")

        self.client.force_login(self.user_b)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Private test message belonging to user B")
        self.assertNotContains(response, "Private test message belonging to user A")

    def test_all_dashboard_history_collections_are_user_scoped(self):
        self.client.force_login(self.user_a)

        response = self.client.get(reverse("dashboard"))

        for collection_name in ("history_items", "feed_items", "dashboard_items"):
            with self.subTest(collection=collection_name):
                visible_ids = list(
                    response.context[collection_name].values_list("id", flat=True)
                )
                self.assertIn(self.scan_a.id, visible_ids)
                self.assertNotIn(self.scan_b.id, visible_ids)

        self.assertEqual(response.context["email_scanned"], 1)
        self.assertEqual(response.context["threat_count"], 1)

        self.client.force_login(self.user_b)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.context["email_scanned"], 1)
        self.assertEqual(response.context["threat_count"], 1)

        for collection_name in ("history_items", "feed_items", "dashboard_items"):
            with self.subTest(collection=collection_name):
                visible_ids = list(
                    response.context[collection_name].values_list("id", flat=True)
                )
                self.assertIn(self.scan_b.id, visible_ids)
                self.assertNotIn(self.scan_a.id, visible_ids)

    def test_administrator_cannot_see_other_users_history(self):
        self.client.force_login(self.admin)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["email_scanned"], 0)

        visible_ids = list(
            response.context["history_items"].values_list(
                "id", flat=True
            )
        )

        self.assertNotIn(self.scan_a.id, visible_ids)
        self.assertNotIn(self.scan_b.id, visible_ids)

class AnonymousAccessTests(TestCase):

    def test_anonymous_users_cannot_access_protected_views(self):
        protected_urls = [
            reverse("dashboard"),
            reverse("update_settings"),
            reverse("connect_email"),
            reverse("disconnect_email"),
            reverse("get_latest_emails"),
            reverse("clear_history"),
        ]

        for url in protected_urls:
            with self.subTest(url=url):
                response = self.client.get(url)

                self.assertEqual(response.status_code, 302)
                self.assertTrue(
                    response.url.startswith(reverse("login"))
                )


class ScanApiTests(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="api_test_user",
            password="Test-password-123!",
        )

        self.email_url = reverse("scan_email_api")
        self.sms_url = reverse("scan_sms_api")

        self.valid_content = (
            "Your account requires immediate verification. "
            "Please review this important security notification."
        )

    def post_json(self, url, data):
        return self.client.post(
            url,
            data=json.dumps(data),
            content_type="application/json",
        )

    def test_anonymous_email_api_request_is_rejected(self):
        response = self.post_json(
            self.email_url,
            {"content": self.valid_content},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_anonymous_sms_api_request_is_rejected(self):
        response = self.post_json(
            self.sms_url,
            {"content": self.valid_content},
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_authenticated_email_api_scan_succeeds(self):
        self.client.force_login(self.user)

        response = self.post_json(
            self.email_url,
            {"content": self.valid_content},
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["content_type"], "email")
        self.assertIn(data["result"], ["SAFE", "PHISHING"])
        self.assertIn("phishing_probability", data)
        self.assertIn("safe_score", data)
        self.assertIn("tactics", data)

        record = ThreatHistory.objects.get(id=data["id"])

        self.assertEqual(record.user, self.user)
        self.assertEqual(record.source_type, "email")
        self.assertEqual(record.content, self.valid_content)

    def test_authenticated_sms_api_scan_succeeds(self):
        self.client.force_login(self.user)

        response = self.post_json(
            self.sms_url,
            {"content": self.valid_content},
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["content_type"], "sms")
        self.assertIn(data["result"], ["SAFE", "PHISHING"])

        record = ThreatHistory.objects.get(id=data["id"])

        self.assertEqual(record.user, self.user)
        self.assertEqual(record.source_type, "sms")

    def test_authenticated_get_request_is_rejected(self):
        self.client.force_login(self.user)

        email_response = self.client.get(self.email_url)
        sms_response = self.client.get(self.sms_url)

        self.assertEqual(email_response.status_code, 405)
        self.assertEqual(sms_response.status_code, 405)

        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_invalid_json_is_rejected(self):
        self.client.force_login(self.user)

        response = self.client.post(
            self.email_url,
            data="{invalid json",
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_json_array_is_rejected(self):
        self.client.force_login(self.user)

        response = self.client.post(
            self.email_url,
            data=json.dumps(["not", "an", "object"]),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_missing_content_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(
            self.email_url,
            {},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_short_content_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(
            self.sms_url,
            {"content": "Hello"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_content_over_20000_characters_is_rejected(self):
        self.client.force_login(self.user)

        response = self.post_json(
            self.email_url,
            {"content": "A" * 20001},
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_oversized_request_body_is_rejected(self):
        self.client.force_login(self.user)

        response = self.client.post(
            self.email_url,
            data=json.dumps({
                "content": "A" * 100001,
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_api_scan_is_saved_only_for_logged_in_user(self):
        another_user = User.objects.create_user(
            username="another_api_user",
            password="Test-password-123!",
        )

        self.client.force_login(self.user)

        response = self.post_json(
            self.email_url,
            {"content": self.valid_content},
        )

        self.assertEqual(response.status_code, 200)

        self.assertEqual(
            ThreatHistory.objects.filter(user=self.user).count(),
            1,
        )

        self.assertEqual(
            ThreatHistory.objects.filter(user=another_user).count(),
            0,
        )

class ExtensionTokenApiTests(TestCase):


    def setUp(self):
        self.user = User.objects.create_user(
            username="extension_owner",
            password="Test-password-123!",
        )

        self.other_user = User.objects.create_user(
            username="extension_other_user",
            password="Test-password-123!",
        )

        self.raw_token = "test-extension-token-123456789"

        token_hash = hashlib.sha256(
            self.raw_token.encode("utf-8")
        ).hexdigest()

        self.token_record = ExtensionAPIToken.objects.create(
            user=self.user,
            token_hash=token_hash,
        )

        self.email_url = reverse("scan_extension_email_api")
        self.sms_url = reverse("scan_extension_sms_api")

        self.valid_content = (
            "Your account requires immediate verification. "
            "Please review this important security notification."
        )

    def post_with_token(self, url, content=None, token=None):

        if token is None:
            token = self.raw_token

        data = {}

        if content is not None:
            data["content"] = content

        return self.client.post(
            url,
            data=json.dumps(data),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    def test_valid_email_token_scan_succeeds(self):

        response = self.post_with_token(
            self.email_url,
            self.valid_content,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["content_type"], "email")
        self.assertIn(data["result"], ["SAFE", "PHISHING"])

        record = ThreatHistory.objects.get(id=data["id"])

        self.assertEqual(record.user, self.user)
        self.assertEqual(record.source_type, "email")
        self.assertEqual(record.content, self.valid_content)

    def test_valid_sms_token_scan_succeeds(self):

        response = self.post_with_token(
            self.sms_url,
            self.valid_content,
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()

        self.assertEqual(data["content_type"], "sms")

        record = ThreatHistory.objects.get(id=data["id"])

        self.assertEqual(record.user, self.user)
        self.assertEqual(record.source_type, "sms")

    def test_missing_token_is_rejected(self):

        response = self.client.post(
            self.email_url,
            data=json.dumps({"content": self.valid_content}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_invalid_token_is_rejected(self):

        response = self.post_with_token(
            self.email_url,
            self.valid_content,
            token="invalid-token",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_revoked_token_is_rejected(self):

        self.token_record.delete()

        response = self.post_with_token(
            self.email_url,
            self.valid_content,
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_token_hash_is_stored_not_raw_token(self):

        self.assertEqual(
            self.token_record.token_hash,
            hashlib.sha256(
                self.raw_token.encode("utf-8")
            ).hexdigest(),
        )

        self.assertNotEqual(
            self.token_record.token_hash,
            self.raw_token,
        )

    def test_scan_is_saved_under_token_owner(self):

        # Simulate a different user being logged in through
        # the browser session.
        self.client.force_login(self.other_user)

        response = self.post_with_token(
            self.email_url,
            self.valid_content,
        )

        self.assertEqual(response.status_code, 200)

        record = ThreatHistory.objects.get(
            id=response.json()["id"]
        )

        # Token identity takes priority over session identity.
        self.assertEqual(record.user, self.user)
        self.assertNotEqual(record.user, self.other_user)

    def test_last_used_timestamp_is_updated(self):

        self.assertIsNone(self.token_record.last_used_at)

        response = self.post_with_token(
            self.email_url,
            self.valid_content,
        )

        self.assertEqual(response.status_code, 200)

        self.token_record.refresh_from_db()

        self.assertIsNotNone(self.token_record.last_used_at)

    def test_extension_get_request_is_rejected(self):

        response = self.client.get(self.email_url)

        self.assertEqual(response.status_code, 405)
        self.assertEqual(ThreatHistory.objects.count(), 0)

    def test_short_content_is_rejected(self):

        response = self.post_with_token(
            self.email_url,
            "Hello",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(ThreatHistory.objects.count(), 0)


    def test_bearer_token_api_does_not_require_csrf_token(self):

        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.post(
            self.email_url,
            data=json.dumps({
                "content": self.valid_content,
            }),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )

        self.assertEqual(response.status_code, 200)


class EmailAuthenticationUpgradeTests(TestCase):

    def test_registration_creates_account_with_email(self):
        response = self.client.post(
            reverse("register"),
            {
                "email": "new.person@example.com",
                "password1": "Strong-test-password-123!",
                "password2": "Strong-test-password-123!",
            },
        )

        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(email__iexact="new.person@example.com")
        self.assertTrue(user.username)
        self.assertTrue(user.check_password("Strong-test-password-123!"))

    def test_registration_rejects_duplicate_email_case_insensitively(self):
        User.objects.create_user(
            username="existing_email_user",
            email="person@example.com",
            password="Strong-test-password-123!",
        )

        response = self.client.post(
            reverse("register"),
            {
                "email": "PERSON@example.com",
                "password1": "Strong-test-password-123!",
                "password2": "Strong-test-password-123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "already exists")
        self.assertEqual(User.objects.filter(email__iexact="person@example.com").count(), 1)

    def test_database_rejects_duplicate_email_case_insensitively(self):
        User.objects.create_user(
            username="database_email_owner",
            email="unique.person@example.com",
            password="Strong-test-password-123!",
        )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                User.objects.create_user(
                    username="database_email_duplicate",
                    email="UNIQUE.PERSON@example.com",
                    password="Strong-test-password-123!",
                )

        self.assertEqual(
            User.objects.filter(email__iexact="unique.person@example.com").count(),
            1,
        )

    def test_database_allows_multiple_blank_legacy_emails(self):
        first = User.objects.create_user(
            username="legacy_blank_email_one",
            email="",
            password="Strong-test-password-123!",
        )
        second = User.objects.create_user(
            username="legacy_blank_email_two",
            email="",
            password="Strong-test-password-123!",
        )

        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(User.objects.filter(email="").count(), 2)

    def test_login_with_email_address(self):
        user = User.objects.create_user(
            username="email_login_user",
            email="login.person@example.com",
            password="Strong-test-password-123!",
        )

        response = self.client.post(
            reverse("login"),
            {
                "username": "LOGIN.PERSON@example.com",
                "password": "Strong-test-password-123!",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            int(self.client.session["_auth_user_id"]),
            user.pk,
        )

    def test_username_only_login_is_rejected(self):
        User.objects.create_user(
            username="legacy_username_only",
            password="Strong-test-password-123!",
        )

        response = self.client.post(
            reverse("login"),
            {
                "username": "legacy_username_only",
                "password": "Strong-test-password-123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_email_login_is_case_insensitive(self):
        user = User.objects.create_user(
            username="email_case_user",
            email="Case.User@example.com",
            password="Strong-test-password-123!",
        )

        response = self.client.post(
            reverse("login"),
            {
                "username": "CASE.USER@EXAMPLE.COM",
                "password": "Strong-test-password-123!",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            int(self.client.session["_auth_user_id"]),
            user.pk,
        )
