
from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register, name="register"),
    path("account/email/", views.update_account_email, name="update_account_email"),
    path("clear-history/", views.clear_history, name="clear_history"),
    path("", views.home, name="dashboard"),
    path("connect-email/", views.connect_email, name="connect_email"),
    path("update-settings/", views.update_settings, name="update_settings"),
    path("api-token-settings/", views.api_token_settings, name="api_token_settings"),
    path("api-token/generate/", views.generate_extension_token, name="generate_extension_token"),
    path("api-token/revoke/", views.revoke_extension_token, name="revoke_extension_token"),
    path("api/scan/email/", views.scan_email_api, name="scan_email_api"),
    path("api/scan/sms/", views.scan_sms_api, name="scan_sms_api"),
    path("disconnect-email/", views.disconnect_email, name="disconnect_email"),
    path("get-latest-emails/", views.get_latest_emails, name="get_latest_emails"),
    path("api/extension/scan/email/", views.scan_extension_email_api, name="scan_extension_email_api"),
    path("api/extension/scan/sms/", views.scan_extension_sms_api, name="scan_extension_sms_api"),
]
