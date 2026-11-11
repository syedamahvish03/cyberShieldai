import hmac
import json
import secrets
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .models import GmailConnection
from .gmail_service import (
    encrypt_refresh_token,
    exchange_authorization_code,
    revoke_refresh_token,
    run_gmail_monitoring,
)


GOOGLE_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
GMAIL_READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


@login_required
@require_POST
def gmail_oauth_start(request):
    if not settings.GOOGLE_OAUTH_CLIENT_ID or not settings.GOOGLE_OAUTH_CLIENT_SECRET:
        messages.error(request, "Gmail connection is not configured yet.")
        return redirect("/#email-monitor")

    if not settings.GMAIL_TOKEN_ENCRYPTION_KEY:
        messages.error(request, "Secure Gmail token storage is not configured yet.")
        return redirect("/#email-monitor")

    state = secrets.token_urlsafe(32)
    request.session["gmail_oauth_state"] = state
    redirect_uri = request.build_absolute_uri(reverse("gmail_oauth_callback"))
    params = {
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GMAIL_READ_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "true",
        "state": state,
    }
    return redirect(f"{GOOGLE_AUTHORIZE_URL}?{urlencode(params)}")


@login_required
def gmail_oauth_callback(request):
    expected_state = request.session.pop("gmail_oauth_state", "")
    supplied_state = request.GET.get("state", "")
    if not expected_state or not supplied_state or not secrets.compare_digest(
        expected_state, supplied_state
    ):
        messages.error(request, "Gmail authorization could not be verified. Please try again.")
        return redirect("/#email-monitor")

    if request.GET.get("error"):
        messages.warning(request, "Gmail connection was cancelled or not approved.")
        return redirect("/#email-monitor")

    code = request.GET.get("code")
    if not code:
        messages.error(request, "Google did not return an authorization code.")
        return redirect("/#email-monitor")

    try:
        redirect_uri = request.build_absolute_uri(reverse("gmail_oauth_callback"))
        token_data = exchange_authorization_code(code, redirect_uri)
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        existing = GmailConnection.objects.filter(user=request.user).first()
        if not access_token:
            raise RuntimeError("Google did not provide an access token.")

        profile_request = Request(
            GOOGLE_PROFILE_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            method="GET",
        )
        with urlopen(profile_request, timeout=20) as response:
            profile = json.loads(response.read().decode("utf-8"))

        gmail_email = (profile.get("emailAddress") or "").strip()
        history_id = str(profile.get("historyId") or "")
        if not gmail_email or not history_id:
            raise RuntimeError("Google did not return the Gmail account details.")

        # Reuse a previously saved refresh token only if Google confirms this
        # is the same Gmail mailbox. Never attach an old mailbox token to a
        # newly selected Gmail account.
        if not refresh_token and existing and existing.gmail_email.lower() == gmail_email.lower():
            from .gmail_service import decrypt_refresh_token
            refresh_token = decrypt_refresh_token(existing.encrypted_refresh_token)

        if not refresh_token:
            raise RuntimeError("Google did not provide a refresh token. Please authorize Gmail again.")

        GmailConnection.objects.update_or_create(
            user=request.user,
            defaults={
                "gmail_email": gmail_email,
                "encrypted_refresh_token": encrypt_refresh_token(refresh_token),
                # This starting point intentionally excludes all older emails.
                "history_id": history_id,
                "is_active": True,
                "last_error": "",
            },
        )
    except Exception:
        messages.error(
            request,
            "Gmail could not be connected. Please check the Google authorization settings and try again.",
        )
        return redirect("/#email-monitor")

    messages.success(
        request,
        f"Gmail ({gmail_email}) is connected. Only new incoming messages from now on will be checked.",
    )
    return redirect("/#email-monitor")


@login_required
@require_POST
def gmail_disconnect(request):
    connection = GmailConnection.objects.filter(user=request.user).first()
    if connection:
        try:
            from .gmail_service import decrypt_refresh_token
            token = decrypt_refresh_token(connection.encrypted_refresh_token)
            revoke_refresh_token(token)
        except Exception:
            pass
        connection.delete()
    messages.success(request, "Your Gmail connection has been disconnected.")
    return redirect("/#email-monitor")


@csrf_exempt
@require_POST
def gmail_monitor_endpoint(request):
    expected_secret = settings.GMAIL_MONITOR_SECRET
    supplied_secret = request.headers.get("Authorization", "")
    if not expected_secret or not hmac.compare_digest(
        supplied_secret, f"Bearer {expected_secret}"
    ):
        return JsonResponse({"error": "Unauthorized"}, status=401)

    try:
        summary = run_gmail_monitoring()
    except Exception:
        return JsonResponse({"error": "Monitoring run failed"}, status=500)

    return JsonResponse({"status": "completed", **summary})
