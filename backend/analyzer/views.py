import json
import hashlib
import secrets

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.mail import send_mail
from django.core.signing import BadSignature, SignatureExpired
from django.db import IntegrityError, transaction
from .forms import EmailRegistrationForm
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.timezone import now
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from django.views.decorators.csrf import csrf_exempt

from dashboard.models import ThreatHistory, ExtensionAPIToken

from .services import analyze_text
from .gmail_service import dashboard_gmail_data


User = get_user_model()


# Maximum JSON request size: 100 KB.
MAX_API_BODY_BYTES = 100_000


# ============================================================
# EMAIL OWNERSHIP VERIFICATION
# ============================================================

EMAIL_VERIFICATION_SALT = "analyzer.email-verification"
EMAIL_VERIFICATION_MAX_AGE = 60 * 60 * 24


def send_verification_email(request, user):
    token = signing.dumps(
        {"user_id": user.pk, "email": user.email},
        salt=EMAIL_VERIFICATION_SALT,
    )
    verification_url = request.build_absolute_uri(
        reverse("verify_email", kwargs={"token": token})
    )
    send_mail(
        subject="Verify your CyberShield AI email address",
        message=(
            "Welcome to CyberShield AI.\n\n"
            "Please verify that you own this email address by opening "
            "the link below:\n\n"
            f"{verification_url}\n\n"
            "This link expires in 24 hours. If you did not create this "
            "account, you can ignore this email."
        ),
        from_email=None,
        recipient_list=[user.email],
        fail_silently=False,
    )


def registration_verification_pending(request):
    return render(request, "registration/verification_pending.html")


def verify_email(request, token):
    if request.user.is_authenticated:
        return redirect("dashboard")

    try:
        payload = signing.loads(
            token,
            salt=EMAIL_VERIFICATION_SALT,
            max_age=EMAIL_VERIFICATION_MAX_AGE,
        )
    except SignatureExpired:
        return render(
            request,
            "registration/verification_result.html",
            {"status": "expired"},
        )
    except (BadSignature, TypeError, ValueError):
        return render(
            request,
            "registration/verification_result.html",
            {"status": "invalid"},
        )

    try:
        user = User.objects.get(
            pk=payload.get("user_id"),
            email__iexact=payload.get("email", ""),
        )
    except (User.DoesNotExist, TypeError, ValueError):
        return render(
            request,
            "registration/verification_result.html",
            {"status": "invalid"},
        )

    if user.is_active:
        return render(
            request,
            "registration/verification_result.html",
            {"status": "verified"},
        )

    password_form = SetPasswordForm(
        user,
        request.POST or None,
    )
    if request.method == "POST" and password_form.is_valid():
        password_form.save()
        user.is_active = True
        user.save(update_fields=["is_active"])
        request.session["show_gmail_connect_prompt"] = True
        return render(
            request,
            "registration/verification_result.html",
            {"status": "verified"},
        )

    # The account has no usable password until the email owner sets one here.
    return render(
        request,
        "registration/verification_result.html",
        {
            "status": "confirm",
            "password_form": password_form,
        },
    )


def resend_verification_email(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    delivery_error = False
    if request.method == "POST":
        email = (request.POST.get("email") or "").strip()
        if email:
            user = User.objects.filter(
                email__iexact=email,
                is_active=False,
            ).first()
            if user:
                try:
                    send_verification_email(request, user)
                except (OSError, RuntimeError, ValueError):
                    delivery_error = True

        # Do not reveal whether an email address has an account.
        return render(
            request,
            "registration/resend_verification.html",
            {
                "submitted": True,
                "delivery_error": delivery_error,
            },
        )

    return render(request, "registration/resend_verification.html")


# ============================================================
# USER REGISTRATION
# ============================================================

def register(request):

    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        form = EmailRegistrationForm(request.POST)

        if form.is_valid():
            try:
                with transaction.atomic():
                    user = form.save()
            except IntegrityError:
                # The database constraint is the final safeguard if two
                # registrations race after the form-level duplicate check.
                form.add_error(
                    "email",
                    "An account with this email already exists. Please log in instead.",
                )
            else:
                try:
                    send_verification_email(request, user)
                except (OSError, RuntimeError, ValueError):
                    messages.warning(
                        request,
                        "Your account is saved but the verification email could not be sent. "
                        "Use the resend verification page after email delivery is configured.",
                    )
                return redirect("registration_verification_pending")

    else:
        form = EmailRegistrationForm()

    return render(
        request,
        "registration/register.html",
        {"form": form},
    )


# ============================================================
# CLEAR CURRENT USER'S THREAT HISTORY
# ============================================================

@login_required
@require_POST
def clear_history(request):

    deleted_count, _ = ThreatHistory.objects.filter(
        user=request.user
    ).delete()

    messages.success(
        request,
        f"Your scan history has been cleared ({deleted_count} records deleted).",
    )

    return redirect("/#threat-history")


# ============================================================
# HOME PAGE AND MANUAL ANALYSIS
# ============================================================

@login_required
def home(request):

    # Password-based email integration is disabled.
    legacy_session_keys = (
        "email_password",
        "email_provider",
        "email_connected",
        "connected_email",
        "provider",
        "email_history",
        "total_emails_scanned",
        "phishing_count",
        "safe_count",
        "risk_level",
    )

    for key in legacy_session_keys:
        request.session.pop(key, None)

    # --------------------------------------------------------
    # RESTORE PREVIOUS SCAN RESULT
    # --------------------------------------------------------
    if request.method == "GET":
        result = request.session.pop("result", None)
        phishing_prob = request.session.pop("phishing_prob", None)
        tactics = request.session.pop("tactics", [])
        email_text = request.session.pop("email_text", "")
        safe_score = request.session.pop("safe_score", None)
        content_type = request.session.pop("content_type", "email")
        url_analysis = request.session.pop(
            "url_analysis",
            {"link_count": 0, "links_needing_review": 0, "urls": []}
        )

    else:
        result = None
        phishing_prob = None
        tactics = []
        email_text = ""
        safe_score = None
        content_type = "email"
        url_analysis = {
        "link_count": 0,
        "links_needing_review": 0,
        "urls": [],
        }

    analysis_details = ""

    # --------------------------------------------------------
    # DEFAULT VALUES
    # --------------------------------------------------------

    gmail_dashboard = dashboard_gmail_data(request.user)
    email_connected = gmail_dashboard["email_connected"]
    show_gmail_connect_prompt = (
        request.session.pop("show_gmail_connect_prompt", False)
        and not email_connected
    )
    connected_email = gmail_dashboard["email_address"]
    provider = gmail_dashboard["provider"]

    # --------------------------------------------------------
    # MANUAL EMAIL / SMS ANALYSIS
    # --------------------------------------------------------

    if request.method == "POST":

        content_type = request.POST.get(
            "content_type",
            "email",
        )

        if content_type not in ("email", "sms"):
            content_type = "email"

        email_text = (
            request.POST.get("email_text") or ""
        ).strip()

        if len(email_text) < 15:

            result = "SAFE - Input too short"
            phishing_prob = 0
            safe_score = 0
            tactics = []

            analysis_details = (
                "Input too short for reliable threat analysis."
            )

        else:

            try:

                analysis = analyze_text(
                    email_text,
                    content_type,
                )

            except ValueError as error:

                result = f"Invalid input: {error}"
                phishing_prob = 0
                safe_score = 0
                tactics = []
                analysis_details = str(error)

            except Exception:

                result = "Analysis service temporarily unavailable."
                phishing_prob = 0
                safe_score = 0
                tactics = []

                analysis_details = (
                    "The detection service encountered an error. "
                    "Please try again later."
                )

            else:

                phishing_prob = analysis["phishing_probability"]
                safe_score = analysis["safe_score"]
                tactics = analysis["tactics"]
                url_analysis = analysis["url_analysis"]

                if analysis["prediction"] == 1:
                    result = "PHISHING EMAIL DETECTED"
                else:
                    result = "SAFE EMAIL"

                # Save result for the current user only.
                ThreatHistory.objects.create(
                    user=request.user,
                    source_type=content_type,
                    content=email_text,
                    result=analysis["result"],
                    phishing_probability=phishing_prob,
                    tactics=tactics,
                    safe_score=safe_score,
                )

                # Store result for dashboard display.
                request.session["result"] = result
                request.session["phishing_prob"] = phishing_prob
                request.session["tactics"] = tactics
                request.session["email_text"] = email_text
                request.session["safe_score"] = safe_score
                request.session["content_type"] = content_type
                request.session["url_analysis"] = url_analysis

                return redirect("/#manual-analysis")

    # ========================================================
    # DASHBOARD STATISTICS
    # ========================================================

    # Only show records belonging to the logged-in user.
    user_history = ThreatHistory.objects.filter(
        user=request.user
    )

    history_items = user_history.exclude(
        result="SAFE"
    ).order_by("-created_at")

    threat_count = user_history.filter(
        result="PHISHING"
    ).count()

    email_scanned = user_history.count()

    safe_count = user_history.filter(
        result="SAFE"
    ).count()

    today = now().date()

    threat_today = user_history.filter(
        result="PHISHING",
        created_at__date=today,
    ).count()

    email_today = user_history.filter(
        created_at__date=today,
    ).count()

    if email_scanned > 0:

        safe_percentage = round(
            (safe_count / email_scanned) * 100,
            1,
        )

    else:
        safe_percentage = 0

    feed_items = user_history.exclude(
        result="SAFE"
    ).order_by("-created_at")[:10]

    dashboard_items = user_history.exclude(
        result="SAFE"
    ).order_by("-created_at")[:5]

    # ========================================================
    # EMAIL MONITOR DEFAULTS
    # Live email integration is disabled.
    # ========================================================

    monitor_email_history = gmail_dashboard["monitor_email_history"]
    monitor_total_scanned = gmail_dashboard["monitor_total_scanned"]
    monitor_phishing_count = gmail_dashboard["monitor_phishing_count"]
    monitor_safe_count = gmail_dashboard["monitor_safe_count"]
    monitor_safe_percentage = gmail_dashboard["monitor_safe_percentage"]

    monitor_today_scanned = gmail_dashboard["monitor_today_scanned"]
    monitor_today_phishing = gmail_dashboard["monitor_today_phishing"]
    monitor_today_safe = gmail_dashboard["monitor_today_safe"]

    risk_level = "LOW"

    # ========================================================
    # FINAL DASHBOARD RENDER
    # ========================================================

    return render(
        request,
        "index.html",
        {
            "result": result,
            "phishing_prob": phishing_prob,
            "tactics": tactics,
            "email_text": email_text,
            "analysis_details": analysis_details,
            "url_analysis": url_analysis,

            "history_items": history_items,
            "feed_items": feed_items,
            "dashboard_items": dashboard_items,

            "safe_score": safe_score,
            "analysis_time": "Just now",

            "model_name": (
                "Email Detection Model"
                if content_type == "email"
                else "SMS/Chat Detection Model"
            ),

            "model_active": True,

            "threat_count": threat_count,
            "email_scanned": email_scanned,
            "safe_count": safe_count,
            "risk_level": risk_level,
            "threat_today": threat_today,
            "email_today": email_today,
            "safe_percentage": safe_percentage,

            "email_connected": email_connected,
            "provider": provider,
            "email_address": connected_email,
            "last_email_scan": gmail_dashboard["last_email_scan"],
            "gmail_connection": gmail_dashboard["gmail_connection"],
            "show_gmail_connect_prompt": show_gmail_connect_prompt,

            "monitor_email_history": monitor_email_history,
            "monitor_total_scanned": monitor_total_scanned,
            "monitor_phishing_count": monitor_phishing_count,
            "monitor_safe_count": monitor_safe_count,
            "monitor_safe_percentage": monitor_safe_percentage,
            "monitor_today_scanned": monitor_today_scanned,
            "monitor_today_phishing": monitor_today_phishing,
            "monitor_today_safe": monitor_today_safe,
        },
    )


# ============================================================
# SETTINGS
# ============================================================

@login_required
def update_settings(request):
    return redirect("/#settings")


# ============================================================
# CHROME EXTENSION API TOKEN MANAGEMENT
# ============================================================

@login_required
@never_cache
def api_token_settings(request):

    token_exists = ExtensionAPIToken.objects.filter(
        user=request.user
    ).exists()

    return render(
        request,
        "api_token_settings.html",
        {
            "token_exists": token_exists,
        },
    )


@login_required
@require_POST
@never_cache
def generate_extension_token(request):

    # Generate a cryptographically secure random token.
    raw_token = secrets.token_urlsafe(32)

    # Store only the SHA-256 hash.
    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    ExtensionAPIToken.objects.update_or_create(
        user=request.user,
        defaults={
            "token_hash": token_hash,
        },
    )

    # Display the original token only in this response.
    return render(
        request,
        "api_token_settings.html",
        {
            "token_exists": True,
            "new_token": raw_token,
        },
    )


@login_required
@require_POST
def revoke_extension_token(request):

    ExtensionAPIToken.objects.filter(
        user=request.user
    ).delete()

    messages.success(
        request,
        "Your Chrome extension API token has been revoked.",
    )

    return redirect("api_token_settings")


# ============================================================
# EMAIL CONNECTION
# Password-based IMAP integration is disabled.
# Secure OAuth support can be implemented later.
# ============================================================

@login_required
def connect_email(request):

    if request.method != "POST":
        return JsonResponse(
            {"error": "POST method required."},
            status=405,
        )

    legacy_session_keys = (
        "email_password",
        "email_provider",
        "email_connected",
        "connected_email",
        "provider",
        "email_history",
        "total_emails_scanned",
        "phishing_count",
        "safe_count",
        "risk_level",
    )

    for key in legacy_session_keys:
        request.session.pop(key, None)

    messages.warning(
        request,
        "Live email integration is temporarily disabled while secure authentication is being developed.",
    )

    return redirect("dashboard")


# ============================================================
# DISCONNECT EMAIL
# ============================================================

@login_required
def disconnect_email(request):

    if request.method != "POST":
        return JsonResponse(
            {"error": "POST method required."},
            status=405,
        )

    legacy_session_keys = (
        "email_password",
        "email_provider",
        "email_connected",
        "connected_email",
        "provider",
        "email_history",
        "total_emails_scanned",
        "phishing_count",
        "safe_count",
        "risk_level",
    )

    for key in legacy_session_keys:
        request.session.pop(key, None)

    messages.success(
        request,
        "Email session data cleared successfully.",
    )

    return redirect("dashboard")


# ============================================================
# LATEST EMAILS API
# Live email fetching is disabled.
# ============================================================

@login_required
def get_latest_emails(request):

    if request.method != "GET":
        return JsonResponse(
            {
                "error": "GET method required.",
                "emails": [],
            },
            status=405,
        )

    return JsonResponse(
        {
            "error": "Live email integration is temporarily disabled.",
            "emails": [],
        },
        status=503,
    )


# ============================================================
# CYBERSHIELD AI - EMAIL AND SMS DETECTION API
# ============================================================


def perform_scan(request, content_type, user):
    """
    Shared scan handler for dashboard sessions and extension tokens.
    The supplied user owns the resulting scan history record.
    """

    # --------------------------------------------------------
    # HTTP METHOD VALIDATION
    # --------------------------------------------------------

    if request.method != "POST":
        return JsonResponse(
            {"error": "POST method required."},
            status=405,
        )

    # --------------------------------------------------------
    # REQUEST SIZE VALIDATION
    # --------------------------------------------------------

    if len(request.body) > MAX_API_BODY_BYTES:
        return JsonResponse(
            {"error": "Request body is too large."},
            status=413,
        )

    # --------------------------------------------------------
    # JSON VALIDATION
    # --------------------------------------------------------

    try:
        data = json.loads(request.body.decode("utf-8"))

    except (json.JSONDecodeError, UnicodeDecodeError):
        return JsonResponse(
            {"error": "Invalid JSON request."},
            status=400,
        )

    if not isinstance(data, dict):
        return JsonResponse(
            {"error": "JSON body must be an object."},
            status=400,
        )

    # --------------------------------------------------------
    # CONTENT VALIDATION
    # --------------------------------------------------------

    content = data.get("content")

    if not isinstance(content, str) or not content.strip():
        return JsonResponse(
            {"error": "A non-empty content field is required."},
            status=400,
        )

    content = content.strip()

    # --------------------------------------------------------
    # MACHINE LEARNING ANALYSIS
    # --------------------------------------------------------

    try:
        analysis = analyze_text(
            content,
            content_type,
        )

    except ValueError as error:
        return JsonResponse(
            {"error": str(error)},
            status=400,
        )

    except Exception:
        return JsonResponse(
            {
                "error": (
                    "Detection service temporarily unavailable."
                )
            },
            status=503,
        )

    # --------------------------------------------------------
    # SAVE RESULT FOR THE AUTHENTICATED USER
    # --------------------------------------------------------

    record = ThreatHistory.objects.create(
        user=user,
        source_type=content_type,
        content=content,
        result=analysis["result"],
        phishing_probability=analysis["phishing_probability"],
        tactics=analysis["tactics"],
        safe_score=analysis["safe_score"],
    )

    # --------------------------------------------------------
    # RETURN JSON RESPONSE
    # --------------------------------------------------------

    return JsonResponse(
        {
            "id": record.id,
            "content_type": content_type,
            "result": analysis["result"],
            "phishing_probability": analysis["phishing_probability"],
            "safe_score": analysis["safe_score"],
            "tactics": analysis["tactics"],
            "url_analysis": analysis["url_analysis"],
            "message": "Analysis completed successfully.",
        },
        status=200,
    )


# ============================================================
# EXISTING SESSION-AUTHENTICATED API
# ============================================================

def scan_api(request, content_type):

    if not request.user.is_authenticated:
        return JsonResponse(
            {"error": "Authentication required."},
            status=401,
        )

    return perform_scan(
        request,
        content_type,
        request.user,
    )


def scan_email_api(request):
    return scan_api(request, "email")


def scan_sms_api(request):
    return scan_api(request, "sms")


# ============================================================
# EXTENSION BEARER TOKEN AUTHENTICATION
# ============================================================

def extension_scan_api(request, content_type):

    # Check HTTP method first.
    if request.method != "POST":
        return JsonResponse(
            {"error": "POST method required."},
            status=405,
        )

    # Read the Authorization header.
    authorization = request.headers.get("Authorization", "")

    parts = authorization.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        return JsonResponse(
            {"error": "Valid Bearer token required."},
            status=401,
        )

    raw_token = parts[1]

    # Hash the supplied token. The original token is never
    # stored in the database.
    token_hash = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    # Find the owner of this token.
    token_record = (
        ExtensionAPIToken.objects
        .select_related("user")
        .filter(token_hash=token_hash)
        .first()
    )

    if token_record is None:
        return JsonResponse(
            {"error": "Invalid or revoked API token."},
            status=401,
        )

    # Record the last successful token authentication.
    token_record.last_used_at = now()
    token_record.save(update_fields=["last_used_at"])

    # Use the token owner's account, not the browser session user.
    return perform_scan(
        request,
        content_type,
        token_record.user,
    )


@csrf_exempt
def scan_extension_email_api(request):
    return extension_scan_api(request, "email")


@csrf_exempt
def scan_extension_sms_api(request):
    return extension_scan_api(request, "sms")
