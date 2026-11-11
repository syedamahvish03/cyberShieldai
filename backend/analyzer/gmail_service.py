import base64
import json
import re
from datetime import timedelta
from urllib.parse import urlencode, urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from dashboard.models import ThreatHistory
from .models import GmailConnection
from .services import analyze_text


TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
TIMEOUT_SECONDS = 20
MAX_EMAIL_TEXT = 20000
GMAIL_HISTORY_RETENTION_DAYS = 30


class GmailAPIError(RuntimeError):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def _fernet():
    key = getattr(settings, "GMAIL_TOKEN_ENCRYPTION_KEY", "")
    if not key:
        raise RuntimeError("Gmail token encryption is not configured.")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise RuntimeError("Gmail token encryption key is invalid.") from None


def encrypt_refresh_token(token):
    return _fernet().encrypt(token.encode("utf-8")).decode("ascii")


def decrypt_refresh_token(encrypted_token):
    try:
        return _fernet().decrypt(encrypted_token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeEncodeError):
        raise RuntimeError("The saved Gmail connection token cannot be decrypted.") from None


def _read_json(response):
    raw = response.read()
    return json.loads(raw.decode("utf-8")) if raw else {}


def _request_json(request):
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return _read_json(response)
    except HTTPError as exc:
        try:
            payload = _read_json(exc)
            reason = payload.get("error", "Google API request failed")
            if isinstance(reason, dict):
                reason = reason.get("message", "Google API request failed")
        except (ValueError, AttributeError):
            reason = "Google API request failed"
        raise GmailAPIError(
            f"Google API request failed (HTTP {exc.code}): {reason}",
            status_code=exc.code,
        ) from None
    except URLError:
        raise GmailAPIError("Could not reach Google Gmail services.") from None


def exchange_authorization_code(code, redirect_uri):
    body = urlencode({
        "code": code,
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }).encode("utf-8")
    request = Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    return _request_json(request)


def revoke_refresh_token(token):
    body = urlencode({"token": token}).encode("utf-8")
    request = Request(
        "https://oauth2.googleapis.com/revoke",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS):
            return True
    except (HTTPError, URLError):
        return False


def _access_token(connection):
    cached = getattr(connection, "_gmail_access_token", None)
    if cached:
        return cached
    refresh_token = decrypt_refresh_token(connection.encrypted_refresh_token)
    body = urlencode({
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }).encode("utf-8")
    request = Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    payload = _request_json(request)
    token = payload.get("access_token")
    if not token:
        raise GmailAPIError("Google did not return an access token.")
    # One monitor run lasts only a few minutes, well inside Google's usual
    # access-token lifetime. Keep this token only on the in-memory model object.
    connection._gmail_access_token = token
    return token


def gmail_api_get(connection, path, params=None):
    token = _access_token(connection)
    query = "?" + urlencode(params or {}, doseq=True) if params else ""
    request = Request(
        f"{GMAIL_API}/{path}{query}",
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    return _request_json(request)


def get_gmail_profile(connection):
    return gmail_api_get(connection, "profile")


class _HTMLTextExtractor:
    def __init__(self):
        from html.parser import HTMLParser

        class Parser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.parts = []

            def handle_data(self, data):
                self.parts.append(data)

        self.parser = Parser()

    def extract(self, source):
        self.parser.feed(source)
        return " ".join(self.parser.parts)


def _decode_body_data(data):
    if not data:
        return ""
    try:
        raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return ""


def _collect_text_parts(payload, collected):
    mime_type = (payload.get("mimeType") or "").lower()
    filename = payload.get("filename") or ""
    body = payload.get("body") or {}

    # Attachments are intentionally excluded from the first release.
    if filename:
        return

    data = body.get("data")
    if data and mime_type in ("text/plain", "text/html"):
        decoded = _decode_body_data(data)
        if mime_type == "text/html":
            decoded = _HTMLTextExtractor().extract(decoded)
        if decoded:
            collected.append(decoded)

    for part in payload.get("parts") or []:
        _collect_text_parts(part, collected)


def _header(headers, name):
    for item in headers or []:
        if (item.get("name") or "").lower() == name.lower():
            return item.get("value", "")
    return ""


def _extract_url_domains(text):
    """Return a small, de-duplicated list of URL hosts and paths without query data."""
    found = []
    seen = set()
    for match in re.findall(r"https?://\S+", text or "", flags=re.IGNORECASE):
        candidate = match.rstrip(".,;:!?)]}")
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            continue
        # Keep enough context to identify the destination, but discard query
        # strings and fragments that may contain personal or tracking tokens.
        destination = hostname
        if parsed.path and parsed.path != "/":
            destination += parsed.path[:120]
        if destination not in seen:
            seen.add(destination)
            found.append(destination)
        if len(found) >= 5:
            break
    return found


def purge_expired_gmail_history(now=None):
    """Delete only automatic Gmail-monitoring records older than 30 days."""
    cutoff = (now or timezone.now()) - timedelta(days=GMAIL_HISTORY_RETENTION_DAYS)
    deleted, _ = ThreatHistory.objects.filter(
        source_type="gmail",
        created_at__lt=cutoff,
    ).delete()
    return deleted


def extract_message(message):
    payload = message.get("payload") or {}
    headers = payload.get("headers") or []
    sender = _header(headers, "From")
    subject = _header(headers, "Subject")
    received = _header(headers, "Date")
    text_parts = []
    _collect_text_parts(payload, text_parts)
    body = "\n".join(text_parts)
    # Include metadata so the model can also inspect suspicious sender names
    # and subject lines. No attachments are read or stored.
    combined = (
        f"From: {sender}\n"
        f"Subject: {subject}\n"
        f"Date: {received}\n\n"
        f"{body}"
    ).strip()
    url_domains = _extract_url_domains(body)
    history_lines = [
        f"From: {sender}",
        f"Subject: {subject}",
        f"Received: {received}",
    ]
    if url_domains:
        history_lines.append("URL destinations: " + ", ".join(url_domains))
    return {
        "sender": sender,
        "subject": subject,
        "received": received,
        # Full text is used only in memory for detection and is never saved.
        "content": combined[:MAX_EMAIL_TEXT],
        # Retain only limited metadata for the user's 30-day Gmail history.
        "history_content": "\n".join(history_lines)[:2000],
    }


def _added_message_ids(history_payload):
    found = set()
    for item in history_payload.get("history") or []:
        for added in item.get("messagesAdded") or []:
            message = added.get("message") or {}
            message_id = message.get("id")
            if message_id:
                found.add(message_id)
    return found


def _alert_owner(connection, subject, sender, probability):
    send_mail(
        subject="CyberShield AI detected a suspicious Gmail message",
        message=(
            "CyberShield AI detected a potentially phishing message in your "
            "connected Gmail inbox.\n\n"
            f"From: {sender or 'Unknown sender'}\n"
            f"Subject: {subject or '(no subject)'}\n"
            f"Estimated phishing probability: {probability:.1f}%\n\n"
            "Please open your CyberShield AI dashboard to review the result. "
            "Do not click suspicious links or share passwords or verification codes."
        ),
        from_email=None,
        recipient_list=[connection.user.email],
        fail_silently=False,
    )


def scan_connection(connection):
    """
    Process Gmail message-added history after the saved checkpoint only.
    The checkpoint advances only after every listed message has been handled.
    """
    scanned = 0
    threats = 0
    connection.last_error = ""

    try:
        history_payload = gmail_api_get(
            connection,
            "history",
            {
                "startHistoryId": connection.history_id,
                "historyTypes": "messageAdded",
                "maxResults": 500,
            },
        )
    except GmailAPIError as exc:
        if exc.status_code != 404:
            raise
        # Gmail history IDs can expire. Re-baseline at the current point rather
        # than scanning the mailbox's old messages.
        profile = get_gmail_profile(connection)
        connection.history_id = str(profile.get("historyId", connection.history_id))
        connection.last_checked_at = timezone.now()
        connection.last_error = (
            "Gmail's old change checkpoint expired. Monitoring was re-synced "
            "without scanning historical messages."
        )
        connection.save(update_fields=["history_id", "last_checked_at", "last_error"])
        return {"scanned": 0, "threats": 0, "reset": True}

    message_ids = _added_message_ids(history_payload)
    next_page = history_payload.get("nextPageToken")
    while next_page:
        page = gmail_api_get(
            connection,
            "history",
            {
                "startHistoryId": connection.history_id,
                "historyTypes": "messageAdded",
                "maxResults": 500,
                "pageToken": next_page,
            },
        )
        message_ids.update(_added_message_ids(page))
        next_page = page.get("nextPageToken")
        history_payload["historyId"] = page.get("historyId", history_payload.get("historyId"))

    for message_id in sorted(message_ids):
        stored_message_id = f"{connection.gmail_email.lower()}:{message_id}"
        if ThreatHistory.objects.filter(
            user=connection.user,
            source_type="gmail",
            message_id=stored_message_id,
        ).exists():
            continue

        try:
            metadata = gmail_api_get(
                connection,
                f"messages/{message_id}",
                {
                    "format": "metadata",
                    "metadataHeaders": ["From", "Subject", "Date"],
                },
            )
        except GmailAPIError as exc:
            if exc.status_code == 404:
                continue
            raise

        # Check the INBOX label before requesting any message body. Sent mail
        # and other non-inbox messages are never downloaded for analysis.
        if "INBOX" not in (metadata.get("labelIds") or []):
            continue

        try:
            message = gmail_api_get(
                connection,
                f"messages/{message_id}",
                {"format": "full"},
            )
        except GmailAPIError as exc:
            if exc.status_code == 404:
                continue
            raise
        details = extract_message(message)
        content = details["content"]
        if len(content.strip()) < 15:
            continue

        analysis = analyze_text(content, "email")
        ThreatHistory.objects.create(
            user=connection.user,
            source_type="gmail",
            content=details["history_content"],
            result=analysis["result"],
            phishing_probability=analysis["phishing_probability"],
            tactics=analysis["tactics"],
            safe_score=analysis["safe_score"],
            message_id=stored_message_id,
        )
        scanned += 1

        if analysis["prediction"] == 1:
            threats += 1
            try:
                _alert_owner(
                    connection,
                    details["subject"],
                    details["sender"],
                    analysis["phishing_probability"],
                )
            except Exception:
                # Dashboard warning is still stored even if outbound alert mail
                # is temporarily unavailable.
                connection.last_error = (
                    "A phishing message was detected, but its email alert "
                    "could not be delivered."
                )

    new_history_id = history_payload.get("historyId")
    if new_history_id:
        connection.history_id = str(new_history_id)
    connection.last_checked_at = timezone.now()
    connection.save(update_fields=["history_id", "last_checked_at", "last_error"])
    return {"scanned": scanned, "threats": threats, "reset": False}


def run_gmail_monitoring():
    # Run retention cleanup with the scheduled monitor. Only source_type="gmail"
    # records are eligible; manual analysis history is never touched.
    expired_deleted = purge_expired_gmail_history()
    summary = {
        "accounts_checked": 0,
        "emails_scanned": 0,
        "threats_found": 0,
        "errors": 0,
        "expired_gmail_history_deleted": expired_deleted,
    }
    for connection in GmailConnection.objects.filter(is_active=True).select_related("user").iterator():
        summary["accounts_checked"] += 1
        try:
            result = scan_connection(connection)
            summary["emails_scanned"] += result["scanned"]
            summary["threats_found"] += result["threats"]
        except Exception:
            summary["errors"] += 1
            connection.last_checked_at = timezone.now()
            connection.last_error = "The latest Gmail check failed. It will be retried automatically."
            connection.save(update_fields=["last_checked_at", "last_error"])
    return summary


def dashboard_gmail_data(user):
    connection = GmailConnection.objects.filter(user=user, is_active=True).first()
    records = ThreatHistory.objects.filter(user=user, source_type="gmail")
    total = records.count()
    phishing = records.filter(result="PHISHING").count()
    safe = records.filter(result="SAFE").count()
    history = []
    for record in records.order_by("-created_at")[:20]:
        lines = record.content.splitlines()
        sender = lines[0].replace("From:", "", 1).strip() if lines else ""
        subject = lines[1].replace("Subject:", "", 1).strip() if len(lines) > 1 else ""
        history.append({
            "sender": sender,
            "subject": subject,
            "timestamp": record.created_at,
            "result": record.result,
            "safe_score": record.safe_score,
            "content": record.content,
            "tactics": record.tactics,
        })
    return {
        "gmail_connection": connection,
        "email_connected": bool(connection),
        "email_address": connection.gmail_email if connection else "",
        "provider": "Gmail" if connection else "Gmail",
        "last_email_scan": connection.last_checked_at if connection and connection.last_checked_at else "Waiting for first check",
        "monitor_email_history": history,
        "monitor_total_scanned": total,
        "monitor_phishing_count": phishing,
        "monitor_safe_count": safe,
        "monitor_safe_percentage": round((safe / total) * 100, 1) if total else 0,
        "monitor_today_scanned": records.filter(created_at__date=timezone.localdate()).count(),
        "monitor_today_phishing": records.filter(result="PHISHING", created_at__date=timezone.localdate()).count(),
        "monitor_today_safe": records.filter(result="SAFE", created_at__date=timezone.localdate()).count(),
    }
