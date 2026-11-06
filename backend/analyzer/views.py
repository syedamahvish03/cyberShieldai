
from django.shortcuts import render
from django.shortcuts import redirect
from django.http import JsonResponse

from django.utils.timezone import now

from django.contrib import messages

from dashboard.models import ThreatHistory

import joblib
import imaplib
import email

from email.header import decode_header
from email.utils import parsedate_to_datetime
from datetime import datetime

# =========================
# LOAD ML MODELS
# =========================

# EMAIL MODEL
email_model = joblib.load(
    "../ml_model/email_model.pkl"
)

email_vectorizer = joblib.load(
    "../ml_model/email_vectorizer.pkl"
)

# SMS / CHAT MODEL
sms_model = joblib.load(
    "../ml_model/sms_model.pkl"
)

sms_vectorizer = joblib.load(
    "../ml_model/sms_vectorizer.pkl"
)


# =========================
# DASHBOARD ITEMS
# =========================

dashboard_items = ThreatHistory.objects.exclude(
    result="SAFE"
).order_by('-created_at')[:5]


# =========================
# HOME PAGE
# =========================

def home(request):

    # =========================
    # RESTORE SESSION RESULT
    # =========================

    if request.method == "GET":

        result = request.session.pop(
            "result",
            None
        )

        phishing_prob = request.session.pop(
            "phishing_prob",
            None
        )

        tactics = request.session.pop(
            "tactics",
            []
        )

        email_text = request.session.pop(
            "email_text",
            ""
        )

        safe_score = request.session.pop(
            "safe_score",
            None
        )

    else:

        result = None
        phishing_prob = None
        tactics = []
        email_text = ""
        safe_score = None

    # =========================
    # DEFAULT TYPE
    # =========================

    content_type = "email"

    # =========================
    # EMAIL SESSION STATE
    # =========================

    email_connected = request.session.get(
        "email_connected",
        False
    )

    connected_email = request.session.get(
        "connected_email",
        ""
    )

    provider = request.session.get(
    "provider",
    "Secure Mail"
)

    # =========================
    # MANUAL ANALYSIS
    # =========================

    if request.method == "POST":

        content_type = request.POST.get(
            "content_type"
        )

        email_text = request.POST.get(
            "email_text"
        )

        # =========================
        # SHORT INPUT CHECK
        # =========================

        if len(email_text.strip()) < 15:

            return render(request, "index.html", {

                "result": "SAFE ✅",

                "analysis_details":
                "Input too short for reliable threat analysis.",

                "phishing_prob": 0,

                "tactics": [],

                "email_text": email_text,

                "safe_score": 0,

                "model_active": True,

                "history_items":
                ThreatHistory.objects.all()
                .order_by('-created_at')[:5],

                "feed_items":
                ThreatHistory.objects
                .exclude(result="SAFE")
                .order_by('-created_at')[:10],

                "analysis_time": "Just now",

                "model_name":
                "Email Detection Model"
                if content_type == "email"
                else "SMS/Chat Detection Model",

                "dashboard_items":
                dashboard_items,

                "email_connected":
                email_connected,

                "email_address":
                connected_email

            })

        # =========================
        # MODEL SELECTION
        # =========================

        if (
            content_type == "sms"
            or
            content_type == "chat"
        ):

            email_vector = sms_vectorizer.transform(
                [email_text]
            )

            prediction = sms_model.predict(
                email_vector
            )

            probability = sms_model.predict_proba(
                email_vector
            )

        else:

            email_vector = email_vectorizer.transform(
                [email_text]
            )

            prediction = email_model.predict(
                email_vector
            )

            probability = email_model.predict_proba(
                email_vector
            )

        phishing_prob = probability[0][1] * 100

        safe_score = round(
            probability[0][0] * 100,
            2
        )

        # =========================
        # MANIPULATION DETECTION
        # =========================

        email_lower = email_text.lower()

        urgency_words = [
            "urgent",
            "immediately",
            "now",
            "asap"
        ]

        fear_words = [
            "suspended",
            "blocked",
            "warning",
            "disabled"
        ]

        authority_words = [
            "bank",
            "government",
            "support",
            "admin"
        ]

        reward_words = [
            "won",
            "prize",
            "gift",
            "reward"
        ]

        if any(
            word in email_lower
            for word in urgency_words
        ):

            tactics.append(
                "Urgency Pressure"
            )

        if any(
            word in email_lower
            for word in fear_words
        ):

            tactics.append(
                "Fear Manipulation"
            )

        if any(
            word in email_lower
            for word in authority_words
        ):

            tactics.append(
                "Fake Authority"
            )

        if any(
            word in email_lower
            for word in reward_words
        ):

            tactics.append(
                "Reward Scam"
            )

        # =========================
        # RESULT
        # =========================

        if prediction[0] == 1:

            result = (
                "⚠️ PHISHING EMAIL DETECTED"
            )

        else:

            result = "SAFE EMAIL ✅"

        # =========================
        # SAVE TO DATABASE
        # =========================

        ThreatHistory.objects.create(

            source_type=content_type,

            content=email_text,

            result=
            "PHISHING"
            if prediction[0] == 1
            else "SAFE",

            phishing_probability=
            phishing_prob,

            tactics=tactics,

            safe_score=safe_score

        )

        # =========================
        # SAVE SESSION RESULT
        # =========================

        request.session["result"] = result

        request.session[
            "phishing_prob"
        ] = phishing_prob

        request.session[
            "tactics"
        ] = tactics

        request.session[
            "email_text"
        ] = email_text

        request.session[
            "safe_score"
        ] = safe_score

        return redirect('/#manual-analysis')

    # =========================
    # DASHBOARD STATS
    # =========================

    history_items = ThreatHistory.objects.exclude(
        result="SAFE"
    ).order_by('-created_at')

    threat_count = ThreatHistory.objects.filter(
        result="PHISHING"
    ).count()

    email_scanned = ThreatHistory.objects.count()

    safe_count = ThreatHistory.objects.filter(
        result="SAFE"
    ).count()

    today = now().date()

    threat_today = ThreatHistory.objects.filter(
        result="PHISHING",
        created_at__date=today
    ).count()

    email_today = ThreatHistory.objects.filter(
        created_at__date=today
    ).count()

    safe_percentage = round(

        (safe_count / email_scanned) * 100,

        1

    ) if email_scanned > 0 else 0

    feed_items = ThreatHistory.objects.exclude(
        result="SAFE"
    ).order_by('-created_at')[:10]

    # =========================
    # EMAIL MONITOR SESSION DATA
    # =========================

    monitor_email_history = request.session.get(
        "email_history",
        []
    )

    monitor_total_scanned = request.session.get(
        "total_emails_scanned",
        0
    )

    monitor_phishing_count = request.session.get(
        "phishing_count",
        0
    )

    monitor_safe_count = request.session.get(
        "safe_count",
        0
    )

    risk_level = request.session.get(
        "risk_level",
        "LOW"
    )

    if email_scanned > 0:
        safe_percentage = round(
            (safe_count / email_scanned) * 100,
            1
        )
    else:
        safe_percentage = 0



    # =========================
    # EMAIL MONITOR STATS
    # =========================
    monitor_safe_percentage = round(
        (
            monitor_safe_count /
            monitor_total_scanned
        ) * 100,
        1
    )if monitor_total_scanned > 0 else 0
    today = now().date()
    monitor_today_scanned = 0
    monitor_today_phishing = 0
    monitor_today_safe = 0
    for email in monitor_email_history:
        scan_date = email.get("scan_date")

        if scan_date:
            try:
                parsed_date = datetime.strptime(
                    str(scan_date),
                    "%Y-%m-%d"
                ).date()
                if parsed_date == today:
                    monitor_today_scanned += 1



                    if (email.get("result") == "PHISHING" or email.get("result") == "phishing"):
                        monitor_today_phishing += 1

                    elif (email.get("result") == "SAFE" or email.get("result") == "safe"):
                        monitor_today_safe += 1
            except:
                pass
    # =========================
    # FINAL RENDER
    # =========================

    print("TODAY PHISHING:", monitor_today_phishing)
    return render(request, "index.html", {

        "result": result,

        "phishing_prob":
        phishing_prob,

        "tactics":
        tactics,

        "email_text":
        email_text,

        "history_items":
        history_items,

        "feed_items":
        feed_items,

        "safe_score":
        safe_score,

        "analysis_time":
        "Just now",

        "model_name":
        "Email Detection Model"
        if content_type == "email"
        else "SMS/Chat Detection Model",

        "threat_count":
        threat_count,

        "model_active":
        True,

        "email_scanned":
        email_scanned,

        "safe_count":
        safe_count,

        "risk_level":
        risk_level,

        "threat_today":
        threat_today,

        "email_today":
        email_today,

        "safe_percentage":
        safe_percentage,

        "dashboard_items":
        dashboard_items,

        "email_connected":
        email_connected,

        "provider": provider,

        "email_address":
        connected_email,

        "monitor_email_history":
        monitor_email_history,

        "monitor_total_scanned":
        monitor_total_scanned,

        "monitor_phishing_count":
        monitor_phishing_count,

        "monitor_safe_count":
        monitor_safe_count,

        "monitor_safe_percentage":
        monitor_safe_percentage,

        "monitor_today_scanned":
        monitor_today_scanned,

        "monitor_today_phishing":
        monitor_today_phishing,

        "monitor_today_safe":
        monitor_today_safe,



    })


# =========================
# SETTINGS
# =========================

def update_settings(request):

    return redirect('/#settings')


# =========================
# EMAIL MONITOR
# =========================

def connect_email(request):

    if request.method == "POST":

        provider = request.POST.get(
            "provider"
        )

        email_address = request.POST.get(
            "email"
        )

        password = request.POST.get(
            "password"
        )

        try:

            # =========================
            # SELECT IMAP SERVER
            # =========================

            if provider == "gmail":

                imap_server = "imap.gmail.com"

            elif provider == "outlook":

                imap_server = (
                    "outlook.office365.com"
                )

            elif provider == "yahoo":

                imap_server = (
                    "imap.mail.yahoo.com"
                )

            else:

                imap_server = (
                    "imap.gmail.com"
                )

            # =========================
            # CONNECT
            # =========================

            mail = imaplib.IMAP4_SSL(
                imap_server
            )

            # =========================
            # LOGIN
            # =========================

            mail.login(
                email_address,
                password
            )

            request.session["email_password"] = password
            request.session["email_provider"] = provider

            # =========================
            # OPEN INBOX
            # =========================

            mail.select("inbox")

            # =========================
            # FETCH EMAIL IDS
            # =========================

            status, email_ids = mail.search(
                None,
                "ALL"
            )

            print("STATUS:", status)

            print(
                "EMAIL IDS:",
                email_ids
            )

            email_id_list = email_ids[0].split()

            # =========================
            # STORAGE VARIABLES
            # =========================

            email_history = []

            phishing_count = 0

            safe_count = 0

            # =========================
            # SCAN LAST 5 EMAILS
            # =========================

            for email_id in email_id_list[-5:]:

                print("SCANNING EMAIL")

                status, msg_data = mail.fetch(

                    email_id,

                    "(RFC822)"

                )

                # =========================
                # RAW EMAIL
                # =========================

                raw_email = msg_data[0][1]

                # =========================
                # MESSAGE OBJECT
                # =========================

                msg = email.message_from_bytes(
                    raw_email
                )

                # =========================
                # SUBJECT
                # =========================

                subject, encoding = decode_header(
                    msg["Subject"]
                )[0]

                if isinstance(subject, bytes):

                    subject = subject.decode(

                        encoding
                        if encoding
                        else "utf-8"

                    )

                # =========================
                # SENDER
                # =========================

                sender = msg.get("From")
                email_date = msg.get("Date")
                try:
                    parsed_date = parsedate_to_datetime(
                        email_date
                    )
                    formatted_time = parsed_date.strftime(
                        "%d %b %Y, %I:%M %p"
                    )
                except:
                    formatted_time = "Unknown Time"

                print("SUBJECT:", subject)

                print("SENDER:", sender)

                # =========================
                # EXTRACT BODY
                # =========================

                body = ""

                if msg.is_multipart():

                    for part in msg.walk():

                        content_type = (
                            part.get_content_type()
                        )

                        try:

                            if (
                                content_type
                                ==
                                "text/plain"
                            ):

                                payload = (
                                    part.get_payload(
                                        decode=True
                                    )
                                )

                                if payload:

                                    body = payload.decode(
                                        errors="ignore"
                                    )

                                    break

                        except:
                            pass

                else:

                    payload = msg.get_payload(
                        decode=True
                    )

                    if payload:

                        body = payload.decode(
                            errors="ignore"
                        )

                print("BODY:")

                print(body[:1000])

                # =========================
                # ML PREDICTION
                # =========================

                clean_body = body.lower()

                body_vector = (
                    email_vectorizer.transform(
                        [clean_body]
                    )
                )

                prediction = email_model.predict(
                    body_vector
                )[0]

                probability = (
                    email_model.predict_proba(
                        body_vector
                    )[0]
                )

                safe_score = round(
                    probability[0] * 100,
                    2
                )

                phishing_score = round(
                    probability[1] * 100,
                    2
                )

                print(
                    "PREDICTION:",
                    prediction
                )

                print(
                    "SAFE SCORE:",
                    safe_score
                )

                print(
                    "PHISHING SCORE:",
                    phishing_score
                )

                # =========================
                # RESULT LABEL
                # =========================

                if prediction == 1:

                    result = "phishing"

                else:

                    result = "safe"

                # =========================
                # TRUSTED DOMAIN CHECK
                # =========================

                trusted_domains = [

                    "google.com",

                    "accounts.google.com",

                    "microsoft.com",

                    "outlook.com",

                    "paypal.com",

                    "amazon.com"

                ]

                sender_lower = sender.lower()

                trusted_sender = any(

                    domain in sender_lower

                    for domain
                    in trusted_domains

                )

                if trusted_sender:

                    phishing_score = round(
                        phishing_score * 0.35,
                        2
                    )

                    safe_score = round(
                        100 - phishing_score,
                        2
                    )

                    prediction = 0

                    result = "safe"

                    print(
                        "TRUSTED DOMAIN DETECTED"
                    )

                # =========================
                # COUNTS
                # =========================

                if result == "phishing":

                    phishing_count += 1

                else:

                    safe_count += 1

                # =========================
                # SAVE EMAIL HISTORY
                # =========================

                email_history.append({

                    "subject": subject,

                    "sender": sender,

                    "result": result,

                    "safe_score": round(
                        safe_score,
                        2
                    ),

                    "timestamp": formatted_time

                })

                # =========================
                # SAVE DATABASE
                # =========================

                ThreatHistory.objects.create(

                    source_type="email",

                    content=body,

                    result=
                    "PHISHING"
                    if result == "phishing"
                    else "SAFE",

                    phishing_probability=
                    phishing_score,

                    safe_score=
                    safe_score,

                    tactics=[]

                )

            # =========================
            # RISK LEVEL
            # =========================

            if phishing_count >= 3:

                risk_level = "HIGH"

            elif phishing_count >= 1:

                risk_level = "MEDIUM"

            else:

                risk_level = "LOW"

            # =========================
            # SAVE SESSION
            # =========================

            request.session[
                "email_history"
            ] = email_history

            request.session[
                "total_emails_scanned"
            ] = len(email_history)

            request.session[
                "phishing_count"
            ] = phishing_count

            request.session[
                "safe_count"
            ] = safe_count

            request.session[
                "risk_level"
            ] = risk_level

            request.session[
                "email_connected"
            ] = True

            request.session[
                "connected_email"
            ] = email_address

            request.session[
    "provider"
] = provider.capitalize()

            # =========================
            # SUCCESS MESSAGE
            # =========================

            messages.success(

                request,

                "Email connected and scanned successfully!"

            )

            return redirect("/")

        except Exception as e:

            print("ERROR:", str(e))

            messages.error(

                request,

                f"Connection failed: {str(e)}"

            )

            return redirect("/")


# =========================
# DISCONNECT EMAIL
# =========================

def disconnect_email(request):

    # REMOVE SESSION DATA

    request.session["email_connected"] = False

    request.session["connected_email"] = ""

    messages.success(
        request,
        "Email disconnected successfully!"
    )

    return redirect("/")


def get_latest_emails(request):

    try:

        email_address = request.session.get(
            "connected_email"
        )

        password = request.session.get(
            "email_password"
        )

        provider = request.session.get(
            "email_provider"
        )

        if not email_address or not password:

            return JsonResponse({
                "emails": []
            })

        # =========================
        # SELECT IMAP SERVER
        # =========================

        if provider == "gmail":

            imap_server = "imap.gmail.com"

        elif provider == "outlook":

            imap_server = (
                "outlook.office365.com"
            )

        elif provider == "yahoo":

            imap_server = (
                "imap.mail.yahoo.com"
            )

        else:

            imap_server = (
                "imap.gmail.com"
            )

        # =========================
        # CONNECT
        # =========================

        mail = imaplib.IMAP4_SSL(
            imap_server
        )

        mail.login(
            email_address,
            password
        )

        mail.select("inbox")

        result, data = mail.search(
            None,
            "ALL"
        )

        email_ids = data[0].split()

        total_email_count = len(email_ids)

        # LAST 20 MAILS ONLY FOR FEED
        latest_email_ids = email_ids[-20:]

        email_history = []

        phishing_count = 0
        safe_count = 0

        # =========================
        # TRUSTED DOMAINS
        # =========================

        trusted_domains = [

            "google.com",
            "accounts.google.com",
            "microsoft.com",
            "outlook.com",
            "paypal.com",
            "amazon.com",
            "linkedin.com",
            "github.com",
            "apple.com",
            "x.com",
            "twitter.com"

        ]

        # =========================
        # LOOP EMAILS
        # =========================

        for email_id in reversed(
            latest_email_ids
        ):

            result, msg_data = mail.fetch(
                email_id,
                "(RFC822)"
            )

            raw_email = msg_data[0][1]

            msg = email.message_from_bytes(
                raw_email
            )

            # =========================
            # SUBJECT
            # =========================

            subject = msg.get(
                "Subject",
                "No Subject"
            )

            # decode subject safely
            decoded_subject = decode_header(
                subject
            )[0][0]

            if isinstance(
                decoded_subject,
                bytes
            ):

                try:

                    subject = decoded_subject.decode(
                        "utf-8",
                        errors="ignore"
                    )

                except:

                    subject = "Unreadable Subject"

            else:

                subject = decoded_subject

            # =========================
            # SENDER
            # =========================

            sender = msg.get(
                "From",
                "Unknown Sender"
            )

            sender_lower = sender.lower()

            # =========================
            # BODY EXTRACTION
            # =========================

            body = ""

            if msg.is_multipart():

                for part in msg.walk():

                    try:

                        if (
                            part.get_content_type()
                            == "text/plain"
                        ):

                            payload = part.get_payload(
                                decode=True
                            )

                            if payload:

                                body = payload.decode(
                                    errors="ignore"
                                )

                                break

                    except:
                        pass

            else:

                try:

                    payload = msg.get_payload(
                        decode=True
                    )

                    if payload:

                        body = payload.decode(
                            errors="ignore"
                        )

                except:
                    pass

            clean_body = body.lower()

            # =========================
            # ML PREDICTION
            # =========================

            body_vector = (
                email_vectorizer.transform(
                    [clean_body]
                )
            )

            prediction = email_model.predict(
                body_vector
            )[0]

            probabilities = (
                email_model.predict_proba(
                    body_vector
                )[0]
            )

            safe_score = round(
                probabilities[0] * 100,
                2
            )

            phishing_score = round(
                probabilities[1] * 100,
                2
            )

            # =========================
            # RESULT
            # =========================

            if prediction == 1:

                result_label = "phishing"

            else:

                result_label = "safe"

            # =========================
            # TRUSTED DOMAIN FIX
            # =========================

            trusted_sender = any(

                domain in sender_lower

                for domain in trusted_domains

            )

            if trusted_sender:

                result_label = "safe"

                phishing_score = round(
                    phishing_score * 0.15,
                    2
                )

                safe_score = round(
                    100 - phishing_score,
                    2
                )

            # =========================
            # COUNTS
            # =========================

            if result_label == "phishing":

                phishing_count += 1

            else:

                safe_count += 1

            # =========================
            # REAL EMAIL TIME
            # =========================

            email_date = msg.get("Date")

            try:

                parsed_date = (
                    parsedate_to_datetime(
                        email_date
                    )
                )

                formatted_time = (
                    parsed_date.strftime(
                        "%d %b %Y, %I:%M %p"
                    )
                )

            except:

                formatted_time = "Unknown Time"

            # =========================
            # EMAIL HISTORY
            # =========================

            email_history.append({

                "subject": subject,

                "sender": sender,

                "result": result_label,

                "safe_score": safe_score,

                "timestamp": formatted_time,

                "body": body,

                "scan_date":
                datetime.now().strftime(
                    "%Y-%m-%d"
                ),

            })

            # =========================
            # DUPLICATE CHECK
            # =========================

            message_id = msg.get(
                "Message-ID",
                str(email_id)
            )
            already_exists = (
                ThreatHistory.objects.filter(
                    message_id=message_id
                ).exists()
            )

            # =========================
            # SAVE DATABASE
            # =========================

            if not already_exists:

                ThreatHistory.objects.create(

                    source_type="email",

                    message_id=message_id,

                    content=body,

                    result=
                    "PHISHING"
                    if result_label == "phishing"
                    else "SAFE",

                    phishing_probability=
                    phishing_score,

                    safe_score=
                    safe_score,

                    tactics=[]

                )

        # =========================
        # RISK LEVEL
        # =========================

        if phishing_count >= 5:

            risk_level = "HIGH"

        elif phishing_count >= 2:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"

        # =========================
        # SAVE SESSION
        # =========================

        request.session[
            "email_history"
        ] = email_history

        request.session[
            "total_emails_scanned"
        ] = total_email_count

        request.session[
            "phishing_count"
        ] = phishing_count

        request.session[
            "safe_count"
        ] = safe_count

        request.session[
            "risk_level"
        ] = risk_level

        return JsonResponse({

            "emails": email_history,

            "total_emails":
            total_email_count,

            "phishing_count":
            phishing_count,

            "safe_count":
            safe_count,

            "risk_level":
            risk_level

        })

    except Exception as e:

        print("EMAIL FETCH ERROR:", e)

        return JsonResponse({
            "emails": []
        })