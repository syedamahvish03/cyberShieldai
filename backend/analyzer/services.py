from pathlib import Path
import ipaddress
import re
from urllib.parse import urlsplit

import joblib


# Load the existing trained models.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_DIR = PROJECT_ROOT / "ml_model"

email_model = joblib.load(MODEL_DIR / "email_model.pkl")
email_vectorizer = joblib.load(MODEL_DIR / "email_vectorizer.pkl")

sms_model = joblib.load(MODEL_DIR / "sms_model.pkl")
sms_vectorizer = joblib.load(MODEL_DIR / "sms_vectorizer.pkl")


# Find web links inside messages.
URL_PATTERN = re.compile(
    r"""(?:https?://|www\.)[^\s<>"']+""",
    re.IGNORECASE,
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}


def analyze_urls(text):
    """
    Find links and identify common suspicious URL characteristics.
    These checks are indicators, not proof that a link is malicious.
    """

    urls = URL_PATTERN.findall(text)
    results = []

    for original_url in urls:
        url = original_url.rstrip(".,!?;:)]}")

        if url.lower().startswith("www."):
            parsed = urlsplit("https://" + url)
        else:
            parsed = urlsplit(url)

        hostname = parsed.hostname
        indicators = []

        if not hostname:
            continue

        hostname = hostname.lower()

        # Check whether the link uses an IP address instead of a domain.
        try:
            ipaddress.ip_address(hostname)
            indicators.append("Link uses an IP address")
        except ValueError:
            pass

        # Check common URL-shortening services.
        if hostname in SHORTENER_DOMAINS:
            indicators.append("Uses a URL-shortening service")

        # Check for internationalized domain-name encoding.
        if "xn--" in hostname:
            indicators.append("Contains an encoded domain name")

        # Check whether the URL contains embedded login details.
        if parsed.username or parsed.password:
            indicators.append("Contains unusual embedded credentials")

        # Check for unusually deep subdomains.
        if hostname.count(".") >= 4:
            indicators.append("Contains many domain levels")

        # HTTP is less secure than HTTPS, but is not proof of phishing.
        if parsed.scheme.lower() == "http":
            indicators.append("Uses an unencrypted HTTP connection")

        results.append({
            "url": url,
            "indicators": indicators,
            "needs_review": bool(indicators),
        })

    flagged_count = sum(
        1 for item in results if item["needs_review"]
    )

    return {
        "link_count": len(results),
        "links_needing_review": flagged_count,
        "urls": results,
    }


def analyze_text(text, content_type):
    """
    Analyze email or SMS text using the existing trained models.
    Also checks links found inside the submitted message.
    """

    if content_type not in ("email", "sms"):
        raise ValueError("Content type must be email or sms.")

    if not isinstance(text, str):
        raise ValueError("Content must be text.")

    text = text.strip()

    if len(text) < 15:
        raise ValueError("Input must contain at least 15 characters.")

    if len(text) > 20000:
        raise ValueError("Input cannot exceed 20,000 characters.")

    if content_type == "sms":
        model = sms_model
        vectorizer = sms_vectorizer
    else:
        model = email_model
        vectorizer = email_vectorizer

    vector = vectorizer.transform([text])

    prediction = int(model.predict(vector)[0])
    probabilities = model.predict_proba(vector)[0]

    classes = list(model.classes_)

    if 1 not in classes or 0 not in classes:
        raise RuntimeError("The model does not contain the expected classes.")

    phishing_index = classes.index(1)
    safe_index = classes.index(0)

    phishing_probability = float(
        probabilities[phishing_index]
    ) * 100

    safe_score = round(
        float(probabilities[safe_index]) * 100,
        2,
    )

    # Detect common manipulation tactics.
    # Detect manipulation tactics using contextual phrases.
    import re

    text_lower = text.lower()

    tactics = []

    tactic_patterns = {
        "Urgency Pressure": [
            r"\bact immediately\b",
            r"\brespond immediately\b",
            r"\bverify immediately\b",
            r"\burgent action required\b",
            r"\bact now\b",
            r"\brespond now\b",
            r"\bwithin \d+ (minutes?|hours?)\b",
            r"\bexpires? today\b",
            r"\bfinal warning\b",
            r"\baccount will be (blocked|suspended|closed)\b",
        ],

        "Fear Manipulation": [
            r"\baccount (has been|will be) suspended\b",
            r"\baccount (has been|will be) blocked\b",
            r"\bpermanently disabled\b",
            r"\bunauthorized access detected\b",
            r"\byour account is at risk\b",
            r"\bavoid (account )?suspension\b",
            r"\bsecurity alert\b",
        ],

        "Fake Authority": [
            r"\bwe are from (your )?(bank|government|support team)\b",
            r"\bofficial (bank|government|support) team\b",
            r"\bverify your (bank )?account\b",
            r"\bgovernment authorities\b",
            r"\baccount security department\b",
            r"\bbank security department\b",
        ],

        "Reward Scam": [
            r"\byou have won\b",
            r"\byou are the winner\b",
            r"\bclaim your prize\b",
            r"\bclaim your reward\b",
            r"\bfree gift waiting\b",
            r"\bcongratulations.{0,40}(prize|reward|won)\b",
        ],
    }

    for tactic, patterns in tactic_patterns.items():
        if any(re.search(pattern, text_lower) for pattern in patterns):
            tactics.append(tactic)

    # Check links separately from the trained model's prediction.
    url_analysis = analyze_urls(text)

    return {
        "prediction": prediction,
        "result": "PHISHING" if prediction == 1 else "SAFE",
        "phishing_probability": round(phishing_probability, 2),
        "safe_score": safe_score,
        "tactics": tactics,
        "content_type": content_type,
        "url_analysis": url_analysis,
    }