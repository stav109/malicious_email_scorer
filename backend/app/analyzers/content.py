"""
Content analyzer: does the text use the classic social-engineering levers?

These signals are deliberately low-weight. Legitimate emails also say
"urgent" or "verify your email"; wording alone should never make an email
look malicious, but it adds weight to the technical signals.

Includes Hebrew phrases, since local phishing (fake Israel Post customs
fees, bank lockouts) is written in Hebrew.
"""
import re

from app.analyzers.base import Finding
from app.schemas import EmailInput

# category -> (signal, points, explanation, phrases)
CATEGORIES = [
    (
        "content_urgency", 10,
        "The email pressures you to act quickly",
        [
            "urgent", "immediately", "within 24 hours", "within 48 hours", "act now",
            "final notice", "last warning", "will be suspended", "will be closed",
            "will be locked", "has been suspended", "has been locked",
            "דחוף", "באופן מיידי", "תוך 24 שעות", "הודעה אחרונה", "יושעה", "ייחסם", "נחסם",
        ],
    ),
    (
        "content_credentials", 15,
        "The email asks you to verify your account or enter sensitive details",
        [
            "verify your account", "confirm your account", "confirm your identity",
            "update your payment", "confirm your password", "enter your password",
            "login details", "update your billing", "credit card details",
            "אמת את החשבון", "אימות החשבון", "עדכן את פרטי התשלום", "הזן את הסיסמה",
            "פרטי כרטיס האשראי", "אמת את זהותך",
        ],
    ),
    (
        "content_money", 10,
        "The email talks about prizes, gift cards or unusual payments",
        [
            "you have won", "you've won", "gift card", "wire transfer", "bitcoin",
            "claim your prize", "lottery",
            "זכית", "כרטיס מתנה", "העברה בנקאית", "פרס",
        ],
    ),
    (
        "content_delivery_fee", 15,
        "The email asks for a delivery or customs fee, a common package scam",
        [
            "customs fee", "delivery fee", "package is waiting", "shipping fee",
            "redelivery", "חבילה ממתינה", "דמי מכס", "דמי משלוח", "תשלום מכס",
        ],
    ),
]


def _contains(text: str, phrase: str) -> bool:
    # English phrases must match whole words ("urgent" but not "insurgent");
    # Hebrew attaches prefixes like ה/ו/ב to words, so a plain substring is used.
    if phrase.isascii():
        return re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", text) is not None
    return phrase in text


def analyze(email: EmailInput) -> list[Finding]:
    text = f"{email.subject}\n{email.plainBody}".lower()
    findings: list[Finding] = []

    for signal, points, message, phrases in CATEGORIES:
        matched = [p for p in phrases if _contains(text, p)]
        if matched:
            # Quote our own phrase list, not the email text itself
            findings.append(Finding(signal, points, f"{message} (e.g. \"{matched[0]}\")."))
    return findings
