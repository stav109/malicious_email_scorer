from app.analyzers import content
from tests.helpers import make_email


def signals(subject="", body=""):
    return [f.signal for f in content.analyze(make_email(subject=subject, plainBody=body))]


def test_ordinary_email_has_no_findings():
    assert signals("Lunch tomorrow?", "Want to grab lunch at 12?") == []


def test_urgency_and_credentials():
    found = signals(
        "Action required",
        "Your account will be suspended within 24 hours. Verify your account now.",
    )
    assert found == ["content_urgency", "content_credentials"]


def test_whole_words_only():
    # "insurgent" contains "urgent" but is not pressure language
    assert signals(body="A documentary about the insurgent movement.") == []


def test_hebrew_package_scam():
    found = signals("דואר ישראל", "שלום, חבילה ממתינה לך. יש לשלם דמי מכס תוך 24 שעות.")
    assert found == ["content_urgency", "content_delivery_fee"]


def test_hebrew_with_prefix():
    # "והחשבון ... נחסם" - Hebrew prefixes must not prevent a match
    assert signals(body="שימו לב: החשבון שלכם נחסם") == ["content_urgency"]


def test_each_category_counts_once():
    found = content.analyze(make_email(plainBody="urgent! urgent! act now! immediately!"))
    assert len(found) == 1


def test_reason_quotes_our_phrase_not_the_email():
    found = content.analyze(make_email(plainBody="<script>URGENT</script>"))
    assert found[0].reason.endswith(': "urgent".')
