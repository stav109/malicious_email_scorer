from app.analyzers import authentication
from tests.helpers import GMAIL_ALL_PASS, make_email


def signals(email):
    return [f.signal for f in authentication.analyze(email)]


def test_all_pass_has_no_findings():
    email = make_email(headers={"authenticationResults": GMAIL_ALL_PASS})
    assert signals(email) == []


def test_dmarc_fail_is_reported_alone():
    header = "mx.google.com; spf=fail smtp.mailfrom=x.com; dkim=fail; dmarc=fail header.from=paypal.com"
    email = make_email(headers={"authenticationResults": header})
    # DMARC already summarizes SPF/DKIM, so we don't double-count them
    assert signals(email) == ["dmarc_fail"]


def test_spf_softfail():
    header = "mx.google.com; spf=softfail smtp.mailfrom=x.com; dkim=pass; dmarc=pass"
    email = make_email(headers={"authenticationResults": header})
    assert signals(email) == ["spf_softfail"]


def test_dkim_fail_ignored_if_another_signature_passes():
    header = "mx.google.com; dkim=fail header.i=@a.com; dkim=pass header.i=@b.com; spf=pass; dmarc=pass"
    email = make_email(headers={"authenticationResults": header})
    assert signals(email) == []


def test_missing_header_is_internal_mail_with_no_findings():
    # Email sent to yourself or within your organization has no such header
    email = make_email()
    assert signals(email) == []


def test_header_not_written_by_gmail_is_not_trusted():
    # An attacker can add their own "all pass" header; we must ignore it
    forged = "evil.example; spf=pass; dkim=pass; dmarc=pass"
    email = make_email(headers={"authenticationResults": forged})
    assert signals(email) == ["auth_unverified"]
