from app.analyzers import links
from tests.helpers import make_email


def signals(html="", plain=""):
    email = make_email(htmlBody=html, plainBody=plain)
    return [f.signal for f in links.analyze(email)]


def test_honest_link_has_no_findings():
    assert signals('<a href="https://www.paypal.com/signin">paypal.com</a>') == []


def test_link_text_with_regular_words_is_ignored():
    assert signals('<a href="https://shop.com/sale">Click here for the sale</a>') == []


def test_brand_text_leading_elsewhere():
    html = '<a href="https://paypal-verify.top/login">www.paypal.com</a>'
    assert "link_text_brand_mismatch" in signals(html)


def test_non_brand_text_leading_elsewhere():
    html = '<a href="https://evil.example/x">mybank-portal.com</a>'
    assert signals(html) == ["link_text_mismatch"]


def test_marketing_tracking_links_are_not_deceptive():
    html = '<a href="https://u123.ct.sendgrid.net/ls/click?x=1">www.shop.com</a>'
    assert signals(html) == []


def test_ip_address_link():
    assert signals('<a href="http://185.23.4.1/login">Log in</a>') == [
        "link_to_ip_address", "link_insecure_http",
    ]


def test_userinfo_trick():
    # Looks like paypal.com, but the real host is evil.xyz
    found = signals('<a href="https://paypal.com@evil.xyz/login">Log in</a>')
    assert "link_userinfo_trick" in found
    assert "link_suspicious_tld" in found


def test_punycode_domain():
    assert signals('<a href="https://xn--pypal-4ve.com/">Log in</a>') == ["link_punycode"]


def test_url_shortener():
    assert signals('<a href="https://bit.ly/3abc">Track your package</a>') == ["link_shortener"]


def test_mailto_and_anchors_are_ignored():
    assert signals('<a href="mailto:a@b.com">a@b.com</a><a href="#top">Top</a>') == []


def test_plain_text_urls_are_checked_when_there_is_no_html():
    assert signals(plain="Verify now: http://10.0.0.5/verify") == [
        "link_to_ip_address", "link_insecure_http",
    ]


def test_many_bad_links_count_once():
    html = "".join(f'<a href="http://1.2.3.{i}/">x</a>' for i in range(10))
    found = links.analyze(make_email(htmlBody=html))
    ip_finding = next(f for f in found if f.signal == "link_to_ip_address")
    assert "and 9 more" in ip_finding.reason


def test_malformed_html_does_not_crash():
    assert signals('<a href="http://[broken/">unclosed <a href=https://ok.com>ok') == []
