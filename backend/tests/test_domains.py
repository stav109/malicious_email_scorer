from app.analyzers.domains import base_domain, is_free_email, parse_address


def test_parse_address_with_display_name():
    assert parse_address('"PayPal" <Security@PayPa1-Support.xyz>') == (
        "PayPal", "security@paypa1-support.xyz", "paypa1-support.xyz",
    )


def test_parse_address_without_display_name():
    assert parse_address("no-reply@us.greenhouse-mail.io") == (
        "", "no-reply@us.greenhouse-mail.io", "us.greenhouse-mail.io",
    )


def test_base_domain_strips_subdomains():
    assert base_domain("mail.accounts.google.com") == "google.com"


def test_base_domain_handles_israeli_suffix():
    assert base_domain("mail.leumi.co.il") == "leumi.co.il"


def test_free_email():
    assert is_free_email("gmail.com")
    assert not is_free_email("paypal.com")
