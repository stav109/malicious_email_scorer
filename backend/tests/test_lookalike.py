from app.analyzers import lookalike
from app.analyzers.lookalike import check_domain, edit_distance, normalize
from tests.helpers import make_email


def kind(host):
    result = check_domain(host)
    return result[0] if result else None


# --- building blocks ---

def test_normalize_maps_lookalike_characters():
    assert normalize("paypa1") == normalize("paypal")
    assert normalize("rnicrosoft") == normalize("microsoft")
    assert normalize("g00gle") == normalize("google")


def test_edit_distance():
    assert edit_distance("amazon", "amazom") == 1
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("netflix", "netfilx") == 2


# --- the three kinds of imitation ---

def test_lookalike_characters():
    assert kind("paypa1.com") == "homoglyph"
    assert kind("rnicrosoft.com") == "homoglyph"
    assert kind("g00gle.com") == "homoglyph"


def test_cyrillic_punycode_domain():
    # "pаypal.com" with a Cyrillic а, as it appears in a link
    assert kind("xn--pypal-4ve.com") == "homoglyph"


def test_typo_squatting():
    assert kind("amazom.com") == "typo"


def test_lookalike_inside_hyphenated_domain():
    assert kind("paypa1-secure.com") == "homoglyph"
    assert kind("linkedln-mail.com") == "homoglyph"


def test_brand_name_inside_foreign_domain():
    assert kind("paypal-verify.top") == "brand_in_domain"
    assert kind("paypal.com.secure-login.xyz") == "brand_in_domain"


# --- things that must NOT be flagged ---

def test_official_domains_are_fine():
    for host in ["paypal.com", "mail.paypal.com", "accounts.google.com", "fonts.googleapis.com"]:
        assert kind(host) is None, host


def test_unrelated_domains_are_fine():
    for host in ["greenhouse-mail.io", "adamtotal.co.il", "render.com", "github.com", "gmail.com"]:
        assert kind(host) is None, host


def test_short_brand_names_are_not_fuzzy_matched():
    # One letter away from a short brand name is usually just a real word
    assert kind("dhw.com") is None
    assert kind("apply-now.com") is None      # not "apple"
    assert kind("cloud-storage.com") is None  # not "icloud"


def test_same_name_on_country_domain_is_not_flagged():
    assert kind("google.co.il") is None
    assert kind("amazon.co.il") is None


# --- full analyzer ---

def test_checks_sender_and_links():
    email = make_email(**{
        "from": "Support <help@paypa1.com>",
        "htmlBody": '<a href="https://amazom.com/deal">deal</a>',
    })
    signals = [f.signal for f in lookalike.analyze(email)]
    assert signals == ["lookalike_characters", "lookalike_typo"]
