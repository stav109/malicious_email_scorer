from app.analyzers import sender
from tests.helpers import make_email


def signals(email):
    return [f.signal for f in sender.analyze(email)]


def test_legitimate_brand_sender_has_no_findings():
    email = make_email(**{"from": "PayPal <service@mail.paypal.com>"})
    assert signals(email) == []


def test_brand_name_from_wrong_domain():
    email = make_email(**{"from": "PayPal Security <security@paypa1-support.xyz>"})
    assert signals(email) == ["display_name_brand_mismatch"]


def test_hebrew_brand_name_from_wrong_domain():
    email = make_email(**{"from": "דואר ישראל <info@il-post-delivery.top>"})
    assert signals(email) == ["display_name_brand_mismatch"]


def test_brand_must_be_a_whole_word():
    # "Pineapple" contains "apple" but is not Apple
    email = make_email(**{"from": "Pineapple Bakery <hello@pineapplebakery.com>"})
    assert signals(email) == []


def test_fake_address_in_display_name():
    email = make_email(**{"from": '"support@bank.com" <x@evil.xyz>'})
    assert signals(email) == ["display_name_fake_address"]


def test_reply_to_free_email():
    email = make_email(**{"from": "CEO <ceo@company.com>", "replyTo": "ceo.private@gmail.com"})
    assert signals(email) == ["reply_to_free_email"]


def test_reply_to_other_domain():
    email = make_email(**{"from": "Shop <news@shop.com>", "replyTo": "replies@other.net"})
    assert signals(email) == ["reply_to_mismatch"]


def test_reply_to_same_organization_is_fine():
    email = make_email(**{"from": "Shop <news@mail.shop.com>", "replyTo": "help@shop.com"})
    assert signals(email) == []


def test_unparseable_sender():
    email = make_email(**{"from": "not an address"})
    assert signals(email) == ["sender_unparseable"]
