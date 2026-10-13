"""
Sender identity analyzer: does the sender look like who they claim to be?

The display name ("PayPal") is free text the sender chooses; only the
address shows where the email really came from. Phishing relies on users
reading the name and not the address.
"""
import re

from app.analyzers.base import Finding
from app.analyzers.brands import BRANDS
from app.analyzers.domains import base_domain, is_free_email, parse_address
from app.schemas import EmailInput

EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+\.[\w.-]+)")


def _brand_in_name(display_name: str) -> str | None:
    """Returns the first brand whose name appears as a whole word in the display name."""
    lowered = display_name.lower()
    for brand, (names, _) in BRANDS.items():
        for name in names:
            if re.search(r"(?<!\w)" + re.escape(name.lower()) + r"(?!\w)", lowered):
                return brand
    return None


def analyze(email: EmailInput) -> list[Finding]:
    findings: list[Finding] = []
    display_name, address, domain = parse_address(email.from_)
    if not domain:
        return [Finding(
            signal="sender_unparseable",
            points=15,
            reason="The sender's address could not be read, which is unusual for legitimate email.",
        )]
    sender_base = base_domain(domain)

    # 1. Display name claims a brand the sending domain doesn't belong to
    brand = _brand_in_name(display_name)
    if brand is not None:
        names, official_domains = BRANDS[brand]
        if sender_base not in official_domains:
            findings.append(Finding(
                signal="display_name_brand_mismatch",
                points=35,
                reason=(
                    f"The sender name mentions '{names[0]}', but the email comes from "
                    f"'{domain}', which is not one of its official domains."
                ),
            ))

    # 2. Display name contains a different email address than the real one,
    #    e.g. "security@paypal.com <x@evil.xyz>"
    for shown_domain in EMAIL_IN_TEXT.findall(display_name):
        if base_domain(shown_domain) != sender_base:
            findings.append(Finding(
                signal="display_name_fake_address",
                points=25,
                reason=(
                    f"The sender name shows an address at '{shown_domain.lower()}', "
                    f"but the email was actually sent from '{domain}'."
                ),
            ))
            break

    # 3. Replies go somewhere other than the sender
    _, reply_address, reply_domain = parse_address(email.replyTo)
    if reply_domain and base_domain(reply_domain) != sender_base:
        if is_free_email(reply_domain) and not is_free_email(domain):
            findings.append(Finding(
                signal="reply_to_free_email",
                points=20,
                reason=(
                    f"Replies would go to a personal email account ({reply_address}) "
                    f"instead of the sender's organization ({domain})."
                ),
            ))
        else:
            findings.append(Finding(
                signal="reply_to_mismatch",
                points=15,
                reason=f"Replies would go to '{reply_domain}', a different domain than the sender's ('{domain}').",
            ))

    return findings
