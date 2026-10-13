"""
Helpers for working with email addresses and domain names.
"""
from email.utils import parseaddr

# Suffixes where the "real" domain has three labels, e.g. leumi.co.il.
# A full solution would use the Public Suffix List; this small set covers
# the cases we care about without a network dependency.
TWO_LEVEL_SUFFIXES = {
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "co.jp", "co.in", "com.br",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
    "yahoo.com", "icloud.com", "me.com", "aol.com", "proton.me",
    "protonmail.com", "gmx.com", "mail.com", "walla.co.il",
}


def parse_address(raw: str) -> tuple[str, str, str]:
    """
    Splits '"PayPal" <a@b.com>' into (display_name, address, domain).
    Everything is lowercased except the display name. Missing parts are "".
    """
    name, address = parseaddr(raw or "")
    address = address.strip().lower()
    domain = address.rsplit("@", 1)[1] if "@" in address else ""
    return name.strip(), address, domain


def base_domain(domain: str) -> str:
    """
    Reduces a hostname to the part its owner registered:
    mail.accounts.google.com -> google.com, mail.leumi.co.il -> leumi.co.il
    """
    labels = [label for label in domain.lower().strip(".").split(".") if label]
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_free_email(domain: str) -> bool:
    return base_domain(domain) in FREE_EMAIL_DOMAINS
