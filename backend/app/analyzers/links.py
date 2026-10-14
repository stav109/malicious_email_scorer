"""
Link analyzer: do the links in the email go where they claim to go?

Security note: links are only parsed as text. We never visit them.
Fetching a URL from a malicious email could confirm to the attacker that
the email was opened, download malware, or make our server request
internal addresses on the attacker's behalf (SSRF).
"""
import ipaddress
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

from app.analyzers.base import Finding
from app.analyzers.brands import BRANDS
from app.analyzers.domains import base_domain
from app.schemas import EmailInput

CATEGORY = "Links"

# Cap work per email: a hostile email could contain thousands of links
MAX_LINKS = 300

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy",
}

# Cheap TLDs that appear disproportionately in phishing campaigns
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf",
    "ga", "work", "rest", "cam", "icu", "buzz",
}

# Email marketing platforms rewrite every link through their own tracking
# domain, so "text says shop.com, link goes to sendgrid.net" is normal there.
TRACKING_DOMAINS = {
    "sendgrid.net", "list-manage.com", "mailchimp.com", "mcsv.net",
    "mandrillapp.com", "mailgun.org", "hubspotlinks.com", "hs-sites.com",
    "sparkpostmail.com", "exacttarget.com", "rs6.net", "mailjet.com",
}

OFFICIAL_BRAND_DOMAINS = {d for _, domains in BRANDS.values() for d in domains}

# Visible text that looks like a URL or a bare domain, e.g. "paypal.com/login"
DOMAIN_LIKE_TEXT = re.compile(
    r"^(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?$"
)
PLAIN_TEXT_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass(frozen=True)
class Link:
    href: str
    text: str  # visible text; empty for links found in plain text


class _LinkCollector(HTMLParser):
    """Collects <a href> targets with their visible text. Never executes anything."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._flush()  # handles an <a> that was never closed
            self._href = dict(attrs).get("href") or None
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a":
            self._flush()

    def close(self):
        super().close()
        self._flush()

    def _flush(self):
        if self._href is not None and len(self.links) < MAX_LINKS:
            text = " ".join("".join(self._text).split())
            self.links.append(Link(self._href.strip(), text))
        self._href = None
        self._text = []


def extract_links(email: EmailInput) -> list[Link]:
    collector = _LinkCollector()
    collector.feed(email.htmlBody)
    collector.close()
    links = collector.links

    # Plain-text emails have no <a> tags; pick up bare URLs instead
    if not links:
        links = [Link(url, "") for url in PLAIN_TEXT_URL.findall(email.plainBody)]

    unique = list(dict.fromkeys(links))  # dedupe, keep order
    return unique[:MAX_LINKS]


def url_host(url: str) -> str | None:
    """Returns the lowercase host of an http(s) URL, or None for other links."""
    try:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ("http", "https"):
            return None  # mailto:, tel:, #anchors and similar
        return parts.hostname  # already lowercase, without user info or port
    except ValueError:
        return None  # malformed URL


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _displayed_domain(text: str) -> str | None:
    match = DOMAIN_LIKE_TEXT.match(text.lower())
    return match.group(1) if match else None


def analyze(email: EmailInput) -> list[Finding]:
    hits: dict[str, list[str]] = {
        "brand": [], "deceptive": [], "ip": [], "userinfo": [],
        "punycode": [], "shortener": [], "tld": [], "http": [],
    }

    for link in extract_links(email):
        host = url_host(link.href)
        if host is None:
            continue
        host_base = base_domain(host)

        # Visible text names one domain, the link goes to another
        shown = _displayed_domain(link.text)
        if shown and base_domain(shown) != host_base and host_base not in TRACKING_DOMAINS:
            key = "brand" if base_domain(shown) in OFFICIAL_BRAND_DOMAINS else "deceptive"
            hits[key].append(f"'{link.text}' leads to {host}")

        if _is_ip(host):
            hits["ip"].append(host)
        # https://paypal.com@evil.xyz/ really goes to evil.xyz
        if "@" in (urlsplit(link.href).netloc or ""):
            hits["userinfo"].append(host)
        if any(label.startswith("xn--") for label in host.split(".")):
            hits["punycode"].append(host)
        if host_base in URL_SHORTENERS:
            hits["shortener"].append(host)
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            hits["tld"].append(host)
        if link.href.lower().startswith("http://"):
            hits["http"].append(host)

    findings: list[Finding] = []

    def add(key: str, signal: str, points: int, message: str) -> None:
        examples = list(dict.fromkeys(hits[key]))
        if examples:
            more = f" (and {len(examples) - 1} more)" if len(examples) > 1 else ""
            findings.append(Finding(signal, points, f"{message}: {examples[0]}{more}."))

    add("brand", "link_text_brand_mismatch", 35, "A link shows a well-known brand's address but goes elsewhere")
    add("deceptive", "link_text_mismatch", 20, "A link's text shows one address but goes to another")
    add("userinfo", "link_userinfo_trick", 30, "A link hides its real destination behind an '@' sign")
    add("ip", "link_to_ip_address", 25, "A link points to a raw IP address instead of a domain name")
    add("punycode", "link_punycode", 25, "A link uses look-alike international characters in its domain")
    add("shortener", "link_shortener", 10, "A link uses a URL shortener that hides its real destination")
    add("tld", "link_suspicious_tld", 10, "A link goes to a domain ending often used in phishing")
    add("http", "link_insecure_http", 5, "A link uses unencrypted HTTP")
    return findings
