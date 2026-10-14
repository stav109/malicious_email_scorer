"""
Look-alike domain analyzer: domains built to be mistaken for a famous brand.

Attackers register domains the eye "autocorrects":
  paypa1.com      digit 1 instead of the letter l         (look-alike characters)
  rnicrosoft.com  "rn" reads as "m"                        (look-alike characters)
  pаypal.com      Cyrillic "а" instead of Latin "a"        (look-alike characters)
  amazom.com      one letter off                           (typo-squatting)
  paypal.com.secure-login.xyz / paypal-verify.top          (brand name inside a foreign domain)

This catches cases the sender analyzer misses: the display name doesn't have
to mention the brand at all, and it also checks every link's domain.
"""
from app.analyzers.base import Finding
from app.analyzers.brands import BRANDS
from app.analyzers.domains import base_domain, parse_address
from app.analyzers.links import _host, extract_links
from app.schemas import EmailInput

MAX_LABEL = 63  # longest valid DNS label; also bounds the distance computation

# Official domain names too generic to compare against ("live", "office"...)
# or that are just technical extras of a brand already covered.
GENERIC_NAMES = {
    "live", "office", "outlook", "meta", "youtube", "microsoftonline", "facebookmail",
    "amazonaws", "googleapis", "googleusercontent", "gstatic", "googlemail", "bankleumi",
}

# Typo matching needs names long enough that one changed letter is unlikely
# to produce a real word: "apple" is one letter from "apply", "icloud" from "cloud".
MIN_TYPO_LENGTH = 6
NO_TYPO_MATCH = {"icloud"}

# Characters and pairs that look alike. Both sides of every comparison are
# normalized the same way, so "paypa1" and "paypal" both become "paypal".
CYRILLIC_LOOKALIKES = str.maketrans("аеорсухіјԁѕɡ", "aeorcyxijdsg")
SEQUENCE_LOOKALIKES = [("rn", "m"), ("vv", "w"), ("cl", "d")]
CHAR_LOOKALIKES = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s"})


def _brand_targets() -> dict[str, tuple[str, str]]:
    """{'paypal': ('PayPal', 'paypal.com'), ...} built from the brand list."""
    targets = {}
    for names, domains in BRANDS.values():
        for domain in sorted(domains):
            name = domain.split(".")[0]
            if name not in GENERIC_NAMES:
                targets[name] = (names[0], domain)
    return targets


BRAND_TARGETS = _brand_targets()
OFFICIAL = {d for _, domains in BRANDS.values() for d in domains}


def _decode_punycode(host: str) -> str:
    """xn--pypal-4ve.com -> pаypal.com (with the Cyrillic letter revealed)."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def normalize(name: str) -> str:
    name = name.lower().translate(CYRILLIC_LOOKALIKES)
    for seq, replacement in SEQUENCE_LOOKALIKES:
        name = name.replace(seq, replacement)
    return name.translate(CHAR_LOOKALIKES)


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance: single-character edits needed to turn a into b."""
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                previous[j] + 1,                  # delete
                current[j - 1] + 1,               # insert
                previous[j - 1] + (ca != cb),     # substitute
            ))
        previous = current
    return previous[-1]


def check_domain(host: str) -> tuple[str, str, str] | None:
    """
    Returns (kind, brand display name, official domain) if host imitates a brand,
    where kind is "homoglyph", "typo" or "brand_in_domain"; otherwise None.
    """
    host = _decode_punycode(host.lower().strip("."))
    if base_domain(host) in OFFICIAL:
        return None

    name = base_domain(host).split(".")[0][:MAX_LABEL]
    if name in BRAND_TARGETS:
        return None  # same name on another TLD (google.co.il); see README limitations

    # Compare the whole name and each hyphen-separated part of it, so that
    # "linkedln-mail.com" is caught through its "linkedln" part
    parts = [name] + [p for p in name.split("-") if p and p != name]
    for part in parts:
        normalized = normalize(part)
        for brand_name, (display, official) in BRAND_TARGETS.items():
            if part == brand_name:
                continue  # exact brand word: handled as brand_in_domain below
            if normalized == normalize(brand_name):
                return "homoglyph", display, official
            allowed = 1 if len(brand_name) < 8 else 2
            long_enough = len(brand_name) >= MIN_TYPO_LENGTH and brand_name not in NO_TYPO_MATCH
            if long_enough and edit_distance(normalized, normalize(brand_name)) <= allowed:
                return "typo", display, official

    # Brand name as a separate word anywhere in the host:
    # paypal-verify.top, paypal.com.secure-login.xyz
    words = set(host.replace("-", ".").split("."))
    for brand_name, (display, official) in BRAND_TARGETS.items():
        if brand_name in words:
            return "brand_in_domain", display, official
    return None


def _candidate_hosts(email: EmailInput) -> list[str]:
    hosts = []
    for raw in (email.from_, email.replyTo):
        domain = parse_address(raw)[2]
        if domain:
            hosts.append(domain)
    for link in extract_links(email):
        host = _host(link.href)
        if host:
            hosts.append(host)
    return list(dict.fromkeys(hosts))


def analyze(email: EmailInput) -> list[Finding]:
    hits: dict[str, list[str]] = {"homoglyph": [], "typo": [], "brand_in_domain": []}

    for host in _candidate_hosts(email):
        result = check_domain(host)
        if result:
            kind, display, official = result
            hits[kind].append(f"'{host}' imitates {display} ({official})")

    findings: list[Finding] = []

    def add(kind: str, signal: str, points: int, message: str) -> None:
        examples = list(dict.fromkeys(hits[kind]))
        if examples:
            more = f" (and {len(examples) - 1} more)" if len(examples) > 1 else ""
            findings.append(Finding(signal, points, f"{message}: {examples[0]}{more}."))

    add("homoglyph", "lookalike_characters", 40,
        "A domain swaps in look-alike characters to imitate a well-known brand")
    add("typo", "lookalike_typo", 35, "A domain is a near-misspelling of a well-known brand")
    add("brand_in_domain", "lookalike_brand_name", 25,
        "A domain uses a well-known brand's name but does not belong to it")
    return findings
