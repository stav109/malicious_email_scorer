"""
Sender authentication analyzer (SPF / DKIM / DMARC).

We do not re-run these checks ourselves: Gmail's receiving server already did,
and it knows things we don't (such as the sending server's IP address).
We read its verdict from the Authentication-Results header.

Security note: anyone can put a fake "Authentication-Results: dmarc=pass" header
into an email they send. We only trust the header written by Gmail itself,
which starts with Google's server id, "mx.google.com".
"""
import re

from app.analyzers.base import Finding
from app.schemas import EmailInput

CATEGORY = "Sender authentication"

TRUSTED_AUTHSERV_ID = "mx.google.com"

# Matches results such as "spf=pass", "dkim=fail", "dmarc=softfail"
RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.IGNORECASE)


def parse_auth_results(header: str) -> dict[str, list[str]] | None:
    """
    Returns {"spf": [...], "dkim": [...], "dmarc": [...]}, or None if the
    header is missing or was not written by Gmail.
    A method can appear more than once (an email can carry several DKIM signatures).
    """
    authserv_id = header.split(";", 1)[0].strip().lower()
    if authserv_id != TRUSTED_AUTHSERV_ID:
        return None

    results: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
    for method, result in RESULT_PATTERN.findall(header):
        results[method.lower()].append(result.lower())
    return results


def analyze(email: EmailInput) -> list[Finding]:
    header = email.headers.authenticationResults

    # Gmail stamps every email that arrives from outside. Mail sent within the
    # same account (or the same Google Workspace organization) never crosses
    # that border, so it has no header at all. That is not a risk signal.
    if not header.strip():
        return []

    results = parse_auth_results(header)
    if results is None:
        return [Finding(
            signal="auth_unverified",
            points=10,
            reason="The sender's authentication results were not written by Gmail, so the sender could not be verified.",
        )]

    # DMARC is the strongest signal: it combines SPF/DKIM with a check that the
    # authenticated domain matches the visible From address.
    if "fail" in results["dmarc"]:
        return [Finding(
            signal="dmarc_fail",
            points=40,
            reason="The sender failed DMARC: the domain in the From address did not authorize this email.",
        )]

    findings: list[Finding] = []

    spf = results["spf"]
    if "fail" in spf:
        findings.append(Finding(
            signal="spf_fail",
            points=20,
            reason="The sending server is not authorized to send email for this domain (SPF fail).",
        ))
    elif "softfail" in spf:
        findings.append(Finding(
            signal="spf_softfail",
            points=10,
            reason="The sending server is probably not authorized to send for this domain (SPF softfail).",
        ))

    dkim = results["dkim"]
    if "pass" not in dkim and "fail" in dkim:
        findings.append(Finding(
            signal="dkim_fail",
            points=15,
            reason="The email's digital signature is invalid, so it may have been altered (DKIM fail).",
        ))

    return findings
