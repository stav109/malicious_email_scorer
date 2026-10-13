from app.schemas import EmailInput


def make_email(**overrides) -> EmailInput:
    """Builds a minimal valid email; tests override only the fields they care about."""
    data = {"from": "Alice <alice@example.com>"}
    headers = overrides.pop("headers", None)
    data.update(overrides)
    if headers is not None:
        data["headers"] = headers
    return EmailInput.model_validate(data)


GMAIL_ALL_PASS = (
    "mx.google.com; dkim=pass header.i=@example.com header.s=s1; "
    "spf=pass (google.com: domain of bounce@example.com designates 1.2.3.4 as permitted sender) "
    "smtp.mailfrom=bounce@example.com; dmarc=pass (p=REJECT) header.from=example.com"
)
