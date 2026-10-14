"""
Data contracts between the Gmail add-on and the backend.

Everything in EmailInput comes from an email, so it is untrusted input.
Pydantic validates every request against these models before our code runs:
wrong types, unknown fields or oversized values are rejected with HTTP 422.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Same limits the add-on applies, enforced again here.
# The backend never trusts the client to have done it.
MAX_BODY_CHARS = 50_000
MAX_HEADER_CHARS = 2_000
MAX_ATTACHMENTS = 50


class StrictModel(BaseModel):
    # extra="forbid": reject any field we did not define
    model_config = ConfigDict(extra="forbid")


class Headers(StrictModel):
    authenticationResults: str = Field(default="", max_length=MAX_HEADER_CHARS)
    returnPath: str = Field(default="", max_length=MAX_HEADER_CHARS)


class Attachment(StrictModel):
    name: str = Field(max_length=500)
    contentType: str = Field(default="", max_length=200)
    size: int = Field(ge=0)
    # Lowercase hex SHA-256, or null if the file was too big to hash
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class EmailInput(StrictModel):
    # "from" is a Python keyword, so the field is from_ and the JSON key is "from"
    from_: str = Field(alias="from", max_length=MAX_HEADER_CHARS)
    replyTo: str = Field(default="", max_length=MAX_HEADER_CHARS)
    subject: str = Field(default="", max_length=MAX_HEADER_CHARS)
    date: str = Field(default="", max_length=100)
    headers: Headers = Field(default_factory=Headers)
    plainBody: str = Field(default="", max_length=MAX_BODY_CHARS)
    htmlBody: str = Field(default="", max_length=MAX_BODY_CHARS)
    attachments: list[Attachment] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)


class FindingOut(BaseModel):
    category: str
    points: int
    reason: str


class AnalysisResult(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Literal["safe", "suspicious", "malicious"]
    reasons: list[str]  # kept for older add-on versions; same order as findings
    findings: list[FindingOut] = []
