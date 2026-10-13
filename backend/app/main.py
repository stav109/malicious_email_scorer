"""
Backend entry point: receives email data from the add-on and returns a verdict.
"""
import logging

from fastapi import Depends, FastAPI

from app import config
from app.schemas import AnalysisResult, EmailInput
from app.scoring import analyze_email
from app.security import require_api_key

logger = logging.getLogger("uvicorn.error")

app = FastAPI(
    title="Malicious Email Scorer API",
    version="0.3.0",
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)

if not config.API_KEY:
    logger.warning("API_KEY is not set: /analyze will reject all requests")


@app.get("/health")
def health() -> dict:
    """Public on purpose: lets the hosting platform check that the server is up."""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalysisResult,
    dependencies=[Depends(require_api_key)],
)
def analyze(email: EmailInput) -> AnalysisResult:
    """Runs all analyzers on the email and returns the score, verdict and reasons."""
    return analyze_email(email)
