"""
Backend entry point: receives email data from the add-on and returns a verdict.
"""
import logging

from fastapi import Depends, FastAPI

from app import config
from app.schemas import AnalysisResult, EmailInput
from app.security import require_api_key

logger = logging.getLogger("uvicorn.error")

app = FastAPI(
    title="Malicious Email Scorer API",
    version="0.2.0",
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
    """
    Placeholder: returns a fixed result.
    The real analyzers and scoring engine are added in the next steps.
    """
    return AnalysisResult(
        score=0,
        verdict="safe",
        reasons=["Analysis not implemented yet"],
    )
