"""
Backend entry point: receives email data from the add-on and returns a verdict.
"""
from fastapi import FastAPI

from app.schemas import AnalysisResult, EmailInput

app = FastAPI(title="Malicious Email Scorer API", version="0.1.0")


@app.get("/health")
def health() -> dict:
    """Lets us (and the hosting platform) check that the server is up."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisResult)
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
