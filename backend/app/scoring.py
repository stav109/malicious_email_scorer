"""
Scoring engine: runs every analyzer and turns their findings into one
score and one verdict.

The score is the sum of all findings' points, capped at 100.
Weights are set by hand per signal, based on how reliably it indicates
an attack. A single strong signal makes an email "suspicious"; it takes
several signals together to call it "malicious".
"""
from dataclasses import replace

from app.analyzers import ANALYZERS
from app.analyzers.base import Finding
from app.schemas import AnalysisResult, EmailInput, FindingOut

MAX_SCORE = 100
SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 70


def verdict_for(score: int) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "safe"


def score_findings(findings: list[Finding]) -> AnalysisResult:
    score = min(sum(f.points for f in findings), MAX_SCORE)
    # Most important reasons first
    ordered = sorted(findings, key=lambda f: f.points, reverse=True)
    return AnalysisResult(
        score=score,
        verdict=verdict_for(score),
        reasons=[f.reason for f in ordered],
        findings=[FindingOut(category=f.category, points=f.points, reason=f.reason) for f in ordered],
    )


def analyze_email(email: EmailInput) -> AnalysisResult:
    findings: list[Finding] = []
    for analyzer in ANALYZERS:
        # Tag each finding with its analyzer's category so the card can group them
        findings.extend(replace(f, category=analyzer.CATEGORY) for f in analyzer.analyze(email))
    return score_findings(findings)
