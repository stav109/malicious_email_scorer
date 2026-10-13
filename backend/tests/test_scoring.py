from app.analyzers.base import Finding
from app.scoring import score_findings, verdict_for


def test_no_findings_is_safe():
    result = score_findings([])
    assert result.score == 0
    assert result.verdict == "safe"
    assert result.reasons == []


def test_score_is_capped_at_100():
    findings = [Finding("a", 60, "A"), Finding("b", 60, "B")]
    assert score_findings(findings).score == 100


def test_reasons_are_ordered_by_points():
    findings = [Finding("low", 5, "Low"), Finding("high", 40, "High")]
    assert score_findings(findings).reasons == ["High", "Low"]


def test_verdict_thresholds():
    assert verdict_for(29) == "safe"
    assert verdict_for(30) == "suspicious"
    assert verdict_for(69) == "suspicious"
    assert verdict_for(70) == "malicious"
