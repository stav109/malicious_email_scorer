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


def test_findings_carry_points_and_category():
    result = score_findings([Finding("a", 10, "A", category="Links")])
    assert result.findings[0].category == "Links"
    assert result.findings[0].points == 10


def test_every_analyzer_declares_a_category():
    from app.analyzers import ANALYZERS
    assert all(isinstance(a.CATEGORY, str) and a.CATEGORY for a in ANALYZERS)


def test_analyze_email_tags_categories():
    from app.scoring import analyze_email
    from tests.helpers import make_email
    email = make_email(htmlBody='<a href="http://1.2.3.4/">x</a>')
    assert {f.category for f in analyze_email(email).findings} == {"Links"}
