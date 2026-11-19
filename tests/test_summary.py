"""Tests for the results summary."""

from pathlib import Path

from promptshield.attacks.loader import load_attacks
from promptshield.models import (
    Attack,
    AttackCategory,
    AttackResult,
    Finding,
    Severity,
)
from promptshield.reports.summary import Summary, Tally, format_summary, summarize
from promptshield.runner import run_attacks
from promptshield.scoring.canary import CanaryScorer
from promptshield.targets.mock import MockTarget

REAL_RULES = Path(__file__).parent.parent / "rules" / "prompt_injection.json"


def make_finding(category, severity, succeeded, error=None) -> Finding:
    attack = Attack(
        id="T-001",
        name="Test attack",
        category=category,
        payload="p",
        severity=severity,
    )
    result = AttackResult(attack=attack, response="", error=error)
    return Finding(result=result, succeeded=succeeded)


def test_empty_findings_give_an_empty_summary():
    summary = summarize([])
    assert summary == Summary()
    assert summary.overall.total == 0
    assert summary.by_category == {}


def test_tally_rate():
    assert Tally(total=4, succeeded=2).rate == 0.5
    assert Tally(total=0, succeeded=0).rate == 0.0


def test_overall_counts():
    findings = [
        make_finding(AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, True),
        make_finding(AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, False),
        make_finding(AttackCategory.JAILBREAK, Severity.HIGH, True),
    ]
    summary = summarize(findings)
    assert summary.overall == Tally(total=3, succeeded=2)


def test_groups_by_category():
    findings = [
        make_finding(AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, True),
        make_finding(AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, False),
        make_finding(AttackCategory.JAILBREAK, Severity.HIGH, True),
    ]
    summary = summarize(findings)
    assert summary.by_category == {
        "prompt_injection": Tally(total=2, succeeded=1),
        "jailbreak": Tally(total=1, succeeded=1),
    }


def test_groups_by_severity():
    findings = [
        make_finding(AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, True),
        make_finding(AttackCategory.PROMPT_INJECTION, Severity.MEDIUM, False),
        make_finding(AttackCategory.JAILBREAK, Severity.HIGH, True),
    ]
    summary = summarize(findings)
    assert summary.by_severity == {
        "medium": Tally(total=2, succeeded=1),
        "high": Tally(total=1, succeeded=1),
    }


def test_errors_are_counted_but_not_judged():
    findings = [
        make_finding(AttackCategory.JAILBREAK, Severity.HIGH, True),
        make_finding(AttackCategory.JAILBREAK, Severity.HIGH, False, error="timeout"),
    ]
    summary = summarize(findings)
    assert summary.errors == 1
    assert summary.overall == Tally(total=1, succeeded=1)


def test_real_attacks_against_vulnerable_mock():
    findings = run_attacks(
        load_attacks(REAL_RULES), MockTarget(vulnerable=True), CanaryScorer()
    )
    summary = summarize(findings)
    assert summary.overall == Tally(total=5, succeeded=5)
    assert summary.by_category["prompt_injection"] == Tally(total=5, succeeded=5)
    assert summary.by_severity["medium"] == Tally(total=3, succeeded=3)
    assert summary.by_severity["high"] == Tally(total=2, succeeded=2)


def test_format_summary_contains_the_key_numbers():
    findings = run_attacks(
        load_attacks(REAL_RULES), MockTarget(vulnerable=True), CanaryScorer()
    )
    text = format_summary(summarize(findings))
    assert "prompt_injection: 5/5 (100%)" in text
    assert "high: 2/2 (100%)" in text
    assert "Errors (not judged): 0" in text
