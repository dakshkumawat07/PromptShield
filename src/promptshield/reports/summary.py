"""Summarise findings into counts by category and severity."""

from collections.abc import Iterable
from dataclasses import dataclass, field

from promptshield.models import Finding, Severity


@dataclass
class Tally:
    """How many attacks were judged and how many succeeded."""

    total: int = 0
    succeeded: int = 0

    @property
    def rate(self) -> float:
        """Share of judged attacks that succeeded, from 0.0 to 1.0."""
        return self.succeeded / self.total if self.total else 0.0


@dataclass
class Summary:
    """Counts for one run: overall, by category and by severity."""

    overall: Tally = field(default_factory=Tally)
    errors: int = 0
    by_category: dict[str, Tally] = field(default_factory=dict)
    by_severity: dict[str, Tally] = field(default_factory=dict)


def summarize(findings: Iterable[Finding]) -> Summary:
    """Count findings overall and grouped by category and severity."""
    summary = Summary()

    for finding in findings:
        if finding.result.error is not None:
            summary.errors += 1
            continue

        attack = finding.result.attack
        tallies = (
            summary.overall,
            summary.by_category.setdefault(attack.category.value, Tally()),
            summary.by_severity.setdefault(attack.severity.value, Tally()),
        )
        for tally in tallies:
            tally.total += 1
            if finding.succeeded:
                tally.succeeded += 1

    return summary


def format_summary(summary: Summary) -> str:
    """Render a summary as plain text for the terminal."""
    overall = summary.overall
    lines = [
        f"Attacks judged: {overall.total}, "
        f"succeeded: {overall.succeeded} ({overall.rate:.0%})",
        f"Errors (not judged): {summary.errors}",
        "By category:",
    ]

    for name in sorted(summary.by_category):
        tally = summary.by_category[name]
        lines.append(f"  {name}: {tally.succeeded}/{tally.total} ({tally.rate:.0%})")

    lines.append("By severity:")
    for severity in reversed(list(Severity)):
        tally = summary.by_severity.get(severity.value)
        if tally is not None:
            lines.append(
                f"  {severity.value}: {tally.succeeded}/{tally.total} ({tally.rate:.0%})"
            )

    return "\n".join(lines)
