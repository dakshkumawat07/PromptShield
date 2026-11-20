"""Command-line interface for PromptShield."""

import argparse
import sys
from collections.abc import Callable, Sequence

from promptshield import __version__
from promptshield.attacks.loader import RuleError, load_attacks
from promptshield.models import Finding
from promptshield.reports.summary import format_summary, summarize
from promptshield.runner import run_attacks
from promptshield.scoring.canary import CanaryScorer
from promptshield.targets.base import Target
from promptshield.targets.mock import MockTarget

TARGETS: dict[str, Callable[[], Target]] = {
    "mock-vulnerable": lambda: MockTarget(vulnerable=True),
    "mock-secure": lambda: MockTarget(vulnerable=False),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="promptshield",
        description="Red-team toolkit for LLM applications.",
    )
    parser.add_argument(
        "--version", action="version", version=f"promptshield {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run attacks against a target.")
    run.add_argument("--rules", required=True, help="Path to a JSON attack rule file.")
    run.add_argument(
        "--target",
        choices=sorted(TARGETS),
        default="mock-vulnerable",
        help="Which target to attack (default: mock-vulnerable).",
    )
    run.add_argument(
        "--fail-on-success",
        action="store_true",
        help="Exit with code 1 if any attack succeeds (useful in CI).",
    )
    return parser


def describe(finding: Finding) -> str:
    """One line per attack for the terminal."""
    attack = finding.result.attack
    if finding.result.error is not None:
        status = "ERROR"
    elif finding.succeeded:
        status = "SUCCESS"
    else:
        status = "blocked"
    return f"  [{status}] {attack.id} {attack.name}"


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        attacks = load_attacks(args.rules)
    except (OSError, RuleError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    target = TARGETS[args.target]()
    findings = run_attacks(attacks, target, CanaryScorer())
    summary = summarize(findings)

    print(f"Target: {target.name}")
    for finding in findings:
        print(describe(finding))
    print()
    print(format_summary(summary))

    if args.fail_on_success and summary.overall.succeeded > 0:
        return 1
    return 0
