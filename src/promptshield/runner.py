"""Run attacks against a target and score the results."""

from collections.abc import Iterable

from promptshield.models import Attack, AttackResult, Finding
from promptshield.scoring.base import Scorer
from promptshield.targets.base import Target, TargetError


def run_attack(attack: Attack, target: Target, scorer: Scorer) -> Finding:
    """Send one attack to the target and return the scored finding."""
    try:
        response = target.send(attack.payload)
        result = AttackResult(attack=attack, response=response)
    except TargetError as exc:
        result = AttackResult(attack=attack, response="", error=str(exc))
    return scorer.score(result)


def run_attacks(
    attacks: Iterable[Attack], target: Target, scorer: Scorer
) -> list[Finding]:
    """Run every attack in order and return one finding per attack."""
    return [run_attack(attack, target, scorer) for attack in attacks]
