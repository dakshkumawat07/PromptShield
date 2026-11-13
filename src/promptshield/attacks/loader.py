"""Load attack definitions from JSON rule files."""

import json
from pathlib import Path

from promptshield.models import Attack, AttackCategory, Severity


class RuleError(ValueError):
    """Raised when a rule file is missing, malformed or inconsistent."""


def load_attacks(path: str | Path) -> list[Attack]:
    """Read a JSON rule file and return its attacks as Attack objects."""
    path = Path(path)

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleError(f"{path}: invalid JSON ({exc})") from exc

    if not isinstance(raw, list):
        raise RuleError(f"{path}: expected a list of attacks")

    attacks: list[Attack] = []
    for index, item in enumerate(raw):
        try:
            attacks.append(
                Attack(
                    id=item["id"],
                    name=item["name"],
                    category=AttackCategory(item["category"]),
                    payload=item["payload"],
                    description=item.get("description", ""),
                    severity=Severity(item.get("severity", "medium")),
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise RuleError(f"{path}: attack #{index} is invalid ({exc!r})") from exc

    ids = [attack.id for attack in attacks]
    if len(ids) != len(set(ids)):
        raise RuleError(f"{path}: duplicate attack ids found")

    return attacks
