"""Tests for the attack rule loader."""

import json
from pathlib import Path

import pytest

from promptshield.attacks.loader import RuleError, load_attacks
from promptshield.models import AttackCategory

REAL_RULES = Path(__file__).parent.parent / "rules" / "prompt_injection.json"


def write_json(tmp_path, data) -> Path:
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def valid_item(**overrides) -> dict:
    item = {
        "id": "T-001",
        "name": "Test attack",
        "category": "jailbreak",
        "payload": "hello",
    }
    item.update(overrides)
    return item


def test_real_rule_file_loads():
    attacks = load_attacks(REAL_RULES)
    assert len(attacks) == 5
    assert all(a.category == AttackCategory.PROMPT_INJECTION for a in attacks)
    assert all("PWNED-7731" in a.payload for a in attacks)


def test_optional_fields_get_defaults(tmp_path):
    attacks = load_attacks(write_json(tmp_path, [valid_item()]))
    assert attacks[0].description == ""
    assert attacks[0].severity == "medium"


def test_invalid_json_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(RuleError):
        load_attacks(path)


def test_top_level_must_be_a_list(tmp_path):
    with pytest.raises(RuleError):
        load_attacks(write_json(tmp_path, {"id": "x"}))


def test_missing_required_field_is_rejected(tmp_path):
    item = valid_item()
    del item["payload"]
    with pytest.raises(RuleError):
        load_attacks(write_json(tmp_path, [item]))


def test_unknown_category_is_rejected(tmp_path):
    with pytest.raises(RuleError):
        load_attacks(write_json(tmp_path, [valid_item(category="nonsense")]))


def test_duplicate_ids_are_rejected(tmp_path):
    with pytest.raises(RuleError):
        load_attacks(write_json(tmp_path, [valid_item(), valid_item()]))
