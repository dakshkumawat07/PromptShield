"""Tests for the command-line interface."""

from pathlib import Path

import pytest

from promptshield import __version__
from promptshield.cli import main

RULES = str(Path(__file__).parent.parent / "rules" / "prompt_injection.json")


def test_run_against_vulnerable_target(capsys):
    code = main(["run", "--rules", RULES, "--target", "mock-vulnerable"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Target: mock-vulnerable" in out
    assert "[SUCCESS] PI-001" in out
    assert "succeeded: 5 (100%)" in out


def test_run_against_secure_target(capsys):
    code = main(["run", "--rules", RULES, "--target", "mock-secure"])
    out = capsys.readouterr().out
    assert code == 0
    assert "[blocked] PI-001" in out
    assert "succeeded: 0 (0%)" in out


def test_default_target_is_the_vulnerable_mock(capsys):
    main(["run", "--rules", RULES])
    assert "Target: mock-vulnerable" in capsys.readouterr().out


def test_fail_on_success_returns_1_when_attacks_succeed():
    assert main(["run", "--rules", RULES, "--fail-on-success"]) == 1


def test_fail_on_success_returns_0_when_all_blocked():
    code = main(
        ["run", "--rules", RULES, "--target", "mock-secure", "--fail-on-success"]
    )
    assert code == 0


def test_missing_rules_file_returns_2(capsys):
    code = main(["run", "--rules", "does/not/exist.json"])
    assert code == 2
    assert "error" in capsys.readouterr().err


def test_invalid_rules_file_returns_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    code = main(["run", "--rules", str(bad)])
    assert code == 2
    assert "invalid JSON" in capsys.readouterr().err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_command_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2
