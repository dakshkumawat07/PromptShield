"""Core data models shared by every PromptShield component."""

from dataclasses import dataclass
from enum import StrEnum


class AttackCategory(StrEnum):
    """The family an attack belongs to."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"


class Severity(StrEnum):
    """How serious it is if an attack succeeds."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Attack:
    """A single attack: the payload we send to a target."""

    id: str
    name: str
    category: AttackCategory
    payload: str
    description: str = ""
    severity: Severity = Severity.MEDIUM


@dataclass
class AttackResult:
    """What a target answered when we sent it an attack."""

    attack: Attack
    response: str
    error: str | None = None


@dataclass
class Finding:
    """A judged result: did the attack work, and why."""

    result: AttackResult
    succeeded: bool
    explanation: str = ""
