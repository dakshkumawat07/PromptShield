"""The interface every scorer must follow."""

from abc import ABC, abstractmethod

from promptshield.models import AttackResult, Finding


class Scorer(ABC):
    """Judges whether an attack succeeded, given the target's reply."""

    @abstractmethod
    def score(self, result: AttackResult) -> Finding:
        """Turn an AttackResult into a Finding."""
