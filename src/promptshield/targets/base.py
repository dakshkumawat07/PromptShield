"""The interface every attack target must follow."""

from abc import ABC, abstractmethod


class TargetError(Exception):
    """Raised when a target cannot be reached or fails to answer."""


class Target(ABC):
    """Something we can send a prompt to and get a text reply from."""

    name: str

    @abstractmethod
    def send(self, prompt: str) -> str:
        """Send one prompt and return the target's reply."""
