"""A local rule-based target, safe to attack. No network, no real LLM."""

import re

from promptshield.targets.base import Target

CANARY_PATTERN = re.compile(r"PWNED-\d+")

OVERRIDE_PHRASES = (
    "ignore all previous",
    "disregard your earlier",
    "system:",
    "end of user input",
    "maintenance mode",
)

NORMAL_REPLY = "How can I help you with our product today?"
REFUSAL = "Sorry, I can't change my instructions."
OVERRIDDEN_REPLY = "Understood. My rules are overridden."


class MockTarget(Target):
    """A fake chatbot. If vulnerable, it obeys instruction-override attempts."""

    def __init__(self, vulnerable: bool = True) -> None:
        self.vulnerable = vulnerable
        self.name = "mock-vulnerable" if vulnerable else "mock-secure"

    def send(self, prompt: str) -> str:
        lowered = prompt.lower()

        if any(phrase in lowered for phrase in OVERRIDE_PHRASES):
            if not self.vulnerable:
                return REFUSAL
            match = CANARY_PATTERN.search(prompt)
            return match.group(0) if match else OVERRIDDEN_REPLY

        return NORMAL_REPLY
