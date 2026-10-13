"""Password policy definition and validation.

A policy keeps every constraint that influences a generated password in one
frozen value object. Centralising the rules means the CLI and the core
generator can never silently disagree, and impossible configurations fail fast
with an actionable message instead of producing a weak or malformed password.
"""

from __future__ import annotations

from dataclasses import dataclass

from .limits import MAX_PASSWORD_LENGTH

# Characters that are easy to confuse when transcribed by hand. Excluding them
# reduces human error; at a fixed length the entropy cost is negligible because
# the remaining alphabet stays large.
AMBIGUOUS_CHARACTERS = frozenset("0Oo1lI|")


class PolicyError(ValueError):
    """Raised when a password policy is impossible or internally inconsistent."""


@dataclass(frozen=True)
class PasswordPolicy:
    """Declarative description of the password we want to generate.

    Attributes are intentionally simple booleans so the policy is easy to
    serialise, test, and reason about.
    """

    length: int
    lowercase: bool = True
    uppercase: bool = True
    digits: bool = True
    symbols: bool = True
    exclude_ambiguous: bool = False

    def enabled_classes(self) -> tuple[str, ...]:
        """Return the names of the character classes that are enabled."""
        classes: list[str] = []
        if self.lowercase:
            classes.append("lowercase")
        if self.uppercase:
            classes.append("uppercase")
        if self.digits:
            classes.append("digits")
        if self.symbols:
            classes.append("symbols")
        return tuple(classes)

    @property
    def required_classes(self) -> int:
        """Number of classes that must each appear at least once."""
        return len(self.enabled_classes())

    def validate(self) -> None:
        """Raise :class:`PolicyError` if the policy cannot be satisfied.

        Validation is separated from construction so callers decide when to pay
        the cost, and so a policy can be built incrementally before checking it.
        """
        if self.length < 1:
            raise PolicyError("length must be >= 1")

        if self.length > MAX_PASSWORD_LENGTH:
            raise PolicyError(f"length {self.length} exceeds the maximum of {MAX_PASSWORD_LENGTH}")

        if self.required_classes == 0:
            raise PolicyError("at least one character class must be enabled")

        # We guarantee at least one character from every enabled class, so a
        # password shorter than the number of enabled classes is impossible.
        if self.length < self.required_classes:
            raise PolicyError(
                f"length {self.length} is too short to include one character "
                f"from every enabled class ({self.required_classes} classes); "
                "increase --length or disable a class"
            )
