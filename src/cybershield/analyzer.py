"""Password strength evaluation."""

import string
from dataclasses import dataclass

MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12
STRONG_SCORE = 80
WEAK_SCORE = 50

_POINTS_LENGTH8 = 25
_POINTS_LENGTH12 = 15
_POINTS_UPPERCASE = 15
_POINTS_LOWERCASE = 15
_POINTS_DIGIT = 15
_POINTS_SYMBOL = 15


@dataclass(frozen=True)
class Criterion:
    """A single strength criterion."""

    name: str
    met: bool
    points: int

    @property
    def score(self) -> int:
        return self.points if self.met else 0


@dataclass(frozen=True)
class PasswordStrength:
    """The complete analysis of a password."""

    criteria: tuple[Criterion, ...]
    score: int
    suggestions: tuple[str, ...]

    @property
    def label(self) -> str:
        if self.score >= STRONG_SCORE:
            return "Strong"
        if self.score >= WEAK_SCORE:
            return "Moderate"
        return "Weak"


def check_password(password: str) -> PasswordStrength:
    """Score ``password`` against six criteria and list actionable suggestions."""
    length = len(password)
    has_uppercase = any(char.isupper() for char in password)
    has_lowercase = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(char in string.punctuation for char in password)

    criteria = (
        Criterion(f"at least {MIN_LENGTH} characters", length >= MIN_LENGTH, _POINTS_LENGTH8),
        Criterion(
            f"at least {RECOMMENDED_LENGTH} characters",
            length >= RECOMMENDED_LENGTH,
            _POINTS_LENGTH12,
        ),
        Criterion("uppercase letter", has_uppercase, _POINTS_UPPERCASE),
        Criterion("lowercase letter", has_lowercase, _POINTS_LOWERCASE),
        Criterion("number", has_digit, _POINTS_DIGIT),
        Criterion("symbol", has_symbol, _POINTS_SYMBOL),
    )

    suggestions = _build_suggestions(length, has_uppercase, has_lowercase, has_digit, has_symbol)
    return PasswordStrength(criteria, sum(criterion.score for criterion in criteria), suggestions)


def _build_suggestions(
    length: int,
    has_uppercase: bool,
    has_lowercase: bool,
    has_digit: bool,
    has_symbol: bool,
) -> tuple[str, ...]:
    suggestions: list[str] = []
    if length < MIN_LENGTH:
        suggestions.append(f"Use at least {MIN_LENGTH} characters.")
    if length < RECOMMENDED_LENGTH:
        suggestions.append(f"Use at least {RECOMMENDED_LENGTH} characters for stronger protection.")
    if not has_uppercase:
        suggestions.append("Add uppercase letters.")
    if not has_lowercase:
        suggestions.append("Add lowercase letters.")
    if not has_digit:
        suggestions.append("Add numbers.")
    if not has_symbol:
        suggestions.append("Add symbols.")
    return tuple(suggestions)


__all__ = [
    "MIN_LENGTH",
    "RECOMMENDED_LENGTH",
    "STRONG_SCORE",
    "WEAK_SCORE",
    "Criterion",
    "PasswordStrength",
    "check_password",
]
