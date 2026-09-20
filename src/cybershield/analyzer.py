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

# Common, breached, or trivially guessable passwords that a character-class
# score would otherwise rate too generously. Not a full breach corpus: it is a
# compiled-in guard list of the worst offenders. Matched case-insensitively on
# the stripped password, so "Admin123", "ADMIN123" and "admin123" all hit it.
COMMON_PASSWORDS: frozenset[str] = frozenset(
    {
        "password",
        "password1",
        "password123",
        "password1234",
        "password!",
        "12345678",
        "123456789",
        "1234567890",
        "qwertyui",
        "qwerty123",
        "admin",
        "admin123",
        "admin1234",
        "administrator",
        "root",
        "root123",
        "iloveyou",
        "iloveyou1",
        "iloveyou!",
        "letmein",
        "welcome",
        "welcome1",
        "monkey",
        "monkey123",
        "dragon",
        "baseball",
        "football",
        "shadow",
        "master",
        "superman",
        "trustno1",
        "mustang",
        "princess",
        "sunshine",
        "charlie",
        "starwars",
        "whatever",
        "access14",
        "hello123",
        "abcd1234",
        "asdfghjk",
        "1q2w3e4r",
        "qweasdzxc",
        "zaq12wsx",
        "passw0rd",
        "p@ssw0rd",
        "pa55word",
        "letmein1",
        "lovely",
        "freedom",
        "nirvana",
    }
)


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


def is_common_password(password: str) -> bool:
    """Return True when ``password`` is on the compiled-in common-password list."""
    return password.strip().lower() in COMMON_PASSWORDS


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

    common = is_common_password(password)
    # Cap the score below WEAK_SCORE so a common password can never be labeled
    # Moderate/Strong and can never pass a --require-score >= 50 gate.
    score = (
        min(sum(criterion.score for criterion in criteria), WEAK_SCORE - 1)
        if common
        else sum(criterion.score for criterion in criteria)
    )
    suggestions = _build_suggestions(
        length, has_uppercase, has_lowercase, has_digit, has_symbol, common
    )
    return PasswordStrength(criteria, score, suggestions)


def _build_suggestions(
    length: int,
    has_uppercase: bool,
    has_lowercase: bool,
    has_digit: bool,
    has_symbol: bool,
    common: bool = False,
) -> tuple[str, ...]:
    suggestions: list[str] = []
    if common:
        suggestions.append(
            "This is a commonly used password that is easily guessed; choose a unique one."
        )
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
    "COMMON_PASSWORDS",
    "MIN_LENGTH",
    "RECOMMENDED_LENGTH",
    "STRONG_SCORE",
    "WEAK_SCORE",
    "Criterion",
    "PasswordStrength",
    "check_password",
    "is_common_password",
]
