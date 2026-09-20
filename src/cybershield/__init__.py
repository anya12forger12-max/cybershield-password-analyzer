"""Cybershield Password Analyzer - strength checks and improvement suggestions."""

__version__ = "0.1.0"

from cybershield.analyzer import (
    MIN_LENGTH,
    RECOMMENDED_LENGTH,
    STRONG_SCORE,
    WEAK_SCORE,
    Criterion,
    PasswordStrength,
    check_password,
)

__all__ = [
    "MIN_LENGTH",
    "RECOMMENDED_LENGTH",
    "STRONG_SCORE",
    "WEAK_SCORE",
    "Criterion",
    "PasswordStrength",
    "__version__",
    "check_password",
]
