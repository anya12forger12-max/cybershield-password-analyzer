"""Tests for cybershield.analyzer."""

from cybershield.analyzer import RECOMMENDED_LENGTH, check_password


def test_full_strength_password_scores_100():
    sample = "Correct-Horse-1!"
    strength = check_password(sample)
    assert strength.score == 100
    assert strength.label == "Strong"
    assert strength.suggestions == ()


def test_only_lowercase_scores_minimal():
    strength = check_password("abc")
    assert strength.score == 15
    assert strength.label == "Weak"
    assert "Add uppercase letters." in strength.suggestions
    assert "Add numbers." in strength.suggestions


def test_eight_chars_plus_classes_but_short_of_recommended():
    strength = check_password("abcdefgh1!")
    assert strength.score == 70
    assert strength.criteria[1].met is False
    assert strength.label == "Moderate"
    suggestions = strength.suggestions
    assert f"Use at least {RECOMMENDED_LENGTH} characters" in suggestions[0]


def test_missing_uppercase_and_digit_reported():
    strength = check_password("abcdefgh")
    assert strength.score == 40
    assert "Add uppercase letters." in strength.suggestions
    assert "Add numbers." in strength.suggestions
    assert "Add symbols." in strength.suggestions


def test_strong_threshold_boundary():
    strength = check_password("abcdefgh1!")
    assert strength.score == 70
    assert strength.label == "Moderate"


def test_length12_criterion_mets_full_score():
    sample = "Abcd1234!xyz"
    strength = check_password(sample)
    assert strength.score == 100


def test_all_six_criteria_present():
    sample = "Abcd1234!xyz"
    strength = check_password(sample)
    assert len(strength.criteria) == 6
    assert all(criterion.met for criterion in strength.criteria)
    assert all(criterion.score > 0 for criterion in strength.criteria)
