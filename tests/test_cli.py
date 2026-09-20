"""Tests for the cybershield CLI."""

import pytest

from cybershield.cli import main

FULL_SAMPLE = "Abcd1234!xyz"
WEAK_SAMPLE = "abc"


def test_reports_score_and_label(capsys):
    rc = main([FULL_SAMPLE])
    capture = capsys.readouterr()
    assert rc == 0
    assert "score: 100/100 (Strong)" in capture.out


def test_prints_suggestions_for_weak_password(capsys):
    rc = main([WEAK_SAMPLE])
    capture = capsys.readouterr()
    assert rc == 0
    assert "score: 15/100 (Weak)" in capture.out
    assert "  - Add uppercase letters." in capture.out
    assert "  - Add numbers." in capture.out


def test_require_score_failing_exits_one(capsys):
    rc = main([WEAK_SAMPLE, "--require-score", "80"])
    capsys.readouterr()
    assert rc == 1


def test_require_score_met_exits_zero(capsys):
    rc = main([FULL_SAMPLE, "--require-score", "80"])
    capsys.readouterr()
    assert rc == 0


def test_positional_and_stdin_conflict():
    with pytest.raises(SystemExit) as exc:
        main([FULL_SAMPLE, "--stdin"])
    assert exc.value.code == 2


def test_require_score_out_of_range():
    with pytest.raises(SystemExit) as exc:
        main([FULL_SAMPLE, "--require-score", "150"])
    assert exc.value.code == 2


def test_common_password_scores_weak_and_gate_fails(capsys):
    rc = main(["Password1", "--require-score", "50"])
    capture = capsys.readouterr()
    assert rc == 1
    assert "(Weak)" in capture.out
    assert "commonly used password" in capture.out
