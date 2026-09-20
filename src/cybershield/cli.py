"""Command-line interface for the Cybershield password analyzer."""

import argparse
import getpass
import sys
from collections.abc import Sequence

from cybershield.analyzer import check_password


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybershield",
        description="Check password strength and print improvement suggestions.",
    )
    parser.add_argument(
        "password",
        nargs="?",
        default=None,
        help="password to analyze (omit to read from stdin)",
    )
    parser.add_argument(
        "-s",
        "--stdin",
        action="store_true",
        help="read the password from stdin even when a terminal is present",
    )
    parser.add_argument(
        "--require-score",
        type=int,
        metavar="N",
        default=None,
        help="exit 1 when the score is below N (0-100)",
    )
    return parser


def _read_password(args: argparse.Namespace) -> str:
    if not args.stdin and args.password is not None:
        password_arg: str = args.password
        return password_arg
    if sys.stdin.isatty():
        password: str = getpass.getpass("Password: ")
        return password
    raw = sys.stdin.read()
    return raw[:-1] if raw.endswith("\n") else raw


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; returns the process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.stdin and args.password is not None:
        parser.error("cannot combine a positional password with --stdin")
    if args.require_score is not None and not 0 <= args.require_score <= 100:
        parser.error("--require-score must be between 0 and 100")

    strength = check_password(_read_password(args))
    print(f"score: {strength.score}/100 ({strength.label})")
    if strength.suggestions:
        print("suggestions:")
        for suggestion in strength.suggestions:
            print(f"  - {suggestion}")

    if args.require_score is not None and strength.score < args.require_score:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
