"""Allow ``python -m cybershield`` and ``pipx run`` entry points."""

from cybershield.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
