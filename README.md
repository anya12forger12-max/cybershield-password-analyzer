# Cybershield Password Analyzer

Password strength checker — evaluates length, uppercase, lowercase,
numbers, and symbols; computes a 0–100 strength score with improvement
suggestions.

## Features

- Objective 0–100 strength score across six criteria.
- Clear suggestions for every unmet criterion.
- Hidden input mode (no echo) when reading from a terminal.
- Optionally exits non-zero when a minimum score is required (`--require-score`).
- Pure Python standard library — no runtime dependencies.
- Common/breached-password guard: well-known weak passwords (e.g. `Password1`,
  `Admin123`, `qwerty123`) can never score Moderate or Strong and always fail
  any `--require-score 50+` gate.

## Install

```bash
pip install .
```

## Usage

```bash
# Analyze a password supplied as an argument
cybershield "Correct Horse Battery Staple"
cybershield-password-analyzer "Correct Horse Battery Staple"

# Read from stdin (no echo on a terminal)
echo "MyP@ssw0rd" | cybershield -s

# Gate scripts on minimum strength
cybershield "MyP@ssw0rd" --require-score 80
echo $?   # 1 when the score is below the requirement
```

## Score model

| Criterion                 | Points |
| ------------------------- | -----: |
| 8+ characters             |     25 |
| 12+ characters            |     15 |
| Contains uppercase        |     15 |
| Contains lowercase        |     15 |
| Contains a digit          |     15 |
| Contains a symbol         |     15 |
| **Total**                 |  **100** |

A missing criterion produces a matching suggestion.

## Common-password guard

If the stripped, lowercased password matches the compiled-in list of
common/breached passwords, its score is capped below the Moderate threshold
(50) and a dedicated suggestion is printed instead — regardless of how many
character classes it happens to contain. The guard is a curated list of the
worst offenders, not a full breach corpus.

## Development

```bash
pip install -r requirements-dev.txt
ruff check src/ tests/
black --check src/ tests/
isort --check-only src/ tests/
mypy src/
pytest
```