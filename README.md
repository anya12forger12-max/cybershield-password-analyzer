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

## Development

```bash
pip install -r requirements-dev.txt
ruff check src/ tests/
black --check src/ tests/
isort --check-only src/ tests/
mypy src/
pytest
```