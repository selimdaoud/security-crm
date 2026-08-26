# Development Guide

## Requirements

- Python 3.10 or later
- No runtime third-party packages
- Network access only for live enrichment tests or manual report generation

## Local setup

```bash
python3 -m pip install -e .
```

The source-tree alternative requires no installation:

```bash
PYTHONPATH=src python3 -m csaf_analytics --help
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Tests use temporary directories and local fixtures. They must not require
Oracle Database or external network access.

## Repository conventions

- Code, documentation, comments, logs, and file names are written in English.
- Generated bundles belong under `var/output/` and are not committed.
- Test fixtures must be minimal and contain no sensitive data.
- Database changes are added as ordered migration scripts.
- File moves and functional changes should be reviewed separately when
  practical.

## Current implementation

`src/csaf_analytics/phase0.py` intentionally preserves the original Phase 0
implementation during the repository reorganization. A later refactor will
extract focused modules without changing the CLI or file contracts.
