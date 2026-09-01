# CSAF Analytics

CSAF Analytics converts an OASIS CSAF 2.0 advisory into row-level findings,
time-stamped threat enrichment, a versioned report model, and a standalone HTML
report. The generator has no Oracle or APEX dependency and uses only the Python
standard library.

Online enrichment supports:

- FIRST EPSS scores
- CISA Known Exploited Vulnerabilities
- NVD references tagged `Exploit`

## Advisory discovery source

Oracle's security publication RSS feed is the source used to discover new or
updated CPU, CSPU and out-of-cycle Security Alert publications:

```text
https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml
```

The APEX automation **Monitor Oracle Security Publications** reads this feed
daily at 06:00 and reconciles its entries into `SECURITY_PUBLICATIONS`. On the
first execution, existing feed entries establish the baseline as `CURRENT`.
Subsequent unseen entries are marked `NEW`; previously known entries whose
title, advisory URL or source publication date changed are marked `UPDATED`.

Publication discovery and CSAF processing are currently separate. The RSS feed
identifies the advisory HTML publication, while the Python generator requires
the corresponding published CSAF JSON URL explicitly through `--url`. For
example:

```text
RSS advisory: https://www.oracle.com/security-alerts/cspuaug2026.html
CSAF input:   https://www.oracle.com/docs/tech/security-alerts/cspuaug2026csaf.json
```

Automatically resolving the CSAF JSON URL and triggering the generator for a
`NEW` or `UPDATED` publication is a planned integration step; it is not part of
the current Phase 0 implementation.

## Quick start

Python 3.10 or later is required.

```bash
python3 -m pip install -e .
csaf-analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output
```

Without installing the package:

```bash
PYTHONPATH=src python3 -m csaf_analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output
```

The original command remains available during the repository transition:

```bash
python3 csaf_phase0.py \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output
```

## Standalone Oracle KEV report

The Oracle KEV report is separate from the advisory-specific Phase 0 report. It
joins Oracle's public CVE-to-advisory mapping with the current CISA Known
Exploited Vulnerabilities catalog and includes entries added during the last
365 days by default:

```bash
python3 oracle_kev_report.py --output-dir var/output
```

Use `-d DIR` (or `--publish-dir DIR`) to additionally publish the generated
HTML and its SHA-256 checksum under stable filenames. The directory is created
when necessary and existing files with the same names are replaced:

```bash
python3 oracle_kev_report.py \
  --output-dir var/output \
  -d /path/to/kev-reports
```

This writes the following files without changing the timestamped bundle:

```text
/path/to/kev-reports/report-oracle-kev.html
/path/to/kev-reports/report-oracle-kev.html.cksum
```

The checksum file uses the conventional format:

```text
<sha256-hex>  report-oracle-kev.html
```

An installed source tree also provides:

```bash
oracle-kev-report --output-dir var/output
```

Use `--days` to change the rolling window or `--as-of YYYY-MM-DD` to reproduce
a report for a historical cutoff. `--oracle-map-file`, `--kev-file`, and
`--nvd-file` accept local source snapshots for offline or reproducible
execution. NVD publication timestamps are used to calculate the elapsed days
between CVE publication and CISA KEV addition. This is a cataloguing-lag metric,
not a measurement of time to first exploitation.

Each run creates a separate bundle:

```text
var/output/oracle-kev/<UTC timestamp>_ORACLE_KEV/
├── manifest.json
├── oracle-kev-report-data.json
└── report-oracle-kev.html
```

The report treats KEV membership as evidence that exploitation has occurred in
the wild, not as proof that exploitation is continuing at report time. Product
and version applicability must be confirmed in the linked Oracle advisory.
The decision list provides two explicit rolling-window views: KEVs added in the
last 90 days and KEVs added in the last year. The 90-day view is selected by
default; selecting the one-year view displays the complete default 365-day
report window. Both views retain the newest-to-oldest KEV addition order and
can be combined with the product, text, and ransomware filters.

For lightweight automation, the standalone HTML contains a server-rendered
90-day count that does not require JavaScript execution:

```html
<meta name="new90D" content="6">
```

The `content` value is regenerated from the report's `added_last_90_days` KPI
on every run and is intended as a stable integration contract for APEX or
PL/SQL consumers.

The current APEX iframe and dashboard-button integration, together with the
proposed automated CLOB delivery design, is documented in
[`../docs/operations/oracle-kev-dashboard.md`](../docs/operations/oracle-kev-dashboard.md).

Set `NVD_API_KEY` in the environment to enable NVD exploit-reference
enrichment. The key is sent only in the HTTP header and is never logged.

```bash
export NVD_API_KEY='your-key'
```

## Generated bundle

Every successful execution creates a new UTC timestamped directory and never
overwrites an existing run:

```text
var/output/
└── 20260806T183246Z_CPUJul2026csaf/
    ├── cpujul2026csaf.json
    ├── findings.csv
    ├── enrichment.csv
    ├── report-data.json
    ├── report-cpujul2026.html
    └── manifest.json
```

The directory name is the `batch_id` carried by the manifest and both CSV
files. The report name is derived from the published CSAF basename:
`cpujul2026csaf.json` becomes `report-cpujul2026.html`. It is generated by
reading the persisted `report-data.json` and embedding the same model for
standalone viewing.

The exact original CSAF source is retained under its published URL basename,
such as `cpujul2026csaf.json`, alongside the five generated artifacts. For the
target APEX workflow, all six files will be packaged into one ZIP; automatic ZIP
creation is not implemented yet.
The exact generated HTML report is retained for historical display, while JSON and CSV
data support metrics and relational analysis. See the [APEX import
design](docs/apex-import.md).

## Project layout

```text
src/csaf_analytics/       Python package
database/phase0/          Current pilot Oracle objects
docs/                     Architecture and operating documentation
examples/                 Reference output
tests/                    Offline automated tests
var/input/                Local CSAF source documents, ignored by Git
var/output/               Local generated bundles, ignored by Git
```

The current implementation remains in `src/csaf_analytics/phase0.py`. It will
be split into focused parser, enrichment, bundle, and reporting modules in a
later refactoring step.

## Documentation

- [Architecture](docs/architecture.md)
- [APEX import design](docs/apex-import.md)
- [Data model and import contract](docs/data-model-import-contract.md)
- [APEX advisory load page implementation plan](docs/apex-advisory-load-page-plan.md)
- [Report data contract](docs/report-data-schema.md)
- [Operations guide](docs/operations.md)
- [Development guide](docs/development.md)
- [Phase 0 database objects](database/README.md)

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite is offline and does not require Oracle Database.

## Current implementation boundary

The database scripts under `database/phase0/` define the original manual CSV
staging pilot as repository reference material; they are not deployed in the
current APEX application. The target single-ZIP APEX upload, historical HTML
storage, and report metric tables are documented but not yet implemented.
