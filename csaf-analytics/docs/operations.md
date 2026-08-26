# Operations Guide

## Generate a report bundle

Run from the repository root after an editable installation:

```bash
csaf-analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output
```

Or run directly from the source tree:

```bash
PYTHONPATH=src python3 -m csaf_analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output
```

Execution is verbose by default. Progress is written to standard error with UTC
timestamps; the final bundle path alone is written to standard output. Use
`--quiet` for scheduled execution.

## Enrichment configuration

FIRST EPSS and CISA KEV do not require credentials. NVD enrichment is enabled
when `NVD_API_KEY` is present in the environment:

```bash
export NVD_API_KEY='your-key'
csaf-analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output
```

Do not place the key on the command line or commit it to a file.

Online reads default to a 15-second hard timeout and one retry:

```bash
csaf-analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output \
  --timeout 10 \
  --retries 0
```

Each enrichment source is isolated. A failed source is recorded as `error` or
`unavailable`; it does not discard the generated bundle.

## Offline enrichment

Disable network access for enrichment sources. The CSAF document itself is
still downloaded from the required `--url`:

```bash
csaf-analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output \
  --offline
```

Local EPSS, KEV, and NVD files may be supplied in offline mode:

```bash
csaf-analytics \
  --url https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json \
  --output-dir var/output \
  --offline \
  --epss-file /path/to/epss-response.json \
  --kev-file /path/to/known-exploited-vulnerabilities.json \
  --nvd-file /path/to/nvd-cves-response.json
```

EPSS accepts API JSON, CSV, or gzip-compressed CSV. KEV and NVD inputs use their
respective JSON feed formats.

## Report output

The output directory name is captured once at execution start:

```text
YYYYMMDDTHHMMSSZ_<advisory-reference>
```

The generator creates the directory exclusively and refuses to overwrite a
previous execution. Temporary directories are removed automatically when a run
fails.

The downloaded CSAF bytes are preserved in this directory under the basename
derived from the URL path. Query parameters and fragments do not become part of
the filename. The manifest records that same basename as both
`source_filename` and `files.source_csaf`.

`--no-html-report` suppresses only the generated `report-<advisory>.html`; JSON
and CSV artifacts remain.
Do not use that option for a bundle intended for the target APEX import, which
requires the generated HTML for historical display.

## Interpreting enrichment

- `public_exploits = 0` means NVD returned no reference tagged `Exploit`; it is
  not proof that no exploit exists elsewhere.
- Missing enrichment is represented as JSON `null`, never as a negative result.
- A later run against the same CSAF creates a new observation and may change
  EPSS, KEV, NVD, and prioritization values while findings remain unchanged.

## Local output retention

`var/output/` is ignored by Git. Archive production bundles according to the
operational retention policy before removing local output.
