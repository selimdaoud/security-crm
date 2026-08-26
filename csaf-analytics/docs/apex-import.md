# CSAF APEX Import Design

## Purpose

This document defines the target import contract between the standalone Python
generator and Oracle APEX. The design keeps Python and APEX decoupled: Python
creates a file bundle, and an authorized operator uploads that bundle through a
dedicated APEX page.

The imported data must support two uses:

1. Display the exact generated HTML report for any historical execution.
2. Support relational and time-series analysis across advisories and enrichment
   observations.

This is the target design. The current Data Workshop procedure remains a pilot
fallback until the upload page, storage tables and import package are deployed.

## Decision summary

The operator uploads one ZIP file. The target ZIP contains six artifacts,
including the exact original CSAF JSON processed by the generator:

```text
20260806T183246Z_CPUJul2026csaf.zip
├── manifest.json
├── cpujul2026csaf.json
├── report-data.json
├── report-cpujul2026.html
├── findings.csv
└── enrichment.csv
```

This six-file contract uses bundle format version `3`; report schema version
`7` remains the initial supported report model.

The operator must not upload the files separately and must not execute a
generated PL/SQL script. A permanent, reviewed PL/SQL package processes the
uploaded data after validation.

The source artifact keeps the original published basename recorded by the
manifest. For example, Oracle's `cpujul2026csaf.json` remains
`cpujul2026csaf.json`; it is not renamed during packaging.

The HTML name is also deterministic: the generator removes a terminal `csaf`
from the source stem and prefixes it with `report-`. Thus
`cpujul2026csaf.json` produces `report-cpujul2026.html`. The authoritative
name is recorded in `manifest.files.report_html`.

The Python generator now retains the original source in its execution directory
and records it in manifest format version `3`. It does not yet create the ZIP
automatically; ZIP creation must be added before the target APEX workflow is
deployed.

## Role of each artifact

| Artifact | Import role |
|---|---|
| `manifest.json` | Batch identity, format version, expected counts, file names, hashes and enrichment-source health |
| Original CSAF filename, for example `cpujul2026csaf.json` | Exact original CSAF source used by Python; retained under its published basename for audit, reprocessing and parser regression testing |
| `report-data.json` | Versioned report model, validation source and basis for extracted KPI/time-series metrics |
| `report-<advisory>.html` | Exact standalone report that an APEX page displays for this historical execution; its name comes from `manifest.files.report_html` |
| `findings.csv` | Row-level advisory, CVE, product-version and VEX facts for relational analysis |
| `enrichment.csv` | EPSS, KEV and NVD observations made during this execution |

Uploading only `report-data.json` is sufficient for replaying the current
JavaScript report and for metrics already present in that schema. It is not a
lossless replacement for the CSV files: the JSON contains aggregates and does
not retain every product/CVE field and relationship. Uploading the complete ZIP
therefore keeps the operational process simple while preserving future
analytical options.

The generated HTML report is deliberately included even though it embeds the same report
model. Keeping it provides byte-for-byte historical report replay and avoids
depending on a future renderer remaining compatible with every older report
schema.

## Storage layers

### 1. Report execution and immutable artifacts

Each Python execution creates one immutable report-run record. A conceptual
table is:

```text
CSAF_REPORT_RUN
- report_run_id
- batch_id                         unique
- bundle_format_version
- report_schema_version
- advisory_id
- advisory_reference
- advisory_revision
- source_hash
- execution_started_at
- observation_date
- findings_count
- enrichment_count
- epss_status
- kev_status
- nvd_status
- import_status
- bundle_hash
- manifest_json                    CLOB/JSON
- source_csaf                      BLOB
- report_json                      CLOB/JSON
- report_html                      BLOB
- uploaded_bundle                  BLOB
- uploaded_by
- uploaded_at
- validated_at
- imported_at
- error_message
```

Recommended status values are `RECEIVED`, `VALIDATING`, `VALIDATED`,
`IMPORTING`, `SUCCESS`, `PARTIAL`, `FAILED`, `CONFLICT`, `CANCELLED` and
`EXPIRED`.

The original ZIP is retained as the immutable audit artifact. The source CSAF,
manifest, report JSON and report HTML are also extracted into dedicated columns
for efficient validation and retrieval. The stored hashes prove that the
extracted files are the files described by the uploaded manifest.

No historical run is overwritten. The latest report is calculated from
`execution_started_at`, not `uploaded_at`, because an older bundle may be
uploaded later.

### 2. Canonical advisory facts

The relational fact model is populated from `findings.csv`:

```text
CSAF_ADVISORY
    └── CSAF_PRODUCT_RELEASE
          └── CSAF_FINDING
                └── CSAF_FINDING_REMEDIATION (when multiple fixes are retained)
```

An advisory is identified by vendor, advisory reference, formal revision and
source hash. Findings are immutable for that advisory revision.

A CSAF `product_id` is document-scoped and must not be assumed to be globally
unique. The product table should use a surrogate `product_release_id` and a
unique constraint such as `(advisory_id, csaf_product_id)`. Findings then refer
to that surrogate identifier.

Before implementing the target importer, the staging and canonical tables must
be aligned with the current `findings.csv` contract. The current CSV also
contains `advisory_title`, `advisory_url`, `component_name`,
`third_party_component` and `cvss_source`; these values must either be persisted
or explicitly excluded by a versioned import contract.

### 3. Enrichment observations

Enrichment belongs to the exact report execution:

```text
CSAF_ENRICHMENT_OBSERVATION
- report_run_id
- cve
- observed_date
- epss
- epss_percentile
- kev
- kev_added
- kev_due
- kev_ransomware
- public_exploits
- exploit_url
- epss_status
- kev_status
- exploit_status
```

The recommended key is `(report_run_id, cve)`. This preserves two executions
performed on the same day and guarantees that relational enrichment can be
traced back to the exact stored HTML and JSON report.

If the same CSAF is processed again, its immutable findings are reused while a
new report run, report HTML, report JSON and enrichment observation set are
inserted.

### 4. Extracted reporting metrics

Frequently charted values are extracted from `report-data.json` during import
so that APEX does not parse every multi-megabyte JSON document for every chart.

Example tables are:

```text
CSAF_REPORT_METRIC
- report_run_id
- metric_name
- metric_value

CSAF_REPORT_FAMILY_METRIC
- report_run_id
- product_family
- affected_findings
- pre_auth_findings
- affected_products
- affected_versions
- affected_cves
```

The existing JSON already exposes `affected_findings` and
`pre_auth_findings` under `aggregates.product_families`. Additional metrics can
be added in later report-schema versions without changing the upload mechanism.

Advisory-scope charts, such as affected findings for a product family across
quarterly CPUs, must use one point per advisory revision/source hash. Repeated
enrichment runs against the same source must not create duplicate scope points.
Enrichment charts use `observation_date` and may retain every report run.

## APEX upload workflow

The dedicated APEX page presents a single file drop zone:

```text
Select ZIP → Validate → Review summary → Import
```

Validation must complete before any canonical data is promoted. The server-side
package performs the following steps:

1. Store the received ZIP and calculate its SHA-256 hash.
2. List the archive entries and reject path traversal, duplicate names,
   unexpected files, excessive file counts or excessive uncompressed sizes.
3. Require exactly the six expected artifacts.
4. Parse `manifest.json` and validate its format version and `batch_id`.
5. Require `files.source_csaf` to equal `source_filename`, validate it as a
   safe root-level JSON basename and locate that exact archive entry.
6. Verify the SHA-256 hash of every payload artifact against the manifest,
   including equality between the original CSAF file hash and
   `csaf_source_hash`.
7. Parse enough of the original CSAF JSON to validate its CSAF version and
   advisory identity against the manifest and generated artifacts.
8. Validate `report-data.json`, its report schema, batch identity and advisory
   identity.
9. Validate the CSV headers, row counts and the `batch_id` carried by every CSV
   row.
10. Display the advisory, revision, execution time, counts and source health for
   operator confirmation.
11. Create the immutable report-run record and store the extracted artifacts.
12. Reuse or insert the advisory and promote findings.
13. Insert the enrichment observations for the report run.
14. Extract KPI and product-family metrics from the JSON.
15. Mark the run `SUCCESS` or `PARTIAL` and commit.

The upload page invokes this package. The operator does not run SQL manually.
Failed validation must not modify canonical facts or enrichment data. The
failed run and diagnostic may be retained for audit according to the retention
policy.

## Historical report display

The CSAF Reporting page accepts a `report_run_id`, retrieves the corresponding
stored HTML report, and displays that exact report. The report-history page
allows selection by advisory, revision, generation timestamp and observation
date.

Uploaded HTML contains JavaScript and must not be inserted directly into an
APEX HTML region or into the parent page DOM. A hash validates integrity but
does not prove that an arbitrary uploader supplied trusted HTML. The report
must therefore be served through a controlled download/application process and
displayed in a sandboxed iframe, preferably from an isolated origin.

An appropriate starting point for the iframe is:

```html
<iframe
  title="CSAF historical report"
  sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"
  src="...controlled report endpoint...">
</iframe>
```

Do not add `allow-same-origin` unless a security review establishes that it is
required. The endpoint should return `Content-Type: text/html; charset=utf-8`,
`X-Content-Type-Options: nosniff`, an appropriate Content Security Policy and
no sensitive data beyond the selected report. Access to the report endpoint
must use the same APEX authorization rules as the history page.

`report-data.json` remains stored independently. It supports validation,
metrics, future native APEX rendering and migration if the HTML renderer later
changes.

## Idempotency and conflict rules

| Situation | Import result |
|---|---|
| Same `batch_id` and same bundle hash | Return the existing successful run; insert nothing |
| Same `batch_id` and different bundle hash | Reject as `CONFLICT` |
| Same advisory revision and same source hash, later execution | Reuse findings; insert a new report/enrichment run |
| Same advisory revision and different source hash | Reject or hold for explicit review |
| New formal advisory revision | Insert a new advisory revision and its findings |
| One enrichment source unavailable | Store the run as `PARTIAL`; do not interpret missing data as a negative finding |

## Why not generate PL/SQL per report?

Generated PL/SQL mixes executable code with uploaded data and requires the
operator to have SQL execution privileges. Large HTML, JSON and description
values are difficult to quote safely, retries are hard to make idempotent, and
generated code can bypass the standard validation path.

PL/SQL is still used, but it is installed once as a controlled import package.
Every report execution supplies data to that package through the single ZIP
upload.

## Operational recommendation

The target operational sequence is:

```text
Run Python
    ↓
Create timestamped directory and ZIP
    ↓
Upload one ZIP in APEX
    ↓
Validate and confirm
    ↓
Store HTML/JSON history, relational facts, enrichment and metrics
    ↓
View any historical HTML report or trend chart
```

This preserves a simple human workflow while retaining the full data needed
for future reporting.
