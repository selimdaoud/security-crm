# CSAF Analytics APEX Page — Advisory Load Implementation Plan

## Status and scope

This document defines the implementation plan for a new **CSAF Analytics** page
linked from the APEX dashboard. The first delivery implements only the
**Import CSAF Package** section, also referred to as the advisory load phase.

The future section that lists previously imported CSAF packages is explicitly
out of scope for this delivery. The page and database APIs should nevertheless
be structured so that the history section can be added without redesigning the
import workflow.

The current APEX application has no deployed CSAF persistence layer. The SQL
under `database/phase0/` is a repository prototype for the earlier manual CSV
pilot, not an inventory of objects present in the application's parsing schema.
The target database objects in this plan must therefore be installed as a new
CSAF subsystem. Deployment must still use existence and compatibility checks so
the scripts remain safe in any non-production schema where the prototype may
have been evaluated.

The imported object is the ZIP bundle defined in `apex-import.md` and
`data-model-import-contract.md`. It contains exactly:

```text
manifest.json
<original-csaf-filename>.json
report-data.json
report-<advisory>.html
findings.csv
enrichment.csv
```

## Target operator journey

The first page section follows a controlled four-step workflow:

```text
Select ZIP -> Validate -> Review summary -> Import
```

1. An authorized operator opens **CSAF Analytics** from the dashboard.
2. The operator selects one ZIP package and starts validation.
3. A server-side service stores the upload temporarily, inspects the archive,
   validates its contract and displays a read-only summary.
4. If validation succeeds, the operator confirms the import.
5. The server promotes the package atomically and displays the final result.
6. If validation or import fails, no canonical advisory or enrichment facts
   are partially committed.

## Implementation phases

### 1. Confirm page and access conventions

- Allocate an unused APEX page number and define the page alias, recommended as
  `CSAF-ANALYTICS`.
- Add a dashboard/navigation entry labelled **CSAF Analytics**.
- Reuse the application's standard page template, breadcrumb and visual
  conventions.
- Define a dedicated authorization scheme for CSAF import operators. General
  dashboard access must not automatically grant upload/import permission.
- Confirm maximum accepted bundle size and the retention policy for successful
  uploads, failed uploads and diagnostics.

### 2. Freeze the upload contract

- Treat manifest format version `3` and report schema version `7` as the first
  supported target contract unless a deliberate version change is approved.
- Require one `.zip` file containing exactly the six expected root-level file
  names; directories and nested paths are not accepted.
- Require the source artifact to keep its original published basename, contain
  the exact bytes processed by the generator, and have a hash matching
  `csaf_source_hash`.
- Require packages intended for APEX to include the HTML file named by
  `manifest.files.report_html`; generator runs
  made with `--no-html-report` are not importable.
- Align the Oracle staging and canonical model with all current
  `findings.csv` columns, including `advisory_title`, `advisory_url`,
  `component_name`, `third_party_component` and `cvss_source`.
- Resolve document-scoped CSAF product identity before importing production
  packages. A raw CSAF `product_id` must not be used as a global key.
- Key enrichment observations to the exact report run so multiple executions
  on the same date remain distinct.
- The Python generator now retains the source under its original published
  basename and adds it to the manifest hashes. Add automatic ZIP creation
  before operational rollout.

### 3. Establish the target persistence layer

Create an ordered target schema installation/migration for the APEX parsing
schema. Use the Phase 0 scripts only as reference; do not deploy them as a
prerequisite for the new page. The target installation should provide:

- an immutable report-run table keyed by an internal `report_run_id`, with
  unique `batch_id`, bundle hash, advisory identity, execution timestamps,
  counts, source-health fields, import status and audit columns;
- storage for the original ZIP, manifest JSON, report JSON and report HTML;
- advisory-scoped product releases and immutable finding facts;
- enrichment observations linked to `report_run_id`;
- reporting metric tables populated from `report-data.json`;
- staging structures used only during validation and promotion;
- constraints and indexes supporting idempotency, conflict detection and the
  future imported-package list.

The installation should detect any pre-existing prototype objects in other
environments and stop for an explicit migration decision rather than silently
discarding or rewriting data. In the current APEX application, the expected
path is a clean installation of the target objects.

### 4. Build the permanent server-side import service

Implement a reviewed PL/SQL package installed once in the APEX parsing schema.
The page calls this package; uploaded packages never contain executable SQL.

The package should expose separate operations for:

- receiving or registering the temporary APEX upload;
- validating a package and returning a structured review summary;
- confirming and promoting a previously validated package;
- abandoning or expiring a pending upload;
- retrieving a sanitized diagnostic for display to the operator.

Validation must occur server-side and include:

- ZIP signature and allowed file type checks;
- archive entry count and normalized-name checks;
- rejection of absolute paths, `..` traversal, nested paths, duplicate names,
  symbolic-link-like entries and unexpected files;
- compressed and uncompressed size limits to prevent ZIP bombs;
- parsing and validation of `manifest.json`;
- supported manifest and report-schema versions;
- valid `batch_id`, advisory identity and execution timestamps;
- SHA-256 verification for every payload file named by the manifest;
- exact CSV headers, per-row `batch_id`, row counts and required values;
- report JSON identity and KPI/count reconciliation;
- agreement between the manifest, JSON and CSV advisory identities;
- duplicate finding and enrichment keys;
- idempotency and advisory revision conflict rules.

The validation operation must not modify canonical facts. It may retain a
pending or failed report-run/upload record for audit according to policy.

### 5. Implement atomic promotion

After explicit operator confirmation, the package should:

1. Lock or claim the validated upload so it cannot be imported twice
   concurrently.
2. Recheck its validation state and bundle identity.
3. Create the immutable report-run record and store the original artifacts.
4. Reuse or insert the advisory revision according to source-hash rules.
5. Promote product releases, vulnerabilities and findings.
6. Insert enrichment observations for the exact report run.
7. Extract report-level and product-family metrics.
8. Set the run to `SUCCESS` or `PARTIAL` and commit once.

Any unexpected failure rolls back the canonical promotion and records a safe
diagnostic. The package must implement these outcomes:

| Condition | Outcome |
|---|---|
| Same `batch_id` and same bundle hash | Return the existing run; insert nothing |
| Same `batch_id` and different bundle hash | `CONFLICT` |
| Same advisory revision and source hash, new execution | Reuse findings and insert a new report/enrichment run |
| Same advisory revision and different source hash | Hold or reject as `CONFLICT` |
| New advisory revision | Insert the revision and its findings |
| One enrichment source unavailable | Import as `PARTIAL` |

### 6. Build the Import CSAF Package page section

Create one top-level page region titled **Import CSAF Package**, containing:

- a single file browse/drop-zone item restricted in the UI to ZIP files;
- a short description of the six-file bundle contract and maximum size;
- a **Validate** button;
- a validation-progress indicator;
- a conditionally displayed review-summary region;
- an **Import** confirmation button enabled only for a successfully validated
  package;
- a **Cancel/Replace Package** action;
- a final success, partial, conflict or failure message region.

The review summary should show at least:

- package file name and calculated bundle hash;
- batch ID and supported format versions;
- advisory reference, title and revision;
- execution timestamp and observation date;
- findings, CVE, product and enrichment counts;
- EPSS, KEV and NVD source-health statuses;
- whether the advisory facts are new or will be reused;
- warnings that will produce a `PARTIAL` import.

The raw uploaded HTML must never be rendered in the import page. Historical
HTML display belongs to a separate, sandboxed report-view workflow.

### 7. Manage APEX page state safely

- Store only a generated pending-upload/report-run identifier in page session
  state after validation; do not trust hidden items containing manifest facts.
- On confirmation, reload validation facts from the database using that
  identifier.
- Use checksum-protected APEX navigation and normal session-state protection.
- Prevent the Import button from being submitted twice and make server-side
  idempotency authoritative even if the browser retries.
- Clear or expire temporary APEX files after success, cancellation or the
  configured timeout.
- Escape all manifest-derived strings before displaying them.

### 8. Add security and operational controls

- Enforce authorization both on the APEX page and inside the import package.
- Record uploader, validation time, confirmation time, import time and outcome.
- Avoid exposing stack traces, filesystem paths, SQL text or uploaded content
  in end-user messages; retain detailed diagnostics for authorized support.
- Configure appropriate limits for ZIP size, individual entries, total
  uncompressed bytes, CSV rows and JSON/HTML sizes.
- Treat MIME type and filename extension as hints only; validate actual archive
  content.
- Define cleanup and retention jobs for abandoned uploads and failed packages.
- Add monitoring for repeated failures, conflicts and unusually large imports.

### 9. Test before deployment

Database/package tests should cover:

- one valid complete package;
- a valid package with a degraded enrichment source (`PARTIAL`);
- exact duplicate upload;
- same batch ID with changed content;
- same advisory revision with a changed source hash;
- later enrichment execution for an existing advisory;
- malformed manifest or report JSON;
- missing, additional, duplicate or nested archive entries;
- path traversal and oversized/over-compressed archives;
- file hash, CSV header, row count and per-row batch-ID mismatches;
- invalid dates, numbers and required values;
- rollback after a failure in each promotion stage;
- concurrent or repeated confirmation requests;
- unauthorized page and package access.

APEX tests should verify the complete operator journey, accessible keyboard and
screen-reader behaviour, understandable validation messages, page refresh and
session expiry handling.

### 10. Deploy in controlled stages

1. Deploy and validate the database migration in a non-production schema.
2. Install the import package and run database-level positive and negative
   package tests.
3. Add automatic or controlled ZIP packaging and test a representative large
   Oracle CSAF bundle.
4. Create the APEX page without adding the dashboard link; test it through its
   direct URL with the import authorization scheme.
5. Add the dashboard/navigation link for authorized users.
6. Run a production-like import and reconcile counts and hashes with the local
   bundle.
7. Enable operational monitoring and document recovery/cleanup procedures.

## Definition of done for the first page section

The first delivery is complete when an authorized operator can upload one
valid CSAF ZIP, validate it, review its identity and counts, confirm the import,
and receive a deterministic result without manually loading CSV files or
running SQL. The original bundle and extracted artifacts are retained, the
relational facts and metrics are traceable to their report run, duplicate and
conflicting imports behave as defined, and failed validation cannot partially
modify canonical data.

The imported-package list and historical report viewer remain separate follow-up
deliveries.
