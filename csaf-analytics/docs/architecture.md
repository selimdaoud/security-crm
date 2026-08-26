# CSAF Vulnerability Analytics Platform

## Design Document

| | |
|---|---|
| **Status** | Draft for review |
| **Version** | 0.4 |
| **Date** | 2026-08-06 |
| **Audience** | Engineering, security operations, CISO advisory |

---

## 1. Summary

We currently generate a decision-oriented HTML report from a single Oracle CSAF advisory using a standalone Python script. The script works and the output is useful, but it is stateless: every run reads one file and forgets it. That constraint blocks the analyses that carry the most weight with a board or a regulator, because those analyses live in the difference between advisories rather than inside any one of them.

This document proposes a persistence layer and the surrounding pipeline: a relational store for advisories, products, vulnerabilities and time-stamped enrichment, feeding both an interactive Oracle APEX application and the existing static HTML report.

Delivery is deliberately phased. The first implementation has no Python-to-APEX integration: Python is run manually and creates a dedicated UTC timestamped execution directory containing the original CSAF JSON under its published basename, two independent exchange files (`findings.csv` and `enrichment.csv`), a versioned `report-data.json` read model, a standalone `report-<advisory>.html`, and `manifest.json`. The CSV files are loaded through APEX Data Workshop and controlled database import routines. Direct ORDS or database integration remains the target architecture, not an MVP prerequisite.

The report generator is retained. During the MVP it continues to work from files; in the target architecture only its data source changes.

---

## 2. Problem statement

### 2.1 What stateless processing cannot do

Three signals are structurally unavailable from a single advisory:

**Recurrence by product family.** A product family that yields pre-authenticated vulnerabilities in every quarterly cycle is no longer a patching problem; it is an architecture decision — decommission, front with a proxy, replace. Establishing this pattern credibly needs six to eight quarters of history. It is the most strategically valuable output of the whole exercise and it is invisible advisory by advisory.

**EPSS drift.** A vulnerability whose exploitation probability moves from 0.2% to 12% in a week is an out-of-cycle trigger. The absolute value at any single point tells you little, particularly for a recently published CVE where a low score reflects absence of observation rather than absence of risk. Only the derivative is actionable, and a derivative requires at least two observations.

**Third-party propagation delay.** The interval between publication of an upstream CVE (Log4j, Netty, Spring) and its appearance in a vendor advisory, measured across many occurrences, is a supplier performance metric. It is defensible in a third-party review under DORA Articles 28–30, and it cannot be computed from one file.

### 2.2 The immutability asymmetry

An advisory is immutable once published; its enrichment is not.

CVE-2026-34486 illustrates the point. It appears in the July 2026 Oracle CPU as an ordinary finding. On 4 August 2026 CISA added it to the KEV catalogue with a three-day remediation deadline. Under the current file-based approach, seeing that change requires regenerating the July report, which overwrites the previous output — destroying the evidence of what was knowable in July.

This matters beyond convenience. "What did you know on 25 July?" is a standard audit question. Answering it requires retaining enrichment snapshots, not just the latest state.

### 2.3 Operational friction

Secondary but real: re-parsing a 5 MB JSON document on every run, re-downloading enrichment sources, and having no way to serve two consumers (an interactive application and a static export) from one computation.

---

## 3. Goals and non-goals

### Goals

- Persist advisories, products, vulnerabilities and facts in a queryable store
- Historise enrichment as a time series, keyed by observation date
- Support point-in-time reconstruction of any past analysis state
- Serve both an APEX application and the static HTML export from one model
- Detect and handle advisory revisions without silent overwrite
- Retain a file-only fallback path for ad-hoc analysis
- Allow a useful first release without an API, OCI Function, direct Python database connection or APEX automation
- Make repeated advisory and enrichment imports deterministic and idempotent

### Non-goals

- Replacing a vulnerability management platform. This is an analytics and decision-support layer, not a ticketing or remediation-tracking system.
- Asset inventory management. Inventory joins are in scope as a consumer of this data; owning the inventory is not.
- Real-time processing. Vendor advisories are quarterly; enrichment is weekly. Nothing here needs to be streaming.
- Multi-vendor support in v1. The model is vendor-agnostic by design, but only Oracle CSAF is implemented initially.

---

## 4. Data model

### 4.1 Design principle

The model separates what is fixed at publication from what changes over time. This asymmetry drives the whole schema.

- `fact` is immutable once an advisory is loaded. A CVE affecting a product at a given CVSS vector is a statement the vendor made on a specific date and does not revise except through a formal advisory revision.
- `enrichment` is a time series. EPSS changes daily; KEV status can flip months after publication; public exploit counts grow.

Keeping these in separate tables is what makes both point-in-time reconstruction and drift calculation possible. Merging them would make one or the other impossible.

### 4.2 Tables

**`advisory`** — one row per vendor advisory, per revision

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | NUMBER | surrogate key |
| `vendor` | VARCHAR2(64) | `Oracle` |
| `reference` | VARCHAR2(64) | `CPUJul2026csaf` |
| `revision` | VARCHAR2(64) | from `tracking.version`; semantic versions are retained verbatim |
| `published_date` | DATE | `initial_release_date` — starts the SLA clock |
| `revised_date` | DATE | `current_release_date` |
| `tlp` | VARCHAR2(16) | |
| `source_url` | VARCHAR2(512) | |
| `source_hash` | VARCHAR2(64) | SHA-256 of the raw file |
| `source_json` | BLOB | retained raw file — audit evidence |
| `loaded_at` | TIMESTAMP | |

Unique constraint on `(vendor, reference, revision)`. The hash detects re-publication with unchanged content and lets the loader skip it.

**`product`** — dimension, reused across advisories

| Column | Type | Notes |
|---|---|---|
| `product_id` | VARCHAR2(256) | vendor identifier, natural key |
| `family` | VARCHAR2(128) | `Oracle Fusion Middleware` |
| `product_name` | VARCHAR2(256) | |
| `version` | VARCHAR2(64) | |
| `cpe` | VARCHAR2(256) | join key to inventory |
| `first_seen` | DATE | |
| `last_seen` | DATE | products disappearing from advisories signal end of support |

**`vulnerability`** — dimension, one row per CVE

| Column | Type | Notes |
|---|---|---|
| `cve` | VARCHAR2(24) | natural key |
| `cve_year` | NUMBER | derived — ageing analysis |
| `description` | CLOB | |
| `component` | VARCHAR2(256) | affected component per vendor text |
| `third_party` | VARCHAR2(128) | embedded library, when identifiable |
| `first_seen_advisory` | NUMBER | FK — first advisory carrying this CVE |

**`fact`** — the grain: one row per (advisory, CVE, product)

| Column | Type | Notes |
|---|---|---|
| `advisory_id` | NUMBER | FK |
| `cve` | VARCHAR2(24) | FK |
| `product_id` | VARCHAR2(256) | FK |
| `status` | VARCHAR2(24) | `affected` / `not_affected` |
| `vex_justification` | VARCHAR2(64) | one of five CSAF flag labels |
| `cvss_score` | NUMBER(3,1) | |
| `cvss_vector` | VARCHAR2(128) | retained verbatim |
| `av`, `pr`, `ui`, `s`, `c`, `i`, `a` | VARCHAR2(2) | decomposed at load time |
| `pre_auth` | NUMBER(1) | virtual: `AV=N AND PR=N AND UI=N` |
| `scope_changed` | NUMBER(1) | virtual: `S=C` |
| `high_impact` | NUMBER(1) | virtual: `C=H OR I=H` |
| `fix_url` | VARCHAR2(512) | |
| `fix_note` | VARCHAR2(32) | support note identifier — the campaign grouping key |
| `fix_category` | VARCHAR2(32) | `vendor_fix`, `workaround`, `none_available` |
| `vendor_bug_id` | VARCHAR2(32) | |

Primary key `(advisory_id, cve, product_id)`.

Decomposing the CVSS vector into physical columns at load time — rather than parsing at query time — makes `pre_auth` an indexable virtual column and removes string manipulation from every subsequent query. This is the single highest-leverage modelling decision in the schema.

**`enrichment`** — time series, one row per CVE per observation

| Column | Type | Notes |
|---|---|---|
| `cve` | VARCHAR2(24) | FK |
| `observed_date` | DATE | |
| `epss` | NUMBER(7,6) | |
| `epss_percentile` | NUMBER(7,6) | |
| `kev` | NUMBER(1) | |
| `kev_added` | DATE | |
| `kev_due` | DATE | CISA deadline |
| `kev_ransomware` | VARCHAR2(16) | |
| `public_exploits` | NUMBER | count of unique NVD references tagged `Exploit` |
| `exploit_url` | VARCHAR2(512) | one representative NVD `Exploit` reference |
| `epss_status` | VARCHAR2(16) | `success` / `unavailable` / `error` |
| `kev_status` | VARCHAR2(16) | `success` / `unavailable` / `error` |
| `exploit_status` | VARCHAR2(16) | `success` / `unavailable` / `error` |
| `imported_at` | TIMESTAMP | last import time for this observation |

Primary key `(cve, observed_date)`. Written weekly. Re-running enrichment on the same observation date updates that day's snapshot with a `MERGE`; running it on a later date inserts a new snapshot. Source status columns distinguish a genuine negative result from a source that could not be queried. An unavailable source must not silently replace the last known value with `NULL`.

**`load_log`** — audit trail

| Column | Type | Notes |
|---|---|---|
| `load_id` | NUMBER | |
| `load_type` | VARCHAR2(32) | `advisory` / `enrichment` |
| `source` | VARCHAR2(256) | |
| `started_at`, `finished_at` | TIMESTAMP | |
| `status` | VARCHAR2(16) | `success` / `partial` / `failed` / `skipped` / `conflict` |
| `rows_affected` | NUMBER | |
| `message` | VARCHAR2(2000) | which sources were unreachable |

This table is not optional. An auditor asking whether the process runs will want evidence of the process, not just the resulting data.

### 4.3 MVP exchange and staging tables

The MVP imports data into staging tables before changing the canonical model. Every CSV row carries a generated `batch_id`; advisory identity and source hash are also repeated in the findings file, while observation date is repeated in the enrichment file:

- `finding_stage` mirrors the immutable advisory/fact fields from `findings.csv`.
- `enrichment_stage` mirrors the time-varying fields from `enrichment.csv`.

Staging tables do not carry business uniqueness constraints. They allow APEX Data Workshop to accept a file first, after which a controlled PL/SQL import validates the complete batch, applies it atomically and writes `load_log`. A failed validation changes no canonical data.

Enrichment columns must not be copied into `finding_stage` or `fact`. Doing so would make a later Python run appear to change the CSAF itself and would either overwrite history or duplicate every CVE-product pair.

### 4.4 Optional: inventory join

Out of scope for v1, but the schema anticipates it. A `customer_asset` table keyed on CPE, carrying business function, internet exposure and remediation ownership (SaaS / managed / on-premises), converts every advisory-level metric into an exposure-level one. This is the table that requires the most negotiation and the least code, which is why it comes last.

---

## 5. Architecture

### 5.1 MVP: manual file exchange

The first implementation intentionally has no runtime integration between Python and APEX:

```
   Oracle CSAF advisory        KEV / EPSS / public exploit index
            │                              │
            └──────────────┬───────────────┘
                           ▼
                  Python run manually
                           │
                           ▼
             timestamped run directory
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
   findings.csv     enrichment.csv    manifest.json
          │                │
          └────────┬───────┘
                   ▼
          APEX Data Workshop
                   ▼
             staging tables
                   ▼
       validated PL/SQL import routine
                   ▼
          Oracle relational store
                   ▼
             APEX application
```

This boundary is operationally simple: Python knows nothing about APEX credentials or the database, and APEX never executes Python. The only hand-off is a small, versioned file contract.

### 5.2 Target: automated ingestion

```
   Oracle CSAF advisory        KEV / EPSS / public exploit index
            │                              │
            └──────────────┬───────────────┘
                           ▼
                  Python ingestion layer
             (parsing, decomposition, enrichment)
                           │
                   ORDS REST / direct insert
                           ▼
              Oracle relational store + MVs
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
      APEX application          Static HTML export
   (facets, drill-down)      (publication, archive)
```

### 5.3 Ingestion outside the database

Parsing stays in Python rather than PL/SQL. The `product_tree` is a recursive structure of variable depth, the CVSS vector needs decomposition, and the enrichment sources each have their own failure modes. This logic benefits from being version-controlled, unit-testable and independent of the database release. A PL/SQL package manipulating JSON would work but would be harder to evolve as the CSAF format changes.

In the MVP, the loader writes normalised CSV files. Later, it may write the same logical records through ORDS or a direct connection without changing the canonical data model. The database receives clean tabular data and does what it is good at: aggregation and history.

### 5.4 Views and materialised views

`v_latest_enrichment` exposes the most recent observation for each CVE, ordered by `observed_date` and then `imported_at`. APEX joins this view to the immutable facts to show the current state without losing older observations.

One per analysis axis, refreshed on demand after each load:

- `mv_family_profile` — affected pairs and pre-auth share by family and advisory
- `mv_third_party` — pair counts by embedded component and advisory
- `mv_blast_radius` — distinct products per CVE
- `mv_recurrence` — pre-auth counts by family across the last N advisories
- `mv_epss_drift` — EPSS delta per CVE over 7 and 30 days
- `mv_fix_coverage` — remediation coverage and support-note grouping

At the current volume — roughly 4,500 rows per advisory — performance is not the driver. Stability of displayed figures is: a materialised view guarantees two users see identical numbers at the same moment, and that a report regenerated for archival purposes matches what was published.

### 5.5 Two consumers, one model

**APEX** serves interactive exploration: faceted search across family, tier, KEV status and pre-auth flag; drill-down to a single CVE; comparison across quarters. This is the analyst's tool.

**Static HTML** serves publication: a frozen artefact for a given advisory, self-contained, suitable for a client portal or an audit file. This is the deliverable.

The existing generator is reused. Its rendering layer — Redwood styling, collapsible sections, sortable tables — is unchanged; only its data access changes from JSON parsing to SQL queries. Estimated effort is low because the two concerns were already separate in the current script.

---

## 6. Ingestion behaviour

### 6.1 MVP file contract

Each Python run creates a new directory whose name begins with the execution timestamp in UTC. The required naming convention is:

```text
YYYYMMDDTHHMMSSZ_<advisory-reference>
```

For example:

```text
20260812T061500Z_CPUJul2026csaf
```

UTC and the trailing `Z` make directory names comparable across machines and avoid daylight-saving ambiguity. The timestamp is captured once at process start and reused throughout the run; it must not be recalculated separately for file creation or manifest generation. The script must create the directory exclusively and must never overwrite an existing execution directory. A name collision fails the run before any artefact is written.

CLI execution is verbose by default. UTC timestamped progress messages are written to standard error for source loading, advisory identity and hash, extracted volumes, status distribution, enrichment source health, file creation and total duration. The final directory path alone is written to standard output so it remains easy to capture from a shell. `--quiet` suppresses progress messages for scheduled use.

The directory name is also the run's `batch_id`. Each Python run therefore produces this structure:

```
var/output/
└── 20260812T061500Z_CPUJul2026csaf/
    ├── cpujul2026csaf.json
    ├── findings.csv
    ├── enrichment.csv
    ├── report-data.json
    ├── report-cpujul2026.html
    └── manifest.json
```

The CLI receives the published HTTPS URL. The exact downloaded CSAF bytes are
retained under the basename derived from that URL, and the manifest records the
same name as `source_filename` and `files.source_csaf`.

`findings.csv` contains only vendor facts that belong to the advisory and its revision. `enrichment.csv` contains only CVE observations obtained during this run. Keeping the files separate is mandatory: re-running Python later against the same CSAF normally leaves `findings.csv` unchanged while changing `enrichment.csv`.

`report-data.json` is a derived, versioned read model rather than a new source of truth. Python computes the CVE-level rollups, technical decision tiers, four provider-facing business priorities, KPI values, aggregates, data-quality checks and per-source health once. Schema version 8 uses English as the default report language and retains product-level VEX semantics in each CVE rollup: `vex_state` distinguishes no VEX, partial VEX and complete VEX, with separate affected/VEX product counts and justifications. It aggregates distinct Oracle Support remediations with their category, note, product coverage and families. Its second read model has one top-level object per functional product and nests the individual CSAF product entries in `versions`. The compact product queue therefore presents one row per product, the affected/total CSAF-entry ratio and the most urgent entry-level decision; an interactive drill-down displays the complete version and component context. The product-family profile appears first in the analytical section list. The product view follows it and groups products into initially collapsed priority sections and then expandable product-family sections; its policy dialog explains the complete P1–P4 cascade in place. When a CVE is affected for one grouped CSAF entry and not affected for another, `mixed_status_cves` reports that overlap separately from `vex_only_cves`, preventing the two lists from appearing contradictory. Product priorities are recalculated from each product-version/CVE pair rather than copied from the global CVE, preventing cross-product signal leakage. Partial VEX is flagged in the active CVE decision queue; fully closed CVEs and products are hidden by default but remain filterable and do not present remediation as required. The HTML performs presentation, filtering and sorting only. By default the derived `report-<advisory>.html` is rendered by reading the persisted JSON and embedding the same payload for direct offline opening. `--no-html-report` suppresses only the HTML. A later APEX page can retrieve the identical JSON from a CLOB through an on-demand process and reuse the renderer.

The manifest provides batch-level controls, for example:

```json
{
  "format_version": 3,
  "batch_id": "20260812T061500Z_CPUJul2026csaf",
  "advisory_reference": "CPUJul2026csaf",
  "advisory_revision": "1",
  "csaf_source_hash": "<sha-256>",
  "observation_date": "2026-08-12",
  "findings_count": 4328,
  "enrichment_count": 1434,
  "report_cve_count": 1461,
  "report_affected_cve_count": 1434,
  "report_product_count": 335,
  "report_affected_product_count": 332,
  "report_product_version_count": 679,
  "report_affected_product_version_count": 668
}
```

The manifest is retained beside the CSV files as a human-readable audit artefact. Its `batch_id` must exactly equal the parent directory name, and every row in both CSV files must carry the same value. In the minimal manual flow, the import routine validates the required batch metadata embedded in the CSV rows and the operator reconciles its counts with the manifest. A later APEX upload page may load the manifest automatically, but that is not required to start.

### 6.2 Advisory loading

1. Fetch or read the CSAF file
2. Compute its SHA-256 and generate the immutable records in `findings.csv`
3. Import the CSV into `finding_stage`
4. If the same source hash has already completed successfully, log `SKIPPED` and change no fact data
5. If the same `(vendor, reference, revision)` exists with a different hash, log `CONFLICT` and require review; never overwrite silently
6. If `tracking.version` is new, insert a new `advisory` row rather than updating the prior revision
7. Upsert `product` and `vulnerability` dimensions and insert `fact` rows in one transaction
8. Refresh dependent views and write `load_log`

**Revision handling deserves emphasis.** Vendors revise advisories after publication, occasionally broadening the affected product set. Overwriting silently would erase the evidence of what was originally published and hide the fact that scope changed. Treating each revision as a new advisory row costs storage and buys auditability.

### 6.3 Enrichment loading

Weekly, independent of advisory loading:

1. Collect the distinct CVE set from `fact`
2. Download the daily EPSS CSV once and filter it to the required CVEs; FIRST recommends the daily file rather than its lookup API for bulk workflows
3. Fetch the KEV catalogue from CISA's official GitHub mirror, with cisa.gov as fallback
4. If `NVD_API_KEY` is configured, query NVD CVE API 2.0 in batches of at most 100 CVEs and retain unique references tagged `Exploit`; the key is sent only in the HTTP header and never logged
5. Write one `enrichment.csv` row per CVE, with an observation date and per-source status
6. Import the CSV into `enrichment_stage`
7. `MERGE` on `(cve, observed_date)`: update a same-day observation or insert a later observation
8. Raise alerts on transitions: new KEV entry, EPSS crossing a threshold, first public exploit

The CSAF source hash does not suppress enrichment loading. A later Python execution against an unchanged CSAF is expected to create a new dated enrichment snapshot. This is what makes EPSS drift, later KEV inclusion and growth in NVD exploit-reference counts observable. A zero count means NVD returned no reference tagged `Exploit`; it is not proof that no public exploit exists elsewhere.

The resulting idempotency rules are:

| Situation | Result |
|---|---|
| Same advisory revision and same CSAF hash | Facts are skipped |
| Same advisory revision and different CSAF hash | Import is blocked as a conflict |
| New formal advisory revision | New advisory and fact rows are inserted |
| Same CVE and same observation date | Existing enrichment snapshot is updated |
| Same CVE and later observation date | New enrichment snapshot is inserted |
| Enrichment source unavailable | Source status records degradation; last known successful value is not interpreted as a current negative result |

Each source is isolated. One unreachable source degrades its own columns and nothing else — a lesson from the current implementation, where a CISA timeout aborted the entire run.

Alerting on transitions is where the persistence layer earns its keep operationally. A CVE moving from quarterly-cycle to KEV-listed is an event, and events belong in a notification, not in a report someone might read next month.

---

## 7. Prioritisation logic

The HTML exposes four provider-facing business priorities. The detailed tiering
cascade remains in the application layer for deterministic ordering and audit
explanation; it is policy, and policy changes more often than structure.

| Priority | Internal tiers | Provider-facing meaning |
|---|---:|---|
| P1 | 1 | Confirmed Exploitation |
| P2 | 3–5 | Elevated Exploitation Signals |
| P3 | 6–8 | Elevated Technical Exposure |
| P4 | 9 | Standard Advisory |

Prioritization policy version 2 uses this technical cascade:

| Tier | Condition | Reading |
|---|---|---|
| 1 | KEV listed | Confirmed exploitation |
| 3 | NVD exploit-tagged reference **and** pre-authenticated | Public exploit signal plus technical exposure |
| 4 | FIRST EPSS percentile ≥ 95th | Elevated predicted exploitation likelihood |
| 5 | NVD exploit-tagged reference | Public exploit signal |
| 6 | Pre-authenticated **and** CVSS ≥ 9 | Critical unauthenticated exposure |
| 7 | Pre-authenticated | Network-reachable without credentials |
| 8 | Scope changed | Cross-authority security impact |
| 9 | Remainder | Standard advisory cycle |

The report displays the EPSS probability as well as its percentile. EPSS does
not assert confirmed exploitation and therefore never produces P1 by itself.

A cascade is preferred over a weighted composite score. A composite collapses the reason for a decision into a number, and prioritisation decisions must be explainable — to a change advisory board, an auditor, or a regulator asking why one item was treated before another.

The cascade should be data-driven (a configuration table) rather than hard-coded, so that a policy change is a configuration change with an audit trail rather than a code release.

---

## 8. Implementation phases

**Phase 0 — Manual exchange MVP (implemented locally).** Each Python execution creates a UTC timestamped directory containing the original CSAF JSON under its published basename, `findings.csv`, `enrichment.csv`, `report-data.json`, the derived `report-<advisory>.html`, and `manifest.json`; the directory name is the shared `batch_id`. A user imports both CSV files through APEX Data Workshop, then runs controlled PL/SQL promotion from staging. There is no Python-to-APEX integration, API, OCI Function or direct database connection. The implementation is in `src/csaf_analytics/phase0.py` and `database/phase0/`, with operating instructions in `operations.md`. The target single-ZIP import is specified separately in `apex-import.md`.

**Phase 1 — Deploy and validate the single-advisory load.** The DDL, staging tables and validation/import routines have been generated. They still require compilation in the target Oracle schema and an end-to-end Data Workshop test with a real Oracle CSAF document. Validate repeated imports, same-revision hash conflicts and later enrichment observations against real data.

**Phase 2 — APEX read-only analytics.** Faceted exploration, current enrichment through `v_latest_enrichment`, cross-quarter comparison and CVE drill-down. APEX consumes database data but does not execute Python.

**Phase 3 — Historical backfill and report repointing.** Load the previous six to eight quarterly advisories and source the existing HTML report from SQL. Historical data unlocks recurrence analysis; byte-comparison with the file-based report provides a regression test.

**Phase 4 — Independent Python scheduling.** Schedule Python outside APEX while retaining the same file contract and manual database promotion if desired.

**Phase 5 — Optional automated hand-off.** Replace manual import with ORDS, an OCI Function or a direct controlled connection. This is an operational optimisation, not a data-model change.

**Phase 6 — Enrichment alerting and inventory join.** Add transition notifications, drift thresholds and organisation-level exposure. This remains the highest-value and highest-governance increment.

Phases 0–2 deliver a usable system without coupling Python and APEX. Later phases automate the hand-off without invalidating the MVP artefacts or import rules.

---

## 9. Open questions

**Database target.** Oracle 19c or 23ai. JSON handling differs materially: 23ai's JSON Relational Duality would allow keeping the document as the source of truth while querying relationally, which changes the ingestion design. This decision should be settled before Phase 1.

**Multi-tenancy.** If the platform serves multiple client organisations, row-level security at the database layer (VPD) is preferable to application-layer predicates. A forgotten predicate in one APEX region exposes another client's data; a VPD policy does not have that failure mode.

**Retention.** Enrichment written weekly across roughly 1,500 CVEs per advisory, accumulating across quarters, grows steadily. A retention policy — full history for the trailing year, monthly samples beyond — should be defined before the volume becomes a problem rather than after.

**Public exploit source.** The current index (PoC-in-GitHub) is community-maintained. It is adequate as a binary and volumetric signal but carries no quality guarantee. Whether to add a commercial source with better curation is a cost decision that can wait until the pipeline is proven.

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| CSAF format evolution breaks the parser | Retain raw source in `advisory.source_json`; reload is always possible |
| Enrichment source unavailability | Per-source isolation, caching, explicit degradation in output |
| Vendor advisory revision missed | Hash comparison plus revision tracking; alert on change |
| Mutable enrichment duplicated inside immutable findings | Separate CSV contracts and separate canonical tables |
| Same CSAF imported repeatedly | Successful source hash produces a logged no-op for facts |
| Same revision republished with different content | Block as `CONFLICT`; require explicit review |
| Manual import is incomplete or malformed | Load staging first; validate manifest and row counts; promote atomically |
| Prioritisation policy drift without record | Configuration table with change history |
| Inventory join never happens | Platform remains useful at advisory level; the join is additive, not foundational |

---

## Appendix A — Glossary

**CSAF** — Common Security Advisory Framework, OASIS standard 2.0. Machine-readable vendor advisory format.

**CVSS** — Common Vulnerability Scoring System. Measures intrinsic severity, not risk.

**EPSS** — Exploit Prediction Scoring System (FIRST). Probability of observed exploitation within thirty days.

**KEV** — Known Exploited Vulnerabilities catalogue (CISA). Documented exploitation in the wild.

**VEX** — Vulnerability Exploitability eXchange. Machine-readable statement that a vulnerability is not exploitable in a given product, with standardised justification.

**Pre-authenticated** — `AV:N/PR:N/UI:N`: remotely reachable, no account, no user interaction. No identity-based control participates in the exploitation chain.

**Blast radius** — Number of distinct products affected by a single CVE. Measures both remediation workload and the leverage of a single upstream decision.

**Pair (CVE × product)** — The analytical grain. One CVE affecting one product identifier. An advisory with 1,434 CVEs can carry 4,328 pairs.
