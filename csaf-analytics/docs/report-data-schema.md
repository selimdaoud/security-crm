# Report Data Contract

`report-data.json` is the versioned read model consumed by the generated
`report-<advisory>.html` and by
the planned APEX reporting pages. It is derived data, not the canonical source
of every product/CVE fact.

## Current version

The current `schema_version` is `8`. English is the default presentation
language.

Version 8 adds four provider-facing business priorities to CVE, product, and
nested product-version records. `priority_code` contains `P1` through `P4` and
`priority_label` contains the corresponding descriptive label. The detailed
numeric `tier` remains available for deterministic ordering and policy audits.
An EPSS percentile at or above 0.95 now contributes to P2 under prioritization
policy version 2.

Version 7 made component-level VEX aggregation explicit in the product view.
Each grouped product exposes `vex_only_cves` for CVEs with a not-affected
declaration and no affected declaration among the represented CSAF product
entries. `mixed_status_cves` identifies CVEs that are affected in at least one
entry but not affected in another. Nested `versions` identify the corresponding
CSAF product ID and component context.

Top-level sections are:

| Property | Purpose |
|---|---|
| `schema_version` | Renderer compatibility contract |
| `prioritization_version` | Business-priority and decision-tier policy version |
| `batch_id` | Execution identity |
| `execution_started_at` | UTC generation timestamp |
| `advisory` | Vendor, reference, revision, dates, URL, and source hash |
| `observation_date` | Enrichment observation date |
| `source_statuses` | EPSS, KEV, and NVD health |
| `kpis` | Report-level counts |
| `cves` | CVE decision view |
| `products` | Product view with nested versions |
| `aggregates` | Product-family, component, age, and VEX aggregates |
| `data_quality` | Pipeline quality controls |

## Compatibility

Consumers must check `schema_version` before rendering or extracting metrics.
Historical JSON is immutable. A future schema change increments the version and
must either retain renderer compatibility or provide an explicit migration.

## Source-of-truth boundary

The report model is sufficient to reproduce the generated report and extract
the metrics represented by its schema. It does not retain every row-level field
and relationship from `findings.csv` and `enrichment.csv`; those files remain
part of the target APEX import bundle.

Detailed product and CVE field definitions currently follow the implementation
in `src/csaf_analytics/phase0.py`. Formal JSON Schema files can be introduced in
a later contract-hardening step.
