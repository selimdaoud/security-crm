# Case management prototype

This folder is a small, file-based first version of the advisor case workflow.
It deliberately has no database, framework, or service layer.

Run the complete evidence refresh from `csaf-analytics`:

```bash
./case-management/run_case_management.sh
```

It creates these local outputs under `case-management/`:

```text
state/                         Runtime SQLite state and Oracle CVE mapping
output/                        Timestamped Oracle KEV report bundles
published/product_report.json  Product-watch news coverage and Oracle advisories
published/case-desk-data.json  Correlated evidence used by the prototype
published/case-desk.html       Browser-local case triage desk
```

In `case-desk.html`, an advisor selects a news-coverage item, chooses the
relevant Oracle product from the local Oracle CVE mapping, and records why the
link is relevant. Creating the case retains a case-create request with the
event, analyst selection, and matching KEV, CSAF, and Oracle mapping evidence
in browser local storage. Use **Export case-create requests** to provide this
data to the case-management backend; that backend assigns the durable case ID.

This is intentionally a triage prototype. A later version can replace browser
storage with the durable case and artifact model without changing its evidence
inputs.
