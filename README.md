# Security CRM

Security CRM is an Oracle APEX application for customer relationship, portfolio,
and security-advisory management. The repository also contains an independent
Python component that converts Oracle CSAF advisories into analysis datasets and
standalone HTML reports.

## Repository layout

| Path | Purpose |
| --- | --- |
| [`apex/`](apex/) | APEX application exports, shared static assets, and page components |
| [`database/sed-dashboard/`](database/sed-dashboard/) | Ordered SQL installation and validation scripts for the APEX application |
| [`csaf-analytics/`](csaf-analytics/) | Python CSAF processing, enrichment, report generation, and APEX import design |
| [`docs/`](docs/) | Product, architecture, operations, and historical handoff documentation |

## Where to start

- For the current product scope, read [`docs/product/mvp.md`](docs/product/mvp.md).
- For the APEX application artifacts, read [`apex/README.md`](apex/README.md).
- For database setup, read [`database/README.md`](database/README.md).
- For CSAF report generation and import, read
  [`csaf-analytics/README.md`](csaf-analytics/README.md).
- For all other documents, use [`docs/README.md`](docs/README.md).

## Repository conventions

- Documentation and file names are in English.
- `apex/static/dashboard.css` is the editable source for the shared dashboard
  stylesheet. Copies inside an APEX export are snapshots of the exported app.
- `apex/exports/sed-dashboard-2/` is the current full split APEX export.
- `apex/exports/legacy/` contains older exports kept only for comparison.
- Generated CSAF inputs and outputs live under `csaf-analytics/var/` and are not
  source code.

