# Database Objects

`phase0/` contains the Oracle 19c-compatible manual CSV staging pilot scripts:

1. `phase0/001_schema.sql`
2. `phase0/002_import_package.sql`

Run them in that order in the APEX parsing schema. These scripts do not yet
implement the target ZIP upload, historical HTML/JSON report storage, or
time-series metric tables described in `../docs/apex-import.md`.

These files are repository prototypes and are not deployed in the current APEX
application. They should not be installed as a prerequisite for the target ZIP
workflow; use them only as reference while building the target schema.

Future database changes should be added as ordered scripts under
`migrations/` rather than silently rewriting deployed objects.
