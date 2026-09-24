# Oracle KEV report: source-design discussion

Date: 2026-09-16

## Current generator

The standalone `oracle_kev_report.py` currently joins:

- Oracle's public CVE-to-advisory mapping;
- CISA's Known Exploited Vulnerabilities (KEV) JSON catalog; and
- NVD's CVE API, used only to calculate the CVE-publication-to-KEV-addition
  elapsed time.

The report is generated as static HTML on an external Linux server and then
uploaded into APEX. APEX does not generate the report and need not access the
data sources.

## Finding: Oracle mapping-page lag

`CVE-2026-64849` was missing from the report despite being a CISA KEV. The
report run on 2026-09-16 confirmed why:

- CISA KEV catalog: version `2026.09.14`, released 2026-09-14;
- Oracle map coverage note: `July 21, 2026 Critical Patch Update`;
- CVE-2026-64849 was not in the Oracle map.

Oracle's September 2026 Critical Security Patch Update (CSPU) risk matrix does
list this CVE for Oracle Communications Unified Assurance (MLflow). Therefore,
the omission is caused by source coverage/timing, not the report window or a
failure to recognize KEV membership.

Generated bundle from this validation:

`var/output/oracle-kev/20260916T073844Z_ORACLE_KEV/`

## Agreed source direction

The Oracle CVE-to-advisory mapping should not be the report's inclusion gate.
It may remain a supplemental cross-check.

Use first-party Oracle source documents as the inclusion sources:

1. Oracle Critical Patch Update (CPU) risk matrices;
2. Oracle Critical Security Patch Update (CSPU) risk matrices; and
3. Oracle Security Alert advisories published through Oracle's Security Alerts
   hub.

Normalize the records from those documents into CVE, product, supported/affected
versions, advisory URL, and source type (`CPU`, `CSPU`, or `Security Alert`),
then join the result with the full current CISA KEV catalog.

## Important historical-coverage caveat

A newly KEV-listed CVE can be old. For example, a CVE fixed in an earlier Oracle
release could be added to CISA KEV years later. Looking only at the newest CPU
or CSPU matrices would then miss it.

The robust design is a persistent, historical Oracle CVE ledger built from all
CPU, CSPU, and Security Alert documents. CISA KEV remains the changing input;
each run joins the complete current KEV catalog against that historical Oracle
coverage.

This could be implemented with a SQLite file on the external Linux report
server. APEX would still receive only the generated static HTML. The ledger
would require persistent storage and backups, however.

## Simpler alternative

To avoid adding persistent local state for now:

- keep report generation stateless;
- ingest the current CPU, CSPU, and Security Alert pages;
- join them with the full CISA KEV catalog; and
- accept that a newly KEV-listed CVE from an older release can require manual
  inclusion or an explicit refresh of historical source material.

This is substantially more timely than using the stale mapping page alone and
catches current releases such as CVE-2026-64849, but it does not fully solve the
old-CVE/new-KEV case.

## Open decision

Choose between:

- **Stateless current-source report:** least operational complexity; incomplete
  historical coverage for newly KEV-listed old CVEs.
- **Persistent historical ledger:** complete and auditable coverage; adds a
  small SQLite database and backup/retention responsibility on the Linux
  report server.
