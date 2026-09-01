# Database scripts

The `sed-dashboard/` directory contains the Oracle database scripts used by the
APEX application. Their numeric prefixes indicate the intended execution order.

Some scripts are design placeholders and contain `TODO` markers. Review
[`../docs/architecture/sql-implementation-plan.md`](../docs/architecture/sql-implementation-plan.md)
and each script before using the complete sequence in an environment.

The CSAF import schema and package are maintained separately under
[`../csaf-analytics/database/`](../csaf-analytics/database/).

`14_security_report_files.sql` creates the BLOB store used by the APEX
automation that retrieves the checksum-validated Oracle KEV HTML report.
