-- sed-dashboard MVP
-- Script 14: Security Report Files
--
-- Purpose:
--   Store the latest validated copy of externally published security reports.
--   The Monitor Oracle KEV Report APEX automation uses this table to retain
--   the current Oracle KEV HTML document as a BLOB.
--
-- Run after:
--   This table has no dependency on the other application tables.
--
-- Rerun behavior:
--   This script is intended for a first-time installation. It does not drop
--   or replace an existing SECURITY_REPORT_FILES table.

prompt Script 14 - Security Report Files

create table security_report_files (
  report_code varchar2(30) not null,
  checksum_sha256 varchar2(64) not null,
  content_blob blob not null,
  mime_type varchar2(255) default 'text/html; charset=UTF-8' not null,
  content_length number not null,
  last_checked_at timestamp with time zone default systimestamp not null,
  last_changed_at timestamp with time zone default systimestamp not null,
  created_at timestamp with time zone default systimestamp not null,
  updated_at timestamp with time zone default systimestamp not null,
  constraint pk_security_report_files primary key (report_code),
  constraint ck_security_report_checksum check (
    regexp_like(checksum_sha256, '^[0-9a-f]{64}$', 'c')
  ),
  constraint ck_security_report_length check (content_length > 0)
);

comment on table security_report_files is
  'Latest checksum-validated copies of externally published security reports';

comment on column security_report_files.report_code is
  'Stable local identifier; ORACLE_KEV for the Oracle KEV HTML report';

comment on column security_report_files.checksum_sha256 is
  'Lowercase SHA-256 digest verified against the downloaded BLOB';

comment on column security_report_files.content_blob is
  'Exact response bytes returned by the validated report URL';

comment on column security_report_files.last_checked_at is
  'Most recent successful checksum check, including an unchanged result';

comment on column security_report_files.last_changed_at is
  'Most recent time a different validated report BLOB was stored';

prompt Script 14 complete
