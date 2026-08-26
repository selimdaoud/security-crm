-- sed-dashboard MVP
-- Script 11: Jobs
--
-- Purpose:
--   Create scheduled jobs for health refresh, health snapshots,
--   and alert generation.
--
-- Run after:
--   09_packages_body.sql
--
-- Important:
--   Keep jobs disabled initially. Enable only after manual package testing.

prompt Script 11 - Jobs

-- TODO:
-- Create disabled DBMS_SCHEDULER jobs:
-- - JOB_SED_REFRESH_HEALTH
-- - JOB_SED_HEALTH_SNAPSHOT
-- - JOB_SED_GENERATE_ALERTS

