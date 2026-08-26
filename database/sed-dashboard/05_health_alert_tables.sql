-- sed-dashboard MVP
-- Script 05: Health and Alert Tables
--
-- Purpose:
--   Create relationship health history and alert tracking tables.
--
-- Run after:
--   04_security_campaign_tables.sql
--
-- Run before:
--   06_constraints_indexes.sql

prompt Script 05 - Health and Alert Tables

-- TODO:
-- Create relationship_health_snapshots.
-- Create alerts.

-- Notes:
-- - Current customer health is stored directly on customers.
-- - Historical health is stored in relationship_health_snapshots.
-- - alert_rules is deferred from MVP. Initial alert logic belongs in
--   pkg_alert_generation.

