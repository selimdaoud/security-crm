-- sed-dashboard MVP
-- Script 12: Validation Queries
--
-- Purpose:
--   Validate schema, sample data, dashboard views, and the Primavera
--   critical CVE workflow.
--
-- Run after:
--   Schema scripts, sample data, views, and package scripts as needed.

prompt Script 12 - Validation Queries

-- TODO:
-- Add validation queries:
-- - Row counts by table.
-- - Lookup values loaded.
-- - Customers have primary Security Advisors.
-- - Customers have health statuses.
-- - Estate items exist for sample customers.
-- - Primavera security case has linked event.
-- - Primavera security case has impacted customers.
-- - Notification campaign has recipients.
-- - Alerts exist.
-- - Dashboard views return rows.

-- Example:
-- select count(*) as customer_count from customers;
-- select count(*) as active_case_count from security_cases;
-- select count(*) as campaign_count from notification_campaigns;
-- select count(*) as open_action_count from actions;
-- select count(*) as alert_count from alerts;

-- Must return no rows before adding UK_CUSTOMERS_REGISTRYID to an existing
-- CUSTOMERS table. Multiple null Registry IDs remain valid.
select registryid,
       count(*) as duplicate_count
  from customers
 where registryid is not null
 group by registryid
having count(*) > 1;
