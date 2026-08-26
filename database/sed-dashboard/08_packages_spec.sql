-- sed-dashboard MVP
-- Script 08: Package Specifications
--
-- Purpose:
--   Create PL/SQL package specifications for MVP business logic.
--
-- Run after:
--   07_views_dashboard.sql
--
-- Run before:
--   09_packages_body.sql

prompt Script 08 - Package Specifications

-- -------------------------------------------------------------------------
-- Customer health risk scoring
--
-- CURRENT_HEALTH_SCORE is an increasing risk score: 0 means no identified
-- risk and higher values mean greater concern. The package body owns all
-- calculation and persistence rules; APEX presentation queries only read the
-- stored score and status.
-- -------------------------------------------------------------------------

create or replace package pkg_health_score as

  function calculate_customer_risk(
    p_customer_id in customers.customer_id%type
  ) return number;

  procedure refresh_customer_health(
    p_customer_id in customers.customer_id%type
  );

  procedure refresh_all_customer_health;

end pkg_health_score;
/

-- TODO: Create package specs for the remaining deferred business logic:
-- - pkg_security_case
-- - pkg_notification_campaign
-- - pkg_alert_generation
-- - pkg_sample_data

prompt Script 08 complete
