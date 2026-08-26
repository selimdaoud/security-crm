-- sed-dashboard MVP
-- Script 04: Security and Campaign Tables
--
-- Purpose:
--   Create security events, security cases, case/event links,
--   customer impact assessment, notification campaigns, and recipients.
--
-- Run after:
--   03_core_tables.sql
--
-- Run before:
--   05_health_alert_tables.sql

prompt Script 04 - Security and Campaign Tables

-- TODO:
-- Create security_events.
-- Create security_cases.
-- Create security_case_events.
-- Create security_case_customer_impacts.
-- Create notification_campaigns.
-- Create notification_campaign_recipients.

-- Core workflow:
--   security_events
--     -> security_cases
--     -> security_case_customer_impacts
--     -> notification_campaigns
--     -> notification_campaign_recipients
--     -> actions

-- Notes:
-- - security_cases are the operational/advisor-facing object.
-- - security_events are source/detail records and can be grouped into cases.
-- - Do not add notification_campaign_recipients.follow_up_action_id in MVP.
--   Follow-up is linked one way from actions.campaign_recipient_id.

