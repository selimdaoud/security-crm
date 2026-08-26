-- sed-dashboard MVP
-- Script 07: Dashboard Views
--
-- Purpose:
--   Create views used by the APEX dashboard and portfolio report.
--
-- Run after:
--   06_constraints_indexes.sql
--
-- Rerun behavior:
--   CREATE OR REPLACE makes this script safe to rerun.

prompt Script 07 - Dashboard Views

-- -------------------------------------------------------------------------
-- APEX customer portfolio
--
-- NEXT_ACTION_ID, NEXT_ACTION, NEXT_ACTION_DUE_DATE, and priority are selected
-- from the same ranked action row. Only outstanding actions are candidates.
-- Aggregating interactions, actions, and estate products separately avoids
-- multiplying rows when a customer has several records in each table.
-- -------------------------------------------------------------------------

create or replace view v_apex_customer_portfolio (
  customer_id,
  customer_name,
  region,
  country,
  registryid,
  arr,
  industry,
  tier_code,
  health_code,
  health_label,
  days_since_last_contact,
  next_action_id,
  next_action,
  next_action_due_date,
  next_action_priority_code,
  oracle_products
) as
with last_interaction as (
  select i.customer_id,
         max(i.interaction_date) as last_interaction_date
    from interactions i
   group by i.customer_id
),
ranked_open_actions as (
  select a.customer_id,
         a.action_id,
         a.title,
         a.due_date,
         p.lookup_code as priority_code,
         row_number() over (
           partition by a.customer_id
           order by a.due_date nulls last, a.action_id
         ) as action_rank
    from actions a
    join action_statuses s
      on s.lookup_id = a.status_id
    join action_priorities p
      on p.lookup_id = a.priority_id
   where s.lookup_code in ('OPEN', 'IN_PROGRESS', 'BLOCKED')
),
estate_products as (
  select e.customer_id,
         listagg(distinct e.product_or_service_name, ', ')
           within group (order by e.product_or_service_name) as oracle_products
    from customer_estate_items e
   group by e.customer_id
)
select c.customer_id,
       c.customer_name,
       c.region,
       c.country,
       c.registryid,
       c.arr,
       c.industry,
       replace(upper(t.lookup_code), 'TIER_', 'T') as tier_code,
       h.lookup_code as health_code,
       case h.lookup_code
         when 'GOOD' then 'Healthy'
         when 'AT_RISK' then 'At Risk'
         when 'NEEDS_ATTENTION' then 'Needs Attention'
         else nvl(h.lookup_name, 'Unknown')
       end as health_label,
       case
         when li.last_interaction_date is null then null
         else trunc(sysdate - li.last_interaction_date)
       end as days_since_last_contact,
       oa.action_id as next_action_id,
       oa.title as next_action,
       oa.due_date as next_action_due_date,
       oa.priority_code as next_action_priority_code,
       ep.oracle_products
  from customers c
  join customer_tiers t
    on t.lookup_id = c.tier_id
  left join health_statuses h
    on h.lookup_id = c.current_health_status_id
  left join last_interaction li
    on li.customer_id = c.customer_id
  left join ranked_open_actions oa
    on oa.customer_id = c.customer_id
   and oa.action_rank = 1
  left join estate_products ep
    on ep.customer_id = c.customer_id;

-- Oracle uses COMMENT ON TABLE for both tables and views.
comment on table v_apex_customer_portfolio is
  'Customer portfolio data prepared for the APEX Home Dashboard report';

comment on column v_apex_customer_portfolio.next_action_id is
  'Primary key passed to the APEX Action form page';

-- Deferred until scripts 04_security_campaign_tables.sql and
-- 05_health_alert_tables.sql create their source tables:
--   v_dashboard_active_security_cases
--   v_dashboard_recent_security_events
--   v_dashboard_active_campaigns
--   v_dashboard_attention_alerts
--   v_campaign_progress
--   v_security_case_impact_summary

prompt Script 07 complete
