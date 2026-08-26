-- sed-dashboard MVP
-- Script 06: Constraints and Indexes
--
-- Purpose:
--   Add deferred foreign keys, unique constraints, and reporting indexes.
--
-- Run after:
--   05_health_alert_tables.sql for full MVP build.
--
-- Minimal ownership test:
--   This script can also run after 02_lookup_tables.sql and
--   03_core_tables.sql. Security/campaign constraints and indexes are added
--   only when their tables exist.
--
-- Run before:
--   07_views_dashboard.sql
--
-- Rerun behavior:
--   This script checks for existing constraints/indexes before creating them.
--   That makes it safe to run once for the minimal ownership test and again
--   later after security/campaign tables have been created.

prompt Script 06 - Constraints and Indexes

declare
  function table_exists(p_table_name varchar2) return boolean is
    l_count number;
  begin
    select count(*)
      into l_count
      from user_tables
     where table_name = upper(p_table_name);

    return l_count > 0;
  end;

  function constraint_exists(p_constraint_name varchar2) return boolean is
    l_count number;
  begin
    select count(*)
      into l_count
      from user_constraints
     where constraint_name = upper(p_constraint_name);

    return l_count > 0;
  end;

  function index_exists(p_index_name varchar2) return boolean is
    l_count number;
  begin
    select count(*)
      into l_count
      from user_indexes
     where index_name = upper(p_index_name);

    return l_count > 0;
  end;

  procedure add_constraint_if_missing(
    p_constraint_name varchar2,
    p_ddl varchar2
  ) is
  begin
    if not constraint_exists(p_constraint_name) then
      execute immediate p_ddl;
    end if;
  end;

  procedure add_index_if_missing(
    p_index_name varchar2,
    p_ddl varchar2
  ) is
  begin
    if not index_exists(p_index_name) then
      execute immediate p_ddl;
    end if;
  end;
begin
  add_constraint_if_missing(
    'fk_customers_current_contact',
    'alter table customers add constraint fk_customers_current_contact
       foreign key (current_security_contact_id)
       references customer_contacts (contact_id)'
  );

  add_constraint_if_missing(
    'uk_customer_contacts_customer_email',
    'alter table customer_contacts add constraint uk_customer_contacts_customer_email
       unique (customer_id, email)'
  );

  add_constraint_if_missing(
    'uk_customers_registryid',
    'alter table customers add constraint uk_customers_registryid
       unique (registryid)'
  );

  add_constraint_if_missing(
    'uk_oatm_customer_user_role',
    'alter table oracle_account_team_members add constraint uk_oatm_customer_user_role
       unique (customer_id, user_id, team_role_id)'
  );

  add_index_if_missing(
    'idx_customers_primary_sa_health',
    'create index idx_customers_primary_sa_health
       on customers (primary_security_advisor_user_id, current_health_status_id)'
  );

  add_index_if_missing(
    'idx_customers_tier_status',
    'create index idx_customers_tier_status
       on customers (tier_id, status_id)'
  );

  add_index_if_missing(
    'idx_contacts_customer',
    'create index idx_contacts_customer
       on customer_contacts (customer_id, active_flag)'
  );

  add_index_if_missing(
    'idx_oatm_customer',
    'create index idx_oatm_customer
       on oracle_account_team_members (customer_id, active_flag)'
  );

  add_index_if_missing(
    'idx_oatm_user',
    'create index idx_oatm_user
       on oracle_account_team_members (user_id, active_flag)'
  );

  add_index_if_missing(
    'idx_estate_customer',
    'create index idx_estate_customer
       on customer_estate_items (customer_id)'
  );

  add_index_if_missing(
    'idx_estate_product_deploy',
    'create index idx_estate_product_deploy
       on customer_estate_items (upper(product_or_service_name), upper(deployment_type))'
  );

  add_index_if_missing(
    'idx_interactions_customer_date',
    'create index idx_interactions_customer_date
       on interactions (customer_id, interaction_date)'
  );

  add_index_if_missing(
    'idx_interactions_owner',
    'create index idx_interactions_owner
       on interactions (owner_user_id)'
  );

  add_index_if_missing(
    'idx_reviews_status_date',
    'create index idx_reviews_status_date
       on reviews (status_id, review_date)'
  );

  add_index_if_missing(
    'idx_reviews_customer_date',
    'create index idx_reviews_customer_date
       on reviews (customer_id, review_date)'
  );

  add_index_if_missing(
    'idx_actions_status_due',
    'create index idx_actions_status_due
       on actions (status_id, due_date)'
  );

  add_index_if_missing(
    'idx_actions_owner_status',
    'create index idx_actions_owner_status
       on actions (owner_user_id, status_id)'
  );

  add_index_if_missing(
    'idx_actions_customer',
    'create index idx_actions_customer
       on actions (customer_id)'
  );

  if table_exists('security_cases') then
    add_constraint_if_missing(
      'fk_actions_security_case',
      'alter table actions add constraint fk_actions_security_case
         foreign key (security_case_id)
         references security_cases (security_case_id)'
    );

    add_index_if_missing(
      'idx_actions_security_case',
      'create index idx_actions_security_case
         on actions (security_case_id)'
    );

    add_index_if_missing(
      'idx_sec_cases_status_due',
      'create index idx_sec_cases_status_due
         on security_cases (status_id, target_completion_date)'
    );
  end if;

  if table_exists('notification_campaign_recipients') then
    add_constraint_if_missing(
      'fk_actions_campaign_recipient',
      'alter table actions add constraint fk_actions_campaign_recipient
         foreign key (campaign_recipient_id)
         references notification_campaign_recipients (campaign_recipient_id)'
    );

    add_index_if_missing(
      'idx_recipients_campaign_status',
      'create index idx_recipients_campaign_status
         on notification_campaign_recipients (campaign_id, recipient_status_id)'
    );
  end if;

  if table_exists('security_case_customer_impacts') then
    add_index_if_missing(
      'idx_sec_impacts_case_status',
      'create index idx_sec_impacts_case_status
         on security_case_customer_impacts (security_case_id, impact_status_id)'
    );
  end if;

  if table_exists('notification_campaigns') then
    add_index_if_missing(
      'idx_campaigns_status_end',
      'create index idx_campaigns_status_end
         on notification_campaigns (status_id, end_date)'
    );
  end if;

  if table_exists('alerts') then
    add_index_if_missing(
      'idx_alerts_status_due',
      'create index idx_alerts_status_due
         on alerts (status_id, due_date)'
    );
  end if;
end;
/
