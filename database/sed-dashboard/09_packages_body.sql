-- sed-dashboard MVP
-- Script 09: Package Bodies
--
-- Purpose:
--   Implement MVP PL/SQL business logic.
--
-- Run after:
--   08_packages_spec.sql
--
-- Run before:
--   10_sample_data.sql, if sample data calls packages.

prompt Script 09 - Package Bodies

-- -------------------------------------------------------------------------
-- Customer health risk scoring
--
-- Confirmed rule implemented in this first version:
-- - Start at 0.
-- - Add 30 once when at least one PRODUCT Estate item maps to an Oracle
--   acronym whose SECALERT Boolean is TRUE.
-- - Persist that same factual condition in CUSTOMERS.SECALERT.
-- - Cap the score at 100.
-- - A score >= 30 maps to NEEDS_ATTENTION; otherwise it maps to GOOD.
--
-- The package recalculates from source facts and never increments the prior
-- stored score. It deliberately does not COMMIT; transaction control belongs
-- to the APEX request, job, or SQL script that calls it.
-- -------------------------------------------------------------------------

create or replace package body pkg_health_score as

  function customer_has_security_alert(
    p_customer_id in customers.customer_id%type
  ) return boolean
  is
    l_has_security_alert boolean;
  begin
    select case
             when exists (
               select 1
                 from customer_estate_items estate
                 join estate_types estate_type
                   on estate_type.lookup_id = estate.estate_type_id
                 join oracle_acronyms acronym
                   on upper(trim(acronym.acronym)) =
                      upper(trim(estate.product_or_service_name))
                where estate.customer_id = p_customer_id
                  and estate_type.lookup_code = 'PRODUCT'
                  and acronym.secalert
             ) then true
             else false
           end
      into l_has_security_alert
      from dual;

    return l_has_security_alert;
  end customer_has_security_alert;


  procedure evaluate_customer_risk(
    p_customer_id       in  customers.customer_id%type,
    p_score             out number,
    p_has_secalert      out boolean
  )
  is
    l_customer_count pls_integer;
  begin
    select count(*)
      into l_customer_count
      from customers customer
     where customer.customer_id = p_customer_id;

    if l_customer_count = 0 then
      raise_application_error(
        -20001,
        'Customer not found: ' || p_customer_id
      );
    end if;

    p_has_secalert := customer_has_security_alert(p_customer_id);
    p_score := 0;

    if p_has_secalert then
      p_score := p_score + 30;
    end if;

    -- Add future risk contributions here. Each contribution must be derived
    -- from current source facts so that recalculation remains idempotent.
    p_score := least(100, greatest(0, p_score));
  end evaluate_customer_risk;

  function calculate_customer_risk(
    p_customer_id in customers.customer_id%type
  ) return number
  is
    l_score         number;
    l_has_secalert  boolean;
  begin
    evaluate_customer_risk(
      p_customer_id  => p_customer_id,
      p_score        => l_score,
      p_has_secalert => l_has_secalert
    );

    return l_score;
  end calculate_customer_risk;


  procedure refresh_customer_health(
    p_customer_id in customers.customer_id%type
  )
  is
    l_score            number;
    l_status_code      health_statuses.lookup_code%type;
    l_status_id        health_statuses.lookup_id%type;
    l_manual_override  customers.manual_health_override_flag%type;
    l_reason            customers.health_score_reason%type;
    l_has_secalert      boolean;
  begin
    begin
      select nvl(customer.manual_health_override_flag, 'N')
        into l_manual_override
        from customers customer
       where customer.customer_id = p_customer_id
         for update;
    exception
      when no_data_found then
        raise_application_error(
          -20001,
          'Customer not found: ' || p_customer_id
        );
    end;

    evaluate_customer_risk(
      p_customer_id  => p_customer_id,
      p_score        => l_score,
      p_has_secalert => l_has_secalert
    );

    -- SECALERT records the current Estate fact even when an authorized user
    -- has manually overridden the calculated health score and status.
    if l_manual_override = 'Y' then
      update customers customer
         set secalert  = l_has_secalert,
             updated_by = coalesce(
                            sys_context('APEX$SESSION', 'APP_USER'),
                            user
                          ),
             updated_at = systimestamp
       where customer.customer_id = p_customer_id;

      return;
    end if;

    if l_score >= 30 then
      l_status_code := 'NEEDS_ATTENTION';
      l_reason :=
        'Active security alert affects at least one Estate product (+30).';
    else
      l_status_code := 'GOOD';
      l_reason := 'No active risk contribution identified.';
    end if;

    begin
      select status.lookup_id
        into l_status_id
        from health_statuses status
       where status.lookup_code = l_status_code
         and status.active_flag = 'Y';
    exception
      when no_data_found then
        raise_application_error(
          -20002,
          'Active health status not found: ' || l_status_code
        );
    end;

    update customers customer
       set secalert                 = l_has_secalert,
           current_health_score     = l_score,
           current_health_status_id = l_status_id,
           health_score_reason      = l_reason,
           health_calculated_at     = systimestamp,
           updated_by               = coalesce(
                                        sys_context(
                                          'APEX$SESSION',
                                          'APP_USER'
                                        ),
                                        user
                                      ),
           updated_at               = systimestamp
     where customer.customer_id = p_customer_id;
  end refresh_customer_health;


  procedure refresh_all_customer_health
  is
  begin
    for customer_rec in (
      select customer.customer_id
        from customers customer
        join customer_statuses status
          on status.lookup_id = customer.status_id
       where status.lookup_code = 'ACTIVE'
       order by customer.customer_id
    )
    loop
      refresh_customer_health(
        p_customer_id => customer_rec.customer_id
      );
    end loop;
  end refresh_all_customer_health;

end pkg_health_score;
/

-- TODO: Implement package bodies for the remaining deferred business logic:
-- - pkg_security_case
-- - pkg_notification_campaign
-- - pkg_alert_generation
-- - pkg_sample_data

prompt Script 09 complete
