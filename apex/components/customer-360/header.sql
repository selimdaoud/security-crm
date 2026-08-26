declare
  l_customer_name customers.customer_name%type;
  l_country       customers.country%type;
  l_region        customers.region%type;
  l_industry      customers.industry%type;
  l_health_score  customers.current_health_score%type;
  l_tier_code     customer_tiers.lookup_code%type;
  l_advisor_name  internal_users.full_name%type;
  l_advisor_active internal_users.active_flag%type;
  l_health_code   health_statuses.lookup_code%type;
  l_initials      varchar2(10);
  l_tier_label    varchar2(30);
  l_advisor_class varchar2(50);
  l_health_class  varchar2(50);
  l_meta          varchar2(1000);
  l_html          clob;
begin
  select c.customer_name,
         c.country,
         c.region,
         c.industry,
         c.current_health_score,
         t.lookup_code,
         sa.full_name,
         sa.active_flag,
         nvl(h.lookup_code, 'UNKNOWN')
    into l_customer_name,
         l_country,
         l_region,
         l_industry,
         l_health_score,
         l_tier_code,
         l_advisor_name,
         l_advisor_active,
         l_health_code
    from customers c
    join customer_tiers t
      on t.lookup_id = c.tier_id
    join internal_users sa
      on sa.user_id = c.primary_security_advisor_user_id
    left join health_statuses h
      on h.lookup_id = c.current_health_status_id
   where c.customer_id = :P21_CUSTOMER_ID;

  l_initials :=
    upper(
      substr(regexp_substr(trim(l_customer_name), '[^[:space:]]+', 1, 1), 1, 1) ||
      case
        when regexp_count(trim(l_customer_name), '[^[:space:]]+') > 1 then
          substr(regexp_substr(trim(l_customer_name), '[^[:space:]]+$'), 1, 1)
      end
    );

  l_tier_label :=
    'Tier ' || regexp_substr(l_tier_code, '[[:digit:]]+');

  l_advisor_class :=
    case l_advisor_active
      when 'Y' then 'sed-c360-badge-advisor'
      else 'sed-c360-badge-advisor-inactive'
    end;

  l_health_class :=
    case l_health_code
      when 'GOOD'            then 'sed-c360-badge-health-good'
      when 'AT_RISK'         then 'sed-c360-badge-health-at_risk'
      when 'NEEDS_ATTENTION' then 'sed-c360-badge-health-needs_attention'
      else                        'sed-c360-badge-health-unknown'
    end;

  l_meta :=
    apex_escape.html(nvl(l_country, 'Pays non renseigné')) ||
    ' &middot; ' ||
    apex_escape.html(nvl(l_region, 'Région non renseignée')) ||
    ' &middot; ' ||
    apex_escape.html(nvl(l_industry, 'Secteur non renseigné'));

  l_html :=
    '<section class="sed-c360-header" aria-labelledby="sed-c360-customer-name">' ||
      '<div class="sed-c360-identity">' ||
        '<div class="sed-c360-avatar" aria-hidden="true">' ||
          apex_escape.html(l_initials) ||
        '</div>' ||
        '<div class="sed-c360-copy">' ||
          '<h1 class="sed-c360-name" id="sed-c360-customer-name">' ||
            apex_escape.html(l_customer_name) ||
          '</h1>' ||
          '<div class="sed-c360-meta">' || l_meta || '</div>' ||
        '</div>' ||
      '</div>' ||
      '<div class="sed-c360-badges" aria-label="Informations principales">' ||
        '<span class="sed-c360-badge sed-c360-badge-tier">' ||
          apex_escape.html(l_tier_label) ||
        '</span>' ||
        '<span class="sed-c360-badge ' || l_advisor_class || '">' ||
          'Security Advisor&nbsp;<strong class="sed-c360-advisor-name">' ||
            apex_escape.html(l_advisor_name) ||
          '</strong>' ||
        '</span>' ||
        '<span class="sed-c360-badge ' || l_health_class || '">' ||
          'Risk ' ||
          case
            when l_health_score is null then '—'
            else to_char(l_health_score, 'FM990')
          end ||
          '/100' ||
        '</span>' ||
      '</div>' ||
    '</section>';

  return l_html;
exception
  when no_data_found then
    return
      '<div class="sed-c360-header">' ||
        '<p class="sed-c360-name">Client introuvable</p>' ||
      '</div>';
end;
