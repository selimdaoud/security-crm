with portfolio_product_flags as (
  select estate.customer_id,
         upper(trim(estate.product_or_service_name)) as acronym,
         max(
           case
             when acronym_ref.secalert then 1
             else 0
           end
         ) as secalert
    from customer_estate_items estate
    join estate_types estate_type
      on estate_type.lookup_id = estate.estate_type_id
    left join oracle_acronyms acronym_ref
      on upper(trim(acronym_ref.acronym)) =
         upper(trim(estate.product_or_service_name))
   where estate_type.lookup_code = 'PRODUCT'
     and trim(estate.product_or_service_name) is not null
   group by estate.customer_id,
            upper(trim(estate.product_or_service_name))
)
select
  '<div class="sed-customer">
     <div class="sed-customer-icon">
       <span class="fa fa-building-o"></span>
     </div>
     <div class="sed-customer-name-row">
       <a class="sed-customer-link" href="' ||
         apex_escape.html_attribute(
           apex_page.get_url(
             p_page        => 5,
             p_clear_cache => '5',
             p_items       => 'P5_CUSTOMER_ID',
             p_values      => p.customer_id
           )
         ) ||
       '">
         <span class="sed-customer-name">' ||
           apex_escape.html(p.customer_name) ||
         '</span>
       </a>
       <a class="sed-customer-360-button t-Button t-Button--small t-Button--hot"
          href="' ||
         apex_escape.html_attribute(
           apex_page.get_url(
             p_page        => 21,
             p_clear_cache => '21',
             p_items       => 'P21_CUSTOMER_ID',
             p_values      => p.customer_id
           )
         ) ||
       '">
         Customer 360
       </a>
     </div>
   </div>' as customer,

  p.country as country,

  p.region as customer_region,

  sa.full_name as security_advisor,

  p.tier_code        as tier,
  lower(p.tier_code) as tier_css_class,

  cs.lookup_name       as customer_status,
  lower(cs.lookup_code) as customer_status_code,

  apex_escape.html(p.industry) as industry,

  p.registryid as registry_id,

  p.arr as arr,

  coalesce(p.health_label, 'Not assessed') as health,

  case p.health_code
    when 'GOOD'            then 'green'
    when 'AT_RISK'         then 'orange'
    when 'NEEDS_ATTENTION' then 'red'
    else                        'gray'
  end as health_css_class,

  case
    when p.days_since_last_contact is null then
      'No contact'
    else
      p.days_since_last_contact || ' days ago'
  end as last_contact,

  coalesce(
    (
      select case
               when count(*) > 0 then
                 '<div class="sed-action">' ||
                 listagg(
               '<div class="sed-action-item">' ||
                 '<div class="sed-action-heading">' ||
                   '<a href="' ||
                     apex_escape.html_attribute(
                       apex_page.get_url(
                         p_page        => 'action',
                         p_clear_cache => '18',
                         p_items       => 'P18_ACTION_ID',
                         p_values      => a.action_id
                       )
                     ) ||
                   '">' || apex_escape.html(a.title) || '</a>' ||
                   '<span class="sed-action-status sed-action-status-' ||
                     lower(s.lookup_code) || '">' ||
                     apex_escape.html(s.lookup_name) ||
                   '</span>' ||
                 '</div>' ||
                 '<div class="sed-action-due">' ||
                   '<strong>Due Date:</strong> ' ||
                   case
                     when a.due_date is not null then
                       to_char(
                         a.due_date,
                         'Mon DD, YYYY',
                         'NLS_DATE_LANGUAGE=English'
                       )
                     else
                       'Not set'
                   end ||
                 '</div>' ||
               '</div>',
               ''
                 ) within group (
                   order by a.due_date nulls last,
                            a.action_id
                 ) ||
                 '<div class="sed-action-create">' ||
                   '<a class="t-Button t-Button--small t-Button--simple" href="' ||
                     apex_escape.html_attribute(
                       apex_page.get_url(
                         p_page        => 'action',
                         p_clear_cache => '18',
                         p_items       => 'P18_CUSTOMER_ID',
                         p_values      => p.customer_id
                       )
                     ) ||
                   '">' ||
                     '<span class="fa fa-plus" aria-hidden="true"></span>' ||
                     ' Create action' ||
                   '</a>' ||
                 '</div>' ||
                 '</div>'
             end
        from actions a
        join action_statuses s
          on s.lookup_id = a.status_id
       where a.customer_id = p.customer_id
         and s.lookup_code in ('OPEN', 'IN_PROGRESS')
    ),
    '<div class="sed-action sed-action-empty">' ||
      '<div class="sed-action-create">' ||
        '<a class="t-Button t-Button--small t-Button--simple" href="' ||
          apex_escape.html_attribute(
            apex_page.get_url(
              p_page        => 'action',
              p_clear_cache => '18',
              p_items       => 'P18_CUSTOMER_ID',
              p_values      => p.customer_id
            )
          ) ||
        '">' ||
          '<span class="fa fa-plus" aria-hidden="true"></span>' ||
          ' Create action' ||
        '</a>' ||
      '</div>' ||
    '</div>'
  ) as next_action,

  (
    select '<div class="sed-products">' ||
           case
             when count(*) = 0 then
               '<span>N/A</span>'
             else
               nvl(
                 listagg(
                   case
                     when product.secalert = 1 then
                       '<span class="sed-product-alert" ' ||
                       'title="Active security alert">' ||
                       apex_escape.html(product.acronym) ||
                       '</span>'
                   end,
                   ''
                 ) within group (order by product.acronym),
                 ''
               ) ||
               case
                 when sum(
                        case when product.secalert = 0 then 1 else 0 end
                      ) = 0 then
                   ''
                 else
                   '<details class="sed-products-details">' ||
                     '<summary>' ||
                       to_char(
                         sum(
                           case
                             when product.secalert = 0 then 1
                             else 0
                           end
                         )
                       ) ||
                       case
                         when sum(
                                case
                                  when product.secalert = 0 then 1
                                  else 0
                                end
                              ) = 1 then
                           case
                             when sum(product.secalert) > 0 then
                               ' other product'
                             else
                               ' product'
                           end
                         else
                           case
                             when sum(product.secalert) > 0 then
                               ' other products'
                             else
                               ' products'
                           end
                       end ||
                     '</summary>' ||
                     '<div class="sed-products-list">' ||
                       nvl(
                         listagg(
                           case
                             when product.secalert = 0 then
                               '<span>' ||
                               apex_escape.html(product.acronym) ||
                               '</span>'
                           end,
                           ''
                         ) within group (order by product.acronym),
                         ''
                       ) ||
                     '</div>' ||
                   '</details>'
               end
           end ||
           '</div>'
      from portfolio_product_flags product
     where product.customer_id = p.customer_id
  ) as oracle_products,

  coalesce(c.css_services, 'Not set') as css_services

from v_apex_customer_portfolio p

join customers c
  on c.customer_id = p.customer_id

join customer_statuses cs
  on cs.lookup_id = c.status_id

join internal_users sa
  on sa.user_id = c.primary_security_advisor_user_id

where (
    :P1_SECURITY_ADVISOR_USER_ID is null
    or c.primary_security_advisor_user_id = :P1_SECURITY_ADVISOR_USER_ID
)
and (
    nvl(:P1_ACTIVE_ACTIONS, 'N') = 'N'
    or exists (
        select 1
        from actions a_filter
        join action_statuses s_filter
          on s_filter.lookup_id = a_filter.status_id
        where a_filter.customer_id = c.customer_id
          and s_filter.lookup_code in ('OPEN', 'IN_PROGRESS')
    )
)

order by p.customer_name
