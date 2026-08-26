select
  '<div class="sed-customer">
     <div class="sed-customer-icon"><span class="fa fa-building-o"></span></div>
     <div>
       <div class="sed-customer-name">' || apex_escape.html(customer_name) || '</div>
       <div class="sed-customer-region">' || apex_escape.html(region) || '</div>
     </div>
   </div>' as customer,

  '<span class="sed-tier sed-tier-' || lower(tier_code) || '">' ||
     apex_escape.html(tier_code) ||
   '</span>' as tier,

  apex_escape.html(industry) as industry,

  '<span class="sed-health sed-health-' ||
    case health_code
      when 'GOOD' then 'green'
      when 'AT_RISK' then 'orange'
      when 'NEEDS_ATTENTION' then 'red'
      else 'gray'
    end ||
  '"><span></span>' || apex_escape.html(health_label) || '</span>' as health,

  case
    when days_since_last_contact is null then 'No contact'
    else days_since_last_contact || ' days ago'
  end as last_contact,

  '<div class="sed-action' ||
     case
       when next_action_priority_code in ('HIGH', 'CRITICAL')
       then ' sed-action-priority-high'
     end ||
  '">' ||
     case
       when next_action_id is not null then
         '<a href="' ||
           apex_escape.html_attribute(
             apex_page.get_url(
               p_page        => 'action',
               p_clear_cache => '18',
               p_items       => 'P18_ACTION_ID',
               p_values      => next_action_id
             )
           ) ||
         '">' || apex_escape.html(next_action) || '</a>'
       else
         '<a href="' ||
           apex_escape.html_attribute(
             apex_page.get_url(
               p_page        => 'action',
               p_clear_cache => '18',
               p_items       => 'P18_CUSTOMER_ID',
               p_values      => customer_id
             )
           ) ||
         '">Create action</a>'
     end ||
     '<div>' ||
       case
         when next_action_due_date is not null
         then to_char(next_action_due_date, 'Mon DD, YYYY')
       end ||
     '</div>
   </div>' as next_action,

  '<div class="sed-products">' ||
    case
      when oracle_products is null then '<span>OCI</span>'
      else '<span>' ||
           regexp_replace(
             apex_escape.html(oracle_products),
             '[[:space:]]*,[[:space:]]*',
             '</span><span>'
           ) ||
           '</span>'
    end ||
  '</div>' as oracle_products

from v_apex_customer_portfolio
order by customer_name
fetch first 50 rows only;
