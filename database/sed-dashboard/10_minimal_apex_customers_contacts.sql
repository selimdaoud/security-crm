-- sed-dashboard MVP
-- Script 10a: Minimal APEX Customers and Contacts
--
-- Purpose:
--   Seed 20 customers and one customer-side contact per customer for the
--   MINIMAL_APEX_APP customer and contact pages.
--
-- Run after:
--   06_constraints_indexes.sql

prompt Script 10a - Minimal APEX Customers and Contacts

declare
  l_advisor_user_id internal_users.user_id%type;
  l_tier_1_id customer_tiers.lookup_id%type;
  l_tier_2_id customer_tiers.lookup_id%type;
  l_tier_3_id customer_tiers.lookup_id%type;
  l_tier_4_id customer_tiers.lookup_id%type;
  l_active_status_id customer_statuses.lookup_id%type;
  l_good_health_id health_statuses.lookup_id%type;
  l_needs_attention_health_id health_statuses.lookup_id%type;
  l_at_risk_health_id health_statuses.lookup_id%type;

  function get_customer_id (
    p_customer_name in customers.customer_name%type
  ) return customers.customer_id%type is
    l_customer_id customers.customer_id%type;
  begin
    select min(customer_id)
      into l_customer_id
      from customers
     where upper(customer_name) = upper(p_customer_name);

    return l_customer_id;
  end get_customer_id;

  function get_contact_id (
    p_customer_id in customer_contacts.customer_id%type,
    p_email in customer_contacts.email%type
  ) return customer_contacts.contact_id%type is
    l_contact_id customer_contacts.contact_id%type;
  begin
    select min(contact_id)
      into l_contact_id
      from customer_contacts
     where customer_id = p_customer_id
       and upper(email) = upper(p_email);

    return l_contact_id;
  end get_contact_id;

  procedure seed_customer (
    p_customer_name in customers.customer_name%type,
    p_industry in customers.industry%type,
    p_region in customers.region%type,
    p_tier_id in customers.tier_id%type,
    p_health_status_id in customers.current_health_status_id%type,
    p_health_score in customers.current_health_score%type,
    p_contact_name in customer_contacts.full_name%type,
    p_contact_title in customer_contacts.job_title%type,
    p_role_type in customer_contacts.role_type%type,
    p_email in customer_contacts.email%type,
    p_phone in customer_contacts.phone%type
  ) is
    l_customer_id customers.customer_id%type;
    l_contact_id customer_contacts.contact_id%type;
  begin
    l_customer_id := get_customer_id(p_customer_name);

    if l_customer_id is null then
      insert into customers (
        customer_name,
        industry,
        region,
        tier_id,
        status_id,
        primary_security_advisor_user_id,
        current_health_status_id,
        current_health_score,
        health_score_reason,
        health_calculated_at,
        notes,
        created_by
      ) values (
        p_customer_name,
        p_industry,
        p_region,
        p_tier_id,
        l_active_status_id,
        l_advisor_user_id,
        p_health_status_id,
        p_health_score,
        'Seeded for MINIMAL_APEX_APP validation.',
        systimestamp,
        'Minimal APEX seed customer with one current security contact.',
        '10_minimal_apex_customers_contacts.sql'
      )
      returning customer_id into l_customer_id;
    end if;

    l_contact_id := get_contact_id(l_customer_id, p_email);

    if l_contact_id is null then
      insert into customer_contacts (
        customer_id,
        full_name,
        job_title,
        role_type,
        email,
        phone,
        is_primary,
        is_current_security_contact,
        active_flag,
        created_by
      ) values (
        l_customer_id,
        p_contact_name,
        p_contact_title,
        p_role_type,
        p_email,
        p_phone,
        'Y',
        'Y',
        'Y',
        '10_minimal_apex_customers_contacts.sql'
      )
      returning contact_id into l_contact_id;
    else
      update customer_contacts
         set full_name = p_contact_name,
             job_title = p_contact_title,
             role_type = p_role_type,
             phone = p_phone,
             is_primary = 'Y',
             is_current_security_contact = 'Y',
             active_flag = 'Y',
             updated_by = '10_minimal_apex_customers_contacts.sql',
             updated_at = systimestamp
       where contact_id = l_contact_id;
    end if;

    update customers
       set current_security_contact_id = l_contact_id,
           current_health_status_id = p_health_status_id,
           current_health_score = p_health_score,
           health_score_reason = 'Seeded for MINIMAL_APEX_APP validation.',
           health_calculated_at = systimestamp,
           updated_by = '10_minimal_apex_customers_contacts.sql',
           updated_at = systimestamp
     where customer_id = l_customer_id;
  end seed_customer;
begin
  begin
    select user_id
      into l_advisor_user_id
      from internal_users
     where upper(email) = 'SARAH.ADVISOR@EXAMPLE.COM';
  exception
    when no_data_found then
      insert into internal_users (
        full_name,
        email,
        role_name,
        department,
        active_flag,
        created_by
      ) values (
        'Sarah Advisor',
        'sarah.advisor@example.com',
        'Security Advisor',
        'CSS Security',
        'Y',
        '10_minimal_apex_customers_contacts.sql'
      )
      returning user_id into l_advisor_user_id;
  end;

  select lookup_id into l_tier_1_id from customer_tiers where lookup_code = 'TIER_1';
  select lookup_id into l_tier_2_id from customer_tiers where lookup_code = 'TIER_2';
  select lookup_id into l_tier_3_id from customer_tiers where lookup_code = 'TIER_3';
  select lookup_id into l_tier_4_id from customer_tiers where lookup_code = 'TIER_4';
  select lookup_id into l_active_status_id from customer_statuses where lookup_code = 'ACTIVE';
  select lookup_id into l_good_health_id from health_statuses where lookup_code = 'GOOD';
  select lookup_id into l_needs_attention_health_id from health_statuses where lookup_code = 'NEEDS_ATTENTION';
  select lookup_id into l_at_risk_health_id from health_statuses where lookup_code = 'AT_RISK';

  seed_customer('Acme Manufacturing', 'Manufacturing', 'EMEA', l_tier_1_id, l_good_health_id, 88, 'Jane CISO', 'Chief Information Security Officer', 'CISO', 'jane.ciso@acme.example', '+33 1 55 0101');
  seed_customer('Contoso Retail Group', 'Retail', 'EMEA', l_tier_2_id, l_needs_attention_health_id, 62, 'Marc Dubois', 'VP Security', 'VP Security', 'marc.dubois@contoso.example', '+33 1 55 0102');
  seed_customer('Northwind Health', 'Healthcare', 'North America', l_tier_1_id, l_at_risk_health_id, 55, 'Priya Shah', 'Director of Security Operations', 'Security Operations', 'priya.shah@northwind.example', '+1 212 555 0103');
  seed_customer('Fabrikam Energy', 'Energy', 'EMEA', l_tier_1_id, l_good_health_id, 91, 'Lena Hoffmann', 'Head of Cybersecurity', 'Security Leader', 'lena.hoffmann@fabrikam.example', '+49 30 555 0104');
  seed_customer('Globex Financial Services', 'Financial Services', 'EMEA', l_tier_1_id, l_needs_attention_health_id, 66, 'Omar Benali', 'CISO', 'CISO', 'omar.benali@globex.example', '+33 1 55 0105');
  seed_customer('Initech Cloud Services', 'Technology', 'North America', l_tier_2_id, l_good_health_id, 84, 'Emily Carter', 'Security Architect', 'Security Architect', 'emily.carter@initech.example', '+1 415 555 0106');
  seed_customer('Umbrella Life Sciences', 'Life Sciences', 'EMEA', l_tier_2_id, l_at_risk_health_id, 58, 'Thomas Meyer', 'IT Security Manager', 'IT Security', 'thomas.meyer@umbrella.example', '+41 22 555 0107');
  seed_customer('Stark Industrial Systems', 'Industrial', 'North America', l_tier_1_id, l_good_health_id, 87, 'Rachel Kim', 'VP Infrastructure Security', 'VP Security', 'rachel.kim@stark.example', '+1 646 555 0108');
  seed_customer('Wayne Public Sector', 'Public Sector', 'North America', l_tier_2_id, l_needs_attention_health_id, 64, 'Daniel Brooks', 'Cyber Risk Lead', 'Risk Lead', 'daniel.brooks@wayne.example', '+1 202 555 0109');
  seed_customer('Hooli Media Platform', 'Media', 'North America', l_tier_3_id, l_good_health_id, 82, 'Sophia Nguyen', 'Security Engineering Manager', 'Security Engineering', 'sophia.nguyen@hooli.example', '+1 650 555 0110');
  seed_customer('Soylent Food Systems', 'Consumer Goods', 'EMEA', l_tier_3_id, l_good_health_id, 79, 'Alice Martin', 'Information Security Officer', 'Security Officer', 'alice.martin@soylent.example', '+33 1 55 0111');
  seed_customer('Cyberdyne Logistics', 'Logistics', 'APAC', l_tier_2_id, l_at_risk_health_id, 52, 'Kenji Tanaka', 'CISO', 'CISO', 'kenji.tanaka@cyberdyne.example', '+81 3 555 0112');
  seed_customer('Tyrell Smart Devices', 'Technology', 'EMEA', l_tier_3_id, l_needs_attention_health_id, 68, 'Nadia Rossi', 'Security Program Manager', 'Security Program', 'nadia.rossi@tyrell.example', '+39 02 555 0113');
  seed_customer('Wonka Consumer Brands', 'Consumer Goods', 'EMEA', l_tier_4_id, l_good_health_id, 76, 'Peter Wilson', 'IT Director', 'IT Director', 'peter.wilson@wonka.example', '+44 20 555 0114');
  seed_customer('Massive Dynamic Research', 'Research', 'North America', l_tier_2_id, l_good_health_id, 86, 'Laura Chen', 'Director, Information Security', 'Security Director', 'laura.chen@massivedynamic.example', '+1 617 555 0115');
  seed_customer('Aperture Engineering', 'Engineering', 'EMEA', l_tier_3_id, l_at_risk_health_id, 57, 'Victor Alvarez', 'Operational Security Lead', 'Operational Security', 'victor.alvarez@aperture.example', '+34 91 555 0116');
  seed_customer('Vehement Capital Partners', 'Financial Services', 'North America', l_tier_2_id, l_good_health_id, 81, 'Monica Reed', 'CISO', 'CISO', 'monica.reed@vehement.example', '+1 212 555 0117');
  seed_customer('Pied Piper Networks', 'Technology', 'North America', l_tier_4_id, l_needs_attention_health_id, 69, 'Ravi Patel', 'Security Architect', 'Security Architect', 'ravi.patel@piedpiper.example', '+1 650 555 0118');
  seed_customer('Blue Sun Aerospace', 'Aerospace', 'APAC', l_tier_2_id, l_good_health_id, 83, 'Mei Lin', 'Head of Security', 'Security Leader', 'mei.lin@bluesun.example', '+65 555 0119');
  seed_customer('Oceanic Airlines', 'Transportation', 'EMEA', l_tier_3_id, l_good_health_id, 78, 'Claire Bernard', 'Security Operations Manager', 'Security Operations', 'claire.bernard@oceanic.example', '+33 1 55 0120');

  commit;
end;
/

prompt Minimal APEX customer/contact seed complete

