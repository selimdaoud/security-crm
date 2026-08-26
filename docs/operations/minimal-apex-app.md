# Minimal APEX Application From Created Tables

## Purpose

This guide describes the smallest useful `sed-dashboard` APEX application you can build after creating the first database tables.

It assumes you have successfully run:

```text
database/sed-dashboard/02_lookup_tables.sql
database/sed-dashboard/03_core_tables.sql
database/sed-dashboard/06_constraints_indexes.sql
```

This minimal app is not the full MVP. It is the first working APEX application based on the created tables.

The goal is to prove:
- You can create a Security Advisor.
- You can create a Customer.
- You can assign the Customer to the Security Advisor.
- You can add customer contacts.
- You can add Oracle account team members.
- You can add estate records.
- You can log interactions.
- You can schedule reviews.
- You can create actions.
- The Security Advisor can see their customer list.

Do not include security cases, security events, notification campaigns, health snapshots, jobs, packages, or integrations in this first minimal app.

## Tables Used

Use only these tables:

- `internal_users`
- `customers`
- `customer_contacts`
- `oracle_account_team_members`
- `customer_estate_items`
- `interactions`
- `reviews`
- `actions`

Use these lookup tables for lists of values:

- `customer_tiers`
- `customer_statuses`
- `team_roles`
- `health_statuses`
- `interaction_types`
- `review_statuses`
- `action_priorities`
- `action_statuses`
- `estate_types`
- `estate_lifecycle_statuses`

## Minimal Application Pages

Create these pages first:

1. Home
2. Security Advisors
3. Customers
4. Customer Detail
5. Contacts
6. Oracle Account Team
7. Estate Items
8. Interactions
9. Reviews
10. Actions

Keep the pages simple. Use APEX generated pages where possible.

## Page 1: Home

Purpose:
- Give a simple entry point.

For the first version, the Home page can contain links/cards to:
- Customers
- Security Advisors
- Actions
- Reviews

Do not build a complex dashboard yet.

## Page 2: Security Advisors

Table:

```text
internal_users
```

Page type:
- Interactive Report with Form

Purpose:
- Manage internal Oracle users for the MVP.
- Create Security Advisors who can own customers.

Fields:
- `full_name`
- `email`
- `role_name`
- `department`
- `active_flag`

Recommended first record:

```text
Full name: Sarah Advisor
Email: sarah.advisor@example.com
Role name: Security Advisor
Department: CSS Security
Active: Y
```

APEX implementation:

1. Open your APEX workspace.

2. Go to `App Builder`.

3. Open the `sed-dashboard` application.

4. Click `Create Page`.

5. Choose `Report`.

6. Choose `Interactive Report`.

   This creates a searchable, filterable table view. It is the easiest first page type for managing records.

7. When APEX asks for the data source, choose:

   ```text
   Table
   ```

8. Select the table:

   ```text
   internal_users
   ```

9. Set the page name to:

   ```text
   Security Advisors
   ```

10. If APEX asks whether to include a form page, choose yes.

   The form page lets you create and edit rows in `internal_users`. Without a form page, you would only have a read-only report.

11. Confirm the primary key is:

   ```text
   user_id
   ```

12. Let APEX create the report and form pages.

13. Run the application.

14. Open `Security Advisors`.

15. Click `Create`.

16. Enter the first Security Advisor:

   ```text
   Full name: Sarah Advisor
   Email: sarah.advisor@example.com
   Role name: Security Advisor
   Department: CSS Security
   Active flag: Y
   ```

17. Save the record.

18. Return to the report and confirm Sarah Advisor appears.

What APEX creates:
- An Interactive Report page listing records from `internal_users`.
- A Form page for creating and editing one `internal_users` row.
- Navigation entry for the page.
- Basic automatic row processing for insert/update/delete.

What to check:
- The report opens without error.
- The `Create` button opens the form.
- The form saves successfully.
- The new Security Advisor appears in the report.
- The `email` value is unique.

If the save fails:
- Check that `full_name` and `email` are filled in.
- Check that `active_flag` is either `Y` or `N`.
- Check that the email is not already used by another row.

## Page 3: Customers

Table:

```text
customers
```

Page type:
- Interactive Report with Form

Purpose:
- Create and list customers.

Fields to show in the report:
- `customer_name`
- `industry`
- `region`
- `tier_id`
- `status_id`
- `primary_security_advisor_user_id`
- `current_health_status_id`
- `current_health_score`

Fields for the create/edit form:
- `customer_name`
- `industry`
- `region`
- `tier_id`
- `status_id`
- `primary_security_advisor_user_id`
- `current_health_status_id`
- `current_health_score`
- `notes`

Do not require:
- `current_security_contact_id`
- health override fields
- source fields

Those can be hidden or left optional.

## Customers Page LOVs

Configure these fields as select lists:

### `tier_id`

LOV SQL:

```sql
select lookup_name d, lookup_id r
from customer_tiers
where active_flag = 'Y'
order by display_order, lookup_name
```

### `status_id`

LOV SQL:

```sql
select lookup_name d, lookup_id r
from customer_statuses
where active_flag = 'Y'
order by display_order, lookup_name
```

### `primary_security_advisor_user_id`

LOV SQL:

```sql
select full_name d, user_id r
from internal_users
where active_flag = 'Y'
  and upper(trim(role_name)) = 'SECURITY ADVISOR'
order by full_name
```

### `current_health_status_id`

LOV SQL:

```sql
select lookup_name d, lookup_id r
from health_statuses
where active_flag = 'Y'
order by display_order, lookup_name
```

## Page 4: Customer Detail

This is the most important page in the minimal app.

Purpose:
- Show one customer and all related records.

Recommended page type:
- Form page on `customers`
- Add subregions below the customer form

Main customer item:

```text
P_CUSTOMER_ID
```

Related regions should filter by:

```sql
customer_id = :P_CUSTOMER_ID
```

Regions:
- Contacts
- Oracle Account Team
- Estate Items
- Interactions
- Reviews
- Actions

Simplest approach:
- Use separate report/form pages for each child table first.
- Add links from Customer Detail to those pages passing `P_CUSTOMER_ID`.

Better approach, once comfortable:
- Add child Interactive Grids directly on Customer Detail.

## Page 5: Contacts

Table:

```text
customer_contacts
```

Page type:
- Interactive Report with Form

Purpose:
- Manage customer-side contacts.

Fields:
- `customer_id`
- `full_name`
- `job_title`
- `role_type`
- `email`
- `phone`
- `is_primary`
- `is_current_security_contact`
- `active_flag`

LOV for `customer_id`:

```sql
select customer_name d, customer_id r
from customers
order by customer_name
```

Recommended first contact:

```text
Customer: Acme Manufacturing
Name: Jane CISO
Role type: CISO
Email: jane.ciso@acme.example
Primary: Y
Current security contact: Y
Active: Y
```

## Page 6: Oracle Account Team

Table:

```text
oracle_account_team_members
```

Page type:
- Interactive Report with Form

Purpose:
- Track the broader Oracle team around the customer.

Fields:
- `customer_id`
- `user_id`
- `team_role_id`
- `primary_flag`
- `start_date`
- `end_date`
- `active_flag`

LOV for `customer_id`:

```sql
select customer_name d, customer_id r
from customers
order by customer_name
```

LOV for `user_id`:

```sql
select full_name d, user_id r
from internal_users
where active_flag = 'Y'
order by full_name
```

LOV for `team_role_id`:

```sql
select lookup_name d, lookup_id r
from team_roles
where active_flag = 'Y'
order by display_order, lookup_name
```

Important:
- This table is not the same as `customers.primary_security_advisor_user_id`.
- The customer has one primary Security Advisor.
- This table records all Oracle people involved in the account.

## Page 7: Estate Items

Table:

```text
customer_estate_items
```

Page type:
- Interactive Report with Form

Purpose:
- Track products/services/workloads relevant to security.

Fields:
- `customer_id`
- `estate_type_id`
- `product_or_service_name`
- `product_version`
- `deployment_type`
- `environment_name`
- `region_name`
- `business_criticality`
- `security_relevance`
- `lifecycle_status_id`
- `last_verified_at`
- `notes`

LOV for `estate_type_id`:

```sql
select lookup_name d, lookup_id r
from estate_types
where active_flag = 'Y'
order by display_order, lookup_name
```

LOV for `lifecycle_status_id`:

```sql
select lookup_name d, lookup_id r
from estate_lifecycle_statuses
where active_flag = 'Y'
order by display_order, lookup_name
```

Recommended first estate item:

```text
Customer: Acme Manufacturing
Type: Product
Product/service: Primavera
Version: 23.x
Deployment type: On-prem
Business criticality: High
Security relevance: High
Lifecycle status: Active
```

## Page 8: Interactions

Table:

```text
interactions
```

Page type:
- Interactive Report with Form

Purpose:
- Log customer engagement.

Fields:
- `customer_id`
- `interaction_type_id`
- `interaction_date`
- `subject`
- `summary`
- `owner_user_id`
- `external_contact_id`
- `next_steps`

LOV for `interaction_type_id`:

```sql
select lookup_name d, lookup_id r
from interaction_types
where active_flag = 'Y'
order by display_order, lookup_name
```

LOV for `owner_user_id`:

```sql
select full_name d, user_id r
from internal_users
where active_flag = 'Y'
order by full_name
```

LOV for `external_contact_id`:

```sql
select full_name d, contact_id r
from customer_contacts
where active_flag = 'Y'
order by full_name
```

Later improvement:
- Filter contacts by selected customer.
- For the first minimal app, a global contact LOV is acceptable.

## Page 9: Reviews

Table:

```text
reviews
```

Page type:
- Interactive Report with Form

Purpose:
- Schedule and complete customer reviews.

Fields:
- `customer_id`
- `review_type`
- `review_date`
- `status_id`
- `owner_user_id`
- `agenda`
- `notes`
- `outcome`
- `completed_at`

LOV for `status_id`:

```sql
select lookup_name d, lookup_id r
from review_statuses
where active_flag = 'Y'
order by display_order, lookup_name
```

## Page 10: Actions

Table:

```text
actions
```

Page type:
- Interactive Report with Form

Purpose:
- Track open work and commitments.

Fields:
- `customer_id`
- `title`
- `description`
- `owner_user_id`
- `priority_id`
- `status_id`
- `due_date`
- `completed_at`
- `resolution_notes`

Hide for minimal app:
- `security_case_id`
- `campaign_recipient_id`

Those are for the later security/campaign workflow.

LOV for `priority_id`:

```sql
select lookup_name d, lookup_id r
from action_priorities
where active_flag = 'Y'
order by display_order, lookup_name
```

LOV for `status_id`:

```sql
select lookup_name d, lookup_id r
from action_statuses
where active_flag = 'Y'
order by display_order, lookup_name
```

## "My Customers" Report

Once the basic Customers page works, create a saved report or separate page called:

```text
My Customers
```

Use this query:

```sql
select c.customer_id,
       c.customer_name,
       c.industry,
       c.region,
       tier.lookup_name as tier,
       status.lookup_name as status,
       u.full_name as primary_security_advisor
from customers c
join internal_users u
  on u.user_id = c.primary_security_advisor_user_id
join customer_tiers tier
  on tier.lookup_id = c.tier_id
join customer_statuses status
  on status.lookup_id = c.status_id
where upper(u.email) = upper(:APP_USER)
order by c.customer_name
```

If your APEX login username is not the email address, manually test first with:

```sql
where upper(u.email) = upper('sarah.advisor@example.com')
```

Later you can add an `apex_username` column to `internal_users` if needed.

## Minimal Build Order in APEX

Build in this order:

1. Create app `sed-dashboard`.
2. Create Security Advisors page from `internal_users`.
3. Add Sarah Advisor.
4. Create Customers page from `customers`.
5. Add Acme Manufacturing and assign Sarah Advisor.
6. Create Contacts page.
7. Add Jane CISO for Acme.
8. Create Oracle Account Team page.
9. Add Sarah Advisor as Primary Security Advisor team member.
10. Create Estate Items page.
11. Add Primavera on-prem estate item.
12. Create Interactions page.
13. Create Reviews page.
14. Create Actions page.
15. Create or configure "My Customers" report.

## What Success Looks Like

The minimal application is successful when:

- You can create a Security Advisor.
- You can create a Customer.
- The Customer is assigned to the Security Advisor.
- You can see the Customer in a customer list.
- You can add contacts for the Customer.
- You can add Oracle account team members.
- You can add estate records.
- You can log interactions.
- You can schedule reviews.
- You can create actions.
- The "My Customers" report shows only the logged-in Security Advisor's customers.

## What To Avoid For Now

Do not build yet:
- Security events.
- Security cases.
- Notification campaigns.
- Alerts.
- Health scoring packages.
- Scheduled jobs.
- Outlook integration.
- Email sending.
- Complex authorization.
- Custom JavaScript.

This first app is only to prove the core customer/advisor workflow.
