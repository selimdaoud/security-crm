# sed-dashboard MVP Deployment Next Steps

## Purpose

This document is a practical deployment guide for building the `sed-dashboard` MVP in an OCI Oracle APEX workspace.

The Oracle KEV report, page-25 iframe, and metadata-driven P1 button added after
this original deployment plan are documented separately in
[`oracle-kev-dashboard.md`](oracle-kev-dashboard.md). The checked-in split APEX
export still needs to be refreshed from the deployed application to include the
latest iframe and Dynamic Action changes.

It assumes:
- You have admin access to the APEX workspace.
- You are technically literate but not APEX-trained.
- You want a reliable MVP, not a perfect enterprise app on day one.
- You will build first with manual/sample data, then add automation and integrations later.

Official references:
- Oracle APEX in Oracle Cloud: https://docs.oracle.com/en/cloud/paas/apex/index.html
- Oracle APEX App Builder Guide: https://docs.oracle.com/en/database/oracle/apex/24.2/htmdb/index.html
- Oracle APEX SQL Workshop Guide: https://docs.oracle.com/en/database/oracle/apex/24.2/aeutl/index.html

## Target MVP

The MVP should prove this workflow:

1. Security event is recorded.
2. Security case/advisory is created.
3. Impacted customers are identified.
4. Notification campaign is created.
5. Customers are tracked as pending, sent, acknowledged, or follow-up required.
6. Follow-up actions are created and closed.
7. Dashboard shows portfolio health, open work, active cases, and active campaigns.

Core workflow:

```text
security_events
  -> security_cases
  -> security_case_customer_impacts
  -> notification_campaigns
  -> notification_campaign_recipients
  -> actions
```

## Phase 0: Before You Touch APEX

### 0.1 Confirm Workspace Access

You need:
- APEX workspace URL.
- Workspace name.
- Admin/developer username.
- Parsing schema name.
- Permission to run SQL scripts in SQL Workshop.

In APEX, confirm you can access:
- App Builder.
- SQL Workshop.
- Shared Components.
- Administration or workspace user management.

### 0.2 Decide Names

Use these names unless you have a reason to change them:

- Application name: `sed-dashboard`
- Parsing schema: whatever your workspace already uses
- SQL folder locally: `database/sed-dashboard/`
- First APEX app alias: `SED_DASHBOARD`

### 0.3 Keep the First Build Manual

Do not start with:
- Outlook integration.
- Email sending.
- SharePoint integration.
- CSAF ingestion.
- OCI service discovery.

The first build should use SQL tables, sample data, APEX reports/forms, and manual workflow tracking.

## Phase 0.5: First Hands-On Data Test

Before loading a large sample dataset, the first meaningful app workflow should be very small:

1. Create one Security Advisor.
2. Create one Customer assigned to that Security Advisor.

This proves the most basic ownership rule in the application:

```text
customers.primary_security_advisor_user_id = internal_users.user_id
```

That rule controls the Security Advisor's default customer list.

### 0.5.1 When To Do This

Do this after the following SQL scripts exist and have been run successfully in SQL Workshop:

```text
02_lookup_tables.sql
03_core_tables.sql
06_constraints_indexes.sql
```

You do not need security cases, campaigns, health packages, or jobs for this first check.

### 0.5.2 Create One Security Advisor

Create a row in `internal_users`.

Example user:

```text
Full name: Sarah Advisor
Email: sarah.advisor@example.com
Role: Security Advisor
Department: CSS Security
Active: Y
```

Purpose:
- This is the Oracle-side person who will own a customer portfolio.
- Later, when Sarah logs in, the app should show Sarah's assigned customers by default.

In SQL terms, this creates:

```text
internal_users.user_id = generated ID for Sarah Advisor
```

Important:
- The email or username should match, or be mappable to, the APEX login user.
- In APEX, the logged-in user is available as `:APP_USER`.
- For MVP, use email matching if your APEX username is the email address.

Example mapping logic:

```sql
select user_id
from internal_users
where upper(email) = upper(:APP_USER)
```

If your APEX usernames are not emails, add a future column such as `apex_username` or agree on a mapping convention before building authorization.

### 0.5.3 Create One Customer

Create a row in `customers`.

Example customer:

```text
Customer name: Acme Manufacturing
Industry: Manufacturing
Region: EMEA
Tier: Tier 1 - Strategic
Status: Active
Primary Security Advisor: Sarah Advisor
Notes: First test customer for SED dashboard MVP.
```

The important field is:

```text
customers.primary_security_advisor_user_id = Sarah Advisor's internal_users.user_id
```

Purpose:
- This proves that a customer can be assigned to one primary Security Advisor.
- This is what drives the default "My Customers" view.

### 0.5.4 Optional: Add Minimal Supporting Records

After the customer exists, add only enough data to make the customer detail page useful:

Customer contact:

```text
Name: Jane CISO
Role: CISO
Email: jane.ciso@acme.example
Primary: Y
Current security contact: Y
```

Oracle account team member:

```text
Customer: Acme Manufacturing
User: Sarah Advisor
Team role: Primary Security Advisor
Primary: Y
Active: Y
```

Estate item:

```text
Product/service: Primavera
Deployment type: On-prem
Business criticality: High
Security relevance: High
Lifecycle status: Active
Last verified: today
```

Initial interaction:

```text
Type: Introductory Call
Subject: Initial customer onboarding
Owner: Sarah Advisor
Summary: Customer created and initial security contact confirmed.
```

Initial review:

```text
Review type: Security onboarding review
Status: Scheduled
Owner: Sarah Advisor
```

Initial action:

```text
Title: Confirm Oracle estate details
Owner: Sarah Advisor
Priority: Medium
Status: Open
```

These records are optional for the first ownership test, but they make the first Customer Detail page more useful.

### 0.5.5 Validate "My Customers"

Once Sarah Advisor and Acme Manufacturing exist, run a query equivalent to:

```sql
select c.customer_id,
       c.customer_name,
       u.full_name as primary_security_advisor
from customers c
join internal_users u
  on u.user_id = c.primary_security_advisor_user_id
where upper(u.email) = upper(:APP_USER);
```

In SQL Workshop, replace `:APP_USER` manually with Sarah's email for testing:

```sql
select c.customer_id,
       c.customer_name,
       u.full_name as primary_security_advisor
from customers c
join internal_users u
  on u.user_id = c.primary_security_advisor_user_id
where upper(u.email) = upper('sarah.advisor@example.com');
```

Expected result:

```text
Acme Manufacturing
```

If this works, the basic customer ownership model is correct.

### 0.5.6 APEX Page Behavior To Build Later

When you build the Customers page in APEX:

- Default report: "My Customers"
- Filter: customers where `primary_security_advisor_user_id` equals the logged-in internal user
- Optional secondary report: "Customers I Support"
- Filter: customers where the logged-in user appears in `oracle_account_team_members`

This gives each Security Advisor a focused portfolio view while still allowing broader team participation.

## Phase 1: Create the SQL Files Locally

Create this folder:

```text
database/sed-dashboard/
```

Create these files:

```text
database/sed-dashboard/01_drop_objects.sql
database/sed-dashboard/02_lookup_tables.sql
database/sed-dashboard/03_core_tables.sql
database/sed-dashboard/04_security_campaign_tables.sql
database/sed-dashboard/05_health_alert_tables.sql
database/sed-dashboard/06_constraints_indexes.sql
database/sed-dashboard/07_views_dashboard.sql
database/sed-dashboard/08_packages_spec.sql
database/sed-dashboard/09_packages_body.sql
database/sed-dashboard/10_sample_data.sql
database/sed-dashboard/11_jobs.sql
database/sed-dashboard/12_validation_queries.sql
```

Use `docs/architecture/sql-implementation-plan.md` as the source of truth for what each script contains.

Recommended build order:

1. Build lookup tables.
2. Build core tables.
3. Build security/campaign tables.
4. Build health/alert tables.
5. Add constraints and indexes.
6. Load sample data.
7. Run validation queries.
8. Create dashboard views.
9. Create PL/SQL packages.
10. Add jobs later, disabled at first.

## Phase 2: Load Schema Objects in APEX

### 2.1 Open SQL Workshop

In APEX:

1. Open your workspace.
2. Go to `SQL Workshop`.
3. Open `SQL Scripts`.
4. Upload or paste the scripts one at a time.

Start with:

```text
02_lookup_tables.sql
03_core_tables.sql
04_security_campaign_tables.sql
05_health_alert_tables.sql
06_constraints_indexes.sql
```

Do not run `01_drop_objects.sql` unless you intentionally want to reset the schema.

### 2.2 Run Scripts in Order

Run each script and check:
- Script completed successfully.
- No failed statements.
- Objects appear in Object Browser.

If a script fails:
- Stop.
- Read the first error.
- Fix that error before continuing.
- Do not keep running later scripts after a failed table/constraint script.

### 2.3 Confirm Tables Exist

In `SQL Workshop -> Object Browser`, confirm key tables exist:

- `customers`
- `customer_contacts`
- `internal_users`
- `oracle_account_team_members`
- `customer_estate_items`
- `interactions`
- `reviews`
- `actions`
- `security_events`
- `security_cases`
- `security_case_events`
- `security_case_customer_impacts`
- `notification_campaigns`
- `notification_campaign_recipients`
- `relationship_health_snapshots`
- `alerts`

## Phase 3: Load Sample Data

Run:

```text
10_sample_data.sql
```

The sample data should include:
- Several customers.
- Security Advisors and Oracle account team members.
- Customer contacts.
- Oracle estate records.
- Interactions.
- Reviews.
- Actions.
- Primavera on-prem critical CVE event.
- Primavera security case.
- Impacted customers.
- Notification campaign.
- Campaign recipients.
- Health snapshots.
- Alerts.

The sample data is important. APEX pages are much easier to build and validate when reports and charts have real-looking records.

## Phase 4: Run Validation Queries

Run:

```text
12_validation_queries.sql
```

Minimum checks:

```sql
select count(*) from customers;
select count(*) from security_events;
select count(*) from security_cases;
select count(*) from security_case_customer_impacts;
select count(*) from notification_campaigns;
select count(*) from notification_campaign_recipients;
select count(*) from actions;
select count(*) from alerts;
```

Validate the critical workflow:

1. Primavera security event exists.
2. Primavera security case exists.
3. Event is linked to the case.
4. Customers with Primavera on-prem estate records are linked as case impacts.
5. Notification campaign exists for the case.
6. Campaign recipients exist.
7. Follow-up actions can be linked through `actions.campaign_recipient_id`.

Do not build APEX pages until this data validates in SQL.

## Phase 5: Create Dashboard Views

Run:

```text
07_views_dashboard.sql
```

Important views:
- `v_customer_portfolio`
- `v_customer_timeline`
- `v_campaign_progress`
- `v_security_case_impact_summary`
- `v_dashboard_health_summary`
- `v_dashboard_upcoming_reviews`
- `v_dashboard_open_actions`
- `v_dashboard_active_security_cases`
- `v_dashboard_active_campaigns`
- `v_dashboard_attention_alerts`

After creating the views, run:

```sql
select * from v_customer_portfolio;
select * from v_campaign_progress;
select * from v_security_case_impact_summary;
```

If the views return sensible rows, you are ready for APEX pages.

## Phase 6: Create the APEX Application

### 6.1 Start App Builder

In APEX:

1. Go to `App Builder`.
2. Click `Create`.
3. Choose `New Application`.
4. Name it `sed-dashboard`.
5. Use your schema.

Use the default Universal Theme first. Do not spend time on branding yet.

### 6.2 Add Initial Pages

Create pages in this order:

1. Dashboard
2. Customers
3. Customer Detail
4. Actions
5. Reviews
6. Security Cases
7. Security Events
8. Notification Campaigns
9. Alerts
10. Administration

Use simple page types first:
- Interactive Report
- Form
- Cards
- Chart

Avoid custom JavaScript in the MVP.

## Phase 7: Build the Pages

### 7.1 Dashboard Page

Use dashboard views.

Suggested regions:
- Portfolio count.
- Health breakdown.
- Upcoming reviews.
- Open actions.
- Active security cases.
- Active notification campaigns.
- Attention alerts.
- Portfolio table.

Start with reports/cards. Add charts only after the data looks correct.

### 7.2 Customers Page

Use:
- `v_customer_portfolio`

Make it an Interactive Report.

Useful filters:
- Primary Security Advisor.
- Tier.
- Region.
- Health status.
- Last interaction.
- Next review.

### 7.3 Customer Detail Page

Use a master-detail style page.

Main customer data:
- `customers`

Related regions:
- `customer_contacts`
- `oracle_account_team_members`
- `customer_estate_items`
- `interactions`
- `reviews`
- `actions`
- `security_case_customer_impacts`
- `notification_campaign_recipients`
- `alerts`
- `relationship_health_snapshots`
- `v_customer_timeline`

Keep this page functional first. It does not need to be visually perfect.

### 7.4 Actions Page

Use:
- `actions`

Create:
- Interactive Report.
- Form to create/edit actions.

Important fields:
- Customer.
- Owner.
- Priority.
- Status.
- Due date.
- Security case, optional.
- Campaign recipient, optional.

### 7.5 Reviews Page

Use:
- `reviews`

Create:
- Interactive Report.
- Form to schedule/complete reviews.

Important fields:
- Customer.
- Review date.
- Status.
- Owner.
- Notes.
- Outcome.

### 7.6 Security Cases Page

Use:
- `security_cases`
- `security_case_events`
- `security_case_customer_impacts`
- `v_security_case_impact_summary`

This is the operational center for security advisories.

The page should answer:
- What is the advisory?
- Which CVEs/events are linked?
- Which customers are impacted?
- Which customers require action?
- Is there an active campaign?

### 7.7 Security Events Page

Use:
- `security_events`

This page is for source/detail records:
- CVE.
- CVSS.
- Product.
- Deployment type.
- Source URL.
- Recommended action.

In MVP, events are manually entered.

### 7.8 Notification Campaigns Page

Use:
- `notification_campaigns`
- `notification_campaign_recipients`
- `v_campaign_progress`

The page should answer:
- What campaign is active?
- Which security case is it for?
- What is the official communication?
- Which customers are pending?
- Which customers were notified?
- Which customers require follow-up?

For MVP, email is sent manually outside the app. The app stores the official text and tracks status.

### 7.9 Alerts Page

Use:
- `alerts`

Create an Interactive Report filtered by:
- Status.
- Severity.
- Owner.
- Due date.
- Customer.

Add simple forms/processes for:
- Acknowledge.
- Resolve.
- Dismiss.

## Phase 8: Create PL/SQL Packages

Run:

```text
08_packages_spec.sql
09_packages_body.sql
```

Packages:
- `pkg_health_score`
- `pkg_security_case`
- `pkg_notification_campaign`
- `pkg_alert_generation`
- `pkg_sample_data`

Build and test one package at a time.

Recommended test order:

1. `pkg_security_case`
2. `pkg_notification_campaign`
3. `pkg_health_score`
4. `pkg_alert_generation`

Why:
- Security case and campaign workflow is the MVP’s core.
- Health/alerts depend on the workflow data being present.

## Phase 9: Test the End-to-End MVP Workflow

Use the Primavera CVSS 9.9 scenario.

### Test Scenario

1. Create security event:
   - Product: Primavera
   - Deployment: On-prem
   - CVSS: 9.9
   - Severity: Critical

2. Create security case:
   - `Primavera Critical Advisory`

3. Link event to case.

4. Create customer impacts from estate records.

5. Create notification campaign from case.

6. Add recipients from impacted customers.

7. Mark some recipients as:
   - Sent
   - Acknowledged
   - Follow-up Required

8. Create follow-up action for a recipient.

9. Refresh health score.

10. Generate alerts.

11. Confirm dashboard reflects:
   - Active security case.
   - Active campaign.
   - Customers needing attention.
   - Open actions.
   - Campaign recipients requiring follow-up.

If this works, the MVP foundation is sound.

## Phase 10: Add Scheduled Jobs Later

Do not enable jobs until manual tests pass.

Later, run:

```text
11_jobs.sql
```

Jobs:
- Daily health refresh.
- Daily health snapshot.
- Daily alert generation.

Keep jobs disabled first. Enable only after:
- Packages compile.
- Manual package calls work.
- Sample workflow works.
- Dashboard views return correct data.

## Phase 11: Basic Security and Access

For MVP, keep authorization simple.

Suggested roles:
- Admin
- Security Advisor
- Manager
- Viewer

Minimum behavior:
- Admin can edit lookups and all data.
- Security Advisor can work assigned customers, cases, campaigns, actions.
- Manager can view broader portfolio.
- Viewer can read dashboards/reports.

If this is too much for the first build, start with:
- Admin/developer access only.
- Then add role separation after pages work.

## Phase 12: Deployment Checklist

Before calling the MVP deployed, confirm:

- SQL scripts run cleanly in order.
- Tables exist.
- Lookup data exists.
- Sample customers exist.
- Dashboard views return rows.
- APEX application exists.
- Customer list works.
- Customer detail page works.
- Security cases page works.
- Notification campaigns page works.
- Actions page works.
- Alerts page works.
- Primavera CVSS 9.9 workflow works end to end.
- No jobs are enabled until package testing is complete.

## Recommended Build Rhythm

Use short build cycles:

1. Build one database layer.
2. Validate in SQL.
3. Build one APEX page.
4. Test with sample data.
5. Fix before moving on.

Do not build all pages first and debug later. In APEX, bad data model decisions become painful once pages and LOVs depend on them.

## What Not To Do Yet

Do not spend time on:
- Custom theme work.
- Email sending.
- Outlook integration.
- SharePoint integration.
- CSAF ingestion.
- Complex authorization.
- Complex health scoring.
- Perfect charts.
- Production jobs.

Those come after the MVP workflow is proven.

## Immediate Next Actions

1. Create the `database/sed-dashboard/` folder.
2. Write `02_lookup_tables.sql`.
3. Write `03_core_tables.sql`.
4. Write `04_security_campaign_tables.sql`.
5. Write `05_health_alert_tables.sql`.
6. Write `06_constraints_indexes.sql`.
7. Load those scripts into APEX SQL Workshop.
8. Run them in order.
9. Load sample data.
10. Validate the Primavera critical CVE workflow in SQL.

Once those steps work, start App Builder and create the dashboard and reports.
