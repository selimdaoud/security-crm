# sed-dashboard MVP Design

## Purpose

The MVP for `sed-dashboard` is an Oracle APEX application that gives Security Advisors a reliable portfolio dashboard and customer detail view for relationship health, reviews, actions, interactions, alerts, security cases, notification campaigns, and Oracle estate tracking.

The MVP should prove the database model, dashboard calculations, manual operational workflows, and health history model before adding external integrations.

## MVP Scope

Included in MVP:
- Oracle APEX dashboard with portfolio summary.
- Customer list and customer detail pages.
- Manual customer, contact, interaction, review, action, security case, security event, notification campaign, and Oracle estate maintenance.
- Manual notification campaign creation for critical CVEs, Oracle security alerts, Critical Patch Updates, or grouped security advisories.
- Impacted customer selection and per-customer notification status tracking.
- Relationship health current state.
- Relationship health historical snapshots.
- Alert generation based on simple rules.
- Security case to customer impact mapping.
- Sample data matching the dashboard mockup.
- Basic role model for advisor, manager, viewer, and administrator.

Excluded from MVP:
- Outlook calendar integration.
- Email interaction discovery.
- SharePoint integration.
- Automated Oracle estate discovery.
- Automated CSAF/security alert ingestion.
- Advanced opportunity forecasting.
- Opportunity management screens.
- Full enterprise CRM synchronization.

A later CSAF analytics pilot may still use manual file exchange without changing this boundary: every Python execution creates a new UTC timestamped directory containing separate immutable findings and dated enrichment CSV files plus a manifest, and an operator imports the CSV files through staging. Automated Python-to-APEX execution remains excluded until that contract and its idempotency rules are proven.

## MVP User Outcomes

The MVP is successful when a Security Advisor can:
- See portfolio health at a glance.
- Identify customers needing attention.
- Understand why a customer is at risk.
- See upcoming and overdue reviews.
- See open and overdue actions.
- Group one or more security events into a security case or advisory.
- Link a security case to impacted customers.
- Create a notification campaign from a critical CVE, security event, or advisory case.
- Select impacted customers for the campaign.
- Track which customers are pending, notified, acknowledged, or require follow-up.
- View customer contacts and Oracle account team members.
- Review customer interaction history.
- See Oracle estate notes for a customer.
- Open a customer record from the dashboard.

## MVP Pages

### Dashboard

Main dashboard regions:
- Total portfolio size.
- Relationship health summary.
- Upcoming reviews.
- Open actions.
- Recent security events.
- Active security cases.
- Customers needing attention.
- Portfolio by tier chart.
- Relationship health trend chart.
- Upcoming reviews card/list.
- Needs my attention card/list.
- My portfolio table.
- Recent security events table.
- Active security cases table.
- Active notification campaigns table.
- Open actions table.

### Customer List

Interactive report with filters for:
- Owner.
- Tier.
- Industry.
- Region.
- Status.
- Health status.
- Last interaction date.
- Next review date.

### Customer Detail

Customer detail sections:
- Customer summary.
- Current health and score reason.
- Customer contacts.
- Oracle account team.
- Oracle estate.
- Interactions.
- Reviews.
- Actions.
- Security case impacts.
- Notification campaigns.
- Alerts.
- Health history.
- Timeline.

### Actions

Interactive report and form for:
- Creating actions.
- Assigning owners.
- Updating due dates.
- Changing priority.
- Closing actions.

### Reviews

Interactive report and form for:
- Scheduling reviews.
- Completing reviews.
- Recording notes and outcomes.
- Tracking overdue reviews.

### Security Cases and Events

Interactive report and form for:
- Creating security cases or advisories.
- Adding one or more security events or CVEs to a case.
- Recording event type, product area, deployment type, CVSS score, and severity.
- Linking impacted customers at the case level.
- Tracking customer impact status.

### Notification Campaigns

Interactive report and form for:
- Creating a campaign from a security case. If the advisor starts from a CVE or security event, the app should first create or select the related security case.
- Recording official communication subject and message body.
- Setting start date, end date, owner, and status.
- Selecting impacted customers.
- Tracking per-customer notification status.
- Recording sent date, acknowledgement, and follow-up requirement.
- Creating follow-up actions for customers that require additional engagement.

### Alerts

Card or report view for:
- New alerts.
- Acknowledged alerts.
- In-progress alerts.
- Resolved alerts.
- Dismissed alerts.

## Data Model

The MVP data model is relational and centered on `customers`.

The security workflow should be centered on `security_cases`, not directly on individual CVEs. A security case is the advisor-facing advisory or work item. It can contain one or more security events, and it is the object used for impact assessment and notification campaigns.

This avoids creating duplicate customer campaigns when several related CVEs affect the same product or customer population.

### MVP Simplification Decisions

To keep the first release focused on the Security Advisor job:
- Use `security_cases` as the only object for customer impact assessment and notification campaign creation.
- Keep `security_events` as source/detail records that can be grouped into a case.
- Defer opportunity management screens and tables unless explicitly required for the first release.
- Keep email sending manual in the MVP; store the official communication and track notification status.
- Keep alert generation rule-based in PL/SQL first; a configurable `alert_rules` table can be added when the rules need to be administered by users.
- Treat health scoring as simple and explainable before making it more sophisticated.

### Core Master Tables

#### customers

Stores the main customer account.

Key columns:
- customer_id
- customer_name
- industry
- region
- tier_id
- status_id
- primary_security_advisor_user_id
- current_security_contact_id
- current_health_status_id
- current_health_score
- health_score_reason
- health_calculated_at
- manual_health_override_flag
- health_override_reason
- health_override_by
- health_override_at
- notes
- created_by
- created_at
- updated_by
- updated_at
- source_system
- source_reference
- last_synced_at

#### customer_contacts

Stores external customer contacts.

Key columns:
- contact_id
- customer_id
- full_name
- job_title
- role_type
- email
- phone
- is_primary
- is_current_security_contact
- active_flag
- created_by
- created_at
- updated_by
- updated_at

#### internal_users

Stores internal application users or account team members.

Key columns:
- user_id
- full_name
- email
- role_name
- department
- active_flag
- created_by
- created_at
- updated_by
- updated_at

Note: this table can use Oracle APEX workspace users, enterprise identity, or manually loaded users in the MVP. The table name may later be changed to `app_users` if that better matches the implementation.

#### oracle_account_team_members

Maps Oracle internal users to customer accounts. This table represents the broader Oracle account team, while `customers.primary_security_advisor_user_id` identifies the primary Security Advisor accountable for the customer in the MVP dashboard.

Key columns:
- account_team_member_id
- customer_id
- user_id
- team_role_id
- primary_flag
- start_date
- end_date
- active_flag

### Oracle Estate Tables

#### customer_estate_items

Stores Oracle products, services, workloads, or estate notes for a customer.

This is intentionally lightweight for the MVP. It is not a full asset inventory. Its purpose is to help advisors identify customers who may be affected by security cases.

Key columns:
- estate_item_id
- customer_id
- estate_type
- product_or_service_name
- product_version
- deployment_type
- environment_name
- region_name
- business_criticality
- security_relevance
- lifecycle_status
- notes
- source_system
- source_reference
- last_verified_at
- created_by
- created_at
- updated_by
- updated_at

### Transaction Tables

#### interactions

Stores meetings, calls, emails, workshops, briefings, and other touchpoints.

Key columns:
- interaction_id
- customer_id
- interaction_type_id
- interaction_date
- subject
- summary
- owner_user_id
- external_contact_id
- next_steps
- created_by
- created_at
- updated_by
- updated_at
- source_system
- source_reference

#### reviews

Stores scheduled or completed customer reviews.

Key columns:
- review_id
- customer_id
- review_type
- review_date
- status_id
- owner_user_id
- agenda
- notes
- outcome
- completed_at
- created_by
- created_at
- updated_by
- updated_at

#### actions

Stores follow-up items, tasks, and customer commitments.

`security_case_id` and `campaign_recipient_id` are optional links. They are used when an action is created from a security case or notification campaign recipient.

Key columns:
- action_id
- customer_id
- security_case_id
- campaign_recipient_id
- title
- description
- owner_user_id
- priority_id
- status_id
- due_date
- completed_at
- resolution_notes
- created_by
- created_at
- updated_by
- updated_at

#### security_events

Stores individual security events, CVEs, Critical Patch Updates, or advisories from Oracle/security sources.

Key columns:
- security_event_id
- event_title
- event_type_id
- severity_id
- cvss_score
- event_date
- published_date
- source_name
- source_url
- cve_reference
- product_area
- affected_product
- affected_version
- deployment_type
- summary
- recommended_action
- status_id
- created_by
- created_at
- updated_by
- updated_at

#### security_cases

Stores the advisor-facing security case or advisory. A case can group one or more security events and is used for customer impact assessment, campaigns, and follow-up tracking.

Key columns:
- security_case_id
- case_title
- case_type_id
- severity_id
- highest_cvss_score
- product_area
- deployment_type
- summary
- recommended_action
- owner_user_id
- status_id
- published_date
- target_completion_date
- created_by
- created_at
- updated_by
- updated_at

#### security_case_events

Links one or more security events to a security case.

Key columns:
- security_case_event_id
- security_case_id
- security_event_id
- created_by
- created_at

#### security_case_customer_impacts

Links security cases to impacted customers. This is the main impact assessment table used by advisors.

Key columns:
- case_impact_id
- security_case_id
- customer_id
- impact_status
- impact_confidence
- impact_summary
- matched_estate_item_id
- action_required_flag
- owner_user_id
- due_date
- remediation_status
- resolved_at
- resolution_notes
- created_by
- created_at
- updated_by
- updated_at

#### notification_campaigns

Stores customer communication campaigns for critical CVEs, Oracle security alerts, Critical Patch Updates, or other security events requiring official customer notification.

Key columns:
- campaign_id
- security_case_id
- campaign_name
- campaign_type_id
- official_email_subject
- official_email_body
- start_date
- end_date
- owner_user_id
- status_id
- approval_required_flag
- approved_by
- approved_at
- notes
- created_by
- created_at
- updated_by
- updated_at

#### notification_campaign_recipients

Stores the selected impacted customers for a campaign and tracks notification progress per customer.

Key columns:
- campaign_recipient_id
- campaign_id
- customer_id
- case_impact_id
- recipient_status_id
- primary_contact_id
- owner_user_id
- selected_reason
- notification_sent_at
- acknowledged_at
- follow_up_required_flag
- follow_up_action_id
- blocked_reason
- notes
- created_by
- created_at
- updated_by
- updated_at

### Health Tables

#### relationship_health_snapshots

Stores historical health values for trend reporting. Current health is stored directly on `customers` for MVP simplicity.

Key columns:
- health_snapshot_id
- customer_id
- snapshot_date
- health_status_id
- health_score
- score_reason
- days_since_last_interaction
- overdue_action_count
- overdue_review_count
- open_high_priority_action_count
- active_security_case_count
- generated_at

### Alert Tables

#### alerts

Stores generated and manually created attention items.

Key columns:
- alert_id
- customer_id
- alert_type_id
- severity_id
- status_id
- title
- description
- related_object_type
- related_object_id
- owner_user_id
- due_date
- generated_at
- acknowledged_at
- resolved_at
- dismissed_at
- resolution_notes
- created_by
- created_at
- updated_by
- updated_at

#### alert_rules

Stores configurable alert rule definitions.

MVP note: this table is optional for the first build. If the alert rules are not user-configurable yet, the MVP can implement the initial rules in `pkg_alert_generation` and add this table later.

Key columns:
- alert_rule_id
- rule_code
- rule_name
- description
- enabled_flag
- threshold_number
- severity_id
- created_by
- created_at
- updated_by
- updated_at

### Lookup Tables

Recommended lookup tables:
- customer_tiers
- customer_statuses
- team_roles
- health_statuses
- interaction_types
- review_statuses
- action_priorities
- action_statuses
- security_case_types
- security_case_statuses
- security_impact_statuses
- security_impact_confidence_levels
- remediation_statuses
- security_event_types
- security_event_severities
- security_event_statuses
- notification_campaign_types
- notification_campaign_statuses
- notification_recipient_statuses
- alert_types
- alert_severities
- alert_statuses
- estate_types
- estate_lifecycle_statuses

### Deferred Tables

The original design included opportunities. Based on the Security Advisor task breakdown, opportunities are not required for the first MVP workflow. They should be deferred unless the first build must also support commercial expansion tracking.

Deferred table:
- opportunities

## Relationship Health MVP Rules

The MVP uses a simple increasing risk model that can be refined later. It
starts at 0; risk-producing signals add points. Engagement, review, action,
case and campaign signals remain candidates for later weighted contributions,
but their weights are not yet confirmed.

Health scoring uses an increasing risk scale: `0` means no identified risk and
higher values mean greater concern. A customer with at least one estate product
whose Oracle acronym has `SECALERT = TRUE` receives one 30-point contribution,
regardless of how many alerted products it has. An effective risk score greater
than or equal to 30 sets the derived status to `NEEDS_ATTENTION`. Contributions
must be recalculated idempotently rather than repeatedly added to the stored
score.

Manual override should be allowed, but it must capture:
- Override flag.
- Override reason.
- Override user.
- Override timestamp.

## Alert Rules for MVP

Initial generated alerts:
- No interaction in 90 days.
- Review overdue.
- Follow-up action overdue.
- High-priority action overdue.
- Security case impact requires action.
- Notification campaign recipient requires follow-up.
- Notification campaign end date passed with pending recipients.
- Health score changed to Needs Attention.
- Key contact changed.

Each generated alert should avoid duplicate open alerts for the same customer, rule, and related object.

## APEX Build Strategy

Use Oracle APEX native components:
- Cards for summary metrics and attention items.
- Interactive Reports for customers, actions, reviews, alerts, and events.
- Forms for maintaining records.
- Charts for portfolio breakdown and health trend.
- List or timeline region for customer history.
- Authorization schemes for basic role separation.

Recommended PL/SQL packages:
- pkg_health_score
- pkg_alert_generation
- pkg_dashboard_metrics
- pkg_security_case
- pkg_notification_campaign
- pkg_sample_data

## Notification Campaign MVP Rules

Notification campaigns are used when a Security Advisor must communicate an official security message to impacted customers.

Typical trigger:
- A new critical CVE is released by Oracle.
- A Critical Patch Update requires customer follow-up.
- One or more related security events affect products or services used by specific customers.

Campaign creation should support:
- Selecting a related `security_cases` record.
- Entering or pasting the official communication email subject.
- Entering or pasting the official communication email body.
- Setting start and end dates.
- Assigning a campaign owner.
- Selecting impacted customers.
- Tracking status at campaign level and recipient level.

Campaign-level statuses:
- Draft.
- Ready for Review.
- Approved.
- In Progress.
- Completed.
- Cancelled.

Recipient-level statuses:
- Pending.
- Ready.
- Sent.
- Acknowledged.
- Follow-up Required.
- Not Applicable.
- Failed or Blocked.

Customer selection should support:
- Customers already linked through `security_case_customer_impacts`.
- Customers with matching Oracle estate items.
- Customers by tier, owner, industry, or region.
- Manual add/remove before campaign launch.

The MVP does not need to send email automatically. It should store the approved communication and track whether the Security Advisor has sent or completed communication for each customer.

## MVP Delivery Plan

### Step 1: Schema Design

Finalize table names, columns, lookup values, constraints, and relationships.

### Step 2: Sample Data

Create sample data matching the dashboard mockup:
- Customers.
- Contacts.
- Internal account team members.
- Interactions.
- Reviews.
- Actions.
- Security cases.
- Security events.
- Security case to event links.
- Security case customer impacts.
- Notification campaigns.
- Notification campaign recipients.
- Estate items.
- Customer current health fields.
- Health snapshots.
- Alerts.

### Step 3: Dashboard Queries

Define SQL queries for:
- Portfolio count.
- Health summary.
- Upcoming reviews.
- Open actions.
- Active security cases.
- Recent security events.
- Active notification campaigns.
- Customers needing attention.
- Portfolio by tier.
- Health trend.

### Step 4: APEX Pages

Build:
- Dashboard.
- Customer list.
- Customer detail.
- Actions report/form.
- Reviews report/form.
- Security cases report/form.
- Security events report/form.
- Notification campaigns report/form.
- Alerts report/cards.
- Admin lookup pages.

### Step 5: Health and Alert Logic

Implement:
- Health score calculation.
- Customer current health refresh.
- Health snapshot creation.
- Alert generation.
- Security case impact assessment.
- Notification campaign recipient tracking.
- Alert lifecycle updates.

### Step 6: Review and Iterate

Validate the MVP against the success questions:
- Which customers need attention right now?
- Why do they need attention?
- Which reviews are upcoming or overdue?
- Which actions are overdue?
- Which customers are affected by a security case?
- Which notification campaigns are active?
- Which customers still need to be notified?
- Which notified customers require follow-up?
- How is the portfolio trending?

## Open Design Questions

Questions to answer before build:
- Should customer ownership be single-owner or multi-owner?
- Should health score run daily, weekly, or on demand?
- Which Oracle estate fields are allowed from a data governance perspective?
- Should opportunity tracking remain deferred, or is it required for the first release?
- Should all customer impact assessment happen at the security case level, or do we need event-level impact exceptions for some products?
- Should notification campaign emails be sent outside the app manually, or should future versions integrate with Outlook/email sending?
- Does official communication require an approval workflow before campaign launch?
- What is the source of truth for customer tier and owner?
- Are all Security Advisors allowed to view all customers, or only assigned customers?
- Should manual health override expire after a defined period?
- What is the minimum audit requirement for the first version?
