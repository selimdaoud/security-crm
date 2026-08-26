Oracle APEX Relationship Management Dashboard

Application name
sed-dashboard

Purpose
We are building an Oracle APEX application for relationship managers, account teams, and security stakeholders to track customer health, engagement, open actions, reviews, opportunities, Oracle estate information, and security-related events in one place.

The goal is to replace scattered spreadsheets, email threads, and manual status tracking with a single dashboard that gives a fast, reliable view of each customer account.

The application is based on Oracle APEX running on OCI and backed by an Oracle database schema designed for reporting, workflow tracking, operational follow-up, and executive visibility.

Primary users
The first target user group is Security Advisors.

Future user groups may include:
- CSS account teams
- Customer Success Managers
- Solution Architects
- Security stakeholders
- Management or executive viewers
- Application administrators

What the application should do
The application should help users:
- See the overall health of their customer portfolio.
- Identify customers that need attention.
- Track upcoming reviews and planned meetings.
- Manage open actions and follow-ups.
- Monitor security events that may affect one or more customers.
- Create notification campaigns for critical CVEs or security events, including impacted customer selection, official communication content, campaign dates, and delivery status tracking.
- Track the Oracle estate for each customer.
- View opportunities, engagement history, and relationship trends over time.
- Navigate from portfolio-level summaries into customer-level detail.

Future integrations
The application should be designed so integrations can be added later without changing the core data model.

Potential future integrations include:
- Outlook calendar integration to identify upcoming customer meetings.
- Email integration to identify recent interactions.
- Oracle SharePoint read access for customer-specific documents.
- Oracle security alert feeds, including CSAF files, Critical Patch Update information, security alerts, and related sources.
- Oracle estate or service inventory sources, where access and data governance allow it.

These integrations are not part of the initial MVP. The MVP should support manual data entry and sample-loaded data first.

The first CSAF analytics increment should also avoid a runtime Python-to-APEX integration. Each Python execution creates a new UTC timestamped directory named `YYYYMMDDTHHMMSSZ_<advisory-reference>`. That directory name is the shared batch identifier and contains separate `findings.csv` and `enrichment.csv` files plus `manifest.json`; an operator imports the CSV files through staging tables. Advisory facts are immutable and idempotent by CSAF source hash, while dated enrichment observations remain independently reloadable so EPSS, KEV, and public-exploit changes are retained over time. ORDS, OCI Functions, or a direct controlled connection can automate the same contract later.

Core dashboard experience
The main dashboard should provide a concise executive-style summary, including:
- Total portfolio size.
- Relationship health breakdown.
- Upcoming reviews.
- Open actions.
- Recent security events.
- Customers needing attention.
- Trend charts showing health over time.
- Portfolio by tier.
- Needs-my-attention alerts.
- Recent security event impact.

Users should be able to click from the dashboard into the underlying customer record, where they can see related contacts, Oracle account team members, interactions, reviews, actions, alerts, security events, opportunities, Oracle estate information, and history.

The dashboard mockup is located in this workspace as:
../assets/security-crm-dashboard.png

Main data areas
The application is organized around the following business areas.

Customers
Each customer account is the center of the model. A customer should have attributes such as name, industry, tier, status, owner, region, and current security contact.

Customer Contacts
Each customer can have one or more external contacts, including key roles such as CISO, VP Security, IT Director, security architect, or operational contact.

Oracle Account Team
Each customer has one primary Security Advisor for MVP ownership and dashboard filtering. Each customer can also have one or more Oracle account team members, such as CSS sales representative, Customer Success Manager, Solution Architect, additional Security Advisor, or executive sponsor.

Interactions
Meetings, calls, emails, workshops, briefings, and other touchpoints should be tracked as interactions.

In the MVP, interactions are manually entered. Later versions may use email, calendar, or collaboration integrations to suggest or import interactions.

Reviews
Scheduled customer reviews should be tracked with status, owner, date, type, notes, and outcome.

Opportunities
Potential expansion or follow-up opportunities should be tracked with stage, value, owner, expected close date, and related customer.

Actions
Open follow-up items, tasks, and customer commitments should be stored as action items with owner, priority, due date, status, and related customer.

Security Events
Oracle or security-related events that affect customers should be tracked centrally and linked to impacted accounts.

The system should support events such as:
- Oracle Critical Patch Updates.
- Security alerts.
- Vulnerability advisories.
- Product-specific security notifications.
- Customer-impacting remediation campaigns.

Notification Campaigns
Security Advisors need to create customer notification campaigns when a critical CVE, Oracle security alert, Critical Patch Update, or other urgent security event requires customer communication.

A notification campaign should capture:
- Related security event or CVE.
- Campaign name.
- Official communication email subject.
- Official communication email body or approved message text.
- Start date.
- End date.
- Campaign owner.
- Campaign status.
- Selected impacted customers.
- Per-customer notification status.
- Sent date or communication completion date.
- Follow-up action requirement.
- Notes and resolution summary.

The campaign should support selecting impacted customers from the security event impact list, customer estate data, customer tier, owner, region, or manual selection.

Campaign statuses should include:
- Draft.
- Ready for Review.
- Approved.
- In Progress.
- Completed.
- Cancelled.

Per-customer notification statuses should include:
- Pending.
- Ready.
- Sent.
- Acknowledged.
- Follow-up Required.
- Not Applicable.
- Failed or Blocked.

Oracle Estate
The application should track relevant Oracle estate information for each customer.

Examples include:
- Products or services used.
- OCI tenancy or region notes, where permitted.
- Critical workloads.
- Security-relevant services.
- Support or lifecycle notes, where permitted.
- Source of truth and last update date.

Relationship Health
The application should store both the current health state and historical health snapshots.

Health should not be just a manually selected label. The model should support a calculated score using signals such as:
- Days since last interaction.
- Overdue review.
- Open high-priority action.
- Security event impact.
- CISO or key contact change.
- Recent executive engagement.
- Upcoming scheduled review.
- Customer tier.
- Manual advisor override, with reason.

The visible health states should be simple:
- Good.
- At Risk.
- Needs Attention.

The underlying model should also store a numeric score and calculation reason so users can understand why a customer appears in a given health state.

Alerts
The system should generate alerts such as:
- No interaction in 90 days.
- CISO or key contact change.
- Review overdue.
- Follow-up pending.
- Action overdue.
- Security event impact.
- Health score deterioration.

Alerts should have a lifecycle:
- New.
- Acknowledged.
- In Progress.
- Resolved.
- Dismissed.

Alerts should also have severity, owner, creation date, related customer, related object, and resolution notes.

Design approach
The data model should be relational and divided into:
1. Core master data tables for customers, contacts, users, and Oracle account teams.
2. Transaction tables for interactions, reviews, actions, opportunities, security events, and notification campaigns.
3. Oracle estate tables for customer product/service footprint.
4. Snapshot tables for relationship health history.
5. Alert tables for generated warnings and attention items.
6. Lookup tables for consistent values such as tier, status, priority, event type, and health state.
7. Audit columns on operational tables.
8. Source-system columns for future integrations.

Why snapshots matter
A key requirement is the ability to see changes over time. For example, a customer's health score should be stored daily or weekly so the dashboard can show a trend line and not just the current state.

Snapshots should capture:
- Customer.
- Snapshot date.
- Numeric health score.
- Health status.
- Scoring reason or summary.
- Key signal values used in the calculation.
- Generated timestamp.

Workflow improvements
The dashboard should not only display status. It should help users act.

Important workflow capabilities include:
- Open customer record from any dashboard metric or table row.
- Log interaction from customer detail or dashboard quick action.
- Create, update, assign, and close actions.
- Schedule, complete, or mark reviews as overdue.
- Link security events to impacted customers.
- Create notification campaigns from security events.
- Select impacted customers for a notification campaign.
- Track notification status per customer.
- Create follow-up actions from campaign recipients that require further engagement.
- Acknowledge, resolve, or dismiss alerts.
- View customer timeline across interactions, reviews, actions, alerts, health changes, opportunities, security events, and notification campaigns.

Customer detail experience
Each customer should have a detail page with:
- Summary and current health.
- External contacts.
- Oracle account team.
- Oracle estate.
- Interactions.
- Reviews.
- Actions.
- Opportunities.
- Security event impacts.
- Notification campaign history.
- Alerts.
- Health history.
- Customer timeline.

Filtering and reporting improvements
Users should be able to filter and report by:
- Owner.
- Customer tier.
- Industry.
- Region.
- Health status.
- Review date.
- Action status.
- Action priority.
- Security event type.
- Notification campaign status.
- Alert severity.
- Customers with no interaction in a defined period.
- Customers affected by a specific security event.
- Customers included in a notification campaign.

Governance and permissions
The design should account for access control from the beginning.

Roles should include:
- Security Advisor: manage assigned customers and related records.
- Manager: view broader portfolio and team dashboards.
- Viewer: read-only dashboard and reports.
- Administrator: manage lookups, users, rules, and configuration.

The application should define who can:
- View all customers.
- View only assigned customers.
- Edit customer data.
- Close actions.
- Resolve or dismiss alerts.
- Configure health scoring and alert rules.
- Maintain lookup values.

Auditability
Operational changes should be traceable.

Important records should include:
- Created by.
- Created at.
- Updated by.
- Updated at.
- Source system.
- Source reference.
- Last synced at, where applicable.

Key workflow events should be auditable, including:
- Customer health override.
- Action closure.
- Alert dismissal or resolution.
- Review completion.
- Security event impact assignment.

Oracle APEX implementation strategy
The application should be built in Oracle APEX using:
- SQL Workshop for loading the database objects.
- Interactive Reports for customer, action, review, event, and alert lists.
- Cards for reviews, alerts, customers needing attention, and summary metrics.
- Charts for health trends and portfolio breakdowns.
- Forms for maintaining customer and related records.
- PL/SQL packages for health calculation, alert generation, and dashboard metrics.
- Scheduled jobs for health snapshots and alert generation.

Recommended PL/SQL package responsibilities:
- pkg_health_score: calculate customer health scores and statuses.
- pkg_alert_generation: generate, update, and close system alerts.
- pkg_dashboard_metrics: provide dashboard-level summary values.
- pkg_notification_campaign: manage campaign recipient selection and notification status.
- pkg_sample_data: load demo or test records for the first build.

Development phases

Phase 1: Foundation
- Create the database schema.
- Create lookup tables.
- Create sample data matching the mockup.
- Define health scoring rules.
- Define alert generation rules.
- Create initial PL/SQL package specifications.

Phase 2: Basic APEX application
- Build the main dashboard.
- Build customer list and customer detail pages.
- Build actions, reviews, alerts, opportunities, and security events reports.
- Build notification campaign report and detail pages.
- Build basic forms for manual data entry.

Phase 3: Operational workflow
- Add log-interaction flow.
- Add create/edit/close action flow.
- Add review scheduling and completion flow.
- Add alert acknowledgement, resolution, and dismissal.
- Add security event to customer impact mapping.
- Add notification campaign creation from a security event.
- Add impacted customer selection and per-customer notification tracking.
- Add customer timeline.

Phase 4: Automation
- Add scheduled health snapshots.
- Add scheduled alert generation.
- Add calculated health status updates.
- Add dashboard metric refresh strategy.

Phase 5: Integrations
- Add structured Oracle security alert ingestion first.
- Add manual CSAF analytics exchange first: one UTC timestamped directory per execution, containing separate immutable findings and dated enrichment CSV imports plus a manifest.
- Make repeated imports idempotent: skip the same CSAF hash, block same-revision hash conflicts, merge same-day enrichment, and insert later snapshots.
- Add automated CSAF/Critical Patch Update/security alert processing only after the manual contract is proven.
- Add Outlook calendar integration.
- Add email interaction discovery.
- Add SharePoint document discovery.
- Add Oracle estate source integration where feasible.

Phase 6: Governance and hardening
- Add role-based authorization.
- Add audit reporting.
- Add data quality checks.
- Add admin pages for rule and lookup maintenance.
- Add performance tuning for dashboard queries.
- Add responsive and accessibility checks.

Initial development goal
The first milestone is to create the database foundation, data model, and a basic APEX dashboard that can:
- Load sample customer data.
- Display customer health and alerts.
- Show upcoming reviews and open actions.
- Present recent security events.
- Create and track a notification campaign for a critical CVE or security event.
- Support manual interaction and action tracking.
- Support future extension into a full operational relationship management tool.

Success criteria
The project will be considered successful when a user can open the dashboard and quickly answer:
- Which customers need attention right now?
- Why does this customer need attention?
- Which reviews are coming up soon?
- Which reviews are overdue?
- Which actions are overdue?
- Which customers were affected by a security event?
- Which customers need to be notified about a critical CVE?
- Which customers have already been notified?
- Which notification campaign recipients require follow-up?
- What is the current Oracle estate for a customer?
- How is the overall portfolio trending?
- What happened recently for this customer?

MVP recommendation
The MVP should focus on the data model, dashboard, manual workflows, health scoring, snapshots, and alerts.

The MVP should not include Outlook, email, SharePoint, or external estate integrations. Those should be designed for but delivered later.

In short
This is a customer relationship and security oversight dashboard built in Oracle APEX, backed by an Oracle database schema designed for reliable reporting, workflow tracking, security event visibility, relationship health scoring, and executive-level portfolio visibility.
