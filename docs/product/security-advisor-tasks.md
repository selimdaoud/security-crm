# Security Advisor Tasks

## Purpose

This document explains the main tasks of a Security Advisor in the `sed-dashboard` application. It is written for a new hire who needs to understand what the role does day to day and how the dashboard supports the work.

The Security Advisor is responsible for maintaining visibility over assigned customers, identifying relationship or security risks early, coordinating follow-up, and ensuring customers are informed when important Oracle security events may affect them.

## Core Responsibility

The Security Advisor owns the security relationship view for a portfolio of customers.

That means the advisor should always be able to answer:
- Which customers need attention?
- Why do they need attention?
- What security events may affect them?
- What actions are open or overdue?
- Which reviews or meetings are coming up?
- Who are the key customer and internal contacts?
- What Oracle products, services, or workloads are relevant for this customer?
- Has the customer been notified about critical security issues?

## Daily Tasks

### 1. Review the Portfolio Dashboard

Start by opening the main dashboard and checking the portfolio summary.

Look at:
- Customers needing attention.
- Open actions.
- Overdue actions.
- Upcoming reviews.
- Recent security events.
- Active notification campaigns.
- Relationship health changes.

Expected outcome:
- You know which customers require work today.
- You know which security or relationship risks need immediate follow-up.

### 2. Review Alerts

Alerts show situations that may require advisor action.

Common alerts include:
- No customer interaction in 90 days.
- Review overdue.
- Follow-up pending.
- High-priority action overdue.
- Security event impact.
- Notification campaign recipient requires follow-up.
- Customer health changed to Needs Attention.
- CISO or key security contact changed.

For each alert:
- Open the related customer.
- Understand why the alert was created.
- Decide whether to acknowledge, resolve, dismiss, or create an action.
- Add notes when closing or dismissing an alert.

Expected outcome:
- Alerts are actively managed and do not become a stale to-do list.

### 3. Work Open Actions

Actions are follow-up items, tasks, or customer commitments.

Examples:
- Schedule a security review.
- Confirm patch status for a critical CVE.
- Send customer communication.
- Follow up with the account team.
- Confirm whether a product is still in use.
- Arrange a technical workshop.

For each action:
- Check priority and due date.
- Update status.
- Add progress notes.
- Close the action when complete.
- Create a new action if additional follow-up is needed.

Expected outcome:
- Customer commitments and internal tasks are visible and tracked to closure.

## Customer Management Tasks

### 4. Maintain Customer Records

Each customer record should stay current.

Maintain:
- Customer name.
- Industry.
- Region.
- Tier.
- Status.
- Owner.
- Notes.
- Current security contact.

Expected outcome:
- The dashboard reflects the real customer portfolio and ownership model.

### 5. Maintain Customer Contacts

Customer contacts are the people on the customer side who matter for security engagement.

Important contact types:
- CISO.
- VP Security.
- IT Director.
- Security Architect.
- Operational security contact.
- Escalation contact.

For each contact:
- Keep name, role, email, phone, and active status current.
- Mark the primary contact where applicable.
- Mark the current security contact where applicable.
- Update records when someone changes role or leaves.

Expected outcome:
- The advisor and account team know who to contact during normal engagement and urgent security events.

### 6. Maintain Internal Account Team

Internal contacts show who at Oracle is involved with the customer.

Examples:
- Security Advisor.
- CSS sales representative.
- Customer Success Manager.
- Solution Architect.
- Executive sponsor.

Expected outcome:
- Everyone can see who owns follow-up and who should be involved in customer communication.

### 7. Maintain Oracle Estate Information

Oracle estate information shows which Oracle products, services, or workloads are relevant for a customer.

Examples:
- Primavera on-prem.
- WebLogic.
- Database.
- OCI services.
- Critical workloads.
- Security-relevant services.

For each estate item, capture:
- Product or service name.
- Environment or deployment type.
- Region, if relevant.
- Business criticality.
- Security relevance.
- Lifecycle status.
- Notes.
- Last verified date.

Expected outcome:
- When a security event is published, advisors can quickly identify potentially impacted customers.

## Engagement Tasks

### 8. Log Interactions

Interactions are meetings, calls, emails, workshops, briefings, or other touchpoints.

Log an interaction when:
- You meet with a customer.
- You have a meaningful call or email exchange.
- You run a workshop.
- You brief the customer on a security topic.
- You discuss an action, review, or security event.

Capture:
- Customer.
- Interaction type.
- Date.
- Subject.
- Summary.
- Owner.
- External contact.
- Next steps.

Expected outcome:
- The customer history is complete and the health score reflects recent engagement.

### 9. Manage Reviews

Reviews are scheduled customer checkpoints.

Examples:
- Quarterly security review.
- Executive security review.
- Architecture review.
- Remediation review.
- Security strategy discussion.

For each review:
- Schedule the review.
- Assign an owner.
- Add agenda and notes.
- Mark it complete after the meeting.
- Capture outcome and follow-up actions.

Expected outcome:
- Important customer reviews are planned, completed, and visible in the dashboard.

## Security Event Tasks

### 10. Monitor Security Events

Security events are Oracle or security-related items that may affect customers.

Examples:
- Critical CVE.
- Oracle Critical Patch Update.
- Security alert.
- Vulnerability advisory.
- Product-specific security notification.

For each event:
- Create or review the security event record.
- Capture severity, CVSS score, product area, published date, source, summary, and recommended action.
- Determine whether the event may affect customers in your portfolio.

Expected outcome:
- Important security events are tracked centrally and can be linked to impacted customers.

### 11. Assess Customer Impact

When a security event is relevant, identify impacted customers.

Use:
- Oracle estate records.
- Product usage information.
- Customer tier.
- Region or owner.
- Account team knowledge.
- Manual confirmation.

Impact statuses may include:
- Potentially Impacted.
- Confirmed Impacted.
- Not Impacted.
- Remediated.
- Unknown.

Expected outcome:
- The advisor has a clear list of customers that may need communication or follow-up.

### 12. Create Notification Campaigns

Create a notification campaign when customers need to be officially informed about a critical CVE, security alert, Critical Patch Update, or related security event.

Example:
- Oracle publishes a CVSS 9.9 CVE affecting Primavera on-prem.
- The advisor identifies customers in its portfolio using Primavera on-prem.
- The advisor creates a campaign to notify those customers with approved communication and channel.

Campaign information should include:
- Related security event or advisory.
- Campaign name.
- Campaign owner.
- Start date.
- End date.
- Status.
- Official email subject.
- Official email body or approved message text.
- Selected impacted customers.
- Per-customer notification status.

Campaign statuses:
- Draft.
- Ready for Review.
- Approved.
- In Progress.
- Completed.
- Cancelled.

Per-customer notification statuses:
- Pending.
- Ready.
- Sent.
- Acknowledged.
- Follow-up Required.
- Not Applicable.
- Failed or Blocked.

Expected outcome:
- Customer notification work is organized, traceable, and not managed through scattered email or spreadsheets.

### 13. Track Notification Progress

After a campaign is started, track progress per customer.

For each recipient:
- Confirm the correct customer contact.
- Confirm whether the communication was sent.
- Record sent date.
- Record acknowledgement if received.
- Mark follow-up required if the customer needs additional support.
- Create an action when follow-up is needed.

Expected outcome:
- The advisor can tell which customers have been notified and which still need work.

## Relationship Health Tasks

### 14. Review Relationship Health

Relationship health helps prioritize customer attention.

Health states:
- Good.
- At Risk.
- Needs Attention.

Signals that may affect health:
- Days since last interaction.
- Overdue review.
- Open high-priority action.
- Active security event impact.
- CISO or key contact change.
- Recent executive engagement.
- Upcoming review.
- Manual advisor override.

Expected outcome:
- The advisor understands not only the health status, but also the reason behind it.

### 15. Update or Override Health When Needed

Most health scoring should be calculated, but the advisor may need to override it when the data does not reflect reality.

Examples:
- The customer is calm despite an overdue review because a meeting already happened outside the system.
- The customer is at risk due to relationship context not captured in structured data.
- A critical stakeholder change has increased risk.

When overriding health:
- Add a clear reason.
- Record who made the override.
- Review overrides regularly.

Expected outcome:
- Health status remains useful, explainable, and trusted.

## Weekly Tasks

### 16. Review Upcoming Reviews and Meetings

Each week, check:
- Reviews due in the next 30 days.
- Reviews overdue.
- Customers with no planned review.
- Customers with no recent interaction.

Expected outcome:
- Customer engagement is planned, not reactive.

### 17. Review Portfolio Trends

Look at the health trend chart and portfolio breakdown.

Questions to ask:
- Is the number of At Risk customers increasing?
- Are more customers moving to Needs Attention?
- Are overdue actions increasing?
- Are security events creating concentrated risk in a product area?

Expected outcome:
- The advisor can explain portfolio movement and escalate patterns early.

### 18. Clean Up Data Quality Issues

Review and fix:
- Missing contacts.
- Missing owners.
- Old open actions.
- Reviews without outcomes.
- Estate items not recently verified.
- Alerts with no action.
- Campaign recipients stuck in Pending.

Expected outcome:
- The dashboard remains reliable enough to support decisions.

## Event-Driven Tasks

### 19. Respond to a Critical CVE or Security Alert

When a critical event is published:

1. Create or review the security event.
2. Identify product, version, deployment type, and severity.
3. Match the event to customer estate records.
4. Build the impacted customer list.
5. Confirm impact with account teams where needed.
6. Create a notification campaign.
7. Add official communication content.
8. Select impacted customers.
9. Track notifications.
10. Create follow-up actions.
11. Monitor completion.
12. Close the campaign when all recipients are handled.

Expected outcome:
- Customers affected by critical security issues are identified and communicated with in a controlled process.

### 20. Escalate High-Risk Customer Situations

Escalate when:
- A strategic customer is impacted by a critical event.
- A customer has multiple overdue critical actions.
- A customer is unresponsive during a security campaign.
- A customer has moved to Needs Attention.
- Required communication is blocked.
- Ownership is unclear.

Expected outcome:
- High-risk situations are visible to managers and account teams before they become unmanaged problems.

## What Good Looks Like

A Security Advisor is doing the job well when:
- The dashboard accurately reflects the portfolio.
- Customer records have current contacts and internal owners.
- Important interactions are logged.
- Reviews are scheduled and completed.
- Actions are tracked to closure.
- Critical security events are linked to impacted customers.
- Notification campaigns are complete and traceable.
- Customers needing attention have clear reasons and next steps.
- Health trends are explainable.
- Managers can understand portfolio risk without asking for a separate spreadsheet.

## Common Mistakes to Avoid

Avoid:
- Leaving alerts open without review.
- Closing alerts without notes.
- Tracking critical customer follow-up only in email.
- Creating duplicate campaigns for related security events without a clear reason.
- Sending customer communication without approved text.
- Marking a customer as notified without recording status.
- Letting estate information become stale.
- Treating health status as a label without checking the reason.
- Closing actions before the customer commitment is actually complete.

## New Hire First Week Checklist

During the first week, a new Security Advisor should learn how to:
- Read the dashboard.
- Open a customer record.
- Identify contacts and internal owners.
- Log an interaction.
- Create and close an action.
- Schedule and complete a review.
- Read relationship health and score reasons.
- Review alerts.
- Open a security event.
- Link impacted customers to a security event.
- Create a notification campaign.
- Track notification status per customer.
- Find customers with stale interactions or overdue actions.

## Summary

The Security Advisor role is about turning customer security information into clear action.

The advisor uses `sed-dashboard` to maintain customer context, track engagement, monitor security events, coordinate notification campaigns, manage follow-up, and keep relationship health visible over time.
