# AI Security Analysis Integration Plan

Last updated: 2026-07-18

## Objective

Extend the SED Dashboard with an LLM-assisted analysis capability that correlates a customer's Oracle estate and operational context with trusted external security publications. The output should highlight potential exposure, missing information, and recommended follow-up actions for a Security Advisor.

The LLM is an advisory layer. It must not declare a customer vulnerable without supporting product, version, patch-level, and deployment evidence.

## Target Architecture

```text
Customer estate, health, cases and actions
                       \
                        -> Evidence package -> LLM analysis -> Stored findings -> APEX UI
                       /
Oracle publications and vetted external signals
```

APEX integrates server-side with an LLM API. For OpenAI, use the Responses API rather than embedding or automating the ChatGPT website.

## MVP Scope

Start with a manual workflow:

1. A Security Advisor opens a customer.
2. The advisor selects one or more relevant security publications.
3. The advisor clicks **Analyze Security Exposure**.
4. APEX collects a minimal customer and evidence snapshot.
5. APEX calls the LLM from server-side PL/SQL.
6. The structured assessment is validated and stored.
7. APEX displays the result in an **AI Security Analysis** card.
8. A Security Advisor reviews the assessment before creating actions or communicating with the customer.

Manual publication selection is appropriate until deterministic customer-to-publication matching is implemented.

## Evidence Sent to the LLM

Include only information needed for the assessment:

- Customer identifier or pseudonym.
- Oracle products and services in the customer estate.
- Product versions and patch levels when available.
- Deployment type and environment exposure.
- Business criticality and security relevance.
- Current health status.
- Open security cases and outstanding actions.
- Selected CPU, CSPU, and Security Alert records.
- Official publication identifiers, dates, URLs, and normalized content.

Exclude contact details, confidential notes, and other personal data unless a specific approved use case requires them.

## Structured Assessment Contract

Require structured JSON rather than uncontrolled prose. Suggested fields:

- `risk_level`: informational, low, medium, high, or critical.
- `confidence`: low, medium, or high.
- `summary`.
- `affected_products`.
- `potential_weaknesses`.
- `evidence`: publication ID, title, official URL, and supporting reason.
- `recommended_actions`.
- `missing_information`.
- `assumptions`.
- `requires_human_review`.

Each finding must link back to stored evidence. Unsupported claims should be rejected or clearly marked as assumptions.

## Proposed APEX Flow

1. Store the provider API key in an APEX Web Credential; never expose it to browser JavaScript.
2. Add an **Analyze Security Exposure** button to the customer page.
3. Build the evidence JSON server-side.
4. Submit the request to the LLM API.
5. Request a schema-constrained response.
6. Validate the response before saving it.
7. Store the request metadata, assessment, evidence links, model identifier, prompt version, generation time, and review status.
8. Render the latest reviewed or pending assessment on the customer page and optionally summarize it on the dashboard.

## Suggested Persistence

A future `ai_security_assessments` table should retain at least:

- Assessment ID and customer ID.
- Request status and timestamps.
- Trigger type: manual or automated.
- Model and prompt version.
- Risk level and confidence.
- Structured assessment JSON.
- Human review status, reviewer, review date, and notes.
- Error details when generation or validation fails.

A related evidence table can associate an assessment with security publications, estate items, cases, and other signals without duplicating their full source data.

## Guardrails

- Describe results as **potential exposure**, not confirmed vulnerability.
- Require official evidence links for every material claim.
- Show confidence, assumptions, and missing information.
- Treat external feed content as untrusted input and strip unsafe markup.
- Restrict evidence sources to an approved allowlist.
- Do not permit the model to update customer data directly.
- Require human approval before creating actions, changing health status, or sending communications.
- Record prompts, results, model versions, and reviews for auditability.
- Evaluate accuracy against a curated test set before enabling automation.
- Apply least-data principles and review provider retention and regional-processing controls.

## Later Phases

### Phase 2: Automated candidate assessment

When a new CPU, CSPU, Security Alert, CVE, or known-exploitation signal is ingested:

1. Deterministic rules identify potentially affected customers.
2. Only candidate customer-signal pairs are sent to the LLM.
3. Assessments are queued in the background.
4. High-risk findings appear in an advisor review queue.

### Phase 3: Portfolio assistant

Add a governed conversational interface for questions such as:

- Which customers may be affected by this publication?
- Which high-risk customers have no open remediation action?
- What product or patch-level information is missing?
- Draft a customer-specific briefing using approved evidence.

The assistant should retrieve current database records through controlled server-side functions rather than receive unrestricted database access.

## Key Design Principle

Use deterministic ingestion, normalization, filtering, and matching wherever possible. Use the LLM to interpret evidence, explain risk, identify missing information, and recommend follow-up. This separation reduces noise, cost, and hallucination risk.

## OpenAI References

- Responses API: https://developers.openai.com/api/docs/guides/migrate-to-responses
- Structured Outputs: https://developers.openai.com/api/docs/guides/structured-outputs
- API data controls: https://developers.openai.com/api/docs/guides/your-data#default-usage-policies-by-endpoint

