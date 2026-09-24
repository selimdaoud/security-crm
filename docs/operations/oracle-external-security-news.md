# Oracle-related external security news

## Purpose and status

This document defines the proposed external-news capability for the SED
Dashboard. It complements, but does not replace, the official Oracle security
publication feed.

- The existing Oracle RSS automation imports official Oracle CPU, CSPU, and
  Security Alert publications.
- The proposed Google News feed identifies third-party reporting that may be
  relevant to Oracle products, services, or customers.

External reporting must always be visibly labelled as **External security news**.
It is not an Oracle advisory, confirmation of a customer impact, or evidence
that a customer is vulnerable.

This is a design and operating contract only. No database object, APEX
automation, dashboard region, or scheduled job is created by this document.

## Source

The initial source is a Google News RSS search that requires both an
Oracle-related phrase and a security-event phrase:

```text
https://news.google.com/rss/search?q=%28%22Oracle%22+OR+%22Oracle+Corporation%22+OR+%22Oracle+Cloud%22+OR+%22Oracle+Database%22+OR+%22Oracle+Java%22+OR+%22Oracle+WebLogic%22%29+%28%22data+breach%22+OR+ransomware+OR+%22security+incident%22+OR+vulnerability+OR+%22zero-day%22%29&hl=en-US&gl=US&ceid=US:en
```

The query may be adjusted as product priorities change. Changes should be
recorded in the automation configuration and its operational log, including
the old and new URL and the date of the change.

Google News search matching is not a relevance guarantee. The implementation
should retain the source title, publisher, publication date, and link, and
should not infer facts that are absent from the linked article.

## Data boundary

External news should use a dedicated runtime table, proposed as
`SECURITY_EXTERNAL_NEWS`, rather than `SECURITY_PUBLICATIONS`.

This separation preserves the meaning of the current official-publication
records and makes provenance unambiguous in queries and UI labels. The table
should retain at least:

| Field | Purpose |
| --- | --- |
| `NEWS_ID` | Local primary key |
| `SOURCE_CODE` | Source identifier, initially `GOOGLE_NEWS` |
| `EXTERNAL_ID` | Normalized RSS GUID; the primary duplicate key |
| `ARTICLE_URL` | Google News item URL used for navigation |
| `TITLE` | Normalized article title |
| `PUBLISHER_NAME` | Publisher supplied by the feed, when available |
| `PUBLISHED_ON` | Source publication timestamp/date |
| `CATEGORY_CODE` | Optional classification: breach, ransomware, incident, vulnerability, or zero-day |
| `NEWS_STATE` | `CURRENT`, `NEW`, or `UPDATED` |
| `FIRST_SEEN_AT`, `LAST_SEEN_AT`, `LAST_CHANGED_AT` | Ingestion traceability |

The table should enforce uniqueness on `(SOURCE_CODE, EXTERNAL_ID)`. When the
RSS GUID is missing, a stable normalized URL may be used only if the source
format makes that safe; otherwise the item should be logged and skipped rather
than inserted with an unstable synthetic identifier.

RSS article data belongs in Oracle Database at runtime. The repository holds
only source-controlled artifacts: the database script, APEX automation/export,
style changes if needed, and this operational document.

## Ingestion automation

Create a separate APEX automation named **Monitor Oracle-related External
Security News**. It should initially run hourly, with the effective APEX
scheduler time zone documented in the deployed environment.

The automation should:

1. Read the configured RSS URL over HTTPS with an explicit timeout.
2. Validate the HTTP response and parse RSS items.
3. Normalize GUID, title, publisher, link, and publication date fields.
4. Apply a lightweight relevance guard: retain only items whose title or
   available summary contains an approved Oracle phrase.
5. Look up the normalized external identifier for source `GOOGLE_NEWS`.
6. Insert unseen entries as `CURRENT` on the first successful baseline run, or
   `NEW` on subsequent runs.
7. Update changed title, publisher, URL, or publication-date values as
   `UPDATED`; refresh `LAST_SEEN_AT` for unchanged entries.
8. Commit only after successful processing and record a concise run summary.

As with the official Oracle RSS feed, a failed fetch or parse must not delete
or overwrite the last known valid news records. The automation should log the
failure and leave the previous dataset available to the dashboard.

## Latest-N dashboard display

The Home dashboard will receive an **External Security News** region. It must
be distinct from the existing **Security Events** region that displays official
Oracle publications.

The region displays the newest `N` retained records, ordered by source
publication time descending and then local ID descending. It should show:

- article title, linked externally with `noopener noreferrer`;
- publisher;
- published date;
- category badge, when classification is available; and
- a `NEW` or `UPDATED` badge for a short freshness window.

The dashboard should default to **5** items. It must not determine the number
of imported or retained articles; ingestion retains all valid deduplicated
records, while the dashboard only limits presentation.

## Display-limit configuration

Store the limit in an APEX application-level setting named
`EXTERNAL_NEWS_DISPLAY_LIMIT`.

| Rule | Value |
| --- | --- |
| Default | `5` |
| Allowed range | `1` to `20` |
| Invalid, missing, or null value | Safely fall back to `5` |
| Change owner | Application administrator |

The region SQL must read this setting through a validated numeric value, not
by interpolating arbitrary text into SQL. Changing the setting changes only
the dashboard presentation; it does not require redeploying the application or
rerunning the RSS importer.

## Full-history view and retention

Provide a separate page or modal report for all retained external-news records.
It should support filters for date, publisher, category, and news state. The
dashboard region should offer a **View all news** navigation path to it.

The initial retention proposal is 12 months. Before enabling any purge job,
confirm that this meets advisor, audit, and operational requirements. A purge
must be explicit, logged, and separate from feed ingestion.

## Implementation artifacts

The planned source-controlled locations are:

```text
database/sed-dashboard/15_external_security_news.sql
apex/exports/sed-dashboard-2/shared-components/automations/
  monitor-oracle-external-security-news.apx
apex/exports/sed-dashboard-2/pages/p00001-home.apx
apex/static/dashboard.css
docs/operations/oracle-external-security-news.md
```

`dashboard.css` changes are optional and only needed if the external-news card
cannot reuse the existing dashboard design language.

## Acceptance checks

Before deployment, verify that:

1. The source URL returns readable RSS from the APEX environment.
2. The first successful run creates a `CURRENT` baseline rather than a set of
   false new-event indicators.
3. A later unseen GUID becomes `NEW`; a changed item becomes `UPDATED`; an
   unchanged item only refreshes its last-seen timestamp.
4. Duplicate runs do not create duplicate rows.
5. Unrelated articles that bypass Google News search matching are rejected by
   the Oracle relevance guard or remain visibly classified as external news.
6. The dashboard honors configured values from 1 to 20 and falls back to 5 for
   invalid configuration.
7. The full-history view contains more records than the dashboard when the
   configured limit is lower than the retained result count.
8. A feed failure leaves existing dashboard data intact and produces an
   actionable automation log entry.
