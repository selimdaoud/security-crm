# Monitor Oracle Security Publications automation

## Purpose and implementation status

`Monitor Oracle Security Publications` is an active Oracle APEX automation that imports Oracle security publication metadata from Oracle's public security RSS feed into the local `SECURITY_PUBLICATIONS` table.

This automation is independent of the Oracle KEV report described in
[`oracle-kev-dashboard.md`](oracle-kev-dashboard.md). Its `Execute Code` action
is server-side PL/SQL; it does not run browser JavaScript or manage the KEV
report's Static Application File.

It handles three local publication categories:

- `CPU` — Critical Patch Update
- `CSPU` — Critical Security Patch Update
- `SECURITY_ALERT` — any feed item whose identifier does not start with `CPU` or `CSPU`

Oracle describes CSPUs as targeted, high-priority fixes that complement the quarterly cumulative CPUs in its [Security Fixing Policies](https://www.oracle.com/corporate/security-practices/assurance/vulnerability/security-fixing/). The automation itself only classifies and stores publication metadata; it does not download patches or evaluate which products and customers are affected.

The implementation is in
[`apex/exports/sed-dashboard-2/shared-components/automations/monitor-oracle-security-publications.apx`](../../apex/exports/sed-dashboard-2/shared-components/automations/monitor-oracle-security-publications.apx).
The target table is defined in
[`database/sed-dashboard/13_security_publications.sql`](../../database/sed-dashboard/13_security_publications.sql),
and the imported records are displayed on the home page by
[`apex/exports/sed-dashboard-2/pages/p00001-home.apx`](../../apex/exports/sed-dashboard-2/pages/p00001-home.apx).

## Execution schedule

The automation is active and uses this schedule expression:

```text
FREQ=DAILY;INTERVAL=1;BYHOUR=6;BYMINUTE=0
```

It therefore runs once per day at 06:00 in the scheduling time zone used by the APEX environment. The export does not state that time zone explicitly, so it should be verified in the deployed APEX instance if the exact UTC/local execution time matters.

There is one action, `Check Oracle Security Publications`, at sequence 10. It is configured to run on every automation execution. Action error handling is `terminate`, so a failure stops the run.

## External source

The action performs an unauthenticated HTTP `GET` request to:

```text
https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml
```

The transfer timeout is 60 seconds. The database/APEX environment must have the required outbound network ACL and TLS trust configuration. The code does not use an APEX Web Credential, add request headers, or implement retries.

Only HTTP status `200` is accepted. Any other status raises application error `-20001` and fails the complete run.

## Processing flow

```text
Daily APEX schedule
        |
        v
Check whether ORACLE_RSS has any stored rows
        |
        v
HTTP GET Oracle RSS feed ---- non-200/error ----> rollback and fail run
        |
        v
Parse /rss/channel/item elements
        |
        v
Normalize and classify each item
        |
        v
Look up (source_code = ORACLE_RSS, external_id = RSS guid)
        |
        +---- existing, content changed ----> update as UPDATED
        |
        +---- existing, unchanged ---------> refresh last-seen time
        |
        +---- missing during first load ---> insert as CURRENT
        |
        +---- missing during later run -----> insert as NEW
        |
        v
Commit all items and write summary log
```

The work is transactional at the run level: the automation commits after processing the entire feed. Any unhandled exception rolls back the run, writes an APEX automation error log entry, and re-raises the exception.

## Initial baseline behavior

Before downloading the feed, the action counts rows where `SOURCE_CODE = 'ORACLE_RSS'`.

- If no such rows exist, the run is considered the initial baseline. Every previously unknown feed item is inserted with `ALERT_STATE = 'CURRENT'`.
- If at least one such row exists, the run is not a baseline. Every previously unknown item is inserted with `ALERT_STATE = 'NEW'`.

This prevents the first import from presenting the whole historical feed as newly published content. Baseline status is all-or-nothing and is based only on whether at least one `ORACLE_RSS` row already exists.

## RSS parsing and field mapping

The response is converted to `XMLTYPE`, and `XMLTABLE('/rss/channel/item')` extracts four child elements from every RSS item.

| RSS value | Normalization | Database column | Use |
|---|---|---|---|
| `guid` | Trim; collapse whitespace to one space | `EXTERNAL_ID` | Stable key used to find an existing publication |
| `title` | Trim; collapse whitespace to one space | `TITLE` | Display text and change detection |
| `link` | Trim; remove all whitespace | `ADVISORY_URL` | Official advisory link and change detection |
| `pubDate` | Trim; collapse whitespace to one space | `SOURCE_PUB_DATE` | Original value retained for traceability and change detection |

The unique constraint on `(SOURCE_CODE, EXTERNAL_ID)` prevents two stored Oracle RSS records from using the same RSS GUID.

### Publication date conversion

The `parse_rss_date` function extracts only a day, English month name, and four-digit year from `pubDate`, then converts that substring to an Oracle `DATE` using `NLS_DATE_LANGUAGE=English`.

For example, both of these values resolve to the same calendar date:

```text
Tue, 16 June 2026 12:30:54
Tue, 16 June 2026 12:30:54 -0700
```

Time-of-day and UTC offset are intentionally discarded. The normalized original string remains in `SOURCE_PUB_DATE`.

## Publication classification

Classification is based on the beginning of the RSS `guid`, case-insensitively:

| Condition | `PUBLICATION_TYPE` |
|---|---|
| GUID starts with `CSPU` | `CSPU` |
| Otherwise, GUID starts with `CPU` | `CPU` |
| Anything else | `SECURITY_ALERT` |

This is a naming convention, not a check of the RSS title, link, description, or advisory contents. Consequently, any unrelated item in the feed whose GUID does not start with `CPU` or `CSPU` would also be stored as `SECURITY_ALERT`.

## Insert and update rules

For each item, the automation selects the existing row using `SOURCE_CODE = 'ORACLE_RSS'` and the normalized RSS GUID. The row is locked with `FOR UPDATE` while it is evaluated.

### New record

When no row exists, the action inserts:

- source code `ORACLE_RSS`;
- normalized RSS GUID, title, and link;
- derived publication type;
- parsed publication date and original normalized `pubDate`;
- state `CURRENT` for the initial baseline, or `NEW` afterward.

The table defaults populate the first-seen, last-seen, last-changed, created, and updated timestamps.

### Existing record with changed content

An item is considered changed if any of the following differs from its stored value:

- title;
- advisory URL;
- normalized original `pubDate` string.

The action updates the publication type and all publication fields, sets `ALERT_STATE = 'UPDATED'`, and refreshes `LAST_SEEN_AT`, `LAST_CHANGED_AT`, and `UPDATED_AT`.

### Existing unchanged record

If none of those three values changed, only `LAST_SEEN_AT` and `UPDATED_AT` are refreshed. `LAST_CHANGED_AT` and `ALERT_STATE` are retained.

This means `NEW` and `UPDATED` are persistent stored states. They are not automatically changed to `CURRENT` on a later unchanged run.

## Logging and counters

The automation writes informational log entries for:

- the start of the RSS read;
- each `NEW` item;
- each `UPDATED` item;
- the final totals for feed items, baseline inserts, new inserts, updated rows, and unchanged rows.

Baseline items and individual unchanged items are counted but not logged one by one. On failure, the action logs `Oracle RSS import failed: <database error>` and the APEX run is marked failed after the exception is re-raised.

## How the dashboard uses the data

The home-page security publications region displays records whose `PUBLISHED_ON` is within the last three months, ordered by publication date and ID descending.

It renders the publication type as `CPU`, `CSPU`, or `SECURITY ALERT`. A `NEW` or `UPDATED` label is displayed only when:

```sql
alert_state in ('NEW', 'UPDATED')
and last_changed_at >= systimestamp - interval '1' day
```

Therefore, although the stored `ALERT_STATE` remains `NEW` or `UPDATED`, its dashboard label disappears after approximately 24 hours. The advisory URL is passed to the report for navigation.

## Operational limitations and review findings

1. **No retry or fallback.** A network error, timeout, non-200 response, malformed XML document, invalid date, or database error fails and rolls back the complete run. The next scheduled run is the only built-in retry.

2. **No handling for removed feed items.** If an item disappears from the RSS feed, its database row is not deleted, expired, or otherwise marked. Its old `LAST_SEEN_AT` can be used to detect this condition separately.

3. **States are not lifecycle statuses.** `NEW` and `UPDATED` never transition back to `CURRENT`; only the dashboard's one-day display rule makes them appear temporary.

4. **`UPDATED_AT` changes for unchanged content.** For unchanged items, `UPDATED_AT` is refreshed together with `LAST_SEEN_AT`. It cannot by itself be used as evidence that publication content changed; use `LAST_CHANGED_AT` for that purpose.

5. **Classification relies entirely on GUID prefixes.** There is no content-based verification that the fallback category is truly a Security Alert.

6. **Date precision is one day.** The database `PUBLISHED_ON` value loses the RSS time and offset. `SOURCE_PUB_DATE` preserves the source text but is not a timestamp value.

7. **The parser expects non-namespaced RSS 2.0 structure.** It specifically reads `/rss/channel/item` and direct `guid`, `title`, `link`, and `pubDate` children. A source format or namespace change can cause missing items or constraint/conversion failures.

8. **Required source values are not validated explicitly.** For a new item, the table's `NOT NULL` constraints reject a missing GUID, title, link, or parsed date and roll back the run. For an existing item, Oracle's null comparison behavior can instead cause a missing title or link to be treated as unchanged when no other compared value changed. Explicit input validation would make both paths predictable.

9. **No stale-run alerting is implemented here.** Errors are written to the APEX automation log, but this action does not send email, create an application alert, or notify an owner when repeated runs fail.

10. **The table is not installed by the application's supporting objects.** The full export includes the automation and dashboard query, but its supporting-object definition only references a deinstallation script. `SECURITY_PUBLICATIONS` must already exist, for example by running `database/sed-dashboard/13_security_publications.sql`, before the automation or dashboard query can work.

## Verification checklist

After importing or changing the application, verify:

1. `SECURITY_PUBLICATIONS` exists with its unique and check constraints.
2. The automation is enabled and its effective scheduling time zone is understood.
3. APEX/database outbound networking can reach the Oracle RSS URL over HTTPS.
4. A manual automation run completes with HTTP 200 and produces a totals log entry.
5. The first run inserts `CURRENT` rows; a controlled later test inserts a new GUID as `NEW`.
6. Changing a stored title, URL, or `SOURCE_PUB_DATE` and rerunning results in `UPDATED`.
7. A second unchanged run refreshes `LAST_SEEN_AT` without changing `LAST_CHANGED_AT`.
8. The home page shows publications from the last three months and limits change labels to the most recent day.
