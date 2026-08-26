# Oracle KEV dashboard report

## Purpose

The Oracle KEV report identifies entries in the CISA Known Exploited
Vulnerabilities catalog that map to Oracle products. It is a standalone report,
separate from both the advisory-specific CSAF Phase 0 report and the
`Monitor Oracle Security Publications` RSS automation.

The report is intended to answer two questions:

1. Which recently added CISA KEVs are associated with Oracle products?
2. How long elapsed between the NVD CVE publication date and the date CISA
   added the CVE to KEV?

KEV membership is evidence that exploitation has occurred in the wild. It does
not prove that exploitation is continuing at the time the report is viewed, and
it does not establish that a particular customer is exposed. Product and
version applicability must be confirmed in the linked Oracle advisory.

## Current implementation status

| Component | Status |
| --- | --- |
| Python report generator | Implemented and committed |
| Self-contained HTML and JSON report bundle | Implemented and committed |
| `new90D` HTML metadata | Implemented and tested |
| APEX Static Application File | Deployed manually in the application |
| Page 25 iframe display | Deployed in the application |
| P1 metadata-driven button label | Deployed in the application |
| APEX automation that downloads and stores the report | Proposed, not implemented |
| Database CLOB endpoint for the iframe | Proposed, not implemented |

The deployed APEX changes for page 25 and the P1 page-load Dynamic Action are
newer than the checked-in split APEX export. Re-export the application before
treating `apex/exports/sed-dashboard-2/` as the source of truth for those two
changes.

## Report generation

The entry point is `csaf-analytics/oracle_kev_report.py`. By default it reports
Oracle-mapped KEVs added during the rolling year ending on the execution date:

```bash
cd csaf-analytics
python3 oracle_kev_report.py --output-dir var/output
```

To also copy the HTML to a stable publication directory, use `-d`. The command
creates the directory when necessary and replaces the stable HTML and checksum
files:

```bash
python3 oracle_kev_report.py \
  --output-dir var/output \
  -d /path/to/kev-reports
```

The published files are:

```text
/path/to/kev-reports/report-oracle-kev.html
/path/to/kev-reports/report-oracle-kev.html.cksum
```

The `.cksum` file contains the SHA-256 digest followed by two spaces and the
HTML filename. Consumers can use it to detect a new report or verify the HTML
before processing its metadata.

Each execution creates a new timestamped bundle:

```text
var/output/oracle-kev/<UTC timestamp>_ORACLE_KEV/
├── manifest.json
├── oracle-kev-report-data.json
└── report-oracle-kev.html
```

The generator uses:

- Oracle's public CVE-to-advisory mapping for Oracle product association;
- the CISA KEV catalog for KEV dates and ransomware-campaign flags; and
- NVD publication dates for the publication-to-KEV lag metric.

The default report order is newest to oldest by CISA KEV addition date. The
interactive `Added in last 90 days` filter is selected by default. The report
does not display CISA due date, past-due status, or required action because
those fields describe US federal remediation requirements and are not useful
for this dashboard's cataloguing view.

The `Ransomware` signal comes from CISA's `knownRansomwareCampaignUse` value. It
means CISA has associated the vulnerability with known ransomware campaign
use; it is not inferred by the report generator.

## HTML metadata contract

The generated HTML contains this element in its `head`:

```html
<meta name="new90D" content="6">
```

The number is regenerated from the report's `added_last_90_days` KPI on every
run. Consumers must treat it as a non-negative integer. Missing or invalid
metadata means unknown, not zero.

The metadata is deliberately server-rendered. Consumers do not need to execute
the report's JavaScript to read it.

## Current APEX delivery

The latest generated HTML is currently uploaded as this Static Application
File:

```text
#APP_FILES#kev-reports/report-oracle-kev.html
```

Page 25 displays that resource in an iframe. The `90D_KEV` button on P1 opens
page 25.

On P1, a Page Load Dynamic Action fetches the static HTML and reads
`meta[name="new90D"]`. It then changes the button label to, for example:

```text
6 KEVs in last 90 days
```

The implementation uses the JavaScript substitution form of the application
file URL:

```javascript
const reportUrl = apex.util.applyTemplate(
    "&APP_FILES.kev-reports/report-oracle-kev.html",
    { defaultEscapeFilter: "RAW" }
);
```

The button does not currently have a user-defined HTML ID. APEX renders a
generated ID such as `B22177920406530709244`, which must not be used as a stable
selector. The deployed button has the custom attribute `mykev`, so the Dynamic
Action locates it with:

```javascript
const button = document.querySelector("button[mykev]");
```

The code updates the `.t-Button-label` child and retains the original label if
the file request, metadata lookup, integer validation, or button lookup fails.
The static file is fetched successfully only when its resolved application URL
is accessible to the current browser session.

For future cleanup, prefer a standards-based custom data attribute such as
`data-kev-button="90d"` or a genuine APEX Static ID beginning with a letter.

## Proposed automated delivery

Static Application Files are deployment artifacts. An APEX automation should
not update APEX internal repository tables or call undocumented `WWV_FLOW_*`
APIs to replace one at runtime.

If automatic refresh is required, use this design:

1. A scheduled APEX automation retrieves the published HTML with
   `APEX_WEB_SERVICE.MAKE_REST_REQUEST`.
2. It accepts only HTTP 200, validates the expected report metadata, and stores
   the last valid HTML in an application-owned CLOB table.
3. It preserves the last successful copy when retrieval or validation fails and
   records the source URL, retrieval time, HTTP status, and error detail.
4. A dedicated authorized APEX endpoint page selects the CLOB and serves it
   inline with `APEX_HTTP.DOWNLOAD`, content type
   `text/html; charset=UTF-8`, and `p_is_inline => true`.
5. Page 25 points its iframe to that endpoint instead of `#APP_FILES#`.

The endpoint gives the iframe a stable URL and supports reports larger than the
PL/SQL `VARCHAR2` limit. The iframe should remain sandboxed because downloaded
HTML served from an application URL is active content. The current generated
report is self-contained; a future externally generated report must use
absolute asset URLs or an appropriate `base` URL.

For the P1 label alone, storing the validated 90-day count in a small metrics
table is cheaper than retrieving and parsing the complete HTML on every page
load. The current browser-side approach remains appropriate while the report is
a manually maintained Static Application File.

## Verification checklist

1. Generate a report and confirm `report-oracle-kev.html` contains one valid
   `meta[name="new90D"]` element.
2. Upload it under `kev-reports/report-oracle-kev.html` in Static Application
   Files.
3. Open page 25 and confirm that the iframe renders the report.
4. Load P1 and confirm the report request returns HTTP 200.
5. Confirm the `mykev` button label matches the metadata count.
6. Test counts of zero, one, and more than one for sensible label text.
7. Test a missing file and malformed metadata; the original button label must
   remain usable.
8. Re-export the APEX application and commit the updated page definitions.
