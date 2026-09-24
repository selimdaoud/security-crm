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
| APEX Static Application File | Legacy delivery path; no longer used at runtime |
| APEX automation that downloads and stores the report | Implemented and deployed |
| Page 26 authenticated BLOB endpoint | Implemented and deployed |
| Page 25 iframe display through page 26 | Implemented and deployed |
| P1 metadata-driven button label through page 26 | Implemented and deployed |

The deployed APEX changes for pages 1, 25, and 26, together with the
application-level frame setting, are newer than the checked-in split APEX
export. Re-export the application before treating
`apex/exports/sed-dashboard-2/` as the source of truth for those components.

## Report generation

The entry point is `csaf-analytics/oracle_kev_report.py`. By default it reports
Oracle-mapped KEVs added during the rolling year ending on the execution date:

### Local Oracle CVE ledger

The report is fed by a local, rolling five-year CVE-to-advisory ledger rather
than Oracle's public CVE-to-advisory mapping page. The ledger builder reads
Oracle's security RSS feed, downloads CPU, CSPU, and Security Alert advisories,
and writes both an SQLite database and a parser-compatible HTML mapping file.
`oracle_kev_report.py` remains unchanged and reads that HTML file through its
existing `--oracle-map-file` option.

Build the ledger before generating the report:

```bash
cd csaf-analytics

python3 oracle_cve_ledger.py rebuild \
  --database /var/lib/oracle-kev/oracle-cve-ledger.sqlite \
  --map-html /var/lib/oracle-kev/oracle-cve-advisory-map.html

python3 oracle_kev_report.py \
  --oracle-map-file /var/lib/oracle-kev/oracle-cve-advisory-map.html \
  --output-dir /var/lib/oracle-kev/output \
  -d /path/to/kev-reports
```

`rebuild` creates a fresh staging database, validates it, retains a timestamped
backup of the prior active database, and atomically replaces the active ledger
and mapping HTML only after success. At the current source volume it completes
in about 20 seconds, so it is the normal scheduled operation. `sync` is
available for incremental updates but is not required for the daily job.

Successful ledger runs are silent by default. Add `--verbose` to print RSS
discovery, each advisory download and parser path, retention pruning, and HTML
publication progress. Errors are written to standard error and return exit code
`2`.

Use one cron job to rebuild the ledger, then generate and publish the report:

```cron
CRON_TZ=UTC
15 02 * * * /usr/bin/python3 /path/to/csaf-analytics/oracle_cve_ledger.py rebuild --database /var/lib/oracle-kev/oracle-cve-ledger.sqlite --map-html /var/lib/oracle-kev/oracle-cve-advisory-map.html && /usr/bin/python3 /path/to/csaf-analytics/oracle_kev_report.py --oracle-map-file /var/lib/oracle-kev/oracle-cve-advisory-map.html --output-dir /var/lib/oracle-kev/output -d /path/to/kev-reports >> /var/log/oracle-kev/oracle-kev-cron.log 2>&1
```

Create the log directory first and replace `/path/to/csaf-analytics` and
`/path/to/kev-reports` with the server's actual locations. The cron schedule is
independent of the APEX automation, which only retrieves an already-published
report.

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

When the local ledger workflow is used, the generator uses:

- the local Oracle CVE ledger, built from CPU, CSPU, and Security Alert
  advisories discovered through Oracle's RSS feed, for Oracle product
  association;
- the CISA KEV catalog for KEV dates and ransomware-campaign flags; and
- NVD publication dates for the publication-to-KEV lag metric.

The default report order is newest to oldest by CISA KEV addition date. The
decision list has mutually exclusive `Added in last 90 days` and `Added in last
1 year` views. The 90-day view is selected by default; the one-year view shows
the complete default 365-day report window. Product, text, and ransomware
filters work with either view. The report does not display CISA due date,
past-due status, or required action because those fields describe US federal
remediation requirements and are not useful for this dashboard's cataloguing
view.

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

The report is delivered from the validated BLOB in
`SECURITY_REPORT_FILES`. A manually uploaded Static Application File is no
longer part of the runtime path.

The authenticated page 26 endpoint has the friendly page alias
`kev-report-endpoint`. Its application-relative URL is:

```text
/pls/apex/r/css-ciso/sed-dashboard/kev-report-endpoint?session=&APP_SESSION.
```

The session ID must not be hard-coded. APEX replaces `&APP_SESSION.` when it
renders the containing page. The endpoint selects `CONTENT_BLOB` and
`MIME_TYPE` for `REPORT_CODE = 'ORACLE_KEV'` and returns the BLOB inline from a
Before Header process. The deployed process uses the Oracle Web Toolkit BLOB
download mechanism:

```plsql
declare
    l_content_blob security_report_files.content_blob%type;
    l_mime_type    security_report_files.mime_type%type;
begin
    select content_blob,
           mime_type
      into l_content_blob,
           l_mime_type
      from security_report_files
     where report_code = 'ORACLE_KEV';

    sys.htp.init;

    owa_util.mime_header(
        ccontent_type => l_mime_type,
        bclose_header => false
    );

    htp.p(
        'Content-Length: ' ||
        to_char(dbms_lob.getlength(l_content_blob))
    );

    htp.p(
        'Content-Disposition: inline; ' ||
        'filename="report-oracle-kev.html"'
    );

    owa_util.http_header_close;
    wpg_docload.download_file(l_content_blob);
    apex_application.stop_apex_engine;

exception
    when no_data_found then
        raise_application_error(
            -20001,
            'No ORACLE_KEV report exists in SECURITY_REPORT_FILES'
        );
    when apex_application.e_stop_apex_engine then
        raise;
end;
```

The process is enabled, has no server-side condition, and executes at
Pre-Rendering / Before Header. Page 26 uses the same authentication and
authorization policy as page 25.

### Page 25 iframe

Page 25 displays the endpoint in a sandboxed iframe. The `90D_KEV` button on P1
opens page 25.

```html
<iframe
    src="/pls/apex/r/css-ciso/sed-dashboard/kev-report-endpoint?session=&APP_SESSION."
    title="Oracle KEV Report"
    sandbox="allow-scripts allow-popups allow-popups-to-escape-sandbox"
    referrerpolicy="no-referrer"
    style="width:100%; height:85vh; border:0;">
</iframe>
```

Do not add `allow-same-origin` to the iframe unless the report develops a
specific requirement for it. The downloaded document contains executable
JavaScript and is served from an application URL.

APEX initially returned `X-Frame-Options: DENY`, which prevented page 26 from
being displayed in page 25. Under Shared Components / Security Attributes /
Browser Security, `Embed in Frames` is set to `Allow from same origin`. This
produces same-origin frame protection: pages in this application can embed the
endpoint, while pages on another origin cannot.

### P1 90-day button

On P1, a Page Load Dynamic Action fetches the same page 26 endpoint and reads
`meta[name="new90D"]`. It then changes the button label to, for example:

```text
6 KEVs in last 90 days
```

The endpoint URL is expanded with `apex.util.applyTemplate`:

```javascript
const reportUrl = apex.util.applyTemplate(
    "/pls/apex/r/css-ciso/sed-dashboard/kev-report-endpoint?session=&APP_SESSION.",
    { defaultEscapeFilter: "RAW" }
);
```

The button is selected through its standards-based custom data attribute. APEX
generated IDs such as `B22177920406530709244` must not be used as stable
selectors:

```javascript
const button = document.querySelector('[data-kev-button="90d"]');
```

The code updates the `.t-Button-label` child and retains the original label if
the endpoint request, metadata lookup, integer validation, or button lookup
fails. The request uses `credentials: "same-origin"` and therefore runs inside
the user's existing authenticated APEX session.

## Checksum-driven APEX automation

The repository includes the split APEX automation definition at
`apex/exports/sed-dashboard-2/shared-components/automations/monitor-oracle-kev-report.apx`.
It runs at 00:15, 06:15, 12:15, and 18:15 in the database server's scheduling
timezone. Imported automations must be reviewed and enabled in the target APEX
environment.

Install `database/sed-dashboard/14_security_report_files.sql` before enabling
the automation. The parsing schema also needs permission to execute
`DBMS_CRYPTO` and outbound HTTPS access to `itx0.com`.

For a manually configured APEX environment:

1. run `14_security_report_files.sql` in the application parsing schema;
2. create an automation named `Monitor Oracle KEV Report` under Shared
   Components;
3. set Actions Initiated On to `Always` and use the schedule from the checked-in
   automation, or choose another appropriate interval;
4. create an Execute Code action and copy the PL/SQL block from the checked-in
   automation definition;
5. save, enable, and run the automation once manually.

After the first successful run, verify the stored report without selecting the
BLOB itself:

```sql
select report_code,
       checksum_sha256,
       content_length,
       last_checked_at,
       last_changed_at
  from security_report_files
 where report_code = 'ORACLE_KEV';
```

On each run, the automation:

1. downloads `report-oracle-kev.html.cksum` and requires HTTP 200;
2. validates the exact SHA-256 checksum-file contract;
3. compares the remote checksum with the `ORACLE_KEV` row in
   `SECURITY_REPORT_FILES`;
4. updates only `LAST_CHECKED_AT` when the checksum is unchanged;
5. downloads the HTML as a BLOB only when the checksum is new;
6. checks the response size and required `new90D` metadata marker;
7. independently calculates the BLOB's SHA-256 with `DBMS_CRYPTO`;
8. replaces or inserts the stored report only when both checksums match.

Any HTTP, format, size, metadata, or checksum failure rolls back the run and
preserves the previous validated BLOB. The failure is written to the APEX
automation execution log. The checksum provides change detection and verifies
that the two downloaded files agree; because both are hosted on the same
origin, it is not a digital signature against compromise of that origin.
The source and checksum URLs remain fixed constants in the automation; they are
not duplicated in `SECURITY_REPORT_FILES` and cannot be changed through table
data.

## BLOB delivery rationale

Static Application Files are deployment artifacts. An APEX automation should
not update APEX internal repository tables or call undocumented `WWV_FLOW_*`
APIs to replace one at runtime.

The implemented endpoint gives the iframe a stable URL and supports reports
larger than the PL/SQL `VARCHAR2` limit. It also removes the need to mutate an
application definition whenever the report changes. The current generated
report is self-contained; a future externally generated report must use
absolute asset URLs or an appropriate `base` URL.

For the P1 label alone, storing the validated 90-day count in a small metrics
table is cheaper than retrieving and parsing the complete HTML on every page
load. The current browser-side approach is acceptable at the present report
size and update frequency.

## Verification checklist

1. Generate a report and confirm `report-oracle-kev.html` contains one valid
   `meta[name="new90D"]` element.
2. Publish the report and checksum to the configured web server location.
3. Run the APEX automation and verify that the `ORACLE_KEV` row contains a
   non-empty BLOB with the expected checksum and content length.
4. Run page 26 directly and confirm that the browser renders the HTML report.
5. Open page 25 and confirm that its sandboxed iframe renders page 26 without
   an `X-Frame-Options` or `frame-ancestors` error.
6. Load P1 and confirm that the endpoint request returns HTTP 200.
7. Confirm the `[data-kev-button="90d"]` label matches the metadata count.
8. Test counts of zero, one, and more than one for sensible label text.
9. Test a missing BLOB and malformed metadata; the original button label must
   remain usable and the previous validated report must not be overwritten.
10. Re-export the APEX application and commit the updated page definitions and
    security attributes.
