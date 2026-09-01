import hashlib
import json
import sys
import tempfile
import unittest
from datetime import date, datetime, timezone
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from csaf_analytics import oracle_kev


ORACLE_MAP = b"""<!doctype html><html><body>
<p>The following table, updated to include the July 21, 2026 Critical Patch
Update, maps CVEs to advisories.</p>
<table><thead><tr><th>Unrelated</th></tr></thead><tbody></tbody></table>
<table><thead><tr>
<th>Vulnerability Identifier</th><th>Product [Product ID]</th><th>Advisory</th>
</tr></thead><tbody>
<tr><td rowspan="2">CVE-2026-21962</td>
<td>Oracle HTTP Server [1042]</td>
<td><a href="/security-alerts/cpujan2026.html">Oracle CPU January 2026</a></td></tr>
<tr><td>Oracle WebLogic Server Proxy Plug-in [1043]</td>
<td><a href="https://www.oracle.com/security-alerts/cpujan2026.html">Oracle CPU January 2026</a></td></tr>
<tr><td rowspan="1">CVE-2025-11111</td><td>Oracle Database [5]</td>
<td><a href="/security-alerts/cpuoct2025.html">Oracle CPU October 2025</a></td></tr>
</tbody></table></body></html>"""


def kev_catalog():
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.08.25",
        "dateReleased": "2026-08-25T17:43:58Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-21962",
                "vendorProject": "Oracle",
                "product": "HTTP Server",
                "vulnerabilityName": "Oracle HTTP Server Access Control",
                "dateAdded": "2026-08-24",
                "shortDescription": "Description </script><script>alert(1)</script>",
                "requiredAction": "Apply mitigations.",
                "dueDate": "2026-08-27",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "https://example.test/cve",
                "cwes": ["CWE-284"],
            },
            {
                "cveID": "CVE-2025-11111",
                "vendorProject": "Oracle",
                "product": "Database",
                "vulnerabilityName": "Old Oracle vulnerability",
                "dateAdded": "2025-01-01",
                "requiredAction": "Apply mitigations.",
                "dueDate": "2025-01-22",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2026-99999",
                "vendorProject": "Other",
                "product": "Other",
                "vulnerabilityName": "Non-Oracle vulnerability",
                "dateAdded": "2026-08-20",
                "requiredAction": "Apply mitigations.",
                "dueDate": "2026-09-01",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ],
    }


def nvd_catalog():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-21962",
                    "published": "2026-01-20T12:00:00.000",
                }
            }
        ]
    }


class OracleKevTests(unittest.TestCase):
    def test_oracle_map_parser_handles_rowspan_products(self):
        mappings, source_note = oracle_kev.parse_oracle_cve_map(ORACLE_MAP)

        self.assertEqual(len(mappings["CVE-2026-21962"]), 2)
        self.assertEqual(
            mappings["CVE-2026-21962"][0],
            {
                "product": "Oracle HTTP Server",
                "product_id": "1042",
                "advisory": "Oracle CPU January 2026",
                "advisory_url": (
                    "https://www.oracle.com/security-alerts/cpujan2026.html"
                ),
            },
        )
        self.assertEqual(source_note, "July 21, 2026 Critical Patch Update")

    def test_correlation_filters_window_and_non_oracle_mappings(self):
        mappings, _source_note = oracle_kev.parse_oracle_cve_map(ORACLE_MAP)
        rows = oracle_kev.correlate_oracle_kevs(
            mappings,
            kev_catalog(),
            as_of=date(2026, 8, 25),
            days=365,
        )

        self.assertEqual([row["cve"] for row in rows], ["CVE-2026-21962"])
        self.assertEqual(rows[0]["days_since_added"], 1)
        self.assertNotIn("overdue", rows[0])
        self.assertEqual(len(rows[0]["oracle_products"]), 2)

    def test_correlation_orders_kev_additions_newest_first(self):
        def mapping(product):
            return {
                "product": product,
                "product_id": "1",
                "advisory": "Oracle Advisory",
                "advisory_url": "https://www.oracle.com/security-alerts/",
            }

        mappings = {
            "CVE-2026-10001": [mapping("Older Oracle Product")],
            "CVE-2026-10002": [mapping("Newest Oracle Product")],
            "CVE-2026-10003": [mapping("Middle Oracle Product")],
        }
        catalog = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-10001",
                    "dateAdded": "2026-01-10",
                },
                {
                    "cveID": "CVE-2026-10002",
                    "dateAdded": "2026-08-24",
                },
                {
                    "cveID": "CVE-2026-10003",
                    "dateAdded": "2026-06-15",
                },
            ]
        }

        rows = oracle_kev.correlate_oracle_kevs(
            mappings,
            catalog,
            as_of=date(2026, 8, 25),
            days=365,
        )

        self.assertEqual(
            [row["date_added"] for row in rows],
            ["2026-08-24", "2026-06-15", "2026-01-10"],
        )

    def test_report_data_counts_90_day_and_one_year_views(self):
        rows = [
            {
                "days_since_added": age,
                "oracle_products": ["Oracle Product"],
                "publication_to_kev_days": None,
                "ransomware": "Unknown",
            }
            for age in (1, 90, 91, 365, 366)
        ]

        report = oracle_kev.build_report_data(
            rows,
            {"vulnerabilities": []},
            as_of=date(2026, 8, 25),
            days=400,
            generated_at=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
            mapping_count=1,
            mapping_source_note="Test mapping",
            nvd_status="disabled",
            nvd_detail="Test",
        )

        self.assertEqual(report["kpis"]["oracle_kevs"], 5)
        self.assertEqual(report["kpis"]["added_last_90_days"], 2)
        self.assertEqual(report["kpis"]["added_last_365_days"], 4)

    def test_offline_generator_creates_separate_safe_html_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            oracle_file = root / "oracle-map.html"
            kev_file = root / "kev.json"
            nvd_file = root / "nvd.json"
            oracle_file.write_bytes(ORACLE_MAP)
            kev_file.write_text(json.dumps(kev_catalog()), encoding="utf-8")
            nvd_file.write_text(json.dumps(nvd_catalog()), encoding="utf-8")
            publish_dir = root / "published" / "kev-reports"

            output = oracle_kev.generate_oracle_kev_report(
                root / "output",
                publish_dir=publish_dir,
                oracle_map_file=oracle_file,
                kev_file=kev_file,
                nvd_file=nvd_file,
                as_of=date(2026, 8, 25),
                now=datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc),
            )

            self.assertEqual(
                output.name,
                "20260825T120000Z_ORACLE_KEV",
            )
            self.assertEqual(output.parent.name, "oracle-kev")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "manifest.json",
                    "oracle-kev-report-data.json",
                    "report-oracle-kev.html",
                },
            )
            report = json.loads(
                (output / "oracle-kev-report-data.json").read_text()
            )
            self.assertEqual(report["schema_version"], 2)
            self.assertEqual(report["kpis"]["oracle_kevs"], 1)
            self.assertEqual(report["kpis"]["added_last_90_days"], 1)
            self.assertEqual(report["kpis"]["added_last_365_days"], 1)
            self.assertNotIn("added_last_60_days", report["kpis"])
            self.assertNotIn("added_last_30_days", report["kpis"])
            self.assertNotIn("past_cisa_due_date", report["kpis"])
            self.assertNotIn("due_date", report["kevs"][0])
            self.assertNotIn("required_action", report["kevs"][0])
            self.assertEqual(report["kevs"][0]["cve_published"], "2026-01-20")
            self.assertEqual(
                report["kevs"][0]["publication_to_kev_days"],
                (date(2026, 8, 24) - date(2026, 1, 20)).days,
            )
            self.assertEqual(
                report["kpis"]["median_publication_to_kev_days"],
                (date(2026, 8, 24) - date(2026, 1, 20)).days,
            )
            rendered = (output / "report-oracle-kev.html").read_text()
            self.assertIn("Oracle Known Exploited Vulnerabilities", rendered)
            self.assertIn("CVE-2026-21962", rendered)
            self.assertNotIn("CISA due", rendered)
            self.assertNotIn("Past CISA due date", rendered)
            self.assertNotIn("Required action", rendered)
            self.assertIn("KEV added ↓", rendered)
            self.assertIn("Publish → KEV", rendered)
            self.assertIn("Added in 90 days", rendered)
            self.assertIn("Added in 1 year", rendered)
            self.assertIn("Added in last 1 year", rendered)
            self.assertNotIn("Added in 60 days", rendered)
            self.assertNotIn("Added in 30 days", rendered)
            self.assertIn(
                'name="kev-age-window" value="90" checked', rendered
            )
            self.assertIn('name="kev-age-window" value="365"', rendered)
            self.assertIn('data-age="${r.days_since_added}"', rendered)
            self.assertIn('<meta name="new90D" content="1">', rendered)
            self.assertNotIn("</script><script>alert(1)</script>", rendered)
            self.assertIn("<\\/script><script>alert(1)<\\/script>", rendered)
            self.assertEqual(
                (publish_dir / "report-oracle-kev.html").read_text(),
                rendered,
            )
            self.assertEqual(
                (publish_dir / "report-oracle-kev.html.cksum").read_text(),
                f"{hashlib.sha256(rendered.encode('utf-8')).hexdigest()}  "
                "report-oracle-kev.html\n",
            )

    def test_publish_dir_overwrites_existing_html(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.html"
            publish_dir = root / "published"
            publish_dir.mkdir()
            destination = publish_dir / "report-oracle-kev.html"
            checksum_destination = publish_dir / "report-oracle-kev.html.cksum"
            source.write_text("new report", encoding="utf-8")
            destination.write_text("old report", encoding="utf-8")
            checksum_destination.write_text("old checksum", encoding="ascii")

            published = oracle_kev._publish_html_report(
                source,
                publish_dir,
                None,
            )

            self.assertEqual(published, destination)
            self.assertEqual(destination.read_text(encoding="utf-8"), "new report")
            self.assertEqual(
                checksum_destination.read_text(encoding="ascii"),
                f"{hashlib.sha256(b'new report').hexdigest()}  "
                "report-oracle-kev.html\n",
            )
            self.assertCountEqual(
                publish_dir.iterdir(),
                [destination, checksum_destination],
            )

    def test_parser_accepts_short_publish_directory_flag(self):
        args = oracle_kev._parser().parse_args(["-d", "published"])

        self.assertEqual(args.publish_dir, Path("published"))


if __name__ == "__main__":
    unittest.main()
