import sqlite3
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from csaf_analytics import oracle_cve_ledger
from csaf_analytics import oracle_kev


RSS = b"""<rss><channel>
<item><guid>CPUJAN2026</guid><title>Critical Patch Update - January 2026</title><link>https://example.test/cpujan2026.html</link><pubDate>Tue, 20 Jan 2026 12:30:54 -0700</pubDate></item>
<item><guid>OLD</guid><title>Critical Patch Update - January 2020</title><link>https://example.test/cpujan2020.html</link><pubDate>Tue, 14 Jan 2020 12:30:54 -0700</pubDate></item>
</channel></rss>"""

ADVISORY = b"""<html><body><table><tr><th>CVE#</th><th>Product</th><th>Supported Versions Affected</th><th>Notes</th></tr>
<tr><td>CVE-2026-10001</td><td>Oracle Test Product</td><td>1.0-1.2</td></tr>
<tr><td>CVE-2026-10002</td><td>Oracle Test Product</td><td>2.0</td><td>Also addresses CVE-2026-10003</td></tr>
</table><p>The patch for CVE-2026-10002 also addresses CVE-2026-10004.</p></body></html>"""

VERBOSE_ADVISORY = b"""<html><body>
<h3>Text Form of Risk Matrix for Oracle Older Product</h3>
<table><tr><th>CVE#</th><th>Description</th></tr>
<tr><td>CVE-2022-12345</td><td>Vulnerability. Supported versions that are affected are 1.0 and 2.0. Easily exploitable.</td></tr>
</table></body></html>"""


class OracleCveLedgerTests(unittest.TestCase):
    def test_rss_filters_to_rolling_eligible_advisories(self):
        items = oracle_cve_ledger.parse_rss(RSS, cutoff=date(2021, 9, 24))

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_type"], "CPU")
        self.assertEqual(items[0]["published_on"], "2026-01-20")

    def test_risk_matrix_parser_extracts_product_and_versions(self):
        rows = oracle_cve_ledger.parse_risk_matrices(ADVISORY)

        self.assertEqual([row["cve"] for row in rows], ["CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003"])
        self.assertEqual(rows[0]["supported_versions"], "1.0-1.2")

    def test_additional_cve_statement_inherits_primary_product_mapping(self):
        rows = oracle_cve_ledger.expand_additional_cves(
            ADVISORY, oracle_cve_ledger.parse_risk_matrices(ADVISORY)
        )

        additional = next(row for row in rows if row["cve"] == "CVE-2026-10004")
        self.assertEqual(additional["product"], "Oracle Test Product")
        self.assertEqual(additional["supported_versions"], "2.0")

    def test_verbose_risk_matrix_parser_handles_older_advisories(self):
        rows = oracle_cve_ledger.parse_verbose_risk_matrices(VERBOSE_ADVISORY)

        self.assertEqual(rows, [{
            "cve": "CVE-2022-12345",
            "product": "Oracle Older Product",
            "supported_versions": "1.0 and 2.0",
        }])

    def test_sync_writes_legacy_parser_compatible_html(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            rss_file = root / "rss.xml"
            rss_file.write_bytes(RSS)
            database = root / "ledger.sqlite"
            mapping = root / "oracle-map.html"

            with patch.object(oracle_cve_ledger, "_fetch", return_value=ADVISORY):
                discovered, changed = oracle_cve_ledger.sync_ledger(
                    database, mapping, retention_years=5, timeout=5,
                    rss_file=rss_file, today=date(2026, 9, 24),
                )

            self.assertEqual((discovered, changed), (1, 1))
            html = mapping.read_text(encoding="utf-8")
            self.assertIn("Vulnerability Identifier", html)
            self.assertIn("CVE-2026-10003", html)
            self.assertIn("https://example.test/cpujan2026.html", html)
            legacy_mappings, _note = oracle_kev.parse_oracle_cve_map(
                html.encode("utf-8")
            )
            self.assertEqual(
                legacy_mappings["CVE-2026-10001"][0]["advisory"],
                "Critical Patch Update - January 2026",
            )
            with sqlite3.connect(database) as connection:
                self.assertEqual(connection.execute("select count(*) from cve_mapping").fetchone()[0], 4)


if __name__ == "__main__":
    unittest.main()
