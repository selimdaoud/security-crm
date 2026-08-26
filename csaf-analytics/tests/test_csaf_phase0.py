import csv
import gzip
import json
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from csaf_analytics import phase0 as csaf_phase0


def sample_csaf():
    return {
        "document": {
            "category": "security_advisory",
            "publisher": {"name": "Oracle", "category": "vendor"},
            "title": "Oracle Test Advisory",
            "references": [
                {
                    "summary": "URL to html version of Advisory",
                    "url": "https://www.oracle.example/security/test.html",
                },
                {
                    "category": "self",
                    "summary": "URL to CSAF version of Advisory",
                    "url": "https://www.oracle.example/security/test.json",
                },
            ],
            "tracking": {
                "id": "CPUJul2026csaf",
                "version": "1.0.0",
                "initial_release_date": "2026-07-21T12:00:00Z",
                "current_release_date": "2026-07-21T12:00:00Z",
                "status": "final",
            },
            "distribution": {"tlp": {"label": "WHITE"}},
        },
        "product_tree": {
            "branches": [
                {
                    "category": "product_family",
                    "name": "Oracle Database",
                    "branches": [
                        {
                            "category": "product_name",
                            "name": "Oracle Database Server",
                            "branches": [
                                {
                                    "category": "product_version",
                                    "name": "19c",
                                    "product": {
                                        "product_id": "CSAFPID-0001",
                                        "name": "Oracle Database 19c",
                                        "product_identification_helper": {
                                            "cpe": "cpe:2.3:a:oracle:database:19c:*:*:*:*:*:*:*"
                                        },
                                    },
                                },
                                {
                                    "category": "product_version",
                                    "name": "23ai",
                                    "product": {
                                        "product_id": "CSAFPID-0002",
                                        "name": "Oracle Database 23ai",
                                    },
                                },
                            ],
                        }
                    ],
                }
            ],
            "product_groups": [
                {
                    "group_id": "CSAFGID-0001",
                    "product_ids": ["CSAFPID-0001", "CSAFPID-0002"],
                }
            ],
        },
        "vulnerabilities": [
            {
                "cve": "CVE-2026-12345",
                "title": "Example vulnerability",
                "notes": [
                    {
                        "category": "description",
                        "text": "Example description (component: Security Framework "
                        "(jackson-databind)). CVSS 3.1 Base Score 9.8. "
                        "CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).",
                    }
                ],
                "product_status": {
                    "known_affected": ["CSAFPID-0001"],
                    "known_not_affected": ["CSAFPID-0002"],
                },
                "scores": [
                    {
                        "products": ["CSAFPID-0001"],
                        "cvss_v3": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    }
                ],
                "flags": [
                    {
                        "label": "component_not_present",
                        "product_ids": ["CSAFPID-0002"],
                    }
                ],
                "remediations": [
                    {
                        "category": "vendor_fix",
                        "details": "Apply patch from MOS Note 123456.1",
                        "url": "https://support.oracle.example/patch",
                        "group_ids": ["CSAFGID-0001"],
                    }
                ],
            }
        ],
    }


class Phase0Tests(unittest.TestCase):
    def _write_fixture(self, directory: Path) -> Path:
        path = directory / "advisory.json"
        path.write_text(json.dumps(sample_csaf()), encoding="utf-8")
        return path

    def test_load_json_bytes_accepts_windows_1252_source_with_warning(self):
        document = sample_csaf()
        document["document"]["acknowledgments"] = [
            {"names": ["Joakim B\u00fclow"]}
        ]
        raw = json.dumps(document, ensure_ascii=False).encode("cp1252")
        messages = []

        loaded = csaf_phase0._load_json_bytes(
            raw,
            "oracle-csaf.json",
            lambda level, message: messages.append((level, message)),
        )

        self.assertEqual(
            loaded["document"]["acknowledgments"][0]["names"],
            ["Joakim B\u00fclow"],
        )
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][0], "WARN")
        self.assertIn("Windows-1252", messages[0][1])
        self.assertIn("offset", messages[0][1])

    def test_load_json_bytes_does_not_warn_for_utf8_source(self):
        messages = []
        raw = json.dumps(sample_csaf(), ensure_ascii=False).encode("utf-8")

        loaded = csaf_phase0._load_json_bytes(
            raw,
            "oracle-csaf.json",
            lambda level, message: messages.append((level, message)),
        )

        self.assertEqual(loaded["document"]["title"], "Oracle Test Advisory")
        self.assertEqual(messages, [])

    def test_business_priority_policy_includes_high_epss(self):
        tier, reason = csaf_phase0._decision_tier(
            {
                "kev": False,
                "public_exploits": 0,
                "epss": 0.124,
                "epss_percentile": 0.95,
                "pre_auth": False,
                "cvss_score": 7.5,
                "scope_changed": False,
            }
        )
        self.assertEqual(tier, 4)
        self.assertEqual(
            csaf_phase0._business_priority(tier),
            ("P2", "Elevated Exploitation Signals"),
        )
        self.assertEqual(
            reason,
            "High EPSS: 12.4% probability, 95th percentile",
        )

        below_threshold_tier, _reason = csaf_phase0._decision_tier(
            {
                "kev": False,
                "public_exploits": 0,
                "epss": 0.08,
                "epss_percentile": 0.949,
                "pre_auth": False,
                "cvss_score": 7.5,
                "scope_changed": True,
            }
        )
        self.assertEqual(below_threshold_tier, 8)
        self.assertEqual(
            csaf_phase0._business_priority(below_threshold_tier),
            ("P3", "Elevated Technical Exposure"),
        )

    def test_offline_bundle_and_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            output = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                now=datetime(2026, 8, 12, 6, 15, tzinfo=timezone.utc),
            )

            self.assertEqual(output.name, "20260812T061500Z_CPUJul2026csaf")
            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "advisory.json",
                    "findings.csv",
                    "enrichment.csv",
                    "report-data.json",
                    "report-advisory.html",
                    "manifest.json",
                },
            )

            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["batch_id"], output.name)
            self.assertEqual(manifest["format_version"], 3)
            self.assertEqual(manifest["source_filename"], "advisory.json")
            self.assertEqual(manifest["files"]["source_csaf"], "advisory.json")
            self.assertEqual(
                manifest["files"]["report_html"], "report-advisory.html"
            )
            self.assertEqual(
                manifest["file_hashes"]["source_csaf"],
                manifest["csaf_source_hash"],
            )
            self.assertEqual((output / "advisory.json").read_bytes(), source.read_bytes())
            self.assertEqual(manifest["findings_count"], 2)
            self.assertEqual(manifest["enrichment_count"], 1)
            self.assertEqual(manifest["report_cve_count"], 1)
            self.assertEqual(manifest["report_affected_cve_count"], 1)
            self.assertEqual(manifest["report_product_count"], 1)
            self.assertEqual(manifest["report_affected_product_count"], 1)
            self.assertEqual(manifest["report_product_version_count"], 2)
            self.assertEqual(manifest["report_affected_product_version_count"], 1)
            self.assertIn("report_data", manifest["file_hashes"])
            self.assertIn("report_html", manifest["file_hashes"])
            self.assertEqual(
                manifest["source_statuses"]["epss"]["status"], "unavailable"
            )

            with (output / "findings.csv").open(newline="", encoding="utf-8") as f:
                findings = list(csv.DictReader(f))
            affected = next(row for row in findings if row["status"] == "known_affected")
            self.assertEqual(affected["batch_id"], output.name)
            self.assertEqual(affected["product_family"], "Oracle Database")
            self.assertEqual(affected["advisory_title"], "Oracle Test Advisory")
            self.assertEqual(
                affected["advisory_url"],
                "https://www.oracle.example/security/test.html",
            )
            self.assertEqual(
                affected["component_name"],
                "Security Framework (jackson-databind)",
            )
            self.assertEqual(affected["third_party_component"], "jackson-databind")
            self.assertEqual(affected["product_version"], "19c")
            self.assertEqual(affected["cvss_score"], "9.8")
            self.assertEqual(affected["cvss_source"], "csaf_scores")
            self.assertEqual(affected["pre_auth"], "1")
            self.assertEqual(affected["high_impact"], "1")
            self.assertEqual(affected["fix_note"], "123456.1")

            with (output / "enrichment.csv").open(
                newline="", encoding="utf-8"
            ) as f:
                enrichment = list(csv.DictReader(f))
            self.assertEqual(len(enrichment), 1)
            self.assertEqual(enrichment[0]["observed_date"], "2026-08-12")
            self.assertEqual(enrichment[0]["epss_status"], "unavailable")

            report_data = json.loads((output / "report-data.json").read_text())
            self.assertEqual(report_data["schema_version"], 8)
            self.assertEqual(report_data["prioritization_version"], 2)
            self.assertEqual(report_data["advisory"]["title"], "Oracle Test Advisory")
            self.assertEqual(report_data["kpis"]["affected_cves"], 1)
            self.assertEqual(report_data["kpis"]["affected_findings"], 1)
            self.assertEqual(report_data["kpis"]["pre_auth_cves"], 1)
            self.assertEqual(report_data["kpis"]["vex_findings"], 1)
            self.assertEqual(report_data["kpis"]["vex_cves"], 1)
            self.assertEqual(report_data["kpis"]["complete_vex_cves"], 0)
            self.assertEqual(report_data["kpis"]["affected_products"], 1)
            self.assertEqual(report_data["kpis"]["complete_vex_products"], 0)
            self.assertEqual(report_data["kpis"]["affected_product_versions"], 1)
            self.assertEqual(
                report_data["kpis"]["complete_vex_product_versions"], 1
            )
            self.assertIsNone(report_data["kpis"]["priority_1_cves"])
            self.assertIsNone(report_data["kpis"]["kev_cves"])
            self.assertIsNone(report_data["kpis"]["public_exploit_cves"])
            self.assertIsNone(report_data["cves"][0]["epss"])
            self.assertEqual(report_data["cves"][0]["vex_state"], "partial")
            self.assertEqual(report_data["cves"][0]["affected_product_count"], 1)
            self.assertEqual(report_data["cves"][0]["vex_product_count"], 1)
            self.assertEqual(len(report_data["cves"][0]["remediations"]), 1)
            self.assertEqual(
                report_data["cves"][0]["remediations"][0]["url"],
                "https://support.oracle.example/patch",
            )
            self.assertEqual(
                report_data["cves"][0]["remediations"][0]["product_count"], 1
            )
            self.assertEqual(len(report_data["products"]), 1)
            product = report_data["products"][0]
            self.assertEqual(product["state"], "active")
            self.assertEqual(product["version_count"], 2)
            self.assertEqual(product["affected_version_count"], 1)
            self.assertEqual(product["complete_vex_version_count"], 1)
            self.assertEqual(product["affected_cve_count"], 1)
            self.assertEqual(product["tier"], 6)
            self.assertEqual(product["priority_code"], "P3")
            self.assertEqual(
                product["priority_label"], "Elevated Technical Exposure"
            )
            self.assertEqual(product["pre_auth_cve_count"], 1)
            self.assertEqual(product["vex_cve_count"], 1)
            self.assertEqual(product["vex_only_cve_count"], 0)
            self.assertEqual(product["vex_only_cves"], [])
            self.assertEqual(product["mixed_status_cve_count"], 1)
            self.assertEqual(product["mixed_status_cves"], ["CVE-2026-12345"])
            self.assertEqual(len(product["versions"]), 2)
            active_version = next(
                row for row in product["versions"] if row["state"] == "active"
            )
            closed_version = next(
                row
                for row in product["versions"]
                if row["state"] == "complete_vex"
            )
            self.assertEqual(active_version["affected_cve_count"], 1)
            self.assertEqual(active_version["mixed_status_cves"], [])
            self.assertEqual(closed_version["affected_cve_count"], 0)
            self.assertEqual(closed_version["vex_cve_count"], 1)
            self.assertEqual(closed_version["vex_only_cve_count"], 1)
            self.assertEqual(closed_version["mixed_status_cves"], [])
            report_html = (output / "report-advisory.html").read_text()
            self.assertIn("Oracle Test Advisory", report_html)
            self.assertIn('id="report-data"', report_html)
            self.assertIn("report-data.json", report_html)
            self.assertIn("fill secondary", report_html)
            self.assertIn(
                'bars(d.aggregates.product_families,"affected_findings",'
                '"pre_auth_findings",null,true)',
                report_html,
            )
            self.assertIn("familyPriorityCodes", report_html)
            self.assertIn("familyPriorityBadges", report_html)
            self.assertIn('class="bar-label-priorities"', report_html)
            self.assertIn("bar-with-priorities", report_html)
            self.assertIn('class="bar-priority-cell"', report_html)
            self.assertIn("affected findings", report_html)
            self.assertIn("including pre-auth", report_html)
            self.assertIn("Partial VEX", report_html)
            self.assertIn("unaffected", report_html)
            self.assertIn("affected", report_html)
            self.assertIn("data-vex-complete", report_html)
            self.assertIn("Fixes", report_html)
            self.assertIn("Oracle Support", report_html)
            self.assertIn("Decision queue — product view", report_html)
            self.assertIn("data-product-filter", report_html)
            self.assertIn("data-product-priority-group", report_html)
            self.assertIn('class="product-priority-group"', report_html)
            self.assertNotIn(
                'data-priority="${esc(priority)}" open', report_html
            )
            self.assertIn("data-priority-policy-open", report_html)
            self.assertIn('id="priority-policy"', report_html)
            self.assertIn("The first matching condition", report_html)
            self.assertIn("EPSS is a prediction signal", report_html)
            self.assertIn("data-product-family-group", report_html)
            self.assertIn('class="product-family-group"', report_html)
            self.assertIn("productHierarchy", report_html)
            self.assertIn("Affected CVE list", report_html)
            self.assertIn("Not affected (VEX)", report_html)
            self.assertIn("Mixed status", report_html)
            self.assertIn("Version / component", report_html)
            self.assertIn("CSAF product entries", report_html)
            self.assertIn("Include products fully closed by VEX", report_html)
            self.assertIn("Affected / CSAF entries", report_html)
            self.assertIn('id="product-detail"', report_html)
            self.assertIn("data-product-index", report_html)
            self.assertIn("Show related CVEs", report_html)
            self.assertIn("signalBadge", report_html)
            self.assertIn('data-section="${esc(title)}"', report_html)
            self.assertIn("root.insertBefore(productSection,cveSection)", report_html)
            self.assertIn("root.insertBefore(familySection,productSection)", report_html)

    def test_complete_vex_cve_is_available_to_the_decision_queue_filter(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = sample_csaf()
            document["vulnerabilities"].append(
                {
                    "cve": "CVE-2026-54321",
                    "notes": [
                        {
                            "category": "description",
                            "text": "Closed example (component: Core).",
                        }
                    ],
                    "product_status": {
                        "known_not_affected": ["CSAFPID-0002"]
                    },
                    "flags": [
                        {
                            "label": "component_not_present",
                            "product_ids": ["CSAFPID-0002"],
                        }
                    ],
                }
            )
            source = root / "advisory.json"
            source.write_text(json.dumps(document), encoding="utf-8")
            output = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                now=datetime(2026, 8, 12, 6, 17, tzinfo=timezone.utc),
            )
            report_data = json.loads((output / "report-data.json").read_text())
            closed = next(
                row for row in report_data["cves"] if row["cve"] == "CVE-2026-54321"
            )
            self.assertEqual(closed["vex_state"], "complete")
            self.assertEqual(closed["affected_product_count"], 0)
            self.assertEqual(closed["vex_product_count"], 1)
            self.assertEqual(closed["remediations"], [])
            self.assertIsNone(closed["tier"])
            self.assertIsNone(closed["priority_code"])
            self.assertIsNone(closed["priority_label"])
            self.assertEqual(report_data["kpis"]["affected_cves"], 1)
            self.assertEqual(report_data["kpis"]["complete_vex_cves"], 1)

    def test_html_report_can_be_disabled_but_json_is_kept(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            output = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                html_report=False,
                now=datetime(2026, 8, 12, 6, 16, tzinfo=timezone.utc),
            )
            self.assertTrue((output / "report-data.json").is_file())
            self.assertTrue((output / "advisory.json").is_file())
            self.assertFalse(any(output.glob("report-*.html")))
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertNotIn("report_html", manifest["files"])

    def test_url_filename_is_preserved_in_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw = json.dumps(sample_csaf()).encode("utf-8")
            source_url = (
                "https://www.oracle.com/docs/tech/security-alerts/"
                "cpujul2026csaf.json"
            )
            with mock.patch.object(
                csaf_phase0,
                "_read_source",
                return_value=(raw, "cpujul2026csaf.json", source_url),
            ):
                output = csaf_phase0.generate_phase0(
                    source_url,
                    root / "output",
                    offline=True,
                    now=datetime(2026, 8, 12, 6, 18, tzinfo=timezone.utc),
                )

            self.assertEqual(
                (output / "cpujul2026csaf.json").read_bytes(), raw
            )
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(
                manifest["files"]["source_csaf"], "cpujul2026csaf.json"
            )
            self.assertEqual(manifest["source_filename"], "cpujul2026csaf.json")
            self.assertEqual(
                manifest["files"]["report_html"], "report-cpujul2026.html"
            )
            self.assertTrue((output / "report-cpujul2026.html").is_file())
            self.assertEqual(
                manifest["file_hashes"]["source_csaf"],
                manifest["csaf_source_hash"],
            )

    def test_source_filename_is_derived_safely_from_url(self):
        self.assertEqual(
            csaf_phase0._source_filename_from_url(
                "https://www.oracle.com/docs/tech/security-alerts/"
                "cpujul2026csaf.json?download=1"
            ),
            "cpujul2026csaf.json",
        )

        self.assertEqual(
            csaf_phase0._report_filename("cspuaug2026csaf.json"),
            "report-cspuaug2026.html",
        )
        self.assertEqual(
            csaf_phase0._report_filename("advisory.json"),
            "report-advisory.html",
        )
        with self.assertRaises(csaf_phase0.Phase0Error):
            csaf_phase0._source_filename_from_url(
                "https://example.test/security-alerts/"
            )
        with self.assertRaises(csaf_phase0.Phase0Error):
            csaf_phase0._source_filename_from_url(
                "https://example.test/security-alerts/manifest.json"
            )

    def test_cli_requires_https_source_url(self):
        source_url = "https://example.test/security-alerts/advisory.json"
        self.assertEqual(csaf_phase0._https_url(source_url), source_url)
        with self.assertRaises(csaf_phase0.argparse.ArgumentTypeError):
            csaf_phase0._https_url("/tmp/advisory.json")
        with self.assertRaises(csaf_phase0.argparse.ArgumentTypeError):
            csaf_phase0._https_url("http://example.test/advisory.json")

    def test_description_cvss_fallback_is_explicit_and_not_applied_to_vex(self):
        document = sample_csaf()
        document["vulnerabilities"][0]["scores"] = []
        rows = csaf_phase0.extract_findings(
            document, "batch", "abc123", "advisory.json", ""
        )
        affected = next(row for row in rows if row["status"] == "known_affected")
        not_affected = next(
            row for row in rows if row["status"] == "known_not_affected"
        )
        self.assertEqual(affected["cvss_score"], "9.8")
        self.assertEqual(
            affected["cvss_vector"],
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        self.assertEqual(affected["cvss_source"], "description_fallback")
        self.assertEqual(affected["pre_auth"], 1)
        self.assertEqual(not_affected["cvss_score"], "")
        self.assertEqual(not_affected["cvss_source"], "")

    def test_existing_execution_directory_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            fixed_now = datetime(2026, 8, 12, 6, 15, tzinfo=timezone.utc)
            csaf_phase0.generate_phase0(
                str(source), root / "output", offline=True, now=fixed_now
            )
            with self.assertRaises(csaf_phase0.Phase0Error):
                csaf_phase0.generate_phase0(
                    str(source), root / "output", offline=True, now=fixed_now
                )

    def test_later_run_keeps_source_hash_and_changes_observation_date(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            first = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                now=datetime(2026, 8, 12, 6, 15, tzinfo=timezone.utc),
            )
            second = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                now=datetime(2026, 8, 19, 6, 15, tzinfo=timezone.utc),
            )
            first_manifest = json.loads((first / "manifest.json").read_text())
            second_manifest = json.loads((second / "manifest.json").read_text())
            self.assertEqual(
                first_manifest["csaf_source_hash"],
                second_manifest["csaf_source_hash"],
            )
            self.assertNotEqual(first_manifest["batch_id"], second_manifest["batch_id"])
            self.assertEqual(second_manifest["observation_date"], "2026-08-19")

    def test_local_enrichment_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            epss_file = root / "epss.json"
            epss_file.write_text(
                json.dumps(
                    {
                        "data": [
                            {
                                "cve": "CVE-2026-12345",
                                "epss": "0.120000000",
                                "percentile": "0.950000000",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            kev_file = root / "kev.json"
            kev_file.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "cveID": "CVE-2026-12345",
                                "dateAdded": "2026-08-10",
                                "dueDate": "2026-08-31",
                                "knownRansomwareCampaignUse": "Unknown",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            nvd_file = root / "nvd.json"
            nvd_file.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-2026-12345",
                                    "references": [
                                        {
                                            "url": "https://example.org/exploit/12345",
                                            "tags": ["Exploit", "Third Party Advisory"],
                                        },
                                        {
                                            "url": "https://example.org/advisory/12345",
                                            "tags": ["Vendor Advisory"],
                                        },
                                    ],
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            output = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                epss_file=epss_file,
                kev_file=kev_file,
                nvd_file=nvd_file,
                now=datetime(2026, 8, 12, 6, 15, tzinfo=timezone.utc),
            )
            with (output / "enrichment.csv").open(
                newline="", encoding="utf-8"
            ) as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["epss"], "0.120000000")
            self.assertEqual(row["kev"], "1")
            self.assertEqual(row["epss_status"], "success")
            self.assertEqual(row["kev_status"], "success")
            self.assertEqual(row["public_exploits"], "1")
            self.assertEqual(row["exploit_url"], "https://example.org/exploit/12345")
            self.assertEqual(row["exploit_status"], "success")
            report_data = json.loads((output / "report-data.json").read_text())
            self.assertEqual(report_data["kpis"]["priority_1_cves"], 1)
            self.assertEqual(report_data["kpis"]["kev_cves"], 1)
            self.assertEqual(report_data["kpis"]["public_exploit_cves"], 1)

    def test_nvd_key_is_sent_only_as_a_header(self):
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-12345",
                        "references": [
                            {"url": "https://example.org/poc", "tags": ["Exploit"]}
                        ],
                    }
                }
            ]
        }
        with mock.patch.object(csaf_phase0, "_http_json", return_value=payload) as get:
            values, status, _message = csaf_phase0._nvd_exploit_values(
                ["CVE-2026-12345"], 15, 0, None, "top-secret", None
            )
        self.assertEqual(status, "success")
        self.assertEqual(values["CVE-2026-12345"], ["https://example.org/poc"])
        request_url = get.call_args.args[0]
        self.assertNotIn("top-secret", request_url)
        self.assertEqual(get.call_args.kwargs["extra_headers"], {"apiKey": "top-secret"})

    def test_progress_reports_key_execution_steps(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            messages = []
            csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                now=datetime(2026, 8, 12, 6, 15, tzinfo=timezone.utc),
                progress=lambda level, message: messages.append((level, message)),
            )
            rendered = "\n".join(f"{level} {message}" for level, message in messages)
            self.assertIn("Starting CSAF Phase 0 execution", rendered)
            self.assertIn("Advisory: CPUJul2026csaf revision 1.0.0", rendered)
            self.assertIn("Extracted 2 findings across 1 CVEs and 2 products", rendered)
            self.assertIn("epss: unavailable", rendered)
            self.assertIn("Writing report-data.json", rendered)
            self.assertIn("Preserving source CSAF as advisory.json", rendered)
            self.assertIn(
                "Rendering report-advisory.html from report-data.json", rendered
            )
            self.assertIn("Writing manifest.json", rendered)
            self.assertIn("Completed successfully", rendered)

    def test_local_gzip_epss_bulk_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            epss_file = root / "epss_scores-current.csv.gz"
            epss_file.write_bytes(
                gzip.compress(
                    b"#model_version:v-test,score_date:2026-08-12\n"
                    b"cve,epss,percentile\n"
                    b"CVE-2026-12345,0.420000000,0.990000000\n"
                    b"CVE-2026-99999,0.010000000,0.100000000\n"
                )
            )
            output = csaf_phase0.generate_phase0(
                str(source),
                root / "output",
                offline=True,
                epss_file=epss_file,
                now=datetime(2026, 8, 12, 6, 15, tzinfo=timezone.utc),
            )
            with (output / "enrichment.csv").open(
                newline="", encoding="utf-8"
            ) as f:
                row = next(csv.DictReader(f))
            self.assertEqual(row["epss"], "0.420000000")
            self.assertEqual(row["epss_percentile"], "0.990000000")
            self.assertEqual(row["epss_status"], "success")

    def test_invalid_network_settings_fail_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self._write_fixture(root)
            with self.assertRaises(csaf_phase0.Phase0Error):
                csaf_phase0.generate_phase0(
                    str(source), root / "output", offline=True, timeout=0
                )
            with self.assertRaises(csaf_phase0.Phase0Error):
                csaf_phase0.generate_phase0(
                    str(source), root / "output", offline=True, retries=-1
                )

    @unittest.skipUnless(
        "fork" in csaf_phase0.multiprocessing.get_all_start_methods(),
        "isolated deadline test requires fork",
    )
    def test_network_deadline_terminates_a_stalled_download(self):
        def stalled_worker(_connection, _url, _headers, _timeout):
            time.sleep(1)

        started = time.monotonic()
        with mock.patch.object(csaf_phase0, "_urlopen_worker", stalled_worker):
            with self.assertRaises(csaf_phase0.Phase0Error) as raised:
                csaf_phase0._http_bytes(
                    "https://example.invalid/slow",
                    timeout=0.1,
                    retries=0,
                    label="slow test source",
                )
            self.assertLess(time.monotonic() - started, 0.8)
            self.assertIn("hard timeout", str(raised.exception))



if __name__ == "__main__":
    unittest.main()
