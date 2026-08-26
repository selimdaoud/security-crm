"""Generate a standalone report of recently added Oracle-related CISA KEVs."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import statistics
import sys
import time
import urllib.parse
import uuid
from datetime import date, datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Mapping

from .phase0 import Phase0Error, ProgressCallback, _emit, _http_bytes, _http_json


ORACLE_CVE_MAP_URL = (
    "https://www.oracle.com/security-alerts/public-vuln-to-advisory-mapping.html"
)
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BATCH_SIZE = 100
REPORT_SCHEMA_VERSION = 1
USER_AGENT = "oracle-kev-report/1.0"
HTML_REPORT_FILENAME = "report-oracle-kev.html"
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_PRODUCT_ID_PATTERN = re.compile(r"\s*\[(\d+)]\s*$")


class _OracleMapParser(HTMLParser):
    """Capture HTML tables while retaining links inside individual cells."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[dict[str, Any]]]] = []
        self.page_text: list[str] = []
        self._table_depth = 0
        self._rows: list[list[dict[str, Any]]] | None = None
        self._row: list[dict[str, Any]] | None = None
        self._cell: dict[str, Any] | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if tag == "table":
            if self._table_depth == 0:
                self._rows = []
            self._table_depth += 1
        elif tag == "tr" and self._table_depth == 1:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = {"text": [], "links": []}
        elif tag == "a" and self._cell is not None and attributes.get("href"):
            self._cell["links"].append(attributes["href"])

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self._cell is not None:
            assert self._row is not None
            self._cell["text"] = " ".join(
                " ".join(self._cell["text"]).split()
            )
            self._row.append(self._cell)
            self._cell = None
        elif tag == "tr" and self._row is not None:
            assert self._rows is not None
            if self._row:
                self._rows.append(self._row)
            self._row = None
        elif tag == "table" and self._table_depth:
            self._table_depth -= 1
            if self._table_depth == 0 and self._rows is not None:
                self.tables.append(self._rows)
                self._rows = None

    def handle_data(self, data: str) -> None:
        self.page_text.append(data)
        if self._cell is not None and data.strip():
            self._cell["text"].append(data)


def _decode_source(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as utf8_error:
        try:
            return raw.decode("cp1252")
        except UnicodeDecodeError:
            raise Phase0Error(f"Unable to decode {label}: {utf8_error}") from utf8_error


def parse_oracle_cve_map(raw: bytes) -> tuple[dict[str, list[dict[str, str]]], str]:
    """Parse Oracle's CVE/product/advisory table into a CVE-indexed mapping."""
    parser = _OracleMapParser()
    parser.feed(_decode_source(raw, "Oracle CVE mapping"))
    target: list[list[dict[str, Any]]] | None = None
    for table in parser.tables:
        if not table:
            continue
        header = [str(cell["text"]).casefold() for cell in table[0]]
        if header[:3] == [
            "vulnerability identifier",
            "product [product id]",
            "advisory",
        ]:
            target = table
            break
    if target is None:
        raise Phase0Error("Oracle CVE mapping table was not found")

    result: dict[str, list[dict[str, str]]] = {}
    current_cve = ""
    for cells in target[1:]:
        if len(cells) >= 3 and _CVE_PATTERN.fullmatch(str(cells[0]["text"])):
            current_cve = str(cells[0]["text"]).upper()
            product_cell, advisory_cell = cells[1], cells[2]
        elif len(cells) >= 2 and current_cve:
            product_cell, advisory_cell = cells[0], cells[1]
        else:
            continue
        product = str(product_cell["text"])
        match = _PRODUCT_ID_PATTERN.search(product)
        product_id = match.group(1) if match else ""
        product_name = product[: match.start()].strip() if match else product
        links = advisory_cell.get("links") or []
        advisory_url = urllib.parse.urljoin(
            ORACLE_CVE_MAP_URL, str(links[0]) if links else ""
        )
        mapping = {
            "product": product_name,
            "product_id": product_id,
            "advisory": str(advisory_cell["text"]),
            "advisory_url": advisory_url,
        }
        if mapping not in result.setdefault(current_cve, []):
            result[current_cve].append(mapping)

    if not result:
        raise Phase0Error("Oracle CVE mapping table contained no CVE records")
    page_text = " ".join(" ".join(parser.page_text).split())
    update_match = re.search(
        r"updated to include the (.+?)(?:\.\s| maps CVEs)",
        page_text,
        re.IGNORECASE,
    )
    source_note = update_match.group(1).strip(" .,;") if update_match else ""
    return result, source_note


def parse_kev_catalog(raw: bytes) -> dict[str, Any]:
    """Validate the minimal CISA KEV fields required by this report."""
    try:
        payload = json.loads(_decode_source(raw, "CISA KEV catalog"))
    except json.JSONDecodeError as exc:
        raise Phase0Error(f"Invalid CISA KEV JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(
        payload.get("vulnerabilities"), list
    ):
        raise Phase0Error("CISA KEV catalog has an unexpected structure")
    return payload


def _parse_nvd_publication_dates(
    payloads: list[Any], requested_cves: set[str]
) -> dict[str, str]:
    values: dict[str, str] = {}
    for payload in payloads:
        if not isinstance(payload, dict) or not isinstance(
            payload.get("vulnerabilities"), list
        ):
            raise Phase0Error("NVD CVE response has an unexpected structure")
        for wrapper in payload["vulnerabilities"]:
            if not isinstance(wrapper, dict) or not isinstance(wrapper.get("cve"), dict):
                continue
            cve_item = wrapper["cve"]
            cve = str(cve_item.get("id") or "").upper()
            published = str(cve_item.get("published") or "")
            if cve not in requested_cves or not published:
                continue
            try:
                published_date = date.fromisoformat(published[:10])
            except ValueError:
                continue
            values[cve] = published_date.isoformat()
    return values


def _nvd_publication_dates(
    cves: list[str],
    *,
    timeout: float,
    retries: int,
    local_file: Path | None,
    api_key: str | None,
    progress: ProgressCallback | None,
) -> tuple[dict[str, str], str, str]:
    """Return NVD publication dates without making them a report prerequisite."""
    if not cves:
        return {}, "success", "no matched CVEs required NVD enrichment"
    try:
        payloads: list[Any] = []
        if local_file is not None:
            if not local_file.is_file():
                raise Phase0Error(f"NVD file does not exist: {local_file}")
            try:
                payloads.append(
                    json.loads(_decode_source(local_file.read_bytes(), "NVD file"))
                )
            except json.JSONDecodeError as exc:
                raise Phase0Error(f"Invalid NVD JSON: {exc}") from exc
            source_name = "local NVD file"
        else:
            batches = [
                cves[index : index + NVD_BATCH_SIZE]
                for index in range(0, len(cves), NVD_BATCH_SIZE)
            ]
            headers = {"apiKey": api_key} if api_key else None
            for batch_number, batch in enumerate(batches, start=1):
                query = urllib.parse.urlencode({"cveIds": ",".join(batch)})
                payloads.append(
                    _http_json(
                        f"{NVD_CVE_API_URL}?{query}",
                        timeout,
                        retries,
                        progress,
                        f"NVD publication dates {batch_number}/{len(batches)}",
                        extra_headers=headers,
                    )
                )
                if batch_number < len(batches):
                    time.sleep(0.7 if api_key else 6)
            source_name = f"NVD CVE API ({len(batches)} batch(es))"
        values = _parse_nvd_publication_dates(payloads, set(cves))
        return (
            values,
            "success",
            f"loaded publication dates for {len(values)}/{len(cves)} CVEs from "
            f"{source_name}",
        )
    except Exception as exc:
        return {}, "error", str(exc)


def add_publication_lag(
    rows: list[dict[str, Any]], publication_dates: Mapping[str, str]
) -> None:
    """Add publication dates and publication-to-KEV elapsed days in place."""
    for row in rows:
        published_text = str(publication_dates.get(str(row["cve"])) or "")
        row["cve_published"] = published_text
        row["publication_to_kev_days"] = None
        if not published_text:
            continue
        try:
            published = date.fromisoformat(published_text)
            kev_added = date.fromisoformat(str(row["date_added"]))
        except ValueError:
            continue
        row["publication_to_kev_days"] = (kev_added - published).days


def correlate_oracle_kevs(
    mappings: Mapping[str, list[dict[str, str]]],
    catalog: Mapping[str, Any],
    *,
    as_of: date,
    days: int = 365,
) -> list[dict[str, Any]]:
    """Return Oracle-mapped KEVs added within the requested rolling window."""
    if days <= 0:
        raise Phase0Error("Report window must be greater than zero days")
    cutoff = as_of - timedelta(days=days)
    rows: list[dict[str, Any]] = []
    for item in catalog.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").upper()
        if cve not in mappings:
            continue
        try:
            added = date.fromisoformat(str(item.get("dateAdded") or ""))
        except ValueError:
            continue
        if not cutoff <= added <= as_of:
            continue
        oracle_mappings = mappings[cve]
        rows.append(
            {
                "cve": cve,
                "date_added": added.isoformat(),
                "days_since_added": (as_of - added).days,
                "vendor_project": str(item.get("vendorProject") or ""),
                "kev_product": str(item.get("product") or ""),
                "vulnerability_name": str(item.get("vulnerabilityName") or ""),
                "description": str(item.get("shortDescription") or ""),
                "ransomware": str(
                    item.get("knownRansomwareCampaignUse") or "Unknown"
                ),
                "notes": str(item.get("notes") or ""),
                "cwes": [str(value) for value in item.get("cwes") or []],
                "oracle_mappings": oracle_mappings,
                "oracle_products": sorted(
                    {mapping["product"] for mapping in oracle_mappings}
                ),
                "oracle_advisories": sorted(
                    {
                        (mapping["advisory"], mapping["advisory_url"])
                        for mapping in oracle_mappings
                    }
                ),
            }
        )
    return sorted(rows, key=lambda row: (row["date_added"], row["cve"]), reverse=True)


def build_report_data(
    rows: list[dict[str, Any]],
    catalog: Mapping[str, Any],
    *,
    as_of: date,
    days: int,
    generated_at: datetime,
    mapping_count: int,
    mapping_source_note: str,
    nvd_status: str,
    nvd_detail: str,
) -> dict[str, Any]:
    products = sorted(
        {product for row in rows for product in row["oracle_products"]}
    )
    publication_lags = [
        row["publication_to_kev_days"]
        for row in rows
        if row.get("publication_to_kev_days") is not None
    ]
    median_lag = statistics.median(publication_lags) if publication_lags else None
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "title": "Oracle Known Exploited Vulnerabilities",
        "generated_at": generated_at.isoformat().replace("+00:00", "Z"),
        "as_of": as_of.isoformat(),
        "window_days": days,
        "window_start": (as_of - timedelta(days=days)).isoformat(),
        "sources": {
            "oracle": {
                "url": ORACLE_CVE_MAP_URL,
                "mapped_cves": mapping_count,
                "coverage_note": mapping_source_note,
            },
            "cisa_kev": {
                "url": CISA_KEV_URL,
                "catalog_version": str(catalog.get("catalogVersion") or ""),
                "date_released": str(catalog.get("dateReleased") or ""),
                "catalog_count": len(catalog.get("vulnerabilities") or []),
            },
            "nvd": {
                "url": NVD_CVE_API_URL,
                "status": nvd_status,
                "detail": nvd_detail,
                "publication_dates": len(publication_lags),
            },
        },
        "kpis": {
            "oracle_kevs": len(rows),
            "oracle_products": len(products),
            "added_last_90_days": sum(row["days_since_added"] <= 90 for row in rows),
            "ransomware_known": sum(
                row["ransomware"].casefold() == "known" for row in rows
            ),
            "median_publication_to_kev_days": median_lag,
        },
        "products": products,
        "kevs": rows,
    }


def render_report_html(report: Mapping[str, Any]) -> str:
    """Render a self-contained report in the Phase 0 dashboard visual style."""
    title = html.escape(str(report.get("title") or "Oracle KEV Report"))
    new_90d = int((report.get("kpis") or {}).get("added_last_90_days") or 0)
    embedded_json = json.dumps(
        report, ensure_ascii=False, separators=(",", ":")
    ).replace("</", "<\\/").replace("\u2028", "\\u2028").replace(
        "\u2029", "\\u2029"
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="report-data" content="oracle-kev-report-data.json">
<meta name="new90D" content="{new_90d}">
<title>{title}</title>
<style>
:root{{--brand:#c74634;--ink:#161513;--muted:#665f58;--line:#e4e1dc;--bg:#fff;--soft:#faf9f8;--blue:#0572ce;--redbg:#fbedeb;--amber:#a65f00;--amberbg:#fdf3e3;--green:#1b7a3e;--greenbg:#eaf5ee;--radius:6px}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:13px/1.5 "Oracle Sans","Helvetica Neue",Arial,sans-serif}}.cr{{max-width:1400px;margin:auto;padding:20px}}a{{color:var(--blue);text-decoration:none}}a:hover{{text-decoration:underline}}
.cr-head{{border-bottom:3px solid var(--brand);padding-bottom:12px;margin-bottom:18px}}h1{{font-size:20px;font-weight:400;margin:0}}.cr-meta{{display:flex;flex-wrap:wrap;gap:14px;margin-top:5px;color:var(--muted);font-size:11px}}.cr-meta b{{color:var(--ink)}}
.cr-note{{border-left:3px solid var(--blue);background:#e8f2fb;padding:9px 12px;margin-bottom:14px;border-radius:0 var(--radius) var(--radius) 0}}.cr-health{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}}.badge{{display:inline-block;border-radius:10px;padding:2px 8px;font-size:10.5px;background:#f5f4f2}}.ok{{color:var(--green);background:var(--greenbg)}}.warn{{color:var(--amber);background:var(--amberbg)}}
.cr-kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px}}.cr-kpi{{border:1px solid var(--line);background:var(--soft);border-radius:var(--radius);padding:11px 13px}}.cr-kpi.danger{{background:var(--redbg)}}.cr-kpi.warning{{background:var(--amberbg)}}.cr-kpi .l{{text-transform:uppercase;letter-spacing:.4px;color:var(--muted);font-size:10.5px}}.cr-kpi .v{{font-size:22px;font-weight:300}}.cr-kpi .s{{color:var(--muted);font-size:10.5px}}
details.section{{border:1px solid var(--line);border-radius:var(--radius);margin-bottom:9px;overflow:hidden}}details.section>summary{{cursor:pointer;background:var(--soft);padding:10px 14px;display:flex;gap:9px;align-items:center}}summary b{{font-weight:600}}summary small{{color:var(--muted)}}summary .count{{margin-left:auto;color:var(--muted)}}.body{{padding:14px;overflow:auto}}
.tools{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}}.tools label{{color:var(--muted);font-size:11px}}input,select{{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:4px;background:white}}table{{width:100%;border-collapse:collapse;font-size:12px}}th{{text-align:left;text-transform:uppercase;letter-spacing:.35px;font-size:10.5px;color:var(--muted);cursor:pointer;white-space:nowrap}}th,td{{padding:7px 8px;border-bottom:1px solid #f0eeea;vertical-align:top}}tbody tr:hover{{background:var(--soft)}}.num{{text-align:right;font-variant-numeric:tabular-nums}}.mono{{font-family:Menlo,Consolas,monospace;font-size:11px}}.tag{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600}}.red{{background:var(--redbg);color:#8a2e22}}.amber{{background:var(--amberbg);color:var(--amber)}}.blue{{background:#e8f2fb;color:#04559b}}.green{{background:var(--greenbg);color:var(--green)}}
.mapping{{border:0;margin:0;overflow:visible}}.mapping summary{{cursor:pointer;color:var(--blue);white-space:nowrap}}.mapping-list{{min-width:280px;padding:5px 0;display:grid;gap:5px}}.mapping-list span{{display:block;color:var(--muted);font-size:10px}}.description{{min-width:260px;max-width:420px}}.foot{{border-top:1px solid var(--line);margin-top:20px;padding-top:10px;color:var(--muted);font-size:10.5px}}
@media(max-width:700px){{.cr{{padding:10px}}}}@media print{{.tools{{display:none}}details.section{{break-inside:avoid}}}}
</style></head><body><main class="cr" id="REPORT_ROOT"></main>
<script type="application/json" id="report-data">{embedded_json}</script>
<script>
(()=>{{"use strict";
const d=JSON.parse(document.getElementById("report-data").textContent),root=document.getElementById("REPORT_ROOT");
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
const n=v=>new Intl.NumberFormat("en-US").format(v??0),safeUrl=v=>{{try{{const u=new URL(v);return /^https?:$/.test(u.protocol)?u.href:""}}catch(_e){{return ""}}}};
const link=(url,label)=>{{const u=safeUrl(url);return u?`<a href="${{esc(u)}}" target="_blank" rel="noopener">${{esc(label)}}</a>`:esc(label)}};
const kpi=(label,value,sub,kind="")=>`<div class="cr-kpi ${{kind}}"><div class="l">${{esc(label)}}</div><div class="v">${{value==null?"n/a":n(value)}}</div><div class="s">${{esc(sub)}}</div></div>`;
const mappings=r=>`<details class="mapping"><summary>${{n(r.oracle_products.length)}} Oracle product${{r.oracle_products.length!==1?"s":""}}</summary><div class="mapping-list">${{r.oracle_mappings.map(m=>`<div><b>${{esc(m.product)}}</b>${{m.product_id?` <span class="mono">[${{esc(m.product_id)}}]</span>`:""}}<span>${{link(m.advisory_url,m.advisory)}}</span></div>`).join("")}}</div></details>`;
const status=r=>[r.days_since_added<=90?'<span class="tag red">NEW 90D</span>':'<span class="tag blue">KEV</span>',r.ransomware.toLowerCase()==="known"?'<span class="tag red">Ransomware</span>':""].filter(Boolean).join(" ");
const rows=d.kevs.map(r=>`<tr data-product="${{esc(r.oracle_products.join(" | "))}}" data-ransomware="${{r.ransomware.toLowerCase()==="known"?1:0}}" data-recent="${{r.days_since_added<=90?1:0}}"><td class="mono">${{link(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${{encodeURIComponent(r.cve)}}`,r.cve)}}</td><td data-sort="${{esc(r.date_added)}}">${{esc(r.date_added)}}<br><small>${{n(r.days_since_added)}} days ago</small></td><td data-sort="${{r.publication_to_kev_days??-1}}">${{r.publication_to_kev_days==null?"n/a":n(r.publication_to_kev_days)+" days"}}${{r.cve_published?`<br><small>Published ${{esc(r.cve_published)}}</small>`:""}}</td><td><b>${{esc(r.vulnerability_name)}}</b><div class="description">${{esc(r.description)}}</div></td><td>${{mappings(r)}}</td><td>${{r.oracle_advisories.map(a=>link(a[1],a[0])).join("<br>")}}</td><td>${{status(r)}}</td></tr>`).join("");
const productOptions=d.products.map(p=>`<option value="${{esc(p)}}">${{esc(p)}}</option>`).join("");
root.innerHTML=`<header class="cr-head"><h1>${{esc(d.title)}}</h1><div class="cr-meta"><span><b>As of</b> ${{esc(d.as_of)}}</span><span><b>Window</b> ${{esc(d.window_start)}} to ${{esc(d.as_of)}}</span><span><b>Generated</b> ${{esc(d.generated_at)}}</span></div></header><div class="cr-note"><b>Interpretation.</b> CISA KEV confirms that exploitation has occurred in the wild; it does not assert that exploitation is continuing today. <b>Publication → KEV lag</b> measures elapsed time from NVD publication to CISA catalog addition, not time to first exploitation. Oracle product relevance comes from Oracle's CVE-to-advisory mapping. Verify affected versions in the linked advisory.</div><div class="cr-health"><span class="badge ok">CISA KEV ${{esc(d.sources.cisa_kev.catalog_version)}}</span><span class="badge ok">${{n(d.sources.oracle.mapped_cves)}} Oracle-mapped CVEs</span><span class="badge ${{d.sources.nvd.status==="success"?"ok":"warn"}}">NVD publication dates: ${{esc(d.sources.nvd.status)}} (${{n(d.sources.nvd.publication_dates)}}/${{n(d.kevs.length)}})</span>${{d.sources.oracle.coverage_note?`<span class="badge">Oracle coverage: ${{esc(d.sources.oracle.coverage_note)}}</span>`:""}}</div><div class="cr-kpis">${{kpi("Oracle KEVs",d.kpis.oracle_kevs,"added in the report window","danger")}}${{kpi("Added in 90 days",d.kpis.added_last_90_days,"newest exploitation evidence","danger")}}${{kpi("Median publish → KEV",d.kpis.median_publication_to_kev_days,"days from NVD publication","warning")}}${{kpi("Oracle products",d.kpis.oracle_products,"distinct mapped products")}}${{kpi("Ransomware known",d.kpis.ransomware_known,"CISA campaign flag","warning")}}</div><details class="section" open><summary><b>Oracle KEV decision list</b><small>newest CISA additions first</small><span class="count">${{n(d.kevs.length)}}</span></summary><div class="body" data-filter><div class="tools"><input type="search" placeholder="Search CVE, product, advisory…"><select data-product><option value="">All Oracle products</option>${{productOptions}}</select><label><input type="checkbox" data-recent checked> Added in last 90 days</label><label><input type="checkbox" data-ransomware> Known ransomware use</label><span data-count></span></div><table><thead><tr><th>CVE</th><th data-asc="0" title="Default order: newest to oldest">KEV added ↓</th><th title="Elapsed days from NVD publication to CISA KEV addition">Publish → KEV</th><th>Vulnerability</th><th>Oracle products</th><th>Oracle advisory</th><th>Signals</th></tr></thead><tbody>${{rows}}</tbody></table></div></details><footer class="foot">Sources: ${{link(d.sources.oracle.url,"Oracle CVE-to-Advisory mapping")}} · ${{link(d.sources.cisa_kev.url,"CISA Known Exploited Vulnerabilities catalog")}} · ${{link(d.sources.nvd.url,"NVD CVE API")}}. This product uses data from the NVD API but is not endorsed or certified by the NVD. This report describes vendor-published applicability, not confirmed exposure in your environment.<br>Report schema v${{esc(d.schema_version)}}</footer>`;
root.querySelectorAll("th").forEach((th,i)=>th.addEventListener("click",()=>{{const body=th.closest("table")?.tBodies[0];if(!body)return;const asc=th.dataset.asc!=="1";th.closest("table").querySelectorAll("th").forEach(x=>delete x.dataset.asc);th.dataset.asc=asc?"1":"0";[...body.rows].sort((x,y)=>{{const av=x.cells[i]?.dataset.sort??x.cells[i]?.textContent.trim()??"",bv=y.cells[i]?.dataset.sort??y.cells[i]?.textContent.trim()??"";return (asc?1:-1)*String(av).localeCompare(String(bv),undefined,{{numeric:true}})}}).forEach(row=>body.appendChild(row))}}));
const scope=root.querySelector("[data-filter]"),apply=()=>{{const q=scope.querySelector('input[type="search"]').value.toLowerCase(),product=scope.querySelector("[data-product]").value,recent=scope.querySelector("[data-recent]").checked,ransomware=scope.querySelector("[data-ransomware]").checked;let count=0;[...scope.querySelector("tbody").rows].forEach(row=>{{const show=(!q||row.textContent.toLowerCase().includes(q))&&(!product||row.dataset.product.split(" | ").includes(product))&&(!recent||row.dataset.recent==="1")&&(!ransomware||row.dataset.ransomware==="1");row.hidden=!show;if(show)count++}});scope.querySelector("[data-count]").textContent=n(count)+" rows"}};scope.querySelectorAll("input,select").forEach(control=>control.addEventListener("input",apply));apply();
}})();
</script></body></html>"""


def _read_bytes(
    path: Path | None,
    url: str,
    *,
    timeout: float,
    retries: int,
    label: str,
    accept: str,
    progress: ProgressCallback | None,
) -> bytes:
    if path is not None:
        if not path.is_file():
            raise Phase0Error(f"{label} file does not exist: {path}")
        raw = path.read_bytes()
        _emit(progress, "INFO", f"Loaded {label}: {path} ({len(raw):,} bytes)")
        return raw
    return _http_bytes(
        url,
        timeout,
        retries,
        progress,
        label,
        accept=accept,
        extra_headers={"User-Agent": USER_AGENT},
    )


def generate_oracle_kev_report(
    output_root: Path,
    *,
    publish_dir: Path | None = None,
    days: int = 365,
    as_of: date | None = None,
    oracle_map_file: Path | None = None,
    kev_file: Path | None = None,
    nvd_file: Path | None = None,
    timeout: float = 15,
    retries: int = 1,
    now: datetime | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    """Create a timestamped Oracle KEV HTML/JSON report bundle."""
    if timeout <= 0:
        raise Phase0Error("HTTP timeout must be greater than zero")
    if retries < 0:
        raise Phase0Error("Retry count cannot be negative")
    if days <= 0:
        raise Phase0Error("Report window must be greater than zero days")
    generated_at = now or datetime.now(timezone.utc)
    if generated_at.tzinfo is None:
        generated_at = generated_at.replace(tzinfo=timezone.utc)
    generated_at = generated_at.astimezone(timezone.utc)
    report_date = as_of or generated_at.date()
    _emit(progress, "INFO", "Starting Oracle KEV report generation")
    _emit(progress, "INFO", f"Report window: {days} days ending {report_date}")

    oracle_raw = _read_bytes(
        oracle_map_file,
        ORACLE_CVE_MAP_URL,
        timeout=timeout,
        retries=retries,
        label="Oracle CVE mapping",
        accept="text/html",
        progress=progress,
    )
    kev_raw = _read_bytes(
        kev_file,
        CISA_KEV_URL,
        timeout=timeout,
        retries=retries,
        label="CISA KEV catalog",
        accept="application/json",
        progress=progress,
    )
    mappings, source_note = parse_oracle_cve_map(oracle_raw)
    catalog = parse_kev_catalog(kev_raw)
    rows = correlate_oracle_kevs(mappings, catalog, as_of=report_date, days=days)
    _emit(
        progress,
        "INFO",
        f"Matched {len(rows)} recent KEVs to {len(mappings):,} Oracle CVEs",
    )
    publication_dates, nvd_status, nvd_detail = _nvd_publication_dates(
        [str(row["cve"]) for row in rows],
        timeout=timeout,
        retries=retries,
        local_file=nvd_file,
        api_key=os.environ.get("NVD_API_KEY"),
        progress=progress,
    )
    add_publication_lag(rows, publication_dates)
    _emit(progress, "INFO" if nvd_status == "success" else "WARN", nvd_detail)
    report = build_report_data(
        rows,
        catalog,
        as_of=report_date,
        days=days,
        generated_at=generated_at,
        mapping_count=len(mappings),
        mapping_source_note=source_note,
        nvd_status=nvd_status,
        nvd_detail=nvd_detail,
    )

    output_root = output_root.expanduser()
    output_root.mkdir(parents=True, exist_ok=True)
    batch_id = generated_at.strftime("%Y%m%dT%H%M%SZ_ORACLE_KEV")
    target = output_root / "oracle-kev" / batch_id
    if target.exists():
        raise Phase0Error(f"Execution directory already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".{batch_id}.tmp-{uuid.uuid4().hex}"
    temporary.mkdir()
    try:
        data_name = "oracle-kev-report-data.json"
        html_name = HTML_REPORT_FILENAME
        manifest_name = "manifest.json"
        data_text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        html_text = render_report_html(report)
        (temporary / data_name).write_text(data_text, encoding="utf-8")
        (temporary / html_name).write_text(html_text, encoding="utf-8")
        manifest = {
            "batch_id": batch_id,
            "generated_at": report["generated_at"],
            "as_of": report["as_of"],
            "window_days": days,
            "oracle_kev_count": len(rows),
            "files": {
                "report_data": data_name,
                "report_html": html_name,
                "manifest": manifest_name,
            },
            "source_urls": {
                "oracle_cve_mapping": ORACLE_CVE_MAP_URL,
                "cisa_kev": CISA_KEV_URL,
                "nvd_cve_api": NVD_CVE_API_URL,
            },
            "source_hashes": {
                "oracle_cve_mapping": hashlib.sha256(oracle_raw).hexdigest(),
                "cisa_kev": hashlib.sha256(kev_raw).hexdigest(),
            },
        }
        (temporary / manifest_name).write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.rename(target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    _emit(progress, "INFO", f"Oracle KEV report created: {target}")
    if publish_dir is not None:
        _publish_html_report(target / HTML_REPORT_FILENAME, publish_dir, progress)
    return target


def _publish_html_report(
    source: Path,
    publish_dir: Path,
    progress: ProgressCallback | None,
) -> Path:
    """Atomically publish the generated HTML under a stable filename."""
    destination_dir = publish_dir.expanduser()
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / HTML_REPORT_FILENAME
    if source.resolve() == destination.resolve():
        _emit(progress, "INFO", f"Oracle KEV HTML already published: {destination}")
        return destination

    temporary = destination_dir / f".{HTML_REPORT_FILENAME}.tmp-{uuid.uuid4().hex}"
    try:
        shutil.copyfile(source, temporary)
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    _emit(progress, "INFO", f"Oracle KEV HTML published: {destination}")
    return destination


def _console_progress(level: str, message: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{timestamp}] {level:<5} {message}", file=sys.stderr, flush=True)


def _date_argument(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must use YYYY-MM-DD") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a report of recent CISA KEVs mapped to Oracle products"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("var/output"),
        help="Parent directory for reports (default: var/output)",
    )
    parser.add_argument(
        "-d",
        "--publish-dir",
        type=Path,
        help=(
            "Copy report-oracle-kev.html to this directory, overwriting "
            "an existing copy"
        ),
    )
    parser.add_argument(
        "--days", type=int, default=365, help="Rolling window in days (default: 365)"
    )
    parser.add_argument(
        "--as-of", type=_date_argument, help="Window end date in YYYY-MM-DD"
    )
    parser.add_argument("--oracle-map-file", type=Path, help="Local Oracle mapping HTML")
    parser.add_argument("--kev-file", type=Path, help="Local CISA KEV JSON")
    parser.add_argument("--nvd-file", type=Path, help="Local NVD CVE API JSON")
    parser.add_argument("--timeout", type=float, default=15, help="HTTP timeout seconds")
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        output = generate_oracle_kev_report(
            args.output_dir,
            publish_dir=args.publish_dir,
            days=args.days,
            as_of=args.as_of,
            oracle_map_file=args.oracle_map_file,
            kev_file=args.kev_file,
            nvd_file=args.nvd_file,
            timeout=args.timeout,
            retries=args.retries,
            progress=None if args.quiet else _console_progress,
        )
    except (Phase0Error, OSError) as exc:
        if args.quiet:
            print(f"error: {exc}", file=sys.stderr)
        else:
            _console_progress("ERROR", str(exc))
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
