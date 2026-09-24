#!/usr/bin/env python3
"""Build a self-contained, browser-local case-triage desk from existing reports.

This is intentionally a small first version: it has no database or web service.
The browser stores cases in local storage and can export them as JSON. Source
snapshots remain in the generated evidence bundle beside the desk.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def text(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", value))).strip()


def map_products(path: Path, cves: set[str]) -> tuple[list[str], dict[str, list[dict]]]:
    """Read the local Oracle CVE map without adding an HTML dependency."""
    source = path.read_text(encoding="utf-8", errors="replace")
    products = sorted(set(text(value) for value in re.findall(r"</td><td>(.*?)</td><td>", source, re.DOTALL) if text(value)))
    by_cve: dict[str, list[dict]] = {}
    for cve in cves:
        rows = re.findall(
            rf"<tr><td>{re.escape(cve)}</td><td>(.*?)</td><td><a href=\"(.*?)\">(.*?)</a></td></tr>",
            source,
            re.DOTALL,
        )
        by_cve[cve] = [{"product": text(product), "advisory_url": url, "advisory": text(advisory)}
                       for product, url, advisory in rows]
    return products, by_cve


def csaf_evidence(output_dir: Path, cves: set[str]) -> tuple[list[str], dict[str, list[dict]]]:
    products, evidence = set(), {cve: [] for cve in cves}
    for path in output_dir.rglob("report-data.json"):
        try:
            report = read_json(path)
        except (OSError, json.JSONDecodeError):
            continue
        advisory = report.get("advisory", {})
        report_cves = {item.get("cve"): item for item in report.get("cves", [])}
        for cve in cves & set(report_cves):
            item = report_cves[cve]
            evidence[cve].append({
                "reference": advisory.get("reference", path.parent.name),
                "title": advisory.get("title", "Oracle CSAF advisory"),
                "url": advisory.get("url", ""),
                "cvss": item.get("cvss_score"),
                "kev": item.get("kev"),
                "remediations": item.get("remediations", []),
            })
        for product in report.get("products", []):
            if set(product.get("affected_cves", [])) & cves:
                products.add(product.get("product_name", ""))
    return sorted(product for product in products if product), evidence


def build_data(product_report: dict, kev_report: dict, oracle_map: Path, csaf_dir: Path) -> dict:
    events = product_report.get("news_coverage", [])
    cves = {cve for event in events for cve in event.get("extracted_cves", [])}
    catalog, mapping = map_products(oracle_map, cves)
    csaf_products, csaf = csaf_evidence(csaf_dir, cves)
    for item in kev_report.get("kevs", []):
        for product in item.get("oracle_products", []):
            catalog.append(product)
    catalog.extend(csaf_products)
    kev = {item.get("cve"): item for item in kev_report.get("kevs", []) if item.get("cve") in cves}
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "events": events,
        "product_catalog": sorted(set(product for product in catalog if product)),
        "evidence_by_cve": {
            cve: {"oracle_mapping": mapping.get(cve, []), "kev": kev.get(cve), "csaf": csaf.get(cve, [])}
            for cve in sorted(cves)
        },
        "source_summary": {
            "news_events": len(events), "oracle_products": len(set(catalog)), "kev_records": len(kev),
            "csaf_matches": sum(len(rows) for rows in csaf.values()),
        },
    }


HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Oracle Security Case Desk</title><style>
:root{--ink:#152a3a;--mute:#5c7180;--line:#d9e3ea;--bg:#f4f7f9;--navy:#102a43;--blue:#126da6;--red:#b52a3a;--amber:#936000;--green:#167347}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}header{background:var(--navy);color:#fff;padding:17px max(22px,calc((100% - 1280px)/2));display:flex;justify-content:space-between;align-items:center}header b{font-size:17px}.shell{max-width:1280px;margin:auto;padding:24px}.intro{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:16px}h1{font-size:25px;margin:0 0 4px}h2{font-size:16px;margin:0}.muted{color:var(--mute)}.metrics{display:flex;gap:9px;flex-wrap:wrap}.metric{background:#fff;border:1px solid var(--line);border-radius:7px;padding:9px 12px;min-width:105px}.metric b{display:block;font-size:18px}.metric small{color:var(--mute)}.grid{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:18px}.card{background:#fff;border:1px solid var(--line);border-radius:9px;padding:16px;box-shadow:0 5px 16px #193a5011}.event{padding:14px 0;border-bottom:1px solid #e6edf1}.event:last-child{border:0}.event-head{display:flex;gap:12px;justify-content:space-between}.event h3{margin:0;font-size:15px}.meta{font-size:12px;color:var(--mute);margin:4px 0 8px}.tag{display:inline-block;padding:3px 7px;border-radius:12px;font-size:11px;font-weight:700;background:#e7f3fb;color:#155d8e;margin-right:4px}.tag.risk{background:#fff0f1;color:var(--red)}button{border:1px solid #b9ccd8;background:#fff;color:#22435b;border-radius:6px;padding:7px 10px;font:inherit;font-weight:650;cursor:pointer}button:hover{background:#f0f6f9}button:disabled{cursor:default;opacity:.7}.primary{background:var(--blue);border-color:var(--blue);color:#fff}.primary:hover{background:#075a90}.case{padding:11px 0;border-bottom:1px solid #e6edf1}.case:last-child{border:0}.empty{color:var(--mute);padding:12px 0}dialog{border:0;border-radius:10px;width:min(560px,calc(100% - 30px));box-shadow:0 20px 55px #102a4366}dialog::backdrop{background:#102a4377}dialog form{padding:16px}label{font-size:12px;font-weight:700;display:block;margin:12px 0 4px}select,textarea{width:100%;font:inherit;padding:8px;border:1px solid #c7d6df;border-radius:6px}textarea{min-height:70px}.dialog-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:15px}.evidence{margin-top:7px;padding-left:16px;color:#40586a;font-size:12px}@media(max-width:820px){.shell{padding:15px}.grid{grid-template-columns:1fr}.intro{display:block}.metrics{margin-top:14px}.event-head{display:block}.event-head button{margin-top:9px}}
</style></head><body><header><b>Oracle Security Case Desk</b><span>Minimal local prototype · evidence-backed triage</span></header><main class="shell"><section class="intro"><div><h1>News coverage triage</h1><div class="muted">Create an investigation only after selecting the relevant Oracle product. The selection is recorded as an analyst assertion, not a fact.</div></div><div class="metrics" id="metrics"></div></section><div class="grid"><section class="card"><h2>Case candidates from product watch</h2><div id="events"></div></section><aside class="card"><h2>Case requests in this browser</h2><p class="muted">Browser-local for this first version. The case-management backend assigns the case ID when these requests are imported.</p><button id="export">Export case-create requests</button> <button id="reset">Reset local view</button><div id="cases"></div></aside></div></main><dialog id="case-dialog"><form method="dialog"><h2>Create investigation case</h2><p class="muted" id="selected-event"></p><label for="product">Concerned Oracle product</label><select id="product"></select><label for="rationale">Why is this product relevant?</label><textarea id="rationale" placeholder="Required analyst rationale; for example, a product/version or CVE is named in the source."></textarea><div class="dialog-actions"><button value="cancel">Cancel</button><button class="primary" id="create" value="default">Create case</button></div></form></dialog><script id="case-data" type="application/json">__DATA__</script><script>
const data=JSON.parse(document.getElementById('case-data').textContent),store='oracle-security-cases-v1',ignoredStore='oracle-security-ignored-events-v1',events=document.getElementById('events'),casesEl=document.getElementById('cases'),dialog=document.getElementById('case-dialog'),product=document.getElementById('product'),rationale=document.getElementById('rationale'),selected=document.getElementById('selected-event');let active=null;
const esc=v=>String(v||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const cases=()=>JSON.parse(localStorage.getItem(store)||'[]');const save=v=>localStorage.setItem(store,JSON.stringify(v));const ignored=()=>new Set(JSON.parse(localStorage.getItem(ignoredStore)||'[]'));const saveIgnored=v=>localStorage.setItem(ignoredStore,JSON.stringify([...v]));
document.getElementById('metrics').innerHTML=`<div class="metric"><b>${data.source_summary.news_events}</b><small>news candidates</small></div><div class="metric"><b>${data.source_summary.oracle_products}</b><small>Oracle products</small></div><div class="metric"><b>${data.source_summary.kev_records}</b><small>KEV matches</small></div><div class="metric"><b>${data.source_summary.csaf_matches}</b><small>CSAF matches</small></div>`;
product.innerHTML='<option value="">Select a product…</option>'+data.product_catalog.map(p=>`<option>${esc(p)}</option>`).join('');
function renderEvents(){const hidden=ignored(),selectedIds=new Set(cases().map(c=>c.event.event_id)),visible=data.events.map((event,index)=>({event,index})).filter(({event})=>!hidden.has(event.event_id));if(!visible.length){events.innerHTML='<p class="empty">No active candidates. Ignored items remain available in the source report.</p>';return}events.innerHTML=visible.map(({event:e,index:i})=>`<article class="event"><div class="event-head"><div><h3>${esc(e.title)}</h3><div class="meta">${esc(e.matched_product)} · ${esc(e.first_seen)} to ${esc(e.last_seen)} · ${e.articles.length} source item(s)</div><span class="tag">${esc(e.status)}</span>${e.extracted_cves.map(c=>`<span class="tag risk">${esc(c)}</span>`).join('')}</div><div><button data-ignore="${i}">Ignore</button> <button data-event="${i}" class="primary" ${selectedIds.has(e.event_id)?'disabled':''}>${selectedIds.has(e.event_id)?'Selected':'Select'}</button></div></div><div class="evidence">${e.articles.slice(0,2).map(a=>`<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.outlet||'Source')}: ${esc(a.title)}</a>`).join('<br>')}</div></article>`).join('');document.querySelectorAll('[data-event]').forEach(b=>b.onclick=()=>{active=data.events[Number(b.dataset.event)];selected.textContent=active.title;product.value='';rationale.value='';dialog.showModal()});document.querySelectorAll('[data-ignore]').forEach(b=>b.onclick=()=>{const hidden=ignored();hidden.add(data.events[Number(b.dataset.ignore)].event_id);saveIgnored(hidden);renderEvents()})}
function renderCases(){const list=cases();casesEl.innerHTML=list.length?list.map(c=>`<article class="case"><b>Awaiting backend case ID</b><br><span class="muted">${esc(c.product)} · ${esc(c.created_at.slice(0,10))}</span><div class="meta">${esc(c.event.title)}</div></article>`).join(''):'<p class="empty">No case-create requests yet.</p>'}
document.getElementById('create').onclick=e=>{if(!product.value||!rationale.value.trim()){e.preventDefault();alert('Select a product and record the reason for the link.');return}const cves=active.extracted_cves||[],evidence=cves.map(c=>({cve:c,...(data.evidence_by_cve[c]||{})}));const list=cases();list.unshift({created_at:new Date().toISOString(),status:'triage',product:product.value,analyst_rationale:rationale.value.trim(),event:active,evidence});save(list);renderCases();renderEvents()};
document.getElementById('export').onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify({schema_version:1,case_create_requests:cases()},null,2)],{type:'application/json'}));a.download='oracle-security-case-create-requests.json';a.click();URL.revokeObjectURL(a.href)};renderEvents();renderCases();
document.getElementById('reset').onclick=()=>{if(confirm('Reset this local view? Case-create requests and ignored candidates saved in this browser will be removed.')){localStorage.removeItem(store);localStorage.removeItem(ignoredStore);renderEvents();renderCases()}};
</script></body></html>'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--product-report", type=Path, required=True)
    parser.add_argument("--kev-report", type=Path, required=True)
    parser.add_argument("--oracle-map", type=Path, required=True)
    parser.add_argument("--csaf-output", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()

    data = build_data(read_json(args.product_report), read_json(args.kev_report), args.oracle_map, args.csaf_output)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "case-desk-data.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    embedded = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    (args.out_dir / "case-desk.html").write_text(HTML.replace("__DATA__", embedded), encoding="utf-8")


if __name__ == "__main__":
    main()
