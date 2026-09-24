"""HTML rendering of the product risk digest (see product_watch.py).

Same look and structure as report-oracle-kev.html: header with metadata, an
interpretation note, source-health badges, KPI tiles, then one collapsible
decision table per kind of information (status changes, stories, mentions) with
product as a column and a filter. Every item links to its source. The only
script is the table sort/filter; the page makes no external requests.
"""

from datetime import date
from html import escape

LEVEL_TAG = {0: "", 1: "amber", 2: "amber", 3: "blue", 4: "blue", 5: "red"}

CSS = """
:root{--brand:#c74634;--ink:#161513;--muted:#665f58;--line:#e4e1dc;--bg:#fff;--soft:#faf9f8;--blue:#0572ce;--redbg:#fbedeb;--amber:#a65f00;--amberbg:#fdf3e3;--green:#1b7a3e;--greenbg:#eaf5ee;--radius:6px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:13px/1.5 "Oracle Sans","Helvetica Neue",Arial,sans-serif}.cr{max-width:1400px;margin:auto;padding:20px}a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
.cr-head{border-bottom:3px solid var(--brand);padding-bottom:12px;margin-bottom:18px}h1{font-size:20px;font-weight:400;margin:0}.cr-meta{display:flex;flex-wrap:wrap;gap:14px;margin-top:5px;color:var(--muted);font-size:11px}.cr-meta b{color:var(--ink)}
.cr-note{border-left:3px solid var(--blue);background:#e8f2fb;padding:9px 12px;margin-bottom:14px;border-radius:0 var(--radius) var(--radius) 0}.cr-health{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}.badge{display:inline-block;border-radius:10px;padding:2px 8px;font-size:10.5px;background:#f5f4f2}.ok{color:var(--green);background:var(--greenbg)}.warn{color:var(--amber);background:var(--amberbg)}
.cr-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:20px}.cr-kpi{border:1px solid var(--line);background:var(--soft);border-radius:var(--radius);padding:11px 13px}.cr-kpi.danger{background:var(--redbg)}.cr-kpi.warning{background:var(--amberbg)}.cr-kpi .l{text-transform:uppercase;letter-spacing:.4px;color:var(--muted);font-size:10.5px}.cr-kpi .v{font-size:22px;font-weight:300}.cr-kpi .s{color:var(--muted);font-size:10.5px}
details.section{border:1px solid var(--line);border-radius:var(--radius);margin-bottom:9px;overflow:hidden}details.section>summary{cursor:pointer;background:var(--soft);padding:10px 14px;display:flex;gap:9px;align-items:center}summary b{font-weight:600}summary small{color:var(--muted)}summary .count{margin-left:auto;color:var(--muted)}.body{padding:14px;overflow:auto}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}.tools label{color:var(--muted);font-size:11px}input,select{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:4px;background:white}table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;text-transform:uppercase;letter-spacing:.35px;font-size:10.5px;color:var(--muted);cursor:pointer;white-space:nowrap}th,td{padding:7px 8px;border-bottom:1px solid #f0eeea;vertical-align:top}tbody tr:hover{background:var(--soft)}.num{text-align:right;font-variant-numeric:tabular-nums}.mono{font-family:Menlo,Consolas,monospace;font-size:11px}.tag{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;background:#f5f4f2;color:var(--muted);white-space:nowrap}.red{background:var(--redbg);color:#8a2e22}.amber{background:var(--amberbg);color:var(--amber)}.blue{background:#e8f2fb;color:#04559b}.green{background:var(--greenbg);color:var(--green)}
.mapping{border:0;margin:0;overflow:visible}.mapping summary{cursor:pointer;color:var(--blue);white-space:nowrap}.mapping-list{min-width:280px;padding:5px 0;display:grid;gap:5px}.mapping-list span{display:block;color:var(--muted);font-size:10px}.description{min-width:260px;max-width:420px}.foot{border-top:1px solid var(--line);margin-top:20px;padding-top:10px;color:var(--muted);font-size:10.5px}
.story{min-width:280px;max-width:480px}.evidence{min-width:220px;max-width:380px}.cves{display:flex;flex-wrap:wrap;gap:4px 10px;min-width:220px;max-width:460px}td small{color:var(--muted)}
@media(max-width:700px){.cr{padding:10px}}@media print{.tools{display:none}details.section{break-inside:avoid}}
"""

SCRIPT = """
(()=>{"use strict";
const n=v=>new Intl.NumberFormat("en-US").format(v??0);
document.querySelectorAll("table").forEach(t=>t.querySelectorAll("th").forEach((th,i)=>th.addEventListener("click",()=>{const body=t.tBodies[0];if(!body)return;const asc=th.dataset.asc!=="1";t.querySelectorAll("th").forEach(x=>delete x.dataset.asc);th.dataset.asc=asc?"1":"0";[...body.rows].sort((x,y)=>{const av=x.cells[i]?.dataset.sort??x.cells[i]?.textContent.trim()??"",bv=y.cells[i]?.dataset.sort??y.cells[i]?.textContent.trim()??"";return (asc?1:-1)*String(av).localeCompare(String(bv),undefined,{numeric:true})}).forEach(r=>body.appendChild(r))})));
document.querySelectorAll("[data-filter]").forEach(scope=>{const q=scope.querySelector('input[type="search"]'),prod=scope.querySelector("[data-product]"),lvl=scope.querySelector("[data-level]"),chk=scope.querySelector("[data-flag]"),cnt=scope.querySelector("[data-count]");
const apply=()=>{const s=(q?.value||"").toLowerCase(),p=prod?.value||"",l=lvl?.value||"",f=chk?.checked;let c=0;[...scope.querySelector("tbody").rows].forEach(r=>{const show=(!s||r.textContent.toLowerCase().includes(s))&&(!p||r.dataset.product===p)&&(!l||r.dataset.level===l)&&(!f||r.dataset.flag==="1");r.hidden=!show;if(show)c++});if(cnt)cnt.textContent=n(c)+" rows"};
scope.querySelectorAll("input,select").forEach(x=>x.addEventListener("input",apply));apply()});
})();
"""


def link(url, label):
    if not url or not str(url).startswith(("http://", "https://")):
        return escape(str(label))
    return f'<a href="{escape(url, quote=True)}" target="_blank" rel="noopener">{escape(str(label))}</a>'


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def age(d):
    try:
        days = (date.today() - date.fromisoformat(d)).days
    except ValueError:
        return ""
    return f"<br><small>{plural(days, 'day')} ago</small>"


def pct(v):
    return f"{v:.1%}" if v is not None else "n/a"


def kpi(label, value, sub, kind=""):
    return (f'<div class="cr-kpi {kind}"><div class="l">{escape(label)}</div>'
            f'<div class="v">{value}</div><div class="s">{escape(sub)}</div></div>')


def section(title, hint, rows, body, open_=False):
    return (f'<details class="section"{" open" if open_ else ""}><summary><b>{escape(title)}</b>'
            f'<small>{escape(hint)}</small><span class="count">{len(rows)}</span></summary>'
            f'<div class="body" data-filter>{body}</div></details>')


def tools(products, placeholder, levels=None, flag=None):
    opts = "".join(f'<option value="{escape(p)}">{escape(p)}</option>' for p in products)
    out = [f'<div class="tools"><input type="search" placeholder="{escape(placeholder)}">',
           f'<select data-product><option value="">All products</option>{opts}</select>']
    if levels:
        lv = "".join(f'<option value="{k}">{escape(v)}</option>' for k, v in sorted(levels.items(), reverse=True))
        out.append(f'<select data-level><option value="">All statuses</option>{lv}</select>')
    if flag:
        out.append(f'<label><input type="checkbox" data-flag> {escape(flag)}</label>')
    out.append("<span data-count></span></div>")
    return "".join(out)


def table(headers, rows):
    cells = []
    for h in headers:
        cls = ' class="num"' if h.startswith("#") else ""
        cells.append(f"<th{cls}>{escape(h.lstrip('#'))}</th>")
    return f"<table><thead><tr>{''.join(cells)}</tr></thead><tbody>{''.join(rows)}</tbody></table>"


def sorted_rows(keyed):
    """keyed: list of (sort_key, html). Newest / highest first."""
    return [html for _, html in sorted(keyed, key=lambda kv: kv[0], reverse=True)]


def product_attrs(name, flag=0, level=None):
    lv = f' data-level="{level}"' if level is not None else ""
    return f'data-product="{escape(name)}" data-flag="{flag}"{lv}'


# ---------- sections ----------

def changes_section(status_changes, levels):
    rows = []
    for name, s, old in status_changes:
        url = s["links"][0]["url"] if s["links"] else ""
        rows.append(
            f'<tr {product_attrs(name)}><td><b>{link(url, s["title"])}</b></td><td>{escape(name)}</td>'
            f'<td><span class="tag">{escape(old)}</span> → <span class="tag {LEVEL_TAG[s["level"]]}">{escape(levels[s["level"]])}</span></td>'
            f'<td class="evidence">{link(s.get("link"), s["note"])}</td></tr>'
        )
    if not rows:
        return ""
    return section("Status changes since the last run", "stories whose confirmation level went up", rows,
                   table(["Story", "Product", "Change", "Evidence"], rows), open_=True)


def stories_section(sections, levels):
    keyed = []
    for sec in sections:
        for s in sec["stories"]:
            arts = s["articles"]
            best = s["links"][0] if s["links"] else arts[0]
            outlets = len({a["outlet"] for a in arts})
            listing = "".join(
                f'<div>{link(a["url"], a["title"])}<span>{escape(a["date"])} · {escape(a["outlet"])}</span></div>'
                for a in sorted(arts, key=lambda a: a["date"], reverse=True)
            )
            new = s["new_articles"]
            new_tag = f' <span class="tag red">+{new} NEW</span>' if new and new != len(arts) else ""
            evidence = link(s.get("link"), s["note"]) if s["level"] else "<small>coverage only</small>"
            oracle = link(s.get("patch_link"), s["patch_note"]) if 1 <= s["level"] <= 2 else ""
            open_claim = 1 if 1 <= s["level"] <= 2 else 0
            keyed.append((s["last_date"],
                f'<tr {product_attrs(sec["name"], open_claim, s["level"])}>'
                f'<td data-sort="{s["level"]}"><span class="tag {LEVEL_TAG[s["level"]]}">{escape(levels[s["level"]])}</span></td>'
                f'<td class="story"><b>{link(best["url"], s["title"])}</b>{new_tag}'
                f'<details class="mapping"><summary>{plural(len(arts), "article")} / {plural(outlets, "outlet")}</summary>'
                f'<div class="mapping-list">{listing}</div></details></td>'
                f'<td>{escape(sec["name"])}</td>'
                f'<td data-sort="{escape(s["first_date"])}">{escape(s["first_date"])}<br><small>{link(arts[0]["url"], arts[0]["outlet"])}</small></td>'
                f'<td data-sort="{escape(s["last_date"])}">{escape(s["last_date"])}{age(s["last_date"])}</td>'
                f'<td class="evidence">{evidence}</td><td class="evidence">{oracle}</td></tr>'))
    rows = sorted_rows(keyed)
    if not rows:
        return ""
    body = tools([s["name"] for s in sections], "Search story, outlet, CVE…", levels,
                 "Open claims only (unconfirmed / victim disclosed)")
    body += table(["Status", "Story", "Product", "First report", "Last report ↓", "Evidence", "Oracle since first report"], rows)
    return section("News Coverage", "news grouped by incident, most recent first", rows, body, open_=True)


def mentions_section(sections):
    rows = sorted_rows([
        (a["date"],
         f'<tr {product_attrs(sec["name"])}><td data-sort="{escape(a["date"])}">{escape(a["date"])}</td>'
         f'<td>{link(a["url"], a["title"])}</td><td>{escape(a["outlet"])}</td><td>{escape(sec["name"])}</td></tr>')
        for sec in sections for a in sec["mentions"]
    ])
    if not rows:
        return ""
    body = tools([s["name"] for s in sections], "Search headline, outlet…")
    body += table(["Date ↓", "Headline", "Outlet", "Product"], rows)
    return section("Also mentioned", "single articles that don't name the product in the headline", rows, body)


def loose_cves_section(sections):
    keyed = []
    for sec in sections:
        for c in sec["loose_cves"]:
            cvss = c["cvss"] if c["cvss"] is not None else "n/a"
            keyed.append(((c["epss"] or 0, c["cvss"] or 0),
                f'<tr {product_attrs(sec["name"], 1 if (c["cvss"] or 0) >= 9 else 0)}>'
                f'<td class="mono">{link(c["url"], c["id"])}</td><td>{escape(sec["name"])}</td>'
                f'<td class="num">{cvss}</td><td class="num" data-sort="{c["epss"] or 0}">{pct(c["epss"])}</td>'
                f'<td><div class="description">{escape(c["summary"][:300])}</div></td></tr>'))
    rows = sorted_rows(keyed)
    if not rows:
        return ""
    body = tools([s["name"] for s in sections], "Search CVE, description…", flag="CVSS ≥ 9 only")
    body += table(["CVE", "Product", "#CVSS", "#EPSS ↓", "Description"], rows)
    return section("Other new CVEs", "published in NVD but not in an Oracle advisory above", rows, body)


# ---------- page ----------

def render_html(sections, status_changes, generated, since, full, levels, sources):
    stories = [s for sec in sections for s in sec["stories"]]
    # News Coverage entries whose first report is less than a week old (exposed as <meta name="new">)
    week_ago = date.fromordinal(date.today().toordinal() - 7).isoformat()
    new_this_week = sum(1 for s in stories if s["first_date"] > week_ago)
    open_claims = sum(1 for s in stories if 1 <= s["level"] <= 2)
    vendor_confirmed = sum(1 for s in stories if s["level"] >= 3)
    articles = sum(len(s["articles"]) for s in stories)
    mentions = sum(len(sec["mentions"]) for sec in sections)
    today = date.today()
    start = date.fromordinal(today.toordinal() - since)
    mode = "full view" if full else "new since last run"

    health = [
        f'<span class="badge ok">CISA KEV {sources["kev"]:,} entries</span>',
        f'<span class="badge ok">{sources["advisories"]} Oracle advisories parsed</span>',
        f'<span class="badge ok">NVD {sources["nvd"]:,} CVEs</span>',
        f'<span class="badge ok">{sources["articles"]:,} news articles</span>',
    ] + [f'<span class="badge warn">{escape(w[:120])}</span>' for w in sources["warnings"]]

    kpis = "".join([
        kpi("Open claims", open_claims, "unconfirmed or victim-disclosed stories", "danger" if open_claims else ""),
        kpi("Stories", len(stories), f"news grouped by incident ({mode})"),
        kpi("Vendor-linked", vendor_confirmed, "stories tied to an Oracle alert, CVE or KEV"),
        kpi("Articles", f"{articles:,}", "grouped into those stories"),
        kpi("Also mentioned", mentions, "single articles, product not in headline"),
    ])

    body = "".join([
        changes_section(status_changes, levels),
        stories_section(sections, levels),
        mentions_section(sections),
        loose_cves_section(sections),
    ]) or '<div class="cr-note">Nothing new since the last run. Run without <b>--no-full</b> to see everything in the window.</div>'

    products = ", ".join(s["name"] for s in sections) or "none"
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="new" content="{new_this_week}">
<title>Product Risk Digest</title>
<style>{CSS}</style>
</head><body><main class="cr">
<header class="cr-head"><h1>Product Risk Digest</h1><div class="cr-meta">
<span><b>As of</b> {today}</span><span><b>Window</b> {start} to {today}</span>
<span><b>Generated</b> {escape(generated)}</span><span><b>View</b> {mode}</span><span><b>Products</b> {escape(products)}</span>
</div></header>
<div class="cr-note"><b>Interpretation.</b> Story statuses are heuristic and only move up:
<b>Claimed</b> (attacker or press claim) → <b>Victim disclosed</b> → <b>Vendor fix (probable)</b> (an Oracle Security Alert
for the product from 45 days before to 90 days after the first report, matched by date, not by CVE) → <b>CVE linked</b>
→ <b>Exploited (KEV)</b>. Oracle often publishes its Security Alert before the press covers an incident. Follow the
linked evidence and verify affected versions in the Oracle advisory.</div>
<div class="cr-health">{"".join(health)}</div>
<div class="cr-kpis">{kpis}</div>
{body}
<footer class="foot">Sources: {link("https://www.oracle.com/security-alerts/", "Oracle Security Alerts & Critical Patch Updates")} ·
{link("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA Known Exploited Vulnerabilities catalog")} ·
{link("https://nvd.nist.gov/developers/vulnerabilities", "NVD CVE API")} · {link("https://www.first.org/epss/", "FIRST EPSS")} ·
security news RSS feeds and Google News. This product uses data from the NVD API but is not endorsed or certified by the NVD.
This report describes public reporting and vendor-published applicability, not confirmed exposure in your environment.</footer>
</main><script>{SCRIPT}</script></body></html>
"""
