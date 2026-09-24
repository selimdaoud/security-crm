#!/usr/bin/env python3
"""Vendor / product risk monitor.

For each product in products.json it tracks:
  - Oracle advisories: out-of-band Security Alerts (Oracle's zero-day confirmations)
    and Critical (Security) Patch Updates, parsed down to the CVEs per product
  - CISA KEV: vulnerabilities confirmed exploited in the wild
  - NVD: new CVEs with CVSS and EPSS (folded into the Oracle patch that ships them)
  - News: security feeds + a Google News search per product, grouped into stories

Each story carries a status that is re-evaluated every run, so a rumour can be
followed until it is confirmed:
  CLAIMED -> VICTIM DISCLOSED -> VENDOR FIX (probable) -> CVE LINKED -> EXPLOITED (KEV)
Status upgrades are listed at the top of the digest.

Writes data/product_digest.md and data/product_digest.html (--full: data/product_report.html);
every entry in the HTML links to its source. State is kept in SQLite. Stdlib only.

Usage:
    python3 product_watch.py                 # everything in the last 90 days -> data/product_report.html
    python3 product_watch.py --since 30      # narrower window
    python3 product_watch.py --no-full       # only new items / story updates since the last run
    python3 product_watch.py --no-full --webhook URL   # daily alert to a Slack-style webhook
Set NVD_API_KEY in the environment for faster NVD queries.
"""

import argparse
import hashlib
import html
import json
import math
import os
import re
import sqlite3
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from digest_html import render_html

HERE = Path(__file__).resolve().parent
USER_AGENT = "myOSINT-product-watch/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
ORACLE_ALERTS_URL = "https://www.oracle.com/security-alerts/"
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

STORY_LOOKBACK_DAYS = 45   # articles re-clustered each run
STORY_LINK_DAYS = 7        # max gap between two articles of the same story
STORY_MATCH = 0.3          # weighted headline overlap needed to link two articles
STORY_MIN_WEIGHT = 4.0     # ...and the shared words must be distinctive enough

# Story status levels. A story only ever moves up.
LEVELS = {
    0: "COVERAGE",
    1: "CLAIMED / UNCONFIRMED",
    2: "VICTIM DISCLOSED",
    3: "VENDOR FIX (probable)",
    4: "CVE LINKED",
    5: "EXPLOITED (KEV)",
}
INCIDENT_RX = re.compile(
    r"breach|hack|stole|stolen|theft|leak|ransom|extort|zero[- ]?day|0-day|exploit|attack|compromise|dump|intrusion",
    re.IGNORECASE,
)
NOT_VICTIM_RX = re.compile(r"\b(cisa|kev|researchers?)\b", re.IGNORECASE)
AGENCY_RX = re.compile(r"\b(cisa|kev|known exploited)\b", re.IGNORECASE)
DISCLOSURE_RX = re.compile(
    r"\b(discloses?|disclosed|confirms?|confirmed|notif(y|ies|ied|ication)|acknowledg\w*|8-k|sec filing|investigat\w*|probes?)\b",
    re.IGNORECASE,
)


# ---------- helpers ----------

def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    if url.startswith(NVD_URL) and os.environ.get("NVD_API_KEY"):
        req.add_header("apiKey", os.environ["NVD_API_KEY"])
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def compile_terms(terms):
    out = []
    for t in terms:
        if t.startswith("re:"):
            out.append(re.compile(t[3:], re.IGNORECASE))
        else:
            out.append(re.compile(re.escape(t), re.IGNORECASE))
    return out


def matches(rules, *texts):
    hay = " ".join(t or "" for t in texts)
    return any(r.search(hay) for r in rules)


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = parsedate_to_datetime(s)
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def strip_html(s):
    s = re.sub(r"(?s)<(script|style)[^>]*>.*?</\1>", " ", s or "")
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", s))).strip()


def days_between(a, b):
    return (date.fromisoformat(b) - date.fromisoformat(a)).days


def nvd_url(cve):
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def kev_url(cve):
    return "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?" + urllib.parse.urlencode(
        {"search_api_fulltext": cve}
    )


def short_hash(s):
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]


WARNINGS = []   # shown as source-health badges in the HTML report


def warn(msg):
    WARNINGS.append(msg)
    print(f"warning: {msg}", file=sys.stderr)


# ---------- KEV / NVD / EPSS ----------

def load_kev():
    data = json.loads(http_get(KEV_URL))
    return {v["cveID"]: v for v in data["vulnerabilities"]}


def kev_items(kev, product, rules):
    # No date cutoff: an old exploited CVE is still a risk if unpatched, and the
    # seen-table means each one is only reported once.
    for v in kev.values():
        if not matches(rules, v["vendorProject"], v["product"], v["vulnerabilityName"], v["shortDescription"]):
            continue
        yield {
            "id": f"kev:{v['cveID']}",
            "product": product,
            "kind": "exploited",
            "cve": v["cveID"],
            "title": v["vulnerabilityName"],
            "date": v["dateAdded"],
            "summary": v["shortDescription"],
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "due": v.get("dueDate"),
            "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
        }


def cvss(cve):
    m = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(key):
            d = m[key][0]["cvssData"]
            return d.get("baseScore"), d.get("baseSeverity") or m[key][0].get("baseSeverity")
    return None, None


def nvd_items(product, keyword, since_days):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=min(since_days, 119))
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    base = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": end.strftime(fmt),
        "resultsPerPage": 2000,
    }
    index = 0
    while True:
        url = NVD_URL + "?" + urllib.parse.urlencode({**base, "startIndex": index})
        data = json.loads(http_get(url, timeout=90))
        for v in data.get("vulnerabilities", []):
            cve = v["cve"]
            desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
            score, sev = cvss(cve)
            yield {
                "id": f"nvd:{cve['id']}",
                "product": product,
                "kind": "cve",
                "cve": cve["id"],
                "title": cve["id"],
                "date": cve["published"][:10],
                "summary": desc,
                "cvss": score,
                "severity": sev,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            }
        index += data.get("resultsPerPage", 0)
        if index >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
            break
        time.sleep(1 if os.environ.get("NVD_API_KEY") else 6)


def fetch_epss(cves):
    scores = {}
    cves = sorted(set(cves))
    for n in range(0, len(cves), 100):
        try:
            data = json.loads(http_get(EPSS_URL + "?cve=" + ",".join(cves[n:n + 100])))
            scores.update({d["cve"]: float(d["epss"]) for d in data.get("data", [])})
        except Exception as e:
            warn(f"EPSS lookup failed: {e}")
    return scores


# ---------- feeds / news ----------

def feed_entries(xml_bytes):
    root = ET.fromstring(xml_bytes)
    atom = "{http://www.w3.org/2005/Atom}"
    for item in root.iter("item"):
        yield {
            "title": (item.findtext("title") or "").strip(),
            "url": (item.findtext("link") or "").strip(),
            "date": parse_date(item.findtext("pubDate")),
            "summary": strip_html(item.findtext("description")),
            "guid": (item.findtext("guid") or item.findtext("link") or "").strip(),
            "outlet": (item.findtext("source") or "").strip(),
        }
    for e in root.iter(atom + "entry"):
        link = e.find(atom + "link")
        yield {
            "title": (e.findtext(atom + "title") or "").strip(),
            "url": link.get("href") if link is not None else "",
            "date": parse_date(e.findtext(atom + "published") or e.findtext(atom + "updated")),
            "summary": strip_html(e.findtext(atom + "summary") or e.findtext(atom + "content")),
            "guid": (e.findtext(atom + "id") or "").strip(),
            "outlet": "",
        }


def news_articles(feed, products, cutoff, fixed_product=None):
    for entry in feed_entries(http_get(feed["url"])):
        if not entry["date"] or entry["date"] < cutoff:
            continue
        if fixed_product:
            names = [fixed_product["name"]]
        else:
            names = [p["name"] for p in products if matches(p["_rules"], entry["title"], entry["summary"])]
        title = entry["title"]
        outlet = entry["outlet"] or feed["name"]
        if entry["outlet"] and title.endswith(" - " + entry["outlet"]):
            title = title[: -len(entry["outlet"]) - 3]
        for name in names:
            yield {
                "id": f"news:{name}:{short_hash(entry['guid'] or entry['url'])}",
                "product": name,
                "date": entry["date"].strftime("%Y-%m-%d"),
                "title": title,
                "outlet": outlet,
                "url": entry["url"],
                "summary": entry["summary"][:400],
                "direct": fixed_product is None,
            }


def google_news_feed(query, since_days):
    q = f"{query} when:{since_days}d"
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode(
        {"q": q, "hl": "en-US", "gl": "US", "ceid": "US:en"}
    )
    return {"name": "Google News", "url": url}


# ---------- Oracle advisories ----------

def parse_oracle_page(text):
    """Map each CVE on an Oracle advisory page to the text that follows it
    (risk-matrix rows name the product right after the CVE)."""
    found = list(CVE_RX.finditer(text))
    # Rows in a family's risk matrix often name only a sub-product ("Oracle Workflow"),
    # so each CVE also carries the heading of the matrix it sits in.
    headers = [(m.start(), m.group(1)) for m in re.finditer(r"(Oracle [\w\-. ]{2,60}?) Risk Matrix", text)]
    contexts = defaultdict(str)
    for n, m in enumerate(found):
        end = found[n + 1].start() if n + 1 < len(found) else m.end() + 300
        header = next((h for pos, h in reversed(headers) if pos < m.start()), "")
        contexts[m.group(0).upper()] += f" [{header}] " + text[m.end():min(end, m.end() + 300)]
    families = re.findall(
        r"contains (\d+) new security patch(?:es)?(?: ,? plus additional third party patches noted below,)? for ([^.]+?)\.",
        text,
    )
    desc = ""
    i = text.find("Description")
    if i >= 0:
        desc = text[i:i + 1200]
    return {
        "cves": contexts,
        "families": [(int(n), fam.strip()) for n, fam in families],
        "iocs": bool(re.search(r"indicators? of compromise", text, re.IGNORECASE)),
        "desc": desc,
    }


def oracle_advisories(feed_url, db, since_days):
    """Security Alerts: all of them (rare, and each is a vendor-confirmed zero-day or
    critical flaw). Patch updates: only within the window."""
    now = datetime.now(timezone.utc)
    out = []
    for e in feed_entries(http_get(feed_url)):
        title = re.sub(r"\s+", " ", e["title"])
        is_alert = "Security Alert" in title
        if not e["date"] or (not is_alert and e["date"] < now - timedelta(days=since_days)):
            continue
        url = e["url"].strip()
        row = db.execute("SELECT fetched, data FROM advisories WHERE url = ?", (url,)).fetchone()
        stale = row is None or (
            e["date"] > now - timedelta(days=21)
            and datetime.fromisoformat(row[0]) < now - timedelta(days=1)
        )
        if stale:
            try:
                parsed = parse_oracle_page(strip_html(http_get(url, timeout=90).decode("utf-8", "ignore")))
                db.execute(
                    "INSERT OR REPLACE INTO advisories VALUES (?, ?, ?)",
                    (url, now.isoformat(timespec="seconds"), json.dumps(parsed)),
                )
                db.commit()
            except Exception as ex:
                warn(f"Oracle advisory {url} failed: {ex}")
                if row is None:
                    continue
                parsed = json.loads(row[1])
        else:
            parsed = json.loads(row[1])
        out.append({
            "url": url,
            "title": title,
            "date": e["date"].strftime("%Y-%m-%d"),
            "type": "alert" if is_alert else "patch",
            **parsed,
        })
    return out


def advisory_items(advisories, product):
    rules = product["_rules"]
    for adv in advisories:
        cves = sorted(c for c, ctx in adv["cves"].items() if matches(rules, ctx))
        if adv["type"] == "alert" and not cves and matches(rules, adv["desc"]):
            cves = sorted(set(CVE_RX.findall(adv["desc"])))
        if not cves:
            continue
        families = [(n, fam) for n, fam in adv["families"] if matches(rules, fam)]
        yield {
            "id": f"oracle:{adv['url']}:{product['name']}",
            "product": product["name"],
            "kind": "vendor alert" if adv["type"] == "alert" else "vendor patch",
            "title": adv["title"],
            "date": adv["date"],
            "url": adv["url"],
            "cves": cves,
            "families": families,
            "iocs": adv["iocs"],
        }


# ---------- stories ----------

_STOP = set(
    """a an the and or of to in on for with by via from at as is are was be it its this that new says say said after
    over how why what who into amid than more about here know now just could may has have had not all but out up""".split()
)


def headline_tokens(title, product_rules):
    t = title.replace(".", "").replace("’s", "").replace("'s", "").lower()
    for r in product_rules:
        t = r.sub(" ", t)
    t = t.replace("oracle", " ")
    out = set()
    for w in re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", t):
        if not w.startswith("cve-") and len(w) > 4:
            w = re.sub(r"(ing|ed|es|s)$", "", w)
        if w not in _STOP and len(w) > 2:
            out.add(w)
    return out


def cluster(articles, product_rules, idf):
    """Union-find over articles of one product: two articles are the same story if
    they share a CVE, or share distinctive headline words within STORY_LINK_DAYS.
    Leftover single articles join the biggest story around the same dates."""
    arts = sorted(articles, key=lambda a: a["date"])
    toks = [headline_tokens(a["title"], product_rules) for a in arts]
    days = [date.fromisoformat(a["date"]) for a in arts]
    parent = list(range(len(arts)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def weight(ws):
        return sum(idf(w) for w in ws)

    for i in range(len(arts)):
        for j in range(i):
            if (days[i] - days[j]).days > STORY_LINK_DAYS:
                continue
            shared = toks[i] & toks[j]
            if any(w.startswith("cve-") for w in shared) or (
                weight(shared) >= STORY_MIN_WEIGHT
                and weight(shared) / max(1e-9, min(weight(toks[i]), weight(toks[j]))) >= STORY_MATCH
            ):
                parent[find(i)] = find(j)

    groups = defaultdict(list)
    for i in range(len(arts)):
        groups[find(i)].append(i)
    big = [g for g in groups.values() if len(g) > 1]
    for root, g in list(groups.items()):
        if len(g) == 1:
            i = g[0]
            near = [b for b in big if any(abs((days[i] - days[k]).days) <= 3 and toks[i] & toks[k] for k in b)]
            if near:
                max(near, key=len).append(i)
                del groups[root]
    return [[arts[i] for i in sorted(g, key=lambda i: days[i])] for g in groups.values()]


def product_alerts(product, advisories):
    rules = product["_rules"]
    return [
        a for a in advisories
        if a["type"] == "alert" and (any(matches(rules, ctx) for ctx in a["cves"].values()) or matches(rules, a["desc"]))
    ]


def story_status(story, product, advisories, product_kev, product_cves):
    """Return (level, note, link) from the evidence available now. Only CVEs known to
    belong to this product count, so a passing mention of another bug doesn't."""
    text = " ".join(a["title"] + " " + a["summary"] for a in story["articles"])
    titles = " ".join(a["title"] for a in story["articles"])
    cves = sorted({c.upper() for c in CVE_RX.findall(text)} & product_cves)
    if not INCIDENT_RX.search(titles):
        return 0, "", ""
    level, note, link = 1, "no confirmation from Oracle or the victim yet", ORACLE_ALERTS_URL

    disclosure = next(
        (a for a in story["articles"] if DISCLOSURE_RX.search(a["title"]) and not NOT_VICTIM_RX.search(a["title"])),
        None,
    )
    if disclosure:
        level, note, link = 2, f'"{disclosure["title"]}" ({disclosure["outlet"]}, {disclosure["date"]})', disclosure["url"]

    # Oracle usually publishes its Security Alert before the press picks the story up,
    # so look back 45 days as well as forward.
    start = story["first_date"]
    near = [a for a in product_alerts(product, advisories) if -45 <= days_between(start, a["date"]) <= 90]
    if near:
        a = min(near, key=lambda a: abs(days_between(start, a["date"])))
        lag = days_between(start, a["date"])
        when = f"{-lag} days before first report" if lag < 0 else f"{lag} days after first report"
        cve = "/".join(sorted(c for c, ctx in a["cves"].items() if matches(product["_rules"], ctx))) or "?"
        level, note, link = 3, f"Oracle Security Alert {cve} on {a['date']} ({when}); not linked by CVE in the coverage - verify", a["url"]

    if cves:
        level, note, link = 4, "CVE " + ", ".join(cves), nvd_url(cves[0])
    exploited = [c for c in cves if c in product_kev]
    if not exploited and AGENCY_RX.search(titles):
        # "CISA adds Oracle flaw to KEV" headlines rarely carry the CVE: match by date.
        exploited = [c for c, k in product_kev.items() if -5 <= days_between(start, k["dateAdded"]) <= 2]
    if exploited:
        level, note, link = 5, "CISA KEV " + ", ".join(f"{c} (added {product_kev[c]['dateAdded']})" for c in exploited), kev_url(exploited[0])
    return level, note, link


def next_patch_note(story, product, advisories):
    """For unconfirmed stories: what Oracle has shipped for this product since.
    Returns (note, link)."""
    rules = product["_rules"]
    after = [
        a for a in advisories
        if a["date"] >= story["first_date"] and any(matches(rules, ctx) for ctx in a["cves"].values())
    ]
    if not after:
        age = days_between(story["first_date"], date.today().isoformat())
        return f"no Oracle alert or patch for {product['name']} since first report ({age} days)", ORACLE_ALERTS_URL
    a = min(after, key=lambda a: a["date"])
    n = sum(1 for ctx in a["cves"].values() if matches(rules, ctx))
    return (f"since first report Oracle shipped: {a['title']} ({a['date']}, {n} {product['name']} CVEs) - check if it covers this",
            a["url"])


# ---------- state ----------

def open_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY, first_seen TEXT, raw TEXT);
        CREATE TABLE IF NOT EXISTS advisories (url TEXT PRIMARY KEY, fetched TEXT, data TEXT);
        CREATE TABLE IF NOT EXISTS articles (
            id TEXT PRIMARY KEY, product TEXT, date TEXT, first_seen TEXT, story TEXT, raw TEXT);
        CREATE TABLE IF NOT EXISTS stories (
            id TEXT PRIMARY KEY, product TEXT, first_date TEXT, title TEXT,
            level INTEGER, note TEXT, reported_articles INTEGER);
        """
    )
    if "link" not in [r[1] for r in db.execute("PRAGMA table_info(stories)")]:
        db.execute("ALTER TABLE stories ADD COLUMN link TEXT")
    return db


# ---------- digest ----------

def cve_view(cve, cve_info, epss):
    info = cve_info.get(cve, {})
    return {"id": cve, "url": nvd_url(cve), "cvss": info.get("cvss"), "epss": epss.get(cve)}


def build_product(prod, new_items, stories, cve_info, epss, since):
    """Everything the digest shows for one product, each entry with its source URL.
    Returns None when there is nothing to show."""
    alerts = [i for i in new_items if i["kind"] == "vendor alert"]
    patches = [i for i in new_items if i["kind"] == "vendor patch"]
    kevs = [i for i in new_items if i["kind"] == "exploited"]
    cves = [i for i in new_items if i["kind"] == "cve"]
    if not (alerts or patches or kevs or cves or stories):
        return None
    cutoff = (date.today() - timedelta(days=since)).isoformat()
    by_date = lambda x: x["date"]
    rank = lambda c: (-(c["epss"] or 0), -(c["cvss"] or 0))

    patch_views = []
    for a in sorted(patches, key=by_date, reverse=True):
        shipped = [cve_view(c, cve_info, epss) for c in a["cves"]]
        patch_views.append({
            "title": a["title"].replace("Oracle ", ""),
            "date": a["date"],
            "url": a["url"],
            "cves": sorted(shipped, key=rank),
            "critical": sum(1 for c in shipped if (c["cvss"] or 0) >= 9),
            "families": a["families"],
        })

    def kev_view(k):
        return {**cve_view(k["cve"], cve_info, epss), "date": k["date"], "title": k["title"],
                "ransomware": k["ransomware"], "due": k["due"], "kev_url": kev_url(k["cve"]),
                "summary": k["summary"]}

    shown = sorted((s for s in stories if s["headline_match"] or len(s["articles"]) >= 3),
                   key=lambda s: s["last_date"], reverse=True)
    mentions = sorted((s for s in stories if s not in shown), key=lambda s: s["last_date"], reverse=True)
    folded = {c for p in patches for c in p["cves"]} | {c for a in alerts for c in a["cves"]}
    loose = sorted(({**cve_view(i["cve"], cve_info, epss), "summary": i["summary"]} for i in cves
                    if i["cve"] not in folded), key=rank)
    alert_view = lambda a: {"date": a["date"], "url": a["url"], "title": a["title"], "iocs": a["iocs"],
                            "cves": [cve_view(c, cve_info, epss) for c in a["cves"]]}
    return {
        "name": prod["name"],
        "alerts": [alert_view(a) for a in sorted(alerts, key=by_date, reverse=True) if a["date"] >= cutoff],
        "patches": patch_views,
        "kev": [kev_view(k) for k in sorted(kevs, key=by_date, reverse=True) if k["date"] >= cutoff],
        "stories": shown,
        "mentions": [s["articles"][0] for s in mentions],
        "loose_cves": loose,
        "baseline_alerts": [alert_view(a) for a in sorted(alerts, key=by_date, reverse=True) if a["date"] < cutoff],
        "baseline_kev": [kev_view(k) for k in sorted(kevs, key=by_date, reverse=True) if k["date"] < cutoff],
    }


def fmt_cve(c):
    tags = []
    if c["cvss"] is not None:
        tags.append(f"CVSS {c['cvss']}")
    if c["epss"] is not None:
        tags.append(f"EPSS {c['epss']:.1%}")
    return f"{c['id']} ({', '.join(tags)})" if tags else c["id"]


def plural(n, word):
    return f"{n} {word}{'s' if n != 1 else ''}"


def render_markdown(sec, max_cves, max_stories):
    lines = [f"\n## {sec['name']}\n"]
    if sec["alerts"] or sec["patches"]:
        lines.append("### Oracle advisories")
        for a in sec["alerts"]:
            ioc = " | IOCs published" if a["iocs"] else ""
            lines.append(f"- **SECURITY ALERT** {a['date']}  {', '.join(c['id'] for c in a['cves'])}{ioc}")
            lines.append(f"    {a['url']}")
        for a in sec["patches"]:
            fam = "; ".join(f"{n} patches for {f}" for n, f in a["families"])
            lines.append(f"- {a['title']} ({a['date']}): {len(a['cves'])} {sec['name']} CVEs, "
                         f"{a['critical']} with CVSS >= 9" + (f" [{fam}]" if fam else ""))
            if a["cves"]:
                lines.append(f"    top: {'; '.join(fmt_cve(c) for c in a['cves'][:3])}")
            lines.append(f"    {a['url']}")
        lines.append("")

    if sec["kev"]:
        lines.append("### Newly exploited (CISA KEV)")
        for k in sec["kev"]:
            tags = ["used by ransomware"] if k["ransomware"] else []
            if k["epss"] is not None:
                tags.append(f"EPSS {k['epss']:.1%}")
            tags.append(f"CISA due {k['due']}")
            lines.append(f"- {k['date']}  {k['id']}: {k['title']}  ({' | '.join(tags)})")
        lines.append("")

    if sec["stories"]:
        lines.append("### Stories")
        for s in sec["stories"][:max_stories]:
            first = s["articles"][0]
            n, outlets = len(s["articles"]), len({a["outlet"] for a in s["articles"]})
            new = f", +{s['new_articles']} new" if s["new_articles"] and s["new_articles"] != n else ""
            lines.append(f"- **[{LEVELS[s['level']]}]** {s['title']}")
            lines.append(f"    first report {s['first_date']} ({first['outlet']}) · last {s['last_date']} · "
                         f"{plural(n, 'article')} / {plural(outlets, 'outlet')}{new}")
            if s["level"] >= 1:
                lines.append(f"    status: {s['note']}")
            if 1 <= s["level"] <= 2:
                lines.append(f"    oracle: {s['patch_note']}")
            for a in s["links"]:
                lines.append(f"    · {a['outlet']}: {a['url']}")
        if len(sec["stories"]) > max_stories:
            lines.append(f"- ... and {len(sec['stories']) - max_stories} more stories")
        lines.append("")
    if sec["mentions"]:
        lines.append("### Also mentioned (product not in headline)")
        for a in sec["mentions"][:5]:
            lines.append(f"- {a['date']}  {a['title']} ({a['outlet']})")
        if len(sec["mentions"]) > 5:
            lines.append(f"- ... and {len(sec['mentions']) - 5} more")
        lines.append("")

    if sec["loose_cves"]:
        lines.append(f"### Other new CVEs ({len(sec['loose_cves'])}, not in an Oracle advisory above)")
        for c in sec["loose_cves"][:max_cves]:
            lines.append(f"- {fmt_cve(c)}: {c['summary'][:150]}")
        if len(sec["loose_cves"]) > max_cves:
            lines.append(f"- ... and {len(sec['loose_cves']) - max_cves} more")
        lines.append("")

    if sec["baseline_alerts"] or sec["baseline_kev"]:
        lines.append("### Baseline (first time seen, older than window)")
        if sec["baseline_alerts"]:
            lines.append("- Oracle Security Alerts: " + ", ".join(
                f"{'/'.join(c['id'] for c in a['cves'])} ({a['date']})" for a in sec["baseline_alerts"]))
        if sec["baseline_kev"]:
            lines.append("- Exploited per CISA KEV: " + ", ".join(
                f"{k['id']}{'*' if k['ransomware'] else ''}" for k in sec["baseline_kev"]) + "  (* = used by ransomware)")
        lines.append("")
    return lines


# ---------- main ----------

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", type=Path, default=HERE / "products.json")
    p.add_argument("--db", type=Path, default=HERE / "data" / "product_watch.db")
    p.add_argument("--out", type=Path, default=HERE / "data")
    p.add_argument("--since", type=int, default=90, help="window in days for news, patches and CVEs (NVD max 119)")
    p.add_argument("--max-cves", type=int, default=5, help="loose CVEs listed per product")
    p.add_argument("--max-stories", type=int, default=8, help="stories listed per product")
    p.add_argument("--full", action=argparse.BooleanOptionalAction, default=True,
                   help="show everything in the window (default; saved state is not changed). "
                        "--no-full shows only what is new since the last run")
    p.add_argument("--webhook", help="Slack-compatible webhook URL for the digest")
    args = p.parse_args()

    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    products = cfg["products"]
    for prod in products:
        prod["_rules"] = compile_terms(prod["terms"])
    now = datetime.now(timezone.utc)
    now_s = now.isoformat(timespec="seconds")
    cutoff = now - timedelta(days=args.since)
    if args.full:
        # Work on a scratch copy with the "already reported" marks cleared; keep the
        # story statuses so status history and the advisory cache still apply.
        import shutil
        import tempfile
        scratch = Path(tempfile.mkdtemp()) / "full.db"
        if args.db.exists():
            shutil.copy(args.db, scratch)
        args.db = scratch
        db = open_db(args.db)
        db.execute("DELETE FROM seen")
        db.execute("UPDATE stories SET reported_articles = 0")
    else:
        db = open_db(args.db)

    # --- collect ---
    items = []
    kev = {}
    try:
        kev = load_kev()
        for prod in products:
            items += kev_items(kev, prod["name"], prod["_rules"])
    except Exception as e:
        warn(f"CISA KEV failed: {e}")

    advisories = []
    if cfg.get("oracle_feed"):
        try:
            advisories = oracle_advisories(cfg["oracle_feed"], db, args.since)
            for prod in products:
                items += advisory_items(advisories, prod)
        except Exception as e:
            warn(f"Oracle advisories failed: {e}")

    nvd = []
    first_query = True
    for prod in products:
        for kw in prod.get("nvd_keywords", []):
            if not first_query:
                time.sleep(1 if os.environ.get("NVD_API_KEY") else 6)
            first_query = False
            try:
                nvd += nvd_items(prod["name"], kw, args.since)
            except Exception as e:
                warn(f"NVD query '{kw}' failed: {e}")
    items += nvd
    cve_info = {i["cve"]: i for i in nvd}

    articles = []
    for prod in products:
        if prod.get("news_query"):
            try:
                articles += news_articles(google_news_feed(prod["news_query"], args.since), products, cutoff, prod)
            except Exception as e:
                warn(f"Google News for {prod['name']} failed: {e}")
    for feed in cfg.get("feeds", []):
        try:
            articles += news_articles(feed, products, cutoff)
        except Exception as e:
            warn(f"feed {feed['name']} failed: {e}")

    # --- dedupe non-news items ---
    new_items, ids = defaultdict(list), set()
    for i in items:
        if i["id"] in ids or db.execute("SELECT 1 FROM seen WHERE id = ?", (i["id"],)).fetchone():
            continue
        ids.add(i["id"])
        new_items[i["product"]].append(i)
        db.execute("INSERT INTO seen VALUES (?, ?, ?)", (i["id"], now_s, json.dumps(i, ensure_ascii=False)))

    epss = fetch_epss([i["cve"] for lst in new_items.values() for i in lst if i.get("cve")]
                      + [c for lst in new_items.values() for i in lst for c in i.get("cves", [])])

    # --- store articles, then rebuild stories over the lookback window ---
    for a in articles:
        db.execute(
            "INSERT OR IGNORE INTO articles (id, product, date, first_seen, story, raw) VALUES (?, ?, ?, ?, NULL, ?)",
            (a["id"], a["product"], a["date"], now_s, json.dumps(a, ensure_ascii=False)),
        )
    lookback = (now - timedelta(days=max(STORY_LOOKBACK_DAYS, args.since))).strftime("%Y-%m-%d")
    rows = db.execute(
        "SELECT id, product, first_seen, story, raw FROM articles WHERE date >= ?", (lookback,)
    ).fetchall()
    corpus = [json.loads(r[4])["title"] for r in rows]
    no_rules = []
    df = Counter(w for t in corpus for w in headline_tokens(t, no_rules))
    n_docs = len(corpus) or 1

    def idf(w):
        return math.log((n_docs + 1) / (df.get(w, 0) + 0.5))

    by_product = defaultdict(list)
    for r in rows:
        a = json.loads(r[4])
        a["_first_seen"], a["_story"] = r[2], r[3]
        by_product[r[1]].append(a)

    stories_by_product = defaultdict(list)
    status_changes = []
    for prod in products:
        prod_kev = {
            c: v for c, v in kev.items()
            if matches(prod["_rules"], v["vendorProject"], v["product"], v["vulnerabilityName"], v["shortDescription"])
        }
        prod_cves = (
            set(prod_kev)
            | {i["cve"] for i in nvd if i["product"] == prod["name"]}
            | {c for a in advisories for c, ctx in a["cves"].items() if matches(prod["_rules"], ctx)}
        )
        for group in cluster(by_product.get(prod["name"], []), prod["_rules"], idf):
            existing = Counter(a["_story"] for a in group if a["_story"])
            sid = existing.most_common(1)[0][0] if existing else "s-" + short_hash(group[0]["id"])
            for a in group:
                if a["_story"] != sid:
                    db.execute("UPDATE articles SET story = ? WHERE id = ?", (sid, a["id"]))
            headline = next((a for a in group if matches(prod["_rules"], a["title"])), group[0])
            story = {
                "id": sid,
                "articles": group,
                "first_date": group[0]["date"],
                "last_date": group[-1]["date"],
                "title": headline["title"],
            }
            level, note, link = story_status(story, prod, advisories, prod_kev, prod_cves)
            row = db.execute("SELECT level, note, reported_articles, link FROM stories WHERE id = ?", (sid,)).fetchone()
            old_level, reported = (row[0], row[2]) if row else (None, 0)
            if old_level is not None and level < old_level:
                level, note, link = old_level, row[1], row[3] or ""   # evidence can age out; never downgrade
            story.update(level=level, note=note, link=link, new_articles=len(group) - reported)
            story["patch_note"], story["patch_link"] = next_patch_note(story, prod, advisories)
            story["headline_match"] = any(matches(prod["_rules"], a["title"]) for a in group)
            direct = [a for a in group if a.get("direct")]
            story["links"] = (direct + [a for a in group if not a.get("direct")])[:3]
            if old_level is not None and level > old_level:
                status_changes.append((prod["name"], story, LEVELS[old_level]))
            if story["new_articles"] > 0 or (old_level is not None and level > old_level):
                stories_by_product[prod["name"]].append(story)
            db.execute(
                "INSERT OR REPLACE INTO stories (id, product, first_date, title, level, note, reported_articles, link)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (sid, prod["name"], story["first_date"], story["title"], level, note, len(group), link),
            )
    db.commit()
    db.close()

    # --- digest ---
    lines = [f"# Product risk digest - {now_s}", ""]
    if status_changes:
        lines.append("## Status changes")
        for name, s, old in status_changes:
            lines.append(f"- **{name}**: {s['title']}")
            lines.append(f"    {old} -> **{LEVELS[s['level']]}**: {s['note']}")
        lines.append("")
    sections = [
        sec for prod in products
        if (sec := build_product(prod, new_items.get(prod["name"], []), stories_by_product.get(prod["name"], []),
                                 cve_info, epss, args.since))
    ]
    body = [line for sec in sections for line in render_markdown(sec, args.max_cves, args.max_stories)]
    if not body and not status_changes:
        body = ["Nothing new since the last run. Run without --no-full to see everything in the window."]
    digest = "\n".join(lines + body) + "\n"
    print(digest)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "product_digest.md").write_text(digest, encoding="utf-8")
    # --full gets its own file so a quiet daily run doesn't overwrite the full picture
    html_path = args.out / ("product_report.html" if args.full else "product_digest.html")
    html_path.write_text(
        render_html(sections, status_changes, generated=now_s, since=args.since, full=args.full, levels=LEVELS,
                    sources={"kev": len(kev), "advisories": len(advisories), "nvd": len(nvd),
                             "articles": len(articles), "warnings": WARNINGS}),
        encoding="utf-8",
    )
    print(f"HTML report: {html_path}", file=sys.stderr)

    if args.webhook and (status_changes or not body[0].startswith("Nothing new")):
        payload = json.dumps({"text": digest[:39000]}).encode("utf-8")
        req = urllib.request.Request(args.webhook, data=payload, headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=15).close()
        except Exception as e:
            warn(f"webhook failed: {e}")


if __name__ == "__main__":
    main()
