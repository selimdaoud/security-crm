"""Build a local Oracle CVE-to-advisory ledger from Oracle's security RSS feed.

The generated HTML deliberately has the same three-column table shape as
Oracle's public CVE-to-advisory map.  It can therefore be supplied to the
existing ``oracle-kev-report --oracle-map-file`` option without changing that
report generator.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import shutil
import sqlite3
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Iterable


ORACLE_SECURITY_RSS_URL = (
    "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/"
    "rss-otn-sec.xml"
)
SCHEMA_VERSION = 1
PARSER_VERSION = 2


class LedgerError(RuntimeError):
    """A source or ledger failure that must leave the active files intact."""


class _TableParser(HTMLParser):
    """Small dependency-free table parser for Oracle advisory risk matrices."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._depth = 0
        self._table: list[list[str]] | None = None
        self._row: list[list[str]] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "table":
            if self._depth == 0:
                self._table = []
            self._depth += 1
        elif tag == "tr" and self._depth == 1:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self._cell is not None:
            assert self._row is not None
            self._row.append(" ".join(" ".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            assert self._table is not None
            if self._row:
                self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._depth:
            self._depth -= 1
            if self._depth == 0 and self._table is not None:
                self.tables.append(self._table)
                self._table = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None and data.strip():
            self._cell.append(data)


class _VerboseTableParser(_TableParser):
    """Also retains the product heading associated with an older text matrix."""

    def __init__(self) -> None:
        super().__init__()
        self.table_headings: list[str] = []
        self._heading_tag: str | None = None
        self._heading_text: list[str] = []
        self._last_heading = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._heading_tag = tag
            self._heading_text = []
        if tag == "table" and self._depth == 0:
            self.table_headings.append(self._last_heading)
        super().handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        super().handle_endtag(tag)
        if tag == self._heading_tag:
            self._last_heading = " ".join(" ".join(self._heading_text).split())
            self._heading_tag = None

    def handle_data(self, data: str) -> None:
        if self._heading_tag is not None:
            self._heading_text.append(data)
        super().handle_data(data)


def _normalise_url(value: str) -> str:
    return "".join(value.split())


def _emit(progress: Callable[[str], None] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _source_type(guid: str, title: str, url: str) -> str | None:
    value = " ".join((guid, title, url)).casefold()
    if "cspu" in value or "critical security patch update" in value:
        return "CSPU"
    if "cpu" in value or "critical patch update" in value:
        return "CPU"
    if "security alert" in value or "/alert-" in value:
        return "SECURITY_ALERT"
    return None


def parse_rss(raw: bytes, *, cutoff: date) -> list[dict[str, str]]:
    """Return eligible CPU, CSPU, and Security Alert RSS items."""
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise LedgerError(f"Oracle RSS is not valid XML: {exc}") from exc
    result: dict[str, dict[str, str]] = {}
    for item in root.findall("./channel/item"):
        value = lambda name: " ".join((item.findtext(name) or "").split())
        guid, title, url, published = value("guid"), value("title"), _normalise_url(value("link")), value("pubDate")
        if not guid or not url or not published:
            continue
        try:
            published_on = parsedate_to_datetime(published).date()
        except (TypeError, ValueError) as exc:
            raise LedgerError(f"Oracle RSS item has invalid pubDate {published!r}") from exc
        source_type = _source_type(guid, title, url)
        if source_type is None or published_on < cutoff:
            continue
        result[url] = {
            "guid": guid,
            "title": title or url,
            "url": url,
            "source_type": source_type,
            "published_on": published_on.isoformat(),
        }
    return list(result.values())


def parse_risk_matrices(raw: bytes) -> list[dict[str, str]]:
    """Extract CVE/product/version rows from the risk-matrix tables in an advisory."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252")
    parser = _TableParser()
    parser.feed(text)
    values: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for table in parser.tables:
        header_index = next(
            (
                index
                for index, row in enumerate(table)
                if any(_is_cve_header(cell) for cell in row)
                and any(cell.casefold() == "product" for cell in row)
            ),
            None,
        )
        if header_index is None:
            continue
        header = table[header_index]
        cve_column = next(i for i, cell in enumerate(header) if _is_cve_header(cell))
        product_column = next(i for i, cell in enumerate(header) if cell.casefold() == "product")
        versions_column = next(
            (i for i, cell in enumerate(header) if "supported versions" in cell.casefold()),
            None,
        )
        for row in table[header_index + 1 :]:
            if len(row) <= max(cve_column, product_column):
                continue
            product = row[product_column].strip()
            # Oracle also records "the patch for CVE-X additionally addresses
            # CVE-Y" in a notes cell on the same product row.  Treat every CVE
            # in that row as an association with that product, not just the
            # first-column identifier.
            cves = _cves(" ".join(row))
            if not cves or not product:
                continue
            versions = row[versions_column].strip() if versions_column is not None and len(row) > versions_column else ""
            for cve in cves:
                key = (cve, product, versions)
                if key not in seen:
                    seen.add(key)
                    values.append({"cve": cve, "product": product, "supported_versions": versions})
    return values


def parse_verbose_risk_matrices(raw: bytes) -> list[dict[str, str]]:
    """Parse Oracle's older ``*verbose.html`` two-column risk matrices."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252")
    parser = _VerboseTableParser()
    parser.feed(text)
    values: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for heading, table in zip(parser.table_headings, parser.tables):
        if not table or not any("cve#" in cell.casefold() or "cve id" in cell.casefold() for cell in table[0]):
            continue
        product = heading.rsplit(" for ", 1)[-1].strip()
        if not product or product == heading:
            continue
        for row in table[1:]:
            cves = _cves(" ".join(row))
            if not cves:
                continue
            description = " ".join(row[1:])
            versions = _supported_versions(description)
            for cve in cves:
                key = (cve, product, versions)
                if key not in seen:
                    seen.add(key)
                    values.append({"cve": cve, "product": product, "supported_versions": versions})
    return values


def expand_additional_cves(raw: bytes, mappings: list[dict[str, str]]) -> list[dict[str, str]]:
    """Add Oracle's ``patch for CVE-X also addresses CVE-Y`` associations.

    Oracle places these statements after a matrix rather than in its CVE column.
    The additional CVE has the same product/version applicability as the named
    primary CVE in that advisory.
    """
    import re

    try:
        source = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        source = raw.decode("cp1252")
    source = html.unescape(re.sub(r"<[^>]+>", " ", source))
    relationships: dict[str, set[str]] = {}
    pattern = re.compile(
        r"[Tt]he\s+patch\s+for\s+(CVE-\d{4}-\d{4,})\s+also\s+addresses\s+(.{1,1000}?)(?:\.|$)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(source):
        primary = match.group(1).upper()
        extras = _cves(match.group(2))
        if extras:
            relationships.setdefault(primary, set()).update(extras)
    result = list(mappings)
    seen = {(m["cve"].upper(), m["product"], m["supported_versions"]) for m in result}
    for mapping in mappings:
        for extra in relationships.get(mapping["cve"].upper(), set()):
            key = (extra, mapping["product"], mapping["supported_versions"])
            if key not in seen:
                seen.add(key)
                result.append({"cve": extra, "product": mapping["product"], "supported_versions": mapping["supported_versions"]})
    return result


def _supported_versions(description: str) -> str:
    import re

    match = re.search(
        r"(?:[Tt]he )?[Ss]upported versions? (?:that (?:are|is) )?affected (?:are|is) (.+?)(?:\.\s+(?:Easily|Difficult|Successful|This)|\.$)",
        description,
    )
    return match.group(1).strip() if match else ""


def _verbose_url(url: str) -> str:
    return url[:-5] + "verbose.html" if url.endswith(".html") else url + "verbose.html"


def _cves(value: str) -> list[str]:
    import re

    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", value, re.IGNORECASE)))


def _is_cve_header(value: str) -> bool:
    return value.casefold().strip() in {"cve id", "cve#"}


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        pragma foreign_keys = on;
        create table if not exists schema_version (version integer primary key);
        create table if not exists source_document (
            advisory_url text primary key,
            rss_guid text not null,
            advisory_title text not null,
            source_type text not null check (source_type in ('CPU','CSPU','SECURITY_ALERT')),
            published_on text not null,
            parser_version integer not null default 1,
            content_sha256 text not null,
            fetched_at text not null,
            parse_status text not null,
            mapping_count integer not null,
            last_error text
        );
        create table if not exists cve_mapping (
            cve text not null,
            product text not null,
            supported_versions text not null,
            advisory_url text not null references source_document(advisory_url),
            first_seen_at text not null,
            last_seen_at text not null,
            primary key (cve, product, supported_versions, advisory_url)
        );
        insert or ignore into schema_version(version) values (1);
        create index if not exists cve_mapping_cve_ix on cve_mapping(cve);
        """
    )
    columns = {row[1] for row in connection.execute("pragma table_info(source_document)")}
    if "parser_version" not in columns:
        connection.execute("alter table source_document add column parser_version integer not null default 1")
    return connection


def _fetch(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "oracle-cve-ledger/1.0", "Accept": "text/html,application/xml"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise LedgerError(f"{url} returned HTTP {response.status}")
            return response.read()
    except LedgerError:
        raise
    except Exception as exc:
        raise LedgerError(f"Unable to download {url}: {exc}") from exc


def sync_ledger(
    database: Path,
    map_html: Path,
    *,
    retention_years: int,
    timeout: float,
    rss_file: Path | None = None,
    today: date | None = None,
    progress: Callable[[str], None] | None = None,
) -> tuple[int, int]:
    """Synchronise the rolling ledger, then atomically write its HTML view."""
    if retention_years <= 0:
        raise LedgerError("Retention years must be greater than zero")
    now = datetime.now(timezone.utc)
    today = today or now.date()
    cutoff = date(today.year - retention_years, today.month, today.day)
    _emit(progress, f"Reading Oracle security RSS ({'local file ' + str(rss_file) if rss_file else ORACLE_SECURITY_RSS_URL})")
    rss_raw = rss_file.read_bytes() if rss_file else _fetch(ORACLE_SECURITY_RSS_URL, timeout)
    items = parse_rss(rss_raw, cutoff=cutoff)
    if not items:
        raise LedgerError("Oracle RSS contained no eligible advisories")
    _emit(progress, f"Found {len(items)} eligible CPU, CSPU, or Security Alert advisories since {cutoff.isoformat()}.")
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = _connect(database)
    changed = 0
    try:
        for index, item in enumerate(items, start=1):
            _emit(progress, f"[{index}/{len(items)}] Downloading {item['source_type']} {item['published_on']}: {item['title']}")
            raw = _fetch(item["url"], timeout)
            mappings = parse_risk_matrices(raw)
            source_bytes = raw
            if not mappings:
                _emit(progress, f"[{index}/{len(items)}] Direct matrix not found; trying text-form matrix {_verbose_url(item['url'])}")
                verbose_raw = _fetch(_verbose_url(item["url"]), timeout)
                mappings = parse_verbose_risk_matrices(verbose_raw)
                source_bytes += verbose_raw
            mappings = expand_additional_cves(raw, mappings)
            digest = hashlib.sha256(source_bytes).hexdigest()
            current = connection.execute(
                "select content_sha256, parse_status, parser_version from source_document where advisory_url = ?", (item["url"],)
            ).fetchone()
            if current and current["content_sha256"] == digest and current["parse_status"] == "success" and current["parser_version"] == PARSER_VERSION:
                connection.execute("update source_document set fetched_at = ? where advisory_url = ?", (now.isoformat(), item["url"]))
                _emit(progress, f"[{index}/{len(items)}] Unchanged; retained existing {current['parse_status']} mappings.")
                continue
            if not mappings:
                raise LedgerError(f"No CVE risk-matrix rows found in {item['url']} or its text-form matrix")
            with connection:
                connection.execute("delete from cve_mapping where advisory_url = ?", (item["url"],))
                connection.execute(
                    """insert into source_document(advisory_url,rss_guid,advisory_title,source_type,published_on,parser_version,content_sha256,fetched_at,parse_status,mapping_count,last_error)
                    values(:url,:guid,:title,:source_type,:published_on,:parser_version,:digest,:fetched_at,'success',:mapping_count,null)
                    on conflict(advisory_url) do update set rss_guid=excluded.rss_guid, advisory_title=excluded.advisory_title,
                    source_type=excluded.source_type, published_on=excluded.published_on, parser_version=excluded.parser_version, content_sha256=excluded.content_sha256,
                    fetched_at=excluded.fetched_at, parse_status=excluded.parse_status, mapping_count=excluded.mapping_count, last_error=null""",
                    {**item, "parser_version": PARSER_VERSION, "digest": digest, "fetched_at": now.isoformat(), "mapping_count": len(mappings)},
                )
                connection.executemany(
                    "insert into cve_mapping(cve,product,supported_versions,advisory_url,first_seen_at,last_seen_at) values(?,?,?,?,?,?)",
                    [(m["cve"].upper(), m["product"], m["supported_versions"], item["url"], now.isoformat(), now.isoformat()) for m in mappings],
                )
            changed += 1
            _emit(progress, f"[{index}/{len(items)}] Stored {len(mappings)} CVE/product mappings.")
        with connection:
            removed_mappings = connection.execute("delete from cve_mapping where advisory_url in (select advisory_url from source_document where published_on < ?)", (cutoff.isoformat(),)).rowcount
            removed_documents = connection.execute("delete from source_document where published_on < ?", (cutoff.isoformat(),)).rowcount
        _emit(progress, f"Retention pruning removed {removed_documents} advisory documents and {removed_mappings} mappings.")
        _emit(progress, f"Writing compatibility map {map_html}")
        export_map_html(connection, map_html, generated_at=now, retention_years=retention_years)
        _emit(progress, "Compatibility map written successfully.")
        return len(items), changed
    finally:
        connection.close()


def export_map_html(connection: sqlite3.Connection, destination: Path, *, generated_at: datetime, retention_years: int) -> None:
    """Write the legacy-parser-compatible map atomically."""
    rows = connection.execute(
        """select m.cve, m.product, m.supported_versions, s.advisory_title, m.advisory_url
           from cve_mapping m join source_document s using(advisory_url)
           order by m.cve, m.product, s.advisory_title"""
    ).fetchall()
    if not rows:
        raise LedgerError("Ledger has no CVE mappings to export")
    body = []
    for row in rows:
        product = row["product"]
        body.append(
            "<tr><td>{}</td><td>{}</td><td><a href=\"{}\">{}</a></td></tr>".format(
                html.escape(row["cve"]), html.escape(product), html.escape(row["advisory_url"], quote=True), html.escape(row["advisory_title"])
            )
        )
    document = """<!doctype html><html><head><meta charset=\"utf-8\"><title>Local Oracle CVE to Advisory Map</title></head><body>
<p>This local Oracle advisory ledger was updated to include the rolling {years}-year RSS-derived coverage. Generated {generated}.</p>
<table><thead><tr><th>Vulnerability Identifier</th><th>Product [Product ID]</th><th>Advisory</th></tr></thead><tbody>{rows}</tbody></table>
</body></html>\n""".format(years=retention_years, generated=generated_at.isoformat(), rows="".join(body))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=destination.parent, delete=False) as temporary:
        temporary.write(document)
        temporary_path = Path(temporary.name)
    temporary_path.replace(destination)


def rebuild_ledger(database: Path, map_html: Path, **kwargs: Any) -> tuple[int, int]:
    """Build a fresh database and replace the active one only after success."""
    database.parent.mkdir(parents=True, exist_ok=True)
    staging = database.with_name(f".{database.name}.rebuild")
    if staging.exists():
        staging.unlink()
    staging_map = map_html.with_name(f".{map_html.name}.rebuild")
    try:
        _emit(kwargs.get("progress"), f"Rebuilding ledger in staging database {staging}")
        result = sync_ledger(staging, staging_map, **kwargs)
        if database.exists():
            backup = database.with_name(f"{database.name}.{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.bak")
            shutil.copy2(database, backup)
            _emit(kwargs.get("progress"), f"Backed up active ledger to {backup}")
        staging.replace(database)
        staging_map.replace(map_html)
        _emit(kwargs.get("progress"), "Rebuild validation succeeded; staging ledger and map are now active.")
        return result
    finally:
        staging.unlink(missing_ok=True)
        staging_map.unlink(missing_ok=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("sync", "rebuild"))
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--map-html", type=Path, required=True)
    parser.add_argument("--retention-years", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--rss-file", type=Path, help="Use a saved RSS XML file (testing/offline use).")
    parser.add_argument("--verbose", action="store_true", help="Print advisory-by-advisory progress.")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        operation = rebuild_ledger if args.command == "rebuild" else sync_ledger
        progress = print if args.verbose else None
        discovered, changed = operation(args.database, args.map_html, retention_years=args.retention_years, timeout=args.timeout, rss_file=args.rss_file, progress=progress)
        if args.verbose:
            print(f"Oracle CVE ledger {args.command} complete: {discovered} advisory documents discovered; {changed} parsed or updated.")
        return 0
    except LedgerError as exc:
        print(f"Oracle CVE ledger failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
