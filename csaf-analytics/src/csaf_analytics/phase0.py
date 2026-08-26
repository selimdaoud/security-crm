#!/usr/bin/env python3
"""Generate Phase 0 CSAF findings and enrichment exchange files.

The program deliberately has no Oracle or APEX dependency.  It reads one CSAF
2.0 JSON document and creates a UTC timestamped directory containing:

* <source>.json    exact source bytes under the published URL basename
* findings.csv     immutable advisory/CVE/product facts
* enrichment.csv   dated EPSS, CISA KEV and NVD exploit-reference observations
* report-data.json versioned CVE-level read model for HTML/APEX
* report-<advisory>.html standalone report rendered from report-data.json
* manifest.json    batch identity, counts, hashes and source statuses
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import html
import io
import json
import multiprocessing
import os
import re
import shutil
import sys
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import Iterable, Mapping
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_GITHUB_URL = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
    "{year}/epss_scores-{date}.csv.gz"
)
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
KEV_GITHUB_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_BATCH_SIZE = 100
NVD_REQUEST_INTERVAL = 0.7
USER_AGENT = "csaf-phase0/1.0"
REPORT_SCHEMA_VERSION = 8
PRIORITIZATION_VERSION = 2
HIGH_EPSS_PERCENTILE = 0.95
BUNDLE_FORMAT_VERSION = 3
GENERATED_ARTIFACT_FILENAMES = {
    "manifest.json",
    "report-data.json",
    "findings.csv",
    "enrichment.csv",
}

AFFECTED_STATUSES = {
    "known_affected",
    "first_affected",
    "last_affected",
    "under_investigation",
}

FINDING_COLUMNS = [
    "batch_id",
    "vendor",
    "advisory_reference",
    "advisory_revision",
    "advisory_title",
    "advisory_url",
    "source_hash",
    "source_filename",
    "source_url",
    "published_date",
    "revised_date",
    "tlp",
    "cve",
    "description",
    "component_name",
    "third_party_component",
    "product_id",
    "product_family",
    "product_name",
    "product_version",
    "cpe",
    "status",
    "vex_justification",
    "cvss_score",
    "cvss_vector",
    "cvss_source",
    "av",
    "pr",
    "ui",
    "scope_value",
    "confidentiality",
    "integrity",
    "availability",
    "pre_auth",
    "scope_changed",
    "high_impact",
    "fix_url",
    "fix_note",
    "fix_category",
    "vendor_bug_id",
]

ENRICHMENT_COLUMNS = [
    "batch_id",
    "cve",
    "observed_date",
    "epss",
    "epss_percentile",
    "kev",
    "kev_added",
    "kev_due",
    "kev_ransomware",
    "public_exploits",
    "exploit_url",
    "epss_status",
    "kev_status",
    "exploit_status",
]

STATUS_PRECEDENCE = [
    "known_affected",
    "first_affected",
    "last_affected",
    "under_investigation",
    "fixed",
    "first_fixed",
    "known_not_affected",
]


class Phase0Error(RuntimeError):
    """Raised for an invalid source document or unsafe output operation."""


ProgressCallback = Callable[[str, str], None]


def _emit(progress: ProgressCallback | None, level: str, message: str) -> None:
    if progress is not None:
        progress(level, message)


def _display_source(source: str) -> str:
    """Return a log-safe source label without URL query strings or fragments."""
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        return urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
    return str(Path(source).expanduser())


def _validate_source_filename(filename: str) -> str:
    """Validate a source basename before using it as an output filename."""
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or any(ord(character) < 32 for character in filename)
    ):
        raise Phase0Error("CSAF URL must end with a safe JSON filename")
    if not filename.casefold().endswith(".json"):
        raise Phase0Error("CSAF URL must end with a .json filename")
    if filename.casefold() in GENERATED_ARTIFACT_FILENAMES:
        raise Phase0Error(
            f"CSAF filename conflicts with a generated artifact: {filename}"
        )
    return filename


def _source_filename_from_url(source_url: str) -> str:
    """Return the decoded published basename from an HTTP(S) source URL."""
    parsed = urllib.parse.urlparse(source_url)
    encoded_name = parsed.path.rsplit("/", 1)[-1]
    return _validate_source_filename(urllib.parse.unquote(encoded_name))


def _report_filename(source_filename: str) -> str:
    """Derive the standalone report name from the published CSAF basename."""
    stem = source_filename[:-5]
    if stem.casefold().endswith("csaf") and len(stem) > 4:
        stem = stem[:-4]
    return f"report-{stem}.html"


def _https_url(value: str) -> str:
    """Argparse type enforcing the public CLI's remote-source contract."""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise argparse.ArgumentTypeError("--url must be a valid HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise argparse.ArgumentTypeError("--url must not contain credentials")
    try:
        _source_filename_from_url(value)
    except Phase0Error as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value


def _urlopen_worker(
    connection: Any,
    url: str,
    headers: dict[str, str],
    timeout: float,
) -> None:
    """Read one URL in an isolated process so the parent can enforce a deadline."""
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            connection.send((True, response.status, response.read(), ""))
    except BaseException as exc:
        connection.send((False, 0, b"", f"{type(exc).__name__}: {exc}"))
    finally:
        connection.close()


def _open_url_with_deadline(
    url: str,
    headers: dict[str, str],
    timeout: float,
    label: str,
) -> tuple[int, bytes]:
    available_methods = multiprocessing.get_all_start_methods()
    context = multiprocessing.get_context(
        "fork" if "fork" in available_methods else "spawn"
    )
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_urlopen_worker,
        args=(send, url, headers, timeout),
        daemon=True,
    )
    process.start()
    send.close()
    try:
        if not receive.poll(timeout):
            process.terminate()
            process.join(timeout=1)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join(timeout=1)
            raise TimeoutError(f"{label} exceeded the {timeout:g}s hard timeout")
        succeeded, status, data, error = receive.recv()
        process.join(timeout=1)
        if not succeeded:
            raise Phase0Error(error)
        return int(status), bytes(data)
    finally:
        receive.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)


def _http_bytes(
    url: str,
    timeout: float,
    retries: int,
    progress: ProgressCallback | None = None,
    label: str = "remote source",
    accept: str = "*/*",
    extra_headers: Mapping[str, str] | None = None,
) -> bytes:
    last_error: Exception | None = None
    headers = {"Accept": accept, "User-Agent": USER_AGENT}
    if extra_headers:
        headers.update(extra_headers)
    for attempt in range(retries + 1):
        _emit(
            progress,
            "INFO",
            f"Downloading {label} (attempt {attempt + 1}/{retries + 1}, "
            f"timeout {timeout:g}s)",
        )
        try:
            status, data = _open_url_with_deadline(url, headers, timeout, label)
            if status != 200:
                raise Phase0Error(
                    f"HTTP {status} returned by {_display_source(url)}"
                )
            _emit(progress, "INFO", f"Downloaded {label}: {len(data):,} bytes")
            return data
        except Exception as exc:  # source failure is reported in the artefacts
            last_error = exc
            _emit(progress, "WARN", f"{label} attempt failed: {exc}")
            if attempt < retries:
                time.sleep(2**attempt)
    raise Phase0Error(
        f"Unable to read {_display_source(url)} after {retries + 1} "
        f"attempt(s): {last_error}"
    )


def _http_json(
    url: str,
    timeout: float,
    retries: int,
    progress: ProgressCallback | None = None,
    label: str = "remote JSON source",
    extra_headers: Mapping[str, str] | None = None,
) -> Any:
    raw = _http_bytes(
        url,
        timeout,
        retries,
        progress,
        label,
        accept="application/json",
        extra_headers=extra_headers,
    )
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Phase0Error(f"Invalid JSON returned by {label}: {exc}") from exc


def _read_source(source: str, timeout: float) -> tuple[bytes, str, str]:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        request = urllib.request.Request(
            source,
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if response.status != 200:
                    raise Phase0Error(
                        f"CSAF source returned HTTP {response.status}: {source}"
                    )
                raw = response.read()
        except Phase0Error:
            raise
        except Exception as exc:
            raise Phase0Error(f"Unable to read CSAF source {source}: {exc}") from exc
        filename = _source_filename_from_url(source)
        return raw, filename, source

    path = Path(source).expanduser()
    if not path.is_file():
        raise Phase0Error(f"CSAF file does not exist: {path}")
    return path.read_bytes(), _validate_source_filename(path.name), ""


def _load_json_bytes(
    raw: bytes,
    label: str,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as utf8_error:
        try:
            text = raw.decode("cp1252")
        except UnicodeDecodeError:
            raise Phase0Error(f"Invalid JSON in {label}: {utf8_error}") from utf8_error
        _emit(
            progress,
            "WARN",
            "CSAF source is not valid UTF-8; decoded as Windows-1252 "
            f"for compatibility (invalid byte at offset {utf8_error.start})",
        )
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Phase0Error(f"Invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise Phase0Error(f"Expected a JSON object in {label}")
    return value


def _safe_component(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    cleaned = cleaned.strip("._-")
    return cleaned[:120] or "advisory"


def _iso_date(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip()
    match = re.match(r"^(\d{4}-\d{2}-\d{2})", text)
    return match.group(1) if match else ""


def _walk_product_branches(
    branches: Iterable[Any],
    products: dict[str, dict[str, str]],
    inherited: Mapping[str, str] | None = None,
) -> None:
    inherited = dict(inherited or {})
    for branch_value in branches:
        if not isinstance(branch_value, dict):
            continue
        branch = branch_value
        context = dict(inherited)
        category = str(branch.get("category") or "").strip()
        name = str(branch.get("name") or "").strip()
        if category and name:
            context[category] = name

        product = branch.get("product")
        if isinstance(product, dict) and product.get("product_id"):
            product_id = str(product["product_id"]).strip()
            helper = product.get("product_identification_helper") or {}
            if not isinstance(helper, dict):
                helper = {}
            products[product_id] = {
                "product_id": product_id,
                "family": context.get("product_family", ""),
                "name": context.get("product_name")
                or str(product.get("name") or name).strip(),
                "version": context.get("product_version", ""),
                "cpe": str(helper.get("cpe") or "").strip(),
            }

        nested = branch.get("branches")
        if isinstance(nested, list):
            _walk_product_branches(nested, products, context)


def _extract_products(document: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    products: dict[str, dict[str, str]] = {}
    tree = document.get("product_tree") or {}
    if not isinstance(tree, dict):
        return products

    branches = tree.get("branches")
    if isinstance(branches, list):
        _walk_product_branches(branches, products)

    full_names = tree.get("full_product_names")
    if isinstance(full_names, list):
        for value in full_names:
            if not isinstance(value, dict) or not value.get("product_id"):
                continue
            product_id = str(value["product_id"]).strip()
            helper = value.get("product_identification_helper") or {}
            if not isinstance(helper, dict):
                helper = {}
            products.setdefault(
                product_id,
                {
                    "product_id": product_id,
                    "family": "",
                    "name": str(value.get("name") or "").strip(),
                    "version": "",
                    "cpe": str(helper.get("cpe") or "").strip(),
                },
            )

    relationships = tree.get("relationships")
    if isinstance(relationships, list):
        for value in relationships:
            if not isinstance(value, dict):
                continue
            full_name = value.get("full_product_name")
            if not isinstance(full_name, dict) or not full_name.get("product_id"):
                continue
            product_id = str(full_name["product_id"]).strip()
            products.setdefault(
                product_id,
                {
                    "product_id": product_id,
                    "family": "",
                    "name": str(full_name.get("name") or "").strip(),
                    "version": "",
                    "cpe": "",
                },
            )
    return products


def _extract_groups(document: Mapping[str, Any]) -> dict[str, set[str]]:
    groups: dict[str, set[str]] = {}
    tree = document.get("product_tree") or {}
    if not isinstance(tree, dict):
        return groups
    for value in tree.get("product_groups") or []:
        if not isinstance(value, dict) or not value.get("group_id"):
            continue
        groups[str(value["group_id"])] = {
            str(item) for item in value.get("product_ids") or [] if item
        }
    return groups


def _target_products(
    value: Mapping[str, Any], groups: Mapping[str, set[str]]
) -> set[str]:
    result = {str(item) for item in value.get("product_ids") or [] if item}
    result.update(str(item) for item in value.get("products") or [] if item)
    for group_id in value.get("group_ids") or []:
        result.update(groups.get(str(group_id), set()))
    return result


def _description(vulnerability: Mapping[str, Any]) -> str:
    notes = vulnerability.get("notes") or []
    preferred = ("description", "summary", "details", "general")
    for category in preferred:
        for note in notes:
            if (
                isinstance(note, dict)
                and str(note.get("category") or "") == category
                and note.get("text")
            ):
                return str(note["text"]).strip()
    return str(vulnerability.get("title") or "").strip()


def _component_values(description: str) -> tuple[str, str]:
    """Extract Oracle's component label and a nested third-party component.

    Oracle descriptions commonly contain ``(component: Security (Log4j))``.
    A small balanced-parenthesis parser is used because a regular expression
    alone would stop at the inner closing parenthesis.
    """
    marker = re.search(r"\(\s*component\s*:\s*", description, re.IGNORECASE)
    if not marker:
        return "", ""
    depth = 1
    end = len(description)
    for index in range(marker.end(), len(description)):
        character = description[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    component = description[marker.end() : end].strip()
    nested = re.search(r"\(([^()]*)\)\s*$", component)
    third_party = nested.group(1).strip() if nested else ""
    return component, third_party


def _description_cvss(description: str) -> dict[str, Any]:
    """Extract an explicitly labelled CVSS score/vector as a fallback."""
    score_match = re.search(
        r"\bCVSS(?:\s+\d(?:\.\d)?)?\s+Base\s+Score\s*[:=]?\s*"
        r"(10(?:\.0+)?|[0-9](?:\.\d+)?)\b",
        description,
        re.IGNORECASE,
    )
    vector_match = re.search(
        r"\b(CVSS:\d(?:\.\d)?/[A-Za-z0-9:/_-]+)", description
    )
    return {
        "baseScore": score_match.group(1) if score_match else "",
        "vectorString": vector_match.group(1) if vector_match else "",
    }


def _status_map(vulnerability: Mapping[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    status = vulnerability.get("product_status") or {}
    if not isinstance(status, dict):
        return result
    for status_name in reversed(STATUS_PRECEDENCE):
        for product_id in status.get(status_name) or []:
            result[str(product_id)] = status_name
    return result


def _cvss_map(
    vulnerability: Mapping[str, Any], groups: Mapping[str, set[str]]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for score in vulnerability.get("scores") or []:
        if not isinstance(score, dict):
            continue
        cvss = (
            score.get("cvss_v3_1")
            or score.get("cvss_v3_0")
            or score.get("cvss_v3")
            or score.get("cvss_v2")
            or {}
        )
        if not isinstance(cvss, dict):
            continue
        for product_id in _target_products(score, groups):
            result[product_id] = cvss
    return result


def _flag_map(
    vulnerability: Mapping[str, Any], groups: Mapping[str, set[str]]
) -> dict[str, str]:
    result: dict[str, str] = {}
    for flag in vulnerability.get("flags") or []:
        if not isinstance(flag, dict):
            continue
        label = str(flag.get("label") or "").strip()
        for product_id in _target_products(flag, groups):
            result[product_id] = label
    return result


def _remediation_map(
    vulnerability: Mapping[str, Any], groups: Mapping[str, set[str]]
) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for remediation in vulnerability.get("remediations") or []:
        if not isinstance(remediation, dict):
            continue
        details = str(remediation.get("details") or "")
        note_match = re.search(
            r"(?:Doc(?:ument)?\s*ID|MOS\s*(?:note)?)\s*[:#-]?\s*"
            r"(\d{5,}(?:\.\d+)?)",
            details,
            flags=re.IGNORECASE,
        )
        value = {
            "url": str(remediation.get("url") or "").strip(),
            "note": note_match.group(1) if note_match else "",
            "category": str(remediation.get("category") or "").strip(),
        }
        targets = _target_products(remediation, groups)
        if not targets:
            continue
        for product_id in targets:
            result.setdefault(product_id, value)
    return result


def _vector_parts(vector: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        if key in {"AV", "PR", "UI", "S", "C", "I", "A"}:
            result[key] = value
    return result


def _tracking_metadata(
    document: Mapping[str, Any], source_hash: str, filename: str, source_url: str
) -> dict[str, str]:
    metadata = document.get("document") or {}
    if not isinstance(metadata, dict):
        raise Phase0Error("CSAF document is missing the required 'document' object")
    tracking = metadata.get("tracking") or {}
    publisher = metadata.get("publisher") or {}
    distribution = metadata.get("distribution") or {}
    tlp = distribution.get("tlp") or {} if isinstance(distribution, dict) else {}
    if not isinstance(tracking, dict):
        tracking = {}
    reference = str(tracking.get("id") or "").strip()
    revision = str(tracking.get("version") or "").strip()
    if not reference or not revision:
        raise Phase0Error("CSAF document requires document.tracking.id and version")
    references = metadata.get("references") or []
    advisory_url = ""
    if isinstance(references, list):
        candidates = [
            value
            for value in references
            if isinstance(value, dict)
            and str(value.get("url") or "").strip()
            and str(value.get("category") or "").casefold() != "self"
        ]
        if candidates:
            preferred = next(
                (
                    value
                    for value in candidates
                    if "advisory" in str(value.get("summary") or "").casefold()
                    or "html" in str(value.get("summary") or "").casefold()
                ),
                candidates[0],
            )
            advisory_url = str(preferred.get("url") or "").strip()
    return {
        "vendor": str(publisher.get("name") or "Unknown").strip()
        if isinstance(publisher, dict)
        else "Unknown",
        "advisory_reference": reference,
        "advisory_revision": revision,
        "advisory_title": str(metadata.get("title") or "").strip(),
        "advisory_url": advisory_url,
        "source_hash": source_hash,
        "source_filename": filename,
        "source_url": source_url,
        "published_date": _iso_date(tracking.get("initial_release_date")),
        "revised_date": _iso_date(tracking.get("current_release_date")),
        "tlp": str(tlp.get("label") or "").strip()
        if isinstance(tlp, dict)
        else "",
    }


def extract_findings(
    document: Mapping[str, Any],
    batch_id: str,
    source_hash: str,
    filename: str,
    source_url: str,
) -> list[dict[str, Any]]:
    metadata = _tracking_metadata(document, source_hash, filename, source_url)
    products = _extract_products(document)
    groups = _extract_groups(document)
    rows: list[dict[str, Any]] = []

    vulnerabilities = document.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        raise Phase0Error("CSAF vulnerabilities must be an array")
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        cve = str(vulnerability.get("cve") or vulnerability.get("id") or "").strip()
        if not cve:
            continue
        statuses = _status_map(vulnerability)
        scores = _cvss_map(vulnerability, groups)
        flags = _flag_map(vulnerability, groups)
        remediations = _remediation_map(vulnerability, groups)
        description = _description(vulnerability)
        component_name, third_party_component = _component_values(description)
        description_score = _description_cvss(description)
        for product_id, status in sorted(statuses.items()):
            product = products.get(
                product_id,
                {
                    "product_id": product_id,
                    "family": "",
                    "name": product_id,
                    "version": "",
                    "cpe": "",
                },
            )
            score = scores.get(product_id, {})
            cvss_source = "csaf_scores" if score else ""
            if not score and status != "known_not_affected" and any(
                description_score.values()
            ):
                score = description_score
                cvss_source = "description_fallback"
            vector = str(
                score.get("vectorString") or score.get("vector_string") or ""
            ).strip()
            parts = _vector_parts(vector)
            remediation = remediations.get(product_id, {})
            row: dict[str, Any] = {
                **metadata,
                "batch_id": batch_id,
                "cve": cve.upper(),
                "description": description,
                "component_name": component_name,
                "third_party_component": third_party_component,
                "product_id": product_id,
                "product_family": product["family"],
                "product_name": product["name"],
                "product_version": product["version"],
                "cpe": product["cpe"],
                "status": status,
                "vex_justification": flags.get(product_id, ""),
                "cvss_score": score.get("baseScore")
                if score.get("baseScore") is not None
                else score.get("base_score", ""),
                "cvss_vector": vector,
                "cvss_source": cvss_source,
                "av": parts.get("AV", ""),
                "pr": parts.get("PR", ""),
                "ui": parts.get("UI", ""),
                "scope_value": parts.get("S", ""),
                "confidentiality": parts.get("C", ""),
                "integrity": parts.get("I", ""),
                "availability": parts.get("A", ""),
                "pre_auth": int(
                    parts.get("AV") == "N"
                    and parts.get("PR") == "N"
                    and parts.get("UI") == "N"
                ),
                "scope_changed": int(parts.get("S") == "C"),
                "high_impact": int(
                    parts.get("C") == "H" or parts.get("I") == "H"
                ),
                "fix_url": remediation.get("url", ""),
                "fix_note": remediation.get("note", ""),
                "fix_category": remediation.get("category", ""),
                "vendor_bug_id": "",
            }
            rows.append(row)
    return rows


def _epss_values(
    cves: list[str],
    timeout: float,
    retries: int,
    local_file: Path | None,
    progress: ProgressCallback | None,
    observed_date: str,
) -> tuple[dict[str, dict[str, Any]], str, str]:
    try:
        if local_file:
            raw = local_file.read_bytes()
            source_label = str(local_file)
        else:
            github_url = EPSS_GITHUB_URL.format(
                year=observed_date[:4], date=observed_date
            )
            try:
                raw = _http_bytes(
                    github_url,
                    timeout,
                    retries,
                    progress,
                    "FIRST EPSS GitHub daily CSV",
                    accept="text/csv, application/gzip, */*",
                )
                source_label = "FIRST EPSS GitHub daily CSV"
            except Exception as github_error:
                _emit(
                    progress,
                    "WARN",
                    "FIRST EPSS GitHub daily file unavailable; trying stable feed",
                )
                raw = _http_bytes(
                    EPSS_CSV_URL,
                    timeout,
                    0,
                    progress,
                    "FIRST EPSS stable daily CSV",
                    accept="text/csv, application/gzip, */*",
                )
                source_label = (
                    f"FIRST EPSS stable daily CSV; GitHub error: {github_error}"
                )

        values: dict[str, dict[str, Any]] = {}
        if raw.lstrip().startswith(b"{"):
            payload = _load_json_bytes(raw, source_label)
            if not isinstance(payload, dict):
                raise Phase0Error("EPSS response is not a JSON object")
            for item in payload.get("data") or []:
                if isinstance(item, dict) and item.get("cve"):
                    values[str(item["cve"]).upper()] = item
        else:
            if raw.startswith(b"\x1f\x8b"):
                raw = gzip.decompress(raw)
            text = raw.decode("utf-8-sig")
            data_lines = (line for line in io.StringIO(text) if not line.startswith("#"))
            wanted = set(cves)
            for item in csv.DictReader(data_lines):
                cve = str(item.get("cve") or "").upper()
                if cve in wanted:
                    values[cve] = item
        missing = sorted(set(cves) - set(values))
        match_message = f"matched {len(values):,}/{len(cves):,} requested CVEs"
        if missing:
            shown = ", ".join(missing[:10])
            remainder = len(missing) - min(len(missing), 10)
            match_message += f"; no score for: {shown}"
            if remainder:
                match_message += f" (+{remainder:,} more)"
        return values, "success", match_message
    except Exception as exc:
        return {}, "error", str(exc)


def _kev_values(
    timeout: float,
    retries: int,
    local_file: Path | None,
    progress: ProgressCallback | None,
) -> tuple[dict[str, dict[str, Any]], str, str]:
    try:
        if local_file:
            payload = _load_json_bytes(local_file.read_bytes(), str(local_file))
            source_name = "local CISA KEV file"
        else:
            try:
                payload = _http_json(
                    KEV_GITHUB_URL,
                    timeout,
                    retries,
                    progress,
                    "CISA KEV GitHub mirror",
                )
                source_name = "CISA KEV GitHub mirror"
            except Exception as github_error:
                _emit(
                    progress,
                    "WARN",
                    "CISA KEV GitHub mirror unavailable; trying cisa.gov",
                )
                payload = _http_json(
                    KEV_URL,
                    timeout,
                    0,
                    progress,
                    "CISA KEV canonical feed",
                )
                source_name = f"CISA KEV canonical feed; mirror error: {github_error}"
        if not isinstance(payload, dict):
            raise Phase0Error("KEV response is not a JSON object")
        values = {
            str(item["cveID"]).upper(): item
            for item in payload.get("vulnerabilities") or []
            if isinstance(item, dict) and item.get("cveID")
        }
        return values, "success", f"loaded {len(values):,} entries from {source_name}"
    except Exception as exc:
        return {}, "error", str(exc)


def _nvd_exploit_values(
    cves: list[str],
    timeout: float,
    retries: int,
    local_file: Path | None,
    api_key: str | None,
    progress: ProgressCallback | None,
) -> tuple[dict[str, list[str]], str, str]:
    """Return NVD references tagged Exploit, keyed by CVE.

    An empty list is a successful negative observation, not proof that no public
    exploit exists outside NVD. The API key is sent only in the HTTP header.
    """
    try:
        payloads: list[Any] = []
        if local_file:
            payloads.append(_load_json_bytes(local_file.read_bytes(), str(local_file)))
            source_name = "local NVD file"
        else:
            if not api_key:
                return {}, "unavailable", "NVD_API_KEY is not configured"
            batches = [
                cves[index : index + NVD_BATCH_SIZE]
                for index in range(0, len(cves), NVD_BATCH_SIZE)
            ]
            headers = {"apiKey": api_key}
            for batch_number, batch in enumerate(batches, start=1):
                query = urllib.parse.urlencode({"cveIds": ",".join(batch)})
                payloads.append(
                    _http_json(
                        f"{NVD_CVE_API_URL}?{query}",
                        timeout,
                        retries,
                        progress,
                        f"NVD CVE batch {batch_number}/{len(batches)}",
                        extra_headers=headers,
                    )
                )
                if batch_number < len(batches):
                    time.sleep(NVD_REQUEST_INTERVAL)
            source_name = f"NVD CVE API ({len(batches):,} batch(es))"

        values: dict[str, list[str]] = {cve: [] for cve in cves}
        returned_cves = 0
        for payload in payloads:
            if not isinstance(payload, dict):
                raise Phase0Error("NVD response is not a JSON object")
            vulnerabilities = payload.get("vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                raise Phase0Error("NVD vulnerabilities is not an array")
            for wrapper in vulnerabilities:
                if not isinstance(wrapper, dict):
                    continue
                cve_item = wrapper.get("cve")
                if not isinstance(cve_item, dict) or not cve_item.get("id"):
                    continue
                cve = str(cve_item["id"]).upper()
                if cve not in values:
                    continue
                returned_cves += 1
                urls = {
                    str(reference.get("url") or "").strip()
                    for reference in cve_item.get("references") or []
                    if isinstance(reference, dict)
                    and any(
                        str(tag).casefold() == "exploit"
                        for tag in reference.get("tags") or []
                    )
                    and str(reference.get("url") or "").strip()
                }
                values[cve] = sorted(urls, key=lambda url: (len(url), url))
        exploit_cves = sum(bool(urls) for urls in values.values())
        exploit_references = sum(len(urls) for urls in values.values())
        message = (
            f"checked {returned_cves:,}/{len(cves):,} CVEs from {source_name}; "
            f"found {exploit_references:,} Exploit-tagged reference(s) across "
            f"{exploit_cves:,} CVE(s)"
        )
        return values, "success", message
    except Exception as exc:
        return {}, "error", str(exc)


def build_enrichment(
    cves: Iterable[str],
    batch_id: str,
    observed_date: str,
    timeout: float,
    retries: int,
    offline: bool,
    epss_file: Path | None = None,
    kev_file: Path | None = None,
    nvd_file: Path | None = None,
    nvd_api_key: str | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    cve_list = sorted(set(cves))
    if offline and not epss_file:
        epss, epss_status, epss_error = {}, "unavailable", "offline mode"
    else:
        epss, epss_status, epss_error = _epss_values(
            cve_list, timeout, retries, epss_file, progress, observed_date
        )
    if offline and not kev_file:
        kev, kev_status, kev_error = {}, "unavailable", "offline mode"
    else:
        kev, kev_status, kev_error = _kev_values(
            timeout, retries, kev_file, progress
        )
    if offline and not nvd_file:
        exploits, exploit_status, exploit_error = {}, "unavailable", "offline mode"
    else:
        exploits, exploit_status, exploit_error = _nvd_exploit_values(
            cve_list, timeout, retries, nvd_file, nvd_api_key, progress
        )

    rows: list[dict[str, Any]] = []
    for cve in cve_list:
        epss_item = epss.get(cve, {})
        kev_item = kev.get(cve, {})
        exploit_urls = exploits.get(cve, [])
        rows.append(
            {
                "batch_id": batch_id,
                "cve": cve,
                "observed_date": observed_date,
                "epss": epss_item.get("epss", ""),
                "epss_percentile": epss_item.get("percentile", ""),
                "kev": int(cve in kev) if kev_status == "success" else "",
                "kev_added": kev_item.get("dateAdded", ""),
                "kev_due": kev_item.get("dueDate", ""),
                "kev_ransomware": kev_item.get("knownRansomwareCampaignUse", ""),
                "public_exploits": len(exploit_urls)
                if exploit_status == "success"
                else "",
                "exploit_url": exploit_urls[0][:512] if exploit_urls else "",
                "epss_status": epss_status,
                "kev_status": kev_status,
                "exploit_status": exploit_status,
            }
        )
    statuses = {
        "epss": {"status": epss_status, "message": epss_error},
        "kev": {"status": kev_status, "message": kev_error},
        "public_exploits": {
            "status": exploit_status,
            "message": exploit_error,
        },
    }
    return rows, statuses


def _number_or_none(value: Any) -> float | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _integer_or_none(value: Any) -> int | None:
    number = _number_or_none(value)
    return int(number) if number is not None else None


def _decision_tier(cve: Mapping[str, Any]) -> tuple[int, str]:
    if cve.get("kev") is True:
        return 1, "KEV: confirmed exploitation"
    if (cve.get("public_exploits") or 0) > 0 and cve.get("pre_auth"):
        return 3, "NVD Exploit reference and pre-auth"
    if (cve.get("epss_percentile") or 0) >= HIGH_EPSS_PERCENTILE:
        probability = _number_or_none(cve.get("epss"))
        percentile = round(float(cve["epss_percentile"]) * 100)
        suffix = "th" if 10 <= percentile % 100 <= 20 else {
            1: "st",
            2: "nd",
            3: "rd",
        }.get(percentile % 10, "th")
        probability_text = (
            f"{probability:.1%} probability, " if probability is not None else ""
        )
        return (
            4,
            f"High EPSS: {probability_text}{percentile}{suffix} percentile",
        )
    if (cve.get("public_exploits") or 0) > 0:
        return 5, "NVD Exploit-tagged reference"
    if cve.get("pre_auth") and (cve.get("cvss_score") or 0) >= 9:
        return 6, "Critical pre-auth"
    if cve.get("pre_auth"):
        return 7, "Pre-auth"
    if cve.get("scope_changed"):
        return 8, "Scope changed"
    return 9, "Standard advisory cycle"


def _business_priority(tier: int) -> tuple[str, str]:
    if tier == 1:
        return "P1", "Confirmed Exploitation"
    if tier <= 5:
        return "P2", "Elevated Exploitation Signals"
    if tier <= 8:
        return "P3", "Elevated Technical Exposure"
    return "P4", "Standard Advisory"


def build_report_data(
    findings: list[dict[str, Any]],
    enrichment: list[dict[str, Any]],
    source_statuses: Mapping[str, Mapping[str, str]],
    execution_started_at: str,
) -> dict[str, Any]:
    """Build the versioned, CVE-level read model consumed by the HTML report."""
    if not findings:
        raise Phase0Error("Cannot build report data without findings")
    first = findings[0]
    enrich_by_cve = {str(row["cve"]): row for row in enrichment}
    affected = [
        row for row in findings if str(row.get("status")) in AFFECTED_STATUSES
    ]
    vex = [row for row in findings if row.get("status") == "known_not_affected"]

    by_cve: dict[str, list[dict[str, Any]]] = {}
    for row in affected:
        by_cve.setdefault(str(row["cve"]), []).append(row)
    vex_by_cve: dict[str, list[dict[str, Any]]] = {}
    for row in vex:
        vex_by_cve.setdefault(str(row["cve"]), []).append(row)

    def enrichment_values(cve: str) -> dict[str, Any]:
        enrichment_row = enrich_by_cve.get(cve, {})
        epss_status = str(enrichment_row.get("epss_status") or "unavailable")
        kev_status = str(enrichment_row.get("kev_status") or "unavailable")
        exploit_status = str(
            enrichment_row.get("exploit_status") or "unavailable"
        )
        return {
            "epss": _number_or_none(enrichment_row.get("epss"))
            if epss_status == "success"
            else None,
            "epss_percentile": _number_or_none(
                enrichment_row.get("epss_percentile")
            )
            if epss_status == "success"
            else None,
            "kev": bool(_integer_or_none(enrichment_row.get("kev")))
            if kev_status == "success"
            else None,
            "kev_added": str(enrichment_row.get("kev_added") or ""),
            "kev_due": str(enrichment_row.get("kev_due") or ""),
            "kev_ransomware": str(
                enrichment_row.get("kev_ransomware") or ""
            ),
            "public_exploits": _integer_or_none(
                enrichment_row.get("public_exploits")
            )
            if exploit_status == "success"
            else None,
            "exploit_url": str(enrichment_row.get("exploit_url") or ""),
            "source_statuses": {
                "epss": epss_status,
                "kev": kev_status,
                "public_exploits": exploit_status,
            },
        }

    def remediation_values(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str, str], dict[str, set[str]]] = {}
        for row in rows:
            url = str(row.get("fix_url") or "").strip()
            if not url:
                continue
            key = (
                url,
                str(row.get("fix_category") or "").strip(),
                str(row.get("fix_note") or "").strip(),
            )
            bucket = grouped.setdefault(
                key, {"product_ids": set(), "families": set()}
            )
            bucket["product_ids"].add(str(row.get("product_id") or ""))
            family = str(row.get("product_family") or "").strip()
            if family:
                bucket["families"].add(family)
        return [
            {
                "url": key[0],
                "category": key[1],
                "note": key[2],
                "product_count": len(values["product_ids"]),
                "families": sorted(values["families"]),
            }
            for key, values in sorted(
                grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])
            )
        ]

    cve_rows: list[dict[str, Any]] = []
    for cve, rows in sorted(by_cve.items()):
        vex_rows = vex_by_cve.get(cve, [])
        scored = [
            (score, row)
            for row in rows
            if (score := _number_or_none(row.get("cvss_score"))) is not None
        ]
        max_score, score_row = max(scored, key=lambda item: item[0]) if scored else (None, {})
        components = Counter(
            str(row.get("third_party_component") or "").strip()
            for row in rows
            if str(row.get("third_party_component") or "").strip()
        )
        component = (
            sorted(components.items(), key=lambda item: (-item[1], item[0]))[0][0]
            if components
            else ""
        )
        affected_product_count = len({str(row["product_id"]) for row in rows})
        vex_product_count = len({str(row["product_id"]) for row in vex_rows})
        cve_row: dict[str, Any] = {
            "cve": cve,
            "description": str(rows[0].get("description") or ""),
            "product_count": affected_product_count,
            "affected_product_count": affected_product_count,
            "vex_product_count": vex_product_count,
            "vex_state": "partial" if vex_rows else "none",
            "vex_justifications": sorted(
                {
                    str(row.get("vex_justification") or "Not specified")
                    for row in vex_rows
                }
            ),
            "remediations": remediation_values(rows),
            "families": sorted(
                {
                    str(row.get("product_family") or "").strip()
                    for row in rows
                    if str(row.get("product_family") or "").strip()
                }
            ),
            "third_party_component": component,
            "cvss_score": max_score,
            "cvss_vector": str(score_row.get("cvss_vector") or ""),
            "cvss_source": str(score_row.get("cvss_source") or ""),
            "pre_auth": any(str(row.get("pre_auth")) == "1" for row in rows),
            "scope_changed": any(
                str(row.get("scope_changed")) == "1" for row in rows
            ),
            "high_impact": any(
                str(row.get("high_impact")) == "1" for row in rows
            ),
            **enrichment_values(cve),
        }
        tier, reason = _decision_tier(cve_row)
        priority_code, priority_label = _business_priority(tier)
        cve_row["tier"] = tier
        cve_row["priority_code"] = priority_code
        cve_row["priority_label"] = priority_label
        cve_row["decision_reason"] = reason
        cve_rows.append(cve_row)

    for cve in sorted(set(vex_by_cve) - set(by_cve)):
        rows = vex_by_cve[cve]
        vex_product_count = len({str(row["product_id"]) for row in rows})
        cve_rows.append(
            {
                "cve": cve,
                "description": str(rows[0].get("description") or ""),
                "product_count": 0,
                "affected_product_count": 0,
                "vex_product_count": vex_product_count,
                "vex_state": "complete",
                "vex_justifications": sorted(
                    {
                        str(row.get("vex_justification") or "Not specified")
                        for row in rows
                    }
                ),
                "remediations": [],
                "families": sorted(
                    {
                        str(row.get("product_family") or "").strip()
                        for row in rows
                        if str(row.get("product_family") or "").strip()
                    }
                ),
                "third_party_component": "",
                "cvss_score": None,
                "cvss_vector": "",
                "cvss_source": "",
                "pre_auth": False,
                "scope_changed": False,
                "high_impact": False,
                "tier": None,
                "priority_code": None,
                "priority_label": None,
                "decision_reason": "Fully closed by VEX",
                **enrichment_values(cve),
            }
        )

    active_cve_rows = [row for row in cve_rows if row["vex_state"] != "complete"]

    findings_by_product: dict[str, list[dict[str, Any]]] = {}
    for row in findings:
        findings_by_product.setdefault(str(row["product_id"]), []).append(row)
    product_rows: list[dict[str, Any]] = []
    for product_id, rows in sorted(findings_by_product.items()):
        affected_rows = [
            row for row in rows if str(row.get("status")) in AFFECTED_STATUSES
        ]
        vex_rows = [row for row in rows if row.get("status") == "known_not_affected"]
        base = affected_rows[0] if affected_rows else rows[0]
        cve_details: list[dict[str, Any]] = []
        for row in affected_rows:
            cve = str(row["cve"])
            signals = enrichment_values(cve)
            decision_input = {
                "kev": signals["kev"],
                "public_exploits": signals["public_exploits"],
                "epss": signals["epss"],
                "epss_percentile": signals["epss_percentile"],
                "pre_auth": str(row.get("pre_auth")) == "1",
                "cvss_score": _number_or_none(row.get("cvss_score")),
                "scope_changed": str(row.get("scope_changed")) == "1",
            }
            tier, reason = _decision_tier(decision_input)
            priority_code, priority_label = _business_priority(tier)
            cve_details.append(
                {
                    "cve": cve,
                    "tier": tier,
                    "priority_code": priority_code,
                    "priority_label": priority_label,
                    "reason": reason,
                    "pre_auth": decision_input["pre_auth"],
                    "scope_changed": decision_input["scope_changed"],
                    "cvss_score": decision_input["cvss_score"],
                    "epss": signals["epss"],
                    "epss_percentile": signals["epss_percentile"],
                    "kev": signals["kev"],
                    "public_exploits": signals["public_exploits"],
                }
            )
        cve_details.sort(
            key=lambda item: (
                item["tier"],
                -(item["epss"] if item["epss"] is not None else -1),
                -(item["cvss_score"] if item["cvss_score"] is not None else -1),
                item["cve"],
            )
        )
        priority = cve_details[0] if cve_details else None
        raw_version = str(base.get("product_version") or "")
        version_match = re.search(r"\bVersion\s+(.+)$", raw_version)
        version_label = (
            version_match.group(1).strip()
            if version_match
            else raw_version or product_id.rsplit("V-", 1)[-1]
        )
        product_name = str(base.get("product_name") or product_id)
        context_match = re.search(r"\(([^()]*)\)\s+Version\b", raw_version)
        product_context = context_match.group(1).strip() if context_match else ""
        if product_context.startswith(product_name):
            product_context = product_context[len(product_name) :].lstrip(" _-")
        version_vex_cves = sorted({str(row["cve"]) for row in vex_rows})
        product_rows.append(
            {
                "product_id": product_id,
                "product_family": str(base.get("product_family") or ""),
                "product_name": product_name,
                "product_version": raw_version,
                "version_label": version_label,
                "product_context": product_context,
                "cpe": str(base.get("cpe") or ""),
                "state": "active" if affected_rows else "complete_vex",
                "tier": priority["tier"] if priority else None,
                "priority_code": priority["priority_code"] if priority else None,
                "priority_label": priority["priority_label"] if priority else None,
                "decision_reason": (
                    f"{priority['reason']} ({priority['cve']})"
                    if priority
                    else "All CVEs are closed by VEX"
                ),
                "affected_cve_count": len(cve_details),
                "affected_cves": [item["cve"] for item in cve_details],
                "pre_auth_cves": [
                    item["cve"] for item in cve_details if item["pre_auth"]
                ],
                "scope_changed_cves": [
                    item["cve"] for item in cve_details if item["scope_changed"]
                ],
                "kev_cves": [
                    item["cve"] for item in cve_details if item["kev"] is True
                ],
                "public_exploit_cves": [
                    item["cve"]
                    for item in cve_details
                    if (item["public_exploits"] or 0) > 0
                ],
                "pre_auth_cve_count": sum(item["pre_auth"] for item in cve_details),
                "scope_changed_cve_count": sum(
                    item["scope_changed"] for item in cve_details
                ),
                "kev_cve_count": sum(item["kev"] is True for item in cve_details)
                if source_statuses.get("kev", {}).get("status") == "success"
                else None,
                "public_exploit_cve_count": sum(
                    (item["public_exploits"] or 0) > 0 for item in cve_details
                )
                if source_statuses.get("public_exploits", {}).get("status")
                == "success"
                else None,
                "max_epss": max(
                    (item["epss"] for item in cve_details if item["epss"] is not None),
                    default=None,
                ),
                "max_cvss": max(
                    (
                        item["cvss_score"]
                        for item in cve_details
                        if item["cvss_score"] is not None
                    ),
                    default=None,
                ),
                "vex_cve_count": len(version_vex_cves),
                "vex_cves": version_vex_cves,
                "vex_only_cve_count": len(version_vex_cves),
                "vex_only_cves": version_vex_cves,
                "mixed_status_cve_count": 0,
                "mixed_status_cves": [],
                "vex_justifications": sorted(
                    {
                        str(row.get("vex_justification") or "Not specified")
                        for row in vex_rows
                    }
                ),
                "remediations": remediation_values(affected_rows),
            }
        )
    product_rows.sort(
        key=lambda row: (
            int(row["tier"]) if row["tier"] is not None else 99,
            -(row["max_epss"] if row["max_epss"] is not None else -1),
            -(row["max_cvss"] if row["max_cvss"] is not None else -1),
            row["product_family"],
            row["product_name"],
            row["product_version"],
        )
    )

    grouped_versions: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in product_rows:
        key = (row["product_family"], row["product_name"])
        grouped_versions.setdefault(key, []).append(row)
    product_groups: list[dict[str, Any]] = []
    for (family, name), versions in grouped_versions.items():
        active_versions = [row for row in versions if row["state"] == "active"]
        priority_version = min(
            active_versions,
            key=lambda row: (
                int(row["tier"]),
                -(row["max_epss"] if row["max_epss"] is not None else -1),
                -(row["max_cvss"] if row["max_cvss"] is not None else -1),
                row["version_label"],
            ),
            default=None,
        )
        remediation_groups: dict[tuple[str, str, str], dict[str, Any]] = {}
        for version in active_versions:
            for item in version["remediations"]:
                key = (item["url"], item["category"], item["note"])
                bucket = remediation_groups.setdefault(
                    key, {"product_ids": set(), "families": set()}
                )
                bucket["product_ids"].add(version["product_id"])
                bucket["families"].update(item["families"])
        remediations = [
            {
                "url": key[0],
                "category": key[1],
                "note": key[2],
                "product_count": len(values["product_ids"]),
                "families": sorted(values["families"]),
            }
            for key, values in sorted(remediation_groups.items())
        ]
        affected_cve_set = {
            cve for version in active_versions for cve in version["affected_cves"]
        }
        affected_cves = sorted(affected_cve_set)
        pre_auth_cves = sorted(
            {cve for version in active_versions for cve in version["pre_auth_cves"]}
        )
        scope_changed_cves = sorted(
            {
                cve
                for version in active_versions
                for cve in version["scope_changed_cves"]
            }
        )
        kev_cves = sorted(
            {cve for version in active_versions for cve in version["kev_cves"]}
        )
        public_exploit_cves = sorted(
            {
                cve
                for version in active_versions
                for cve in version["public_exploit_cves"]
            }
        )
        vex_cve_set = {cve for version in versions for cve in version["vex_cves"]}
        vex_cves = sorted(vex_cve_set)
        vex_only_cves = sorted(vex_cve_set - affected_cve_set)
        mixed_status_cves = sorted(vex_cve_set & affected_cve_set)
        product_groups.append(
            {
                "product_family": family,
                "product_name": name,
                "state": "active" if active_versions else "complete_vex",
                "tier": priority_version["tier"] if priority_version else None,
                "priority_code": (
                    priority_version["priority_code"] if priority_version else None
                ),
                "priority_label": (
                    priority_version["priority_label"] if priority_version else None
                ),
                "decision_reason": (
                    priority_version["decision_reason"]
                    if priority_version
                    else "All versions are closed by VEX"
                ),
                "version_count": len(versions),
                "affected_version_count": len(active_versions),
                "complete_vex_version_count": len(versions) - len(active_versions),
                "affected_cve_count": len(affected_cves),
                "affected_cves": affected_cves,
                "pre_auth_cve_count": len(pre_auth_cves),
                "pre_auth_cves": pre_auth_cves,
                "scope_changed_cve_count": len(scope_changed_cves),
                "scope_changed_cves": scope_changed_cves,
                "kev_cve_count": len(kev_cves)
                if source_statuses.get("kev", {}).get("status") == "success"
                else None,
                "kev_cves": kev_cves,
                "public_exploit_cve_count": len(public_exploit_cves)
                if source_statuses.get("public_exploits", {}).get("status")
                == "success"
                else None,
                "public_exploit_cves": public_exploit_cves,
                "max_epss": max(
                    (
                        version["max_epss"]
                        for version in active_versions
                        if version["max_epss"] is not None
                    ),
                    default=None,
                ),
                "max_cvss": max(
                    (
                        version["max_cvss"]
                        for version in active_versions
                        if version["max_cvss"] is not None
                    ),
                    default=None,
                ),
                "vex_cve_count": len(vex_cves),
                "vex_cves": vex_cves,
                "vex_only_cve_count": len(vex_only_cves),
                "vex_only_cves": vex_only_cves,
                "mixed_status_cve_count": len(mixed_status_cves),
                "mixed_status_cves": mixed_status_cves,
                "vex_justifications": sorted(
                    {
                        justification
                        for version in versions
                        for justification in version["vex_justifications"]
                    }
                ),
                "remediations": remediations,
                "versions": sorted(
                    versions,
                    key=lambda row: (
                        int(row["tier"]) if row["tier"] is not None else 99,
                        row["version_label"],
                        row["product_id"],
                    ),
                ),
            }
        )
    product_groups.sort(
        key=lambda row: (
            int(row["tier"]) if row["tier"] is not None else 99,
            -(row["max_epss"] if row["max_epss"] is not None else -1),
            -(row["max_cvss"] if row["max_cvss"] is not None else -1),
            row["product_family"],
            row["product_name"],
        )
    )

    family_counts: Counter[str] = Counter()
    family_pre_auth: Counter[str] = Counter()
    component_counts: Counter[str] = Counter()
    age_counts: Counter[str] = Counter()
    for row in affected:
        family = str(row.get("product_family") or "").strip() or "Unclassified"
        family_counts[family] += 1
        if str(row.get("pre_auth")) == "1":
            family_pre_auth[family] += 1
        component = str(row.get("third_party_component") or "").strip()
        if component:
            component_counts[component] += 1
        match = re.match(r"^CVE-(\d{4})-", str(row.get("cve") or ""))
        if match:
            age_counts[match.group(1)] += 1

    vex_counts = Counter(
        str(row.get("vex_justification") or "Not specified") for row in vex
    )
    epss_success = source_statuses.get("epss", {}).get("status") == "success"
    kev_success = source_statuses.get("kev", {}).get("status") == "success"
    exploit_success = (
        source_statuses.get("public_exploits", {}).get("status") == "success"
    )
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "prioritization_version": PRIORITIZATION_VERSION,
        "batch_id": str(first.get("batch_id") or ""),
        "execution_started_at": execution_started_at,
        "advisory": {
            "vendor": str(first.get("vendor") or ""),
            "reference": str(first.get("advisory_reference") or ""),
            "revision": str(first.get("advisory_revision") or ""),
            "title": str(first.get("advisory_title") or ""),
            "url": str(first.get("advisory_url") or ""),
            "published_date": str(first.get("published_date") or ""),
            "revised_date": str(first.get("revised_date") or ""),
            "tlp": str(first.get("tlp") or ""),
            "source_hash": str(first.get("source_hash") or ""),
        },
        "observation_date": str(enrichment[0].get("observed_date") or "")
        if enrichment
        else "",
        "source_statuses": dict(source_statuses),
        "kpis": {
            "priority_1_cves": sum(
                row["priority_code"] == "P1" for row in active_cve_rows
            )
            if kev_success
            else None,
            "affected_cves": len(active_cve_rows),
            "affected_findings": len(affected),
            "pre_auth_cves": sum(row["pre_auth"] for row in active_cve_rows),
            "kev_cves": sum(row["kev"] is True for row in active_cve_rows)
            if kev_success
            else None,
            "public_exploit_cves": sum(
                (row["public_exploits"] or 0) > 0 for row in active_cve_rows
            )
            if exploit_success
            else None,
            "scope_changed_cves": sum(
                row["scope_changed"] for row in active_cve_rows
            ),
            "vex_findings": len(vex),
            "vex_cves": len(vex_by_cve),
            "complete_vex_cves": sum(
                row["vex_state"] == "complete" for row in cve_rows
            ),
            "affected_products": sum(
                row["state"] == "active" for row in product_groups
            ),
            "complete_vex_products": sum(
                row["state"] == "complete_vex" for row in product_groups
            ),
            "affected_product_versions": sum(
                row["state"] == "active" for row in product_rows
            ),
            "complete_vex_product_versions": sum(
                row["state"] == "complete_vex" for row in product_rows
            ),
        },
        "cves": sorted(
            cve_rows,
            key=lambda row: (
                int(row["tier"]) if row["tier"] is not None else 99,
                -(row["epss"] if row["epss"] is not None else -1),
                -(row["cvss_score"] if row["cvss_score"] is not None else -1),
                row["cve"],
            ),
        ),
        "products": product_groups,
        "aggregates": {
            "product_families": [
                {
                    "name": name,
                    "affected_findings": count,
                    "pre_auth_findings": family_pre_auth[name],
                }
                for name, count in sorted(
                    family_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "third_party_components": [
                {"name": name, "affected_findings": count}
                for name, count in sorted(
                    component_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
            "cve_age": [
                {"year": year, "affected_findings": age_counts[year]}
                for year in sorted(age_counts)
            ],
            "vex_justifications": [
                {"name": name, "findings": count}
                for name, count in sorted(
                    vex_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ],
        },
        "data_quality": {
            "affected_findings_without_cvss": sum(
                not str(row.get("cvss_score") or "").strip() for row in affected
            ),
            "affected_cves_without_epss": sum(
                row["epss"] is None for row in active_cve_rows
            )
            if epss_success
            else None,
            "affected_findings_without_component": sum(
                not str(row.get("component_name") or "").strip() for row in affected
            ),
        },
    }
    return report


def render_report_html(report: Mapping[str, Any]) -> str:
    """Render a standalone report whose sole data model is report-data JSON."""
    title = html.escape(
        str((report.get("advisory") or {}).get("title") or "CSAF Analytics Report")
    )
    embedded_json = json.dumps(
        report, ensure_ascii=False, separators=(",", ":")
    ).replace("</", "<\\/").replace("\u2028", "\\u2028").replace(
        "\u2029", "\\u2029"
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="report-data" content="report-data.json">
<title>{title}</title>
<style>
:root{{--brand:#c74634;--ink:#161513;--muted:#665f58;--line:#e4e1dc;--bg:#fff;--soft:#faf9f8;--blue:#0572ce;--redbg:#fbedeb;--amber:#a65f00;--amberbg:#fdf3e3;--green:#1b7a3e;--greenbg:#eaf5ee;--radius:6px}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--ink);font:13px/1.5 "Oracle Sans","Helvetica Neue",Arial,sans-serif}}.cr{{max-width:1400px;margin:auto;padding:20px}}a{{color:var(--blue);text-decoration:none}}a:hover{{text-decoration:underline}}
.cr-head{{border-bottom:3px solid var(--brand);padding-bottom:12px;margin-bottom:18px}}h1{{font-size:20px;font-weight:400;margin:0}}.cr-meta{{display:flex;flex-wrap:wrap;gap:14px;margin-top:5px;color:var(--muted);font-size:11px}}.cr-meta b{{color:var(--ink)}}
.cr-note{{border-left:3px solid var(--blue);background:#e8f2fb;padding:9px 12px;margin-bottom:14px;border-radius:0 var(--radius) var(--radius) 0}}.cr-health{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:18px}}.badge{{display:inline-block;border-radius:10px;padding:2px 8px;font-size:10.5px;background:#f5f4f2}}.ok{{color:var(--green);background:var(--greenbg)}}.warn{{color:var(--amber);background:var(--amberbg)}}
.cr-kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));gap:10px;margin-bottom:20px}}.cr-kpi{{border:1px solid var(--line);background:var(--soft);border-radius:var(--radius);padding:11px 13px}}.cr-kpi.danger{{background:var(--redbg)}}.cr-kpi.warning{{background:var(--amberbg)}}.cr-kpi.good{{background:var(--greenbg)}}.cr-kpi .l{{text-transform:uppercase;letter-spacing:.4px;color:var(--muted);font-size:10.5px}}.cr-kpi .v{{font-size:22px;font-weight:300}}.cr-kpi .s{{color:var(--muted);font-size:10.5px}}
details{{border:1px solid var(--line);border-radius:var(--radius);margin-bottom:9px;overflow:hidden}}summary{{cursor:pointer;background:var(--soft);padding:10px 14px;display:flex;gap:9px;align-items:center}}summary b{{font-weight:600}}summary small{{color:var(--muted)}}summary .count{{margin-left:auto;color:var(--muted)}}.body{{padding:14px;overflow:auto}}
.tools{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}}.tools label{{color:var(--muted);font-size:11px}}input,select{{font:inherit;padding:5px 8px;border:1px solid var(--line);border-radius:4px;background:white}}table{{width:100%;border-collapse:collapse;font-size:12px}}th{{text-align:left;text-transform:uppercase;letter-spacing:.35px;font-size:10.5px;color:var(--muted);cursor:pointer;white-space:nowrap}}th,td{{padding:6px 8px;border-bottom:1px solid #f0eeea;vertical-align:top}}tbody tr:hover{{background:var(--soft)}}.num{{text-align:right;font-variant-numeric:tabular-nums}}.mono{{font-family:Menlo,Consolas,monospace;font-size:11px}}.tag{{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600}}.red{{background:var(--redbg);color:#8a2e22}}.amber{{background:var(--amberbg);color:var(--amber)}}.blue{{background:#e8f2fb;color:#04559b}}.green{{background:var(--greenbg);color:var(--green)}}.priority{{display:inline-grid;place-items:center;min-width:27px;height:20px;padding:0 5px;border-radius:3px;font-size:10px;font-weight:700}}.priority-p1{{color:#8a2e22;background:var(--redbg)}}.priority-p2{{color:var(--amber);background:var(--amberbg)}}.priority-p3{{color:#04559b;background:#e8f2fb}}.priority-p4{{color:#514c47;background:#efedeb}}.priority-name{{margin-left:6px;font-size:10.5px;white-space:nowrap}}
.fix-list{{border:0;margin:0;overflow:visible}}.fix-list summary{{display:inline;padding:0;background:none;color:var(--blue);font-size:11px;white-space:nowrap}}.fix-list .fix-items{{min-width:250px;padding:5px 0;display:grid;gap:3px}}.fix-list .fix-items span{{color:var(--muted);font-size:10px}}.bars{{display:grid;gap:7px}}.bar{{display:grid;grid-template-columns:minmax(150px,210px) 1fr 100px;gap:10px;align-items:center}}.bar-label{{display:flex;min-width:0;align-items:center;gap:5px}}.bar-label-text{{min-width:0;overflow-wrap:anywhere}}.bar-label-priorities{{display:inline-flex;flex:0 0 auto;gap:3px}}.bar-label-priorities .priority{{min-width:24px;height:18px}}.track{{height:15px;background:#f5f4f2;border-radius:3px;overflow:hidden;position:relative}}.fill{{height:100%;background:var(--blue)}}.fill.secondary{{position:absolute;left:0;top:0;background:var(--brand)}}.barval{{text-align:right;color:var(--muted)}}.barval .secondary-value{{color:var(--brand)}}.legend{{display:flex;gap:14px;margin-bottom:10px;color:var(--muted);font-size:11px}}.legend i{{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px}}.legend .affected{{background:var(--blue)}}.legend .preauth{{background:var(--brand)}}.drill{{font:inherit;border:1px solid var(--blue);background:white;color:var(--blue);border-radius:4px;padding:4px 8px;cursor:pointer;white-space:nowrap}}.drill:hover{{background:#e8f2fb}}.signals{{display:flex;gap:3px;flex-wrap:wrap;min-width:115px}}.signal-list{{position:relative;border:0;margin:0;overflow:visible}}.signal-list summary{{display:inline-block;padding:0;background:none;line-height:1;list-style:none}}.signal-list summary::-webkit-details-marker{{display:none}}.signal-list summary .tag{{cursor:pointer}}.signal-list[open] summary .tag{{outline:1px solid currentColor}}.signal-cves{{position:absolute;z-index:5;top:22px;left:0;min-width:155px;max-width:280px;max-height:180px;overflow:auto;padding:8px 10px;background:white;border:1px solid var(--line);border-radius:5px;box-shadow:0 7px 20px #0003;display:grid;gap:3px;white-space:nowrap}}.signal-cves::before{{content:"CVE concernées";font:600 9px/1.4 inherit;text-transform:uppercase;color:var(--muted);letter-spacing:.35px;margin-bottom:2px}}.search-data{{display:none}}dialog.product-detail{{width:min(1320px,96vw);max-height:90vh;border:1px solid var(--line);border-radius:8px;padding:0;box-shadow:0 16px 48px #0004}}dialog.product-detail::backdrop{{background:#16151399}}.dialog-head{{position:sticky;top:0;z-index:1;display:flex;align-items:flex-start;gap:12px;background:white;border-bottom:1px solid var(--line);padding:14px 18px}}.dialog-head h2{{font-size:17px;font-weight:500;margin:0}}.dialog-head p{{color:var(--muted);margin:2px 0 0}}.dialog-head button{{margin-left:auto}}.dialog-body{{padding:14px 18px;overflow:auto}}.dialog-summary{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}.version-state{{white-space:nowrap}}.priority-policy{{width:min(720px,94vw)!important}}.policy-intro{{margin:0 0 14px;color:var(--muted)}}.policy-grid{{display:grid;gap:8px}}.policy-row{{display:grid;grid-template-columns:minmax(215px,auto) 1fr;gap:14px;align-items:start;padding:10px;border:1px solid var(--line);border-radius:5px}}.policy-row p{{margin:0;color:#403c38}}.policy-note{{margin:14px 0 0;padding:9px 11px;border-left:3px solid var(--blue);background:#e8f2fb}}.foot{{border-top:1px solid var(--line);margin-top:20px;padding-top:10px;color:var(--muted);font-size:10.5px}}
.product-priority-group{{margin:18px 0 24px;border:0;overflow:visible}}.product-priority-heading{{display:flex;align-items:center;gap:9px;margin:0 0 8px;padding:0 0 6px;border-bottom:2px solid var(--line);background:none}}.product-priority-heading::before{{content:"▸";color:var(--muted);font-size:12px;transition:transform .15s ease}}.product-priority-group[open]>.product-priority-heading::before{{transform:rotate(90deg)}}.product-priority-heading h3{{display:flex;align-items:center;gap:7px;margin:0;font-size:14px;font-weight:600}}.product-priority-heading .count{{margin-left:auto;color:var(--muted);font-size:11px}}.product-priority-body{{padding-left:12px}}.product-family-group{{margin:0 0 8px;border-radius:4px}}.product-family-group>summary{{padding:8px 12px;background:#f5f4f2}}.product-family-group>summary .count{{margin-left:auto}}.product-family-body{{overflow:auto;padding:0 10px 8px}}.product-family-body th,.product-family-body td{{padding-left:6px;padding-right:6px}}
.signal-cves::before{{content:"Related CVEs";font-family:inherit;font-size:9px;font-weight:600;line-height:1.4}}
.bar-with-priorities{{grid-template-columns:minmax(150px,210px) 52px 1fr 100px}}.bar-priority-cell{{display:flex;min-height:18px;align-items:center}}
@media(max-width:700px){{.cr{{padding:10px}}.bar{{grid-template-columns:120px 1fr 70px}}.bar-with-priorities{{grid-template-columns:minmax(100px,140px) 52px minmax(110px,1fr) 70px}}.policy-row{{grid-template-columns:1fr}}}}@media print{{.tools{{display:none}}details{{break-inside:avoid}}}}
</style></head><body><main class="cr" id="REPORT_ROOT"></main>
<script type="application/json" id="report-data">{embedded_json}</script>
<script>
(()=>{{"use strict";
const d=JSON.parse(document.getElementById("report-data").textContent),root=document.getElementById("REPORT_ROOT");
const esc=v=>String(v??"").replace(/[&<>"']/g,c=>({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
const n=v=>new Intl.NumberFormat("en-US").format(v??0),pct=v=>v==null?"n/a":(v*100).toFixed(2)+"%",score=v=>v==null?"n/a":Number(v).toFixed(1);
const safeUrl=v=>{{try{{const u=new URL(v);return /^https?:$/.test(u.protocol)?u.href:""}}catch(_e){{return ""}}}};
const link=(url,label)=>{{const u=safeUrl(url);return u?`<a href="${{esc(u)}}" target="_blank" rel="noopener">${{label}}</a>`:label}};
const remediationLinks=r=>{{const items=(r.remediations||[]).map(x=>{{const u=safeUrl(x.url);if(!u)return "";let label=x.note;try{{label=label||new URL(u).searchParams.get("documentId")}}catch(_e){{}}label=label||"Oracle Support";const context=`${{n(x.product_count)}} product${{x.product_count!==1?"s":""}}${{x.families?.length?" · "+x.families.join(", "):""}}`;return `<div><a href="${{esc(u)}}" target="_blank" rel="noopener">${{esc(label)}} ↗</a> <span>${{esc(context)}}</span></div>`}}).filter(Boolean);if(!items.length)return "";if(items.length===1)return items[0];return `<details class="fix-list"><summary>${{n(items.length)}} Support documents</summary><div class="fix-items">${{items.join("")}}</div></details>`}};
const status=(name,obj)=>{{const s=obj?.status||"unavailable",good=s==="success";return `<span class="badge ${{good?"ok":"warn"}}">${{esc(name)}} : ${{esc(s)}}</span>`}};
const kpi=(label,value,sub,kind="")=>`<div class="cr-kpi ${{kind}}"><div class="l">${{esc(label)}}</div><div class="v">${{value==null?"n/d":n(value)}}</div><div class="s">${{esc(sub)}}</div></div>`;
const section=(title,sub,count,content)=>`<details data-section="${{esc(title)}}"><summary><b>${{esc(title)}}</b><small>${{esc(sub)}}</small><span class="count">${{count==null?"":n(count)}}</span></summary><div class="body">${{content}}</div></details>`;
const tags=r=>{{const vex=r.vex_state==="partial"?`<span class="tag blue" title="Justifications: ${{esc(r.vex_justifications.join(", "))}}">Partial VEX: ${{n(r.vex_product_count)}} unaffected · ${{n(r.affected_product_count)}} affected</span>`:r.vex_state==="complete"?`<span class="tag green" title="Justifications: ${{esc(r.vex_justifications.join(", "))}}">Complete VEX: ${{n(r.vex_product_count)}} unaffected</span>`:"";return [r.kev===true?'<span class="tag red">KEV</span>':"",(r.public_exploits||0)>0?'<span class="tag amber">NVD Exploit</span>':"",r.pre_auth?'<span class="tag red">pre-auth</span>':"",r.scope_changed?'<span class="tag blue">S:C</span>':"",vex].filter(Boolean).join(" ")}};
const priorityLabels={{P1:"Confirmed Exploitation",P2:"Elevated Exploitation Signals",P3:"Elevated Technical Exposure",P4:"Standard Advisory"}};
const priorityBadge=r=>r.priority_code==null?'<span class="tag green">VEX</span>':`<span class="priority priority-${{esc(r.priority_code.toLowerCase())}}">${{esc(r.priority_code)}}</span><span class="priority-name">${{esc(r.priority_label||priorityLabels[r.priority_code])}}</span>`;
const priorityOptions=Object.entries(priorityLabels).map(([code,label])=>`<option value="${{code}}">${{code}} — ${{esc(label)}}</option>`).join("");
const familyPriorityCodes=new Map();(d.products||[]).forEach(p=>{{const code=p.priority_code,family=String(p.product_family||"").trim()||"Unclassified";if(code!=="P1"&&code!=="P2")return;if(!familyPriorityCodes.has(family))familyPriorityCodes.set(family,new Set());familyPriorityCodes.get(family).add(code)}});
const familyPriorityBadges=name=>{{const codes=[...(familyPriorityCodes.get(name)||[])].sort();return codes.length?`<span class="bar-label-priorities">${{codes.map(code=>`<span class="priority priority-${{esc(code.toLowerCase())}}" title="${{esc(priorityLabels[code])}}">${{esc(code)}}</span>`).join("")}}</span>`:""}};
const rows=d.cves.map(r=>`<tr data-priority="${{r.priority_code??"vex"}}" data-kev="${{r.kev===true?1:0}}" data-exploit="${{(r.public_exploits||0)>0?1:0}}" data-pre="${{r.pre_auth?1:0}}" data-vex="${{r.vex_state}}"><td data-sort="${{r.tier??99}}">${{priorityBadge(r)}}</td><td class="mono">${{esc(r.cve)}}</td><td>${{esc(r.decision_reason)}}</td><td class="num" data-sort="${{r.epss??-1}}">${{pct(r.epss)}}</td><td class="num" data-sort="${{r.cvss_score??-1}}">${{score(r.cvss_score)}}</td><td class="num" data-sort="${{r.product_count}}">${{n(r.product_count)}}</td><td>${{remediationLinks(r)}}</td><td>${{esc(r.third_party_component)}}</td><td>${{tags(r)}}</td><td>${{esc(r.families.join(", "))}}</td></tr>`).join("");
const decision=`<div data-filter><div class="tools"><input type="search" placeholder="Search…"><select data-key="priority"><option value="">All priorities</option>${{priorityOptions}}</select><select data-key="kev"><option value="">KEV</option><option value="1">In KEV</option></select><select data-key="exploit"><option value="">NVD Exploit</option><option value="1">Reference found</option></select><select data-key="pre"><option value="">Pre-auth</option><option value="1">Yes</option></select><label><input type="checkbox" data-vex-complete> Include CVEs fully closed by VEX</label><span data-count></span></div><table><thead><tr><th>Priority</th><th>CVE</th><th>Reason</th><th class="num">EPSS</th><th class="num">CVSS</th><th class="num">Affected products</th><th>Fixes</th><th>Third-party component</th><th>Signals</th><th>Families</th></tr></thead><tbody>${{rows}}</tbody></table></div>`;
const cveList=p=>{{const all=p.affected_cves||[];if(!all.length)return "";if(all.length<=3)return all.map(x=>`<span class="mono">${{esc(x)}}</span>`).join(", ");return `<details class="fix-list"><summary>${{n(all.length)}} affected CVE${{all.length!==1?"s":""}}</summary><div class="fix-items mono">${{all.map(esc).join(" · ")}}</div></details>`}};
const signalBadge=(label,cves,kind,title="Show related CVEs")=>{{const all=[...new Set(cves||[])].sort();if(!all.length)return "";return `<details class="signal-list"><summary title="${{esc(title)}}"><span class="tag ${{kind}}">${{esc(label)}} ${{n(all.length)}}</span></summary><div class="signal-cves mono">${{all.map(esc).join("<br>")}}</div></details>`}};
const productStatusSets=p=>{{const affected=new Set(p.affected_cves||[]),vex=[...new Set(p.vex_cves||[])];return {{vexOnly:p.vex_only_cves??vex.filter(cve=>!affected.has(cve)),mixed:p.mixed_status_cves??vex.filter(cve=>affected.has(cve))}}}};
const productSignals=p=>{{const statusSets=productStatusSets(p);return `<div class="signals">${{signalBadge("pre-auth",p.pre_auth_cves,"red")}}${{signalBadge("S:C",p.scope_changed_cves,"blue")}}${{signalBadge("KEV",p.kev_cves,"red")}}${{signalBadge("NVD",p.public_exploit_cves,"amber")}}${{signalBadge("Not affected (VEX)",statusSets.vexOnly,"green","Declared not affected with no affected declaration among the represented CSAF product entries")}}${{signalBadge("Mixed status",statusSets.mixed,"amber","Affected in at least one grouped CSAF product entry and not affected in another")}}</div>`}};
const productFamily=p=>p.product_family||"Unclassified";
const productFamilies=[...new Set(d.products.map(productFamily))].sort((a,b)=>a.localeCompare(b));
const productRow=({{p,index}})=>{{const searchable=[...(p.affected_cves||[]),...(p.vex_cves||[]),...(p.mixed_status_cves||[]),...(p.versions||[]).flatMap(v=>[v.version_label,v.product_context,v.product_version,v.product_id])].join(" ");return `<tr data-product-row data-state="${{p.state}}" data-priority="${{p.priority_code??"vex"}}" data-family="${{esc(productFamily(p))}}"><td><b>${{esc(p.product_name)}}</b><span class="search-data">${{esc(searchable)}}</span></td><td data-sort="${{p.affected_version_count}}"><b>${{n(p.affected_version_count)}}</b> affected / ${{n(p.version_count)}}</td><td>${{esc(p.decision_reason)}}</td><td class="num" data-sort="${{p.affected_cve_count}}">${{n(p.affected_cve_count)}}</td><td>${{productSignals(p)}}</td><td class="num" data-sort="${{p.max_epss??-1}}">${{pct(p.max_epss)}}</td><td class="num" data-sort="${{p.max_cvss??-1}}">${{score(p.max_cvss)}}</td><td>${{remediationLinks(p)}}</td><td><button class="drill" type="button" data-product-index="${{index}}">View ${{n(p.version_count)}} CSAF entr${{p.version_count!==1?"ies":"y"}}</button></td></tr>`}};
const productBuckets=new Map();d.products.forEach((p,index)=>{{const priority=p.priority_code??"vex",family=productFamily(p);if(!productBuckets.has(priority))productBuckets.set(priority,new Map());const families=productBuckets.get(priority);if(!families.has(family))families.set(family,[]);families.get(family).push({{p,index}})}});
const priorityRank=value=>value==="vex"?99:Number(value.slice(1));
const productHierarchy=[...productBuckets.entries()].sort((a,b)=>priorityRank(a[0])-priorityRank(b[0])).map(([priority,families])=>{{const familyGroups=[...families.entries()].sort((a,b)=>a[0].localeCompare(b[0])).map(([family,entries])=>`<details class="product-family-group" data-product-family-group data-family="${{esc(family)}}"><summary><b>${{esc(family)}}</b><span class="count" data-family-count>${{n(entries.length)}} product${{entries.length!==1?"s":""}}</span></summary><div class="product-family-body"><table><thead><tr><th>Product</th><th>Affected / CSAF entries</th><th>Priority reason</th><th class="num">Affected CVEs</th><th>Signals</th><th class="num">Max EPSS</th><th class="num">Max CVSS</th><th>Fixes</th><th>Details</th></tr></thead><tbody>${{entries.map(productRow).join("")}}</tbody></table></div></details>`).join("");const count=[...families.values()].reduce((total,entries)=>total+entries.length,0),sample=[...families.values()][0][0].p,label=priority==="vex"?'<span class="tag green">Not affected (VEX)</span>':priorityBadge(sample);return `<details class="product-priority-group" data-product-priority-group data-priority="${{esc(priority)}}"><summary class="product-priority-heading"><h3>${{label}}</h3><span class="count" data-priority-count>${{n(count)}} products</span></summary><div class="product-priority-body">${{familyGroups}}</div></details>`}}).join("");
const productDecision=`<div data-product-filter><div class="tools"><input type="search" placeholder="Search for a product, version, or CVE…"><select data-key="priority"><option value="">All priorities</option>${{priorityOptions}}</select><select data-product-family><option value="">All families</option>${{productFamilies.map(x=>`<option value="${{esc(x)}}">${{esc(x)}}</option>`).join("")}}</select><label><input type="checkbox" data-product-complete> Include products fully closed by VEX</label><button class="drill" type="button" data-priority-policy-open aria-haspopup="dialog">Priority policy</button><span data-count></span></div><div class="product-hierarchy">${{productHierarchy}}</div></div>`;
const versionDetail=p=>{{const rows=(p.versions||[]).map(v=>`<tr><td><b>${{esc(v.version_label||v.product_version)}}</b>${{v.product_context?`<div><span class="tag blue">${{esc(v.product_context)}}</span></div>`:""}}<div class="mono">${{esc(v.product_id)}}</div></td><td class="version-state">${{v.state==="complete_vex"?'<span class="tag green">not affected (VEX)</span>':'<span class="tag red">affected</span>'}}</td><td data-sort="${{v.tier??99}}">${{priorityBadge(v)}}</td><td>${{esc(v.decision_reason)}}</td><td class="num">${{n(v.affected_cve_count)}}</td><td>${{productSignals(v)}}</td><td class="num">${{pct(v.max_epss)}}</td><td class="num">${{score(v.max_cvss)}}</td><td>${{remediationLinks(v)}}</td><td>${{cveList(v)}}</td></tr>`).join("");return `<div class="dialog-summary"><span class="badge">${{n(p.version_count)}} CSAF product entries</span><span class="badge ok">${{n(p.affected_version_count)}} affected entries</span>${{p.complete_vex_version_count?`<span class="badge ok">${{n(p.complete_vex_version_count)}} not affected (VEX)</span>`:""}}${{p.mixed_status_cve_count?`<span class="badge warn">${{n(p.mixed_status_cve_count)}} mixed-status CVE${{p.mixed_status_cve_count!==1?"s":""}}</span>`:""}}</div><table><thead><tr><th>Version / component</th><th>Status</th><th>Priority</th><th>Reason</th><th class="num">Affected CVEs</th><th>Signals</th><th class="num">Max EPSS</th><th class="num">Max CVSS</th><th>Fixes</th><th>Affected CVE list</th></tr></thead><tbody>${{rows}}</tbody></table>`}};
const priorityPolicyDialog=`<dialog class="product-detail priority-policy" id="priority-policy" aria-labelledby="priority-policy-title"><div class="dialog-head"><div><h2 id="priority-policy-title">Priority policy</h2><p>Provider-facing classification of affected CVEs and products</p></div><button class="drill" type="button" data-priority-policy-close>Close</button></div><div class="dialog-body"><p class="policy-intro">The first matching condition determines the detailed technical tier. The tier is then presented through one of four business priorities.</p><div class="policy-grid"><div class="policy-row"><div><span class="priority priority-p1">P1</span><span class="priority-name">Confirmed Exploitation</span></div><p>Applied when the CVE is listed in the CISA Known Exploited Vulnerabilities catalog.</p></div><div class="policy-row"><div><span class="priority priority-p2">P2</span><span class="priority-name">Elevated Exploitation Signals</span></div><p>Applied for an NVD exploit-tagged reference with pre-authentication, an EPSS percentile at or above the 95th percentile, or an NVD exploit-tagged reference.</p></div><div class="policy-row"><div><span class="priority priority-p3">P3</span><span class="priority-name">Elevated Technical Exposure</span></div><p>Applied for critical pre-authentication, pre-authentication, or scope changed when no P1 or P2 condition applies.</p></div><div class="policy-row"><div><span class="priority priority-p4">P4</span><span class="priority-name">Standard Advisory</span></div><p>Applied to the remaining affected CVEs in the standard advisory cycle.</p></div></div><p class="policy-note"><strong>EPSS is a prediction signal.</strong> It estimates exploitation likelihood over the next 30 days and does not by itself indicate confirmed exploitation.</p></div></dialog>`;
const simpleTable=(headers,rows)=>`<table><thead><tr>${{headers.map(h=>`<th>${{esc(h)}}</th>`).join("")}}</tr></thead><tbody>${{rows.join("")}}</tbody></table>`;
const active=d.cves.filter(r=>r.vex_state!=="complete"),kev=active.filter(r=>r.kev===true),exploits=active.filter(r=>(r.public_exploits||0)>0),epss=active.filter(r=>r.epss!=null).sort((a,b)=>b.epss-a.epss);
const kevTable=simpleTable(["CVE","Added","Due date","Ransomware","CVSS","Products","Fixes"],kev.map(r=>`<tr><td class="mono">${{esc(r.cve)}}</td><td>${{esc(r.kev_added)}}</td><td>${{esc(r.kev_due)}}</td><td>${{esc(r.kev_ransomware)}}</td><td class="num">${{score(r.cvss_score)}}</td><td class="num">${{n(r.product_count)}}</td><td>${{remediationLinks(r)}}</td></tr>`));
const exploitTable=simpleTable(["CVE","NVD references","Pre-auth","CVSS","Products","Fixes","NVD link"],exploits.map(r=>`<tr><td class="mono">${{esc(r.cve)}}</td><td class="num">${{n(r.public_exploits)}}</td><td>${{r.pre_auth?"yes":""}}</td><td class="num">${{score(r.cvss_score)}}</td><td class="num">${{n(r.product_count)}}</td><td>${{remediationLinks(r)}}</td><td>${{link(r.exploit_url,"reference ↗")}}</td></tr>`));
const epssTable=simpleTable(["CVE","EPSS","Percentile","CVSS","Pre-auth","Products"],epss.map(r=>`<tr><td class="mono">${{esc(r.cve)}}</td><td class="num" data-sort="${{r.epss}}">${{pct(r.epss)}}</td><td class="num">${{pct(r.epss_percentile)}}</td><td class="num">${{score(r.cvss_score)}}</td><td>${{r.pre_auth?"yes":""}}</td><td class="num">${{n(r.product_count)}}</td></tr>`));
const bars=(items,valueKey,secondaryKey,limit=15,showPriorities=false)=>{{const shown=limit==null?items:items.slice(0,limit),max=Math.max(1,...shown.map(x=>x[valueKey])),legend=secondaryKey?'<div class="legend"><span><i class="affected"></i>affected findings</span><span><i class="preauth"></i>including pre-auth</span></div>':"";return `${{legend}}<div class="bars">${{shown.map(x=>{{const label=x.name||x.year;return `<div class="bar ${{showPriorities?"bar-with-priorities":""}}"><div class="bar-label"><span class="bar-label-text" title="${{esc(label)}}">${{esc(label)}}</span></div>${{showPriorities?`<div class="bar-priority-cell">${{familyPriorityBadges(label)}}</div>`:""}}<div class="track"><div class="fill" style="width:${{100*x[valueKey]/max}}%"></div>${{secondaryKey?`<div class="fill secondary" style="width:${{100*x[secondaryKey]/max}}%"></div>`:""}}</div><div class="barval">${{n(x[valueKey])}}${{secondaryKey?` / <span class="secondary-value">${{n(x[secondaryKey])}}</span>`:""}}</div></div>`}}).join("")}}</div>`}};
const blast=[...active].sort((a,b)=>b.product_count-a.product_count).slice(0,25),blastTable=simpleTable(["CVE","Products","Component","Pre-auth","CVSS","Fixes"],blast.map(r=>`<tr><td class="mono">${{esc(r.cve)}}</td><td class="num">${{n(r.product_count)}}</td><td>${{esc(r.third_party_component)}}</td><td>${{r.pre_auth?"yes":""}}</td><td class="num">${{score(r.cvss_score)}}</td><td>${{remediationLinks(r)}}</td></tr>`));
const q=d.data_quality,k=d.kpis,a=d.advisory,advisoryLink=link(a.url,"advisory ↗");
root.innerHTML=`<header class="cr-head"><h1>${{esc(a.title||a.reference)}}</h1><div class="cr-meta"><span>Publié <b>${{esc(a.published_date)}}</b></span><span>Réf. <b>${{esc(a.reference)}}</b></span><span>Version <b>${{esc(a.revision)}}</b></span><span>Analyse du <b>${{esc(d.observation_date)}}</b></span><span>TLP <b>${{esc(a.tlp)}}</b></span><span>${{advisoryLink}}</span></div></header><div class="cr-note"><b>Vue avis.</b> Ces chiffres décrivent le corpus publié par l'éditeur, non votre exposition.</div><div class="cr-health">${{status("EPSS",d.source_statuses.epss)}}${{status("KEV",d.source_statuses.kev)}}${{status("NVD Exploit",d.source_statuses.public_exploits)}}</div><div class="cr-kpis">${{kpi("P1 CVEs",k.priority_1_cves,"Confirmed exploitation","danger")}}${{kpi("CVE affectées",k.affected_cves,n(k.affected_findings)+" couples")}}${{kpi("Produits affectés",k.affected_products,n(k.affected_product_versions)+" versions affectées")}}${{kpi("Pré-authentifiées",k.pre_auth_cves,"AV:N / PR:N / UI:N","danger")}}${{kpi("Au catalogue KEV",k.kev_cves,"exploitation confirmée","danger")}}${{kpi("Références NVD Exploit",k.public_exploit_cves,"CVE avec référence","warning")}}${{kpi("Scope changed",k.scope_changed_cves,"enjeu segmentation","warning")}}${{kpi("Fermées par VEX",k.vex_findings,n(k.vex_cves)+" CVE concernées","good")}}</div>${{section("File de décision — vue CVE",n(k.affected_cves)+" CVE affectées · "+n(k.complete_vex_cves)+" entièrement VEX",d.cves.length,decision,true)}}${{section("File de décision — vue produit",n(k.affected_products)+" produits · "+n(k.affected_product_versions)+" versions affectées",d.products.length,productDecision,true)}}${{section("Catalogue KEV","exploitation confirmée",kev.length,kevTable)}}${{section("Références NVD marquées Exploit","indicateur non exhaustif",exploits.length,exploitTable)}}${{section("EPSS","probabilité d'exploitation à trente jours",epss.length,epssTable)}}${{section("Profil par famille produit","couples affectés / pré-authentifiés",d.aggregates.product_families.length,bars(d.aggregates.product_families,"affected_findings","pre_auth_findings",null,true))}}${{section("Composants tiers embarqués","dépendances les plus présentes",d.aggregates.third_party_components.length,bars(d.aggregates.third_party_components,"affected_findings"))}}${{section("Blast radius","produits distincts touchés par une CVE",active.length,blastTable)}}${{section("Ancienneté des CVE","couples affectés par année",d.aggregates.cve_age.length,bars(d.aggregates.cve_age,"affected_findings"))}}${{section("Déclarations VEX","justifications normalisées",k.vex_findings,bars(d.aggregates.vex_justifications,"findings"))}}${{section("Qualité de la donnée source","contrôles du pipeline",null,simpleTable(["Contrôle","Valeur"],[`<tr><td>Couples affectés sans CVSS</td><td class="num">${{n(q.affected_findings_without_cvss)}}</td></tr>`,`<tr><td>CVE affectées sans EPSS</td><td class="num">${{q.affected_cves_without_epss==null?"n/d":n(q.affected_cves_without_epss)}}</td></tr>`,`<tr><td>Couples sans composant</td><td class="num">${{n(q.affected_findings_without_component)}}</td></tr>`]))}}<footer class="foot">Sources : advisory CSAF 2.0 · CISA KEV · FIRST EPSS · références NVD marquées Exploit. Le CVSS mesure une sévérité intrinsèque, non le risque propre à l'organisation.<br>Batch ${{esc(d.batch_id)}} · schéma rapport v${{esc(d.schema_version)}} · priorisation v${{esc(d.prioritization_version)}}</footer><dialog class="product-detail" id="product-detail"><div class="dialog-head"><div><h2 data-product-title></h2><p data-product-subtitle></p></div><button class="drill" type="button" data-dialog-close>Fermer</button></div><div class="dialog-body" data-product-detail></div></dialog>`;
const uiTranslations=[["Publié","Published"],["Réf.","Ref."],["Analyse du","Analysis date"],["Vue avis.","Advisory view."],["Ces chiffres décrivent le corpus publié par l'éditeur, non votre exposition.","These figures describe the vendor-published advisory, not your organizational exposure."],["Action immédiate","Immediate action"],["paliers 1 à 3","tiers 1 to 3"],["CVE affectées","Affected CVEs"],[" couples"," findings"],["Produits affectés","Affected products"],[" versions affectées"," affected versions"],["Pré-authentifiées","Pre-auth"],["Au catalogue KEV","In KEV catalog"],["exploitation confirmée","confirmed exploitation"],["Références NVD Exploit","NVD Exploit references"],["CVE avec référence","CVEs with references"],["enjeu segmentation","segmentation concern"],["Fermées par VEX","Closed by VEX"],["CVE concernées","related CVEs"],["File de décision — vue CVE","Decision queue — CVE view"],[" entièrement VEX"," fully closed by VEX"],["File de décision — vue produit","Decision queue — product view"],[" produits · "," products · "],["Catalogue KEV","KEV catalog"],["Références NVD marquées Exploit","NVD Exploit-tagged references"],["indicateur non exhaustif","non-exhaustive indicator"],["probabilité d'exploitation à trente jours","thirty-day exploitation probability"],["Profil par famille produit","Product family profile"],["couples affectés / pré-authentifiés","affected / pre-auth findings"],["Composants tiers embarqués","Embedded third-party components"],["dépendances les plus présentes","most frequent dependencies"],["produits distincts touchés par une CVE","distinct products affected by a CVE"],["Ancienneté des CVE","CVE age"],["couples affectés par année","affected findings by year"],["Déclarations VEX","VEX statements"],["justifications normalisées","normalized justifications"],["Qualité de la donnée source","Source data quality"],["contrôles du pipeline","pipeline checks"],["Contrôle","Check"],["Valeur","Value"],["Couples affectés sans CVSS","Affected findings without CVSS"],["CVE affectées sans EPSS","Affected CVEs without EPSS"],["Couples sans composant","Findings without a component"],["Sources : advisory CSAF 2.0 · CISA KEV · FIRST EPSS · références NVD marquées Exploit.","Sources: CSAF 2.0 advisory · CISA KEV · FIRST EPSS · NVD Exploit-tagged references."],["Le CVSS mesure une sévérité intrinsèque, non le risque propre à l'organisation.","CVSS measures intrinsic severity, not organization-specific risk."],["schéma rapport","report schema"],["priorisation","prioritization"],["Fermer","Close"],["n/d","n/a"]];root.innerHTML=uiTranslations.reduce((value,[from,to])=>value.replaceAll(from,to),root.innerHTML);
root.insertAdjacentHTML("beforeend",priorityPolicyDialog);
root.innerHTML=root.innerHTML.replaceAll("Affected CVEs sans EPSS","Affected CVEs without EPSS");
const familySection=root.querySelector('[data-section="Product family profile"]'),productSection=root.querySelector('[data-section="Decision queue — product view"]'),cveSection=root.querySelector('[data-section="Decision queue — CVE view"]');if(productSection&&cveSection)root.insertBefore(productSection,cveSection);if(familySection&&productSection)root.insertBefore(familySection,productSection);
root.querySelectorAll("th").forEach((th,i)=>th.addEventListener("click",()=>{{const table=th.closest("table"),body=table?.tBodies[0];if(!body)return;const asc=th.dataset.asc!=="1";table.querySelectorAll("th").forEach(x=>delete x.dataset.asc);th.dataset.asc=asc?"1":"0";[...body.rows].sort((x,y)=>{{const a=x.cells[i],b=y.cells[i],av=a?.dataset.sort??a?.textContent.trim()??"",bv=b?.dataset.sort??b?.textContent.trim()??"",an=Number(av),bn=Number(bv),cmp=av!==""&&bv!==""&&!Number.isNaN(an)&&!Number.isNaN(bn)?an-bn:String(av).localeCompare(String(bv));return asc?cmp:-cmp}}).forEach(r=>body.appendChild(r))}}));
root.querySelectorAll("[data-filter]").forEach(scope=>{{const apply=()=>{{const q=scope.querySelector('input[type="search"]').value.toLowerCase(),includeComplete=scope.querySelector("[data-vex-complete]").checked,sels=[...scope.querySelectorAll("select")];let count=0;[...scope.querySelector("tbody").rows].forEach(r=>{{let show=(includeComplete||r.dataset.vex!=="complete")&&(!q||r.textContent.toLowerCase().includes(q));sels.forEach(s=>{{if(s.value&&r.dataset[s.dataset.key]!==s.value)show=false}});r.hidden=!show;if(show)count++}});scope.querySelector("[data-count]").textContent=n(count)+" rows"}};scope.querySelectorAll("input,select").forEach(x=>x.addEventListener("input",apply));apply()}});
root.querySelectorAll("[data-product-filter]").forEach(scope=>{{const apply=()=>{{const q=scope.querySelector('input[type="search"]').value.toLowerCase(),includeComplete=scope.querySelector("[data-product-complete]").checked,family=scope.querySelector("[data-product-family]").value,priority=scope.querySelector('[data-key="priority"]').value,filtering=Boolean(q||includeComplete||family||priority);let count=0;scope.querySelectorAll("[data-product-row]").forEach(r=>{{const show=(includeComplete||r.dataset.state!=="complete_vex")&&(!q||r.textContent.toLowerCase().includes(q))&&(!family||r.dataset.family===family)&&(!priority||r.dataset.priority===priority);r.hidden=!show;if(show)count++}});scope.querySelectorAll("[data-product-family-group]").forEach(group=>{{const visible=[...group.querySelectorAll("[data-product-row]")].filter(r=>!r.hidden).length;group.hidden=visible===0;group.querySelector("[data-family-count]").textContent=n(visible)+" product"+(visible!==1?"s":"");if(filtering&&visible)group.open=true}});scope.querySelectorAll("[data-product-priority-group]").forEach(group=>{{const visible=[...group.querySelectorAll("[data-product-row]")].filter(r=>!r.hidden).length;group.hidden=visible===0;group.querySelector("[data-priority-count]").textContent=n(visible)+" product"+(visible!==1?"s":"");if(filtering&&visible)group.open=true}});scope.querySelector("[data-count]").textContent=n(count)+" products"}};scope.querySelectorAll("input,select").forEach(x=>x.addEventListener("input",apply));apply()}});
const productDialog=root.querySelector("#product-detail");root.querySelectorAll("[data-product-index]").forEach(button=>button.addEventListener("click",()=>{{const p=d.products[Number(button.dataset.productIndex)];productDialog.querySelector("[data-product-title]").textContent=p.product_name;productDialog.querySelector("[data-product-subtitle]").textContent=p.product_family;productDialog.querySelector("[data-product-detail]").innerHTML=versionDetail(p);typeof productDialog.showModal==="function"?productDialog.showModal():productDialog.setAttribute("open","")}}));productDialog.querySelector("[data-dialog-close]").addEventListener("click",()=>{{typeof productDialog.close==="function"?productDialog.close():productDialog.removeAttribute("open")}});productDialog.addEventListener("click",event=>{{if(event.target===productDialog&&typeof productDialog.close==="function")productDialog.close()}});
const policyDialog=root.querySelector("#priority-policy");root.querySelectorAll("[data-priority-policy-open]").forEach(button=>button.addEventListener("click",()=>{{typeof policyDialog.showModal==="function"?policyDialog.showModal():policyDialog.setAttribute("open","")}}));policyDialog.querySelector("[data-priority-policy-close]").addEventListener("click",()=>{{typeof policyDialog.close==="function"?policyDialog.close():policyDialog.removeAttribute("open")}});policyDialog.addEventListener("click",event=>{{if(event.target===policyDialog&&typeof policyDialog.close==="function")policyDialog.close()}});
}})();
</script></body></html>"""


def _write_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def generate_phase0(
    source: str,
    output_root: Path,
    *,
    offline: bool = False,
    timeout: float = 30,
    retries: int = 1,
    epss_file: Path | None = None,
    kev_file: Path | None = None,
    nvd_file: Path | None = None,
    nvd_api_key: str | None = None,
    html_report: bool = True,
    now: datetime | None = None,
    progress: ProgressCallback | None = None,
) -> Path:
    if timeout <= 0:
        raise Phase0Error("HTTP timeout must be greater than zero")
    if retries < 0:
        raise Phase0Error("Retry count cannot be negative")
    monotonic_start = time.monotonic()
    started = now or datetime.now(timezone.utc)
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    started = started.astimezone(timezone.utc)
    timestamp = started.strftime("%Y%m%dT%H%M%SZ")
    observed_date = started.date().isoformat()

    _emit(progress, "INFO", "Starting CSAF Phase 0 execution")
    _emit(progress, "INFO", f"Source: {_display_source(source)}")
    _emit(progress, "INFO", f"Observation date: {observed_date}")
    _emit(
        progress,
        "INFO",
        "Enrichment mode: offline/local files" if offline else "Enrichment mode: online",
    )
    if nvd_api_key is None:
        nvd_api_key = os.environ.get("NVD_API_KEY")
    if not offline:
        _emit(
            progress,
            "INFO",
            "NVD exploit-reference enrichment: "
            + ("enabled" if nvd_api_key or nvd_file else "disabled (NVD_API_KEY not set)"),
        )

    raw, filename, source_url = _read_source(source, timeout)
    _emit(progress, "INFO", f"Loaded CSAF document: {filename} ({len(raw):,} bytes)")
    document = _load_json_bytes(raw, source, progress)
    source_hash = hashlib.sha256(raw).hexdigest()
    preliminary = _tracking_metadata(document, source_hash, filename, source_url)
    batch_id = f"{timestamp}_{_safe_component(preliminary['advisory_reference'])}"
    _emit(
        progress,
        "INFO",
        "Advisory: "
        f"{preliminary['advisory_reference']} revision "
        f"{preliminary['advisory_revision']} ({preliminary['vendor']})",
    )
    _emit(progress, "INFO", f"CSAF SHA-256: {source_hash}")
    _emit(progress, "INFO", f"Batch ID: {batch_id}")

    output_root = output_root.expanduser()
    output_root.mkdir(parents=True, exist_ok=True)
    target = output_root / batch_id
    if target.exists():
        _emit(progress, "ERROR", f"Execution directory already exists: {target}")
        raise Phase0Error(f"Execution directory already exists: {target}")
    temporary = output_root / f".{batch_id}.tmp-{uuid.uuid4().hex}"
    temporary.mkdir()

    try:
        findings = extract_findings(
            document, batch_id, source_hash, filename, source_url
        )
        if not findings:
            raise Phase0Error("CSAF document produced no CVE/product findings")
        finding_keys = {
            (str(row["cve"]), str(row["product_id"])) for row in findings
        }
        if len(finding_keys) != len(findings):
            raise Phase0Error("CSAF document produced duplicate CVE/product findings")
        cves = [str(row["cve"]) for row in findings]
        distinct_cves = sorted(set(cves))
        distinct_products = {str(row["product_id"]) for row in findings}
        status_counts = Counter(str(row["status"]) for row in findings)
        _emit(
            progress,
            "INFO",
            f"Extracted {len(findings):,} findings across "
            f"{len(distinct_cves):,} CVEs and {len(distinct_products):,} products",
        )
        _emit(
            progress,
            "INFO",
            "Finding statuses: "
            + ", ".join(
                f"{status}={count:,}" for status, count in sorted(status_counts.items())
            ),
        )
        _emit(progress, "INFO", f"Collecting enrichment for {len(distinct_cves):,} CVEs")
        enrichment, source_statuses = build_enrichment(
            distinct_cves,
            batch_id,
            observed_date,
            timeout,
            retries,
            offline,
            epss_file,
            kev_file,
            nvd_file,
            nvd_api_key,
            progress,
        )
        for source_name, details in source_statuses.items():
            source_message = f"{source_name}: {details['status']}"
            if details.get("message"):
                source_message += f" ({details['message']})"
            _emit(
                progress,
                "INFO" if details["status"] == "success" else "WARN",
                source_message,
            )
        _emit(progress, "INFO", f"Prepared {len(enrichment):,} enrichment rows")

        _emit(progress, "INFO", "Writing findings.csv")
        _emit(progress, "INFO", f"Preserving source CSAF as {filename}")
        (temporary / filename).write_bytes(raw)
        _write_csv(temporary / "findings.csv", FINDING_COLUMNS, findings)
        _emit(progress, "INFO", "Writing enrichment.csv")
        _write_csv(
            temporary / "enrichment.csv", ENRICHMENT_COLUMNS, enrichment
        )
        execution_started_at = started.isoformat().replace("+00:00", "Z")
        _emit(progress, "INFO", "Writing report-data.json")
        report_data = build_report_data(
            findings,
            enrichment,
            source_statuses,
            execution_started_at,
        )
        report_data_path = temporary / "report-data.json"
        report_data_path.write_text(
            json.dumps(report_data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        files = {
            "source_csaf": filename,
            "findings": "findings.csv",
            "enrichment": "enrichment.csv",
            "report_data": "report-data.json",
        }
        if html_report:
            report_filename = _report_filename(filename)
            _emit(
                progress,
                "INFO",
                f"Rendering {report_filename} from report-data.json",
            )
            persisted_report_data = json.loads(
                report_data_path.read_text(encoding="utf-8")
            )
            (temporary / report_filename).write_text(
                render_report_html(persisted_report_data), encoding="utf-8"
            )
            files["report_html"] = report_filename
        file_hashes = {
            name: hashlib.sha256((temporary / filename).read_bytes()).hexdigest()
            for name, filename in files.items()
        }
        manifest = {
            "format_version": BUNDLE_FORMAT_VERSION,
            "batch_id": batch_id,
            "execution_started_at": execution_started_at,
            "advisory_reference": preliminary["advisory_reference"],
            "advisory_revision": preliminary["advisory_revision"],
            "csaf_source_hash": source_hash,
            "source_filename": filename,
            "source_url": source_url,
            "observation_date": observed_date,
            "findings_count": len(findings),
            "enrichment_count": len(enrichment),
            "report_cve_count": len(report_data["cves"]),
            "report_affected_cve_count": report_data["kpis"]["affected_cves"],
            "report_product_count": len(report_data["products"]),
            "report_affected_product_count": report_data["kpis"][
                "affected_products"
            ],
            "report_product_version_count": sum(
                row["version_count"] for row in report_data["products"]
            ),
            "report_affected_product_version_count": report_data["kpis"][
                "affected_product_versions"
            ],
            "source_statuses": source_statuses,
            "files": files,
            "file_hashes": file_hashes,
        }
        _emit(progress, "INFO", "Writing manifest.json")
        (temporary / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        temporary.rename(target)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    elapsed = time.monotonic() - monotonic_start
    _emit(progress, "INFO", f"Execution bundle created: {target}")
    _emit(progress, "INFO", f"Completed successfully in {elapsed:.2f} seconds")
    return target


def _console_progress(level: str, message: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{timestamp}] {level:<5} {message}", file=sys.stderr, flush=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate Phase 0 CSAF CSV exchange files"
    )
    parser.add_argument(
        "--url",
        required=True,
        type=_https_url,
        help="HTTPS URL of the published CSAF JSON document",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Parent directory for timestamped runs (default: ./output)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Do not query EPSS, KEV or NVD unless local files are supplied",
    )
    parser.add_argument(
        "--epss-file",
        type=Path,
        help="Local EPSS API JSON, CSV, or gzip-compressed CSV file",
    )
    parser.add_argument(
        "--nvd-file",
        type=Path,
        help="Local NVD CVE API 2.0 JSON file (also usable with --offline)",
    )
    parser.add_argument("--kev-file", type=Path, help="Local CISA KEV JSON feed")
    parser.add_argument("--timeout", type=float, default=15, help="HTTP timeout seconds")
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        help="Retries per enrichment download after the first attempt (default: 1)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress messages and print only the final directory or an error",
    )
    parser.add_argument(
        "--no-html-report",
        action="store_true",
        help="Generate report-data.json but skip the standalone HTML report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        output = generate_phase0(
            args.url,
            args.output_dir,
            offline=args.offline,
            timeout=args.timeout,
            retries=args.retries,
            epss_file=args.epss_file,
            kev_file=args.kev_file,
            nvd_file=args.nvd_file,
            html_report=not args.no_html_report,
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
