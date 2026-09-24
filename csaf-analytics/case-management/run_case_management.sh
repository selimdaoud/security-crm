#!/usr/bin/env bash
# Build the minimal case-management evidence bundle from the existing reports.

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYTICS_DIR="$(cd "$CASE_DIR/.." && pwd)"
STATE_DIR="$CASE_DIR/state"
PUBLISH_DIR="$CASE_DIR/published"
OUTPUT_DIR="$CASE_DIR/output"

mkdir -p "$STATE_DIR" "$PUBLISH_DIR" "$OUTPUT_DIR"
cd "$ANALYTICS_DIR"

python3 oracle_cve_ledger.py rebuild \
  --database "$STATE_DIR/oracle-cve-ledger.sqlite" \
  --map-html "$STATE_DIR/oracle-cve-advisory-map.html"

python3 oracle_kev_report.py \
  --oracle-map-file "$STATE_DIR/oracle-cve-advisory-map.html" \
  --output-dir "$OUTPUT_DIR" \
  -d "$PUBLISH_DIR"

python3 osint/product_watch.py \
  --db "$STATE_DIR/product_watch.db" \
  --out "$PUBLISH_DIR"

LATEST_KEV="$(find "$OUTPUT_DIR/oracle-kev" -name oracle-kev-report-data.json -type f | sort | tail -n 1)"
if [[ -z "$LATEST_KEV" ]]; then
  echo "No Oracle KEV report data was generated." >&2
  exit 1
fi

python3 "$CASE_DIR/build_case_desk.py" \
  --product-report "$PUBLISH_DIR/product_report.json" \
  --kev-report "$LATEST_KEV" \
  --oracle-map "$STATE_DIR/oracle-cve-advisory-map.html" \
  --csaf-output "$ANALYTICS_DIR/var/output" \
  --out-dir "$PUBLISH_DIR"

echo "Case desk: $PUBLISH_DIR/case-desk.html"
