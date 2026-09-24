#!/usr/bin/env bash
# Rebuild the local Oracle CVE ledger, then generate and publish the KEV report.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEDGER_DIR="$SCRIPT_DIR/var/oracle-kev"
PUBLISH_DIR="/var/www/html/security-crm/kev-reports"

mkdir -p "$LEDGER_DIR" "$PUBLISH_DIR"

cd "$SCRIPT_DIR"

python3 oracle_cve_ledger.py rebuild \
  --database "$LEDGER_DIR/oracle-cve-ledger.sqlite" \
  --map-html "$LEDGER_DIR/oracle-cve-advisory-map.html"

python3 oracle_kev_report.py \
  --oracle-map-file "$LEDGER_DIR/oracle-cve-advisory-map.html" \
  --output-dir var/output \
  -d "$PUBLISH_DIR"
