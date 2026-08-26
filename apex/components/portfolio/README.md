# Portfolio report

`report.sql` is the current Portfolio report query. The `legacy/` directory
contains an older SQL and CSS variant kept for comparison; it is not the
preferred implementation.

Shared visual styling belongs in [`../../static/dashboard.css`](../../static/dashboard.css).

## Tier column configuration

Keep `TIER` as the plain report value and render its badge with the Interactive
Report column HTML Expression. This prevents APEX from putting the badge markup
in filter labels, downloads, and other report operations.

After applying `report.sql` in Page Designer, synchronize the report columns and
configure them as follows:

- `TIER`: Plain Text, Escape Special Characters = No, HTML Expression:
  `<span class="sed-tier sed-tier-#TIER_CSS_CLASS!ATTR#">#TIER!HTML#</span>`
- `TIER_CSS_CLASS`: Hidden

Remove and recreate any Tier filters saved before this change because their
comparison values contain the old HTML markup.
