# Oracle APEX application

This directory contains the deployable APEX artifacts and the editable source
fragments used by individual pages.

## Layout

- `exports/sed-dashboard-2/` — current full split export of the application.
- `exports/legacy/` — older exports retained for reference only.
- `static/dashboard.css` — source of truth for the shared application stylesheet.
- `components/customer-360/` — Customer 360 dynamic-content header.
- `components/portfolio/` — current Portfolio report SQL and its legacy variant.

Do not edit generated files inside the full export as the primary source. Make
the change in APEX or in the corresponding source fragment, then refresh the
export so that it represents the deployed application.

