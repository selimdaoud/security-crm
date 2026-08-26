# Customer 360 header

Configure APEX page 21 as follows:

1. Create a **Dynamic Content** region at the top of the page.
2. Use the **Standard** region template.
3. Set its **Static ID** to `customer360-header`.
4. Paste `header.sql` into **PL/SQL Function Body**.
5. Confirm that page item `P21_CUSTOMER_ID` receives the customer identifier.
6. Load [`../../static/dashboard.css`](../../static/dashboard.css) in the
   application. If the shared stylesheet is not loaded, paste `header.css` into
   **Page 21 > CSS > Inline**.
7. Hide the region title, or let the CSS associated with the Static ID hide it.

The header dynamically displays the customer name and initials, location,
industry, tier, primary Security Advisor name, and health score. The advisor
badge color still reflects the advisor's active status. Database values are
escaped before HTML is generated. If the identifier is invalid, the component
displays a customer-not-found state.

The French strings currently present in `header.sql` are application UI text;
they were left unchanged during the repository-only reorganization.
