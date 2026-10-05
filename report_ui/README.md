# Observability assessment report UI

This directory builds a single, self-contained Cloudscape React bundle for
single-account and organization reports. It reads the JSON text of
`<script id="assessment-data" type="application/json">` from the host HTML.
`reportType: "organization"` selects the organization view; an absent
`reportType` selects the single-account view. The script mounts in
`<div id="root">`, creating that element if the host has not supplied it.

Use Node.js 24 and run `npm ci && npm run typecheck && npm run build` here. The build writes
`report-ui.js` and `report-ui.css` to
`observability_assessment/reporting/assets/`. Commit the generated assets
alongside UI source changes. Python assessment runs consume these assets
without running Node.js. Embed the CSS in a `<style>`
element and the JavaScript after the JSON script in a `<script>` element
inside each generated report. Do not add URLs, module loading, or runtime
fetches. Keep the embedded JSON escaped for HTML script context, including
`<`, `>`, and `&`.

The single-account schema is `meta`, `summary`, `categories`, `questions`, and
`discovery` as defined by the report generator contract. The organization
schema is `reportType`, `meta`, `summary`, `categories`, and `accounts`; its
summary includes `assessedAccounts` (successful assessments) and
`scoredAccounts` (accounts with at least one assessed question). The frontend
renders AWS evidence as text and accepts only HTTP(S) URLs or simple `.html`
filenames for navigation.

Both report views use Cloudscape TopNavigation and a light/dark mode control.
The control applies Cloudscape's global mode and saves the preference when
browser storage is available. Without a saved preference, the report follows
the browser's preferred color scheme.

The single-account discovery table uses Cloudscape single-row selection.
Selecting a check opens its evidence, command, and status in a side SplitPanel;
the user can also move the panel below the content through its preferences,
and Cloudscape moves it below the content on small screens. Keep evidence
rendered as text and preserve search, sorting, and pagination when changing
the table. Each discovery row includes `evidenceText` for search and
`evidenceSummary`/`evidenceDetails` for the panel. The panel separates
pipe-delimited summary metrics and places supporting resource details in an
expandable section. The generator extracts those text fields from legacy
evidence markup; the frontend never renders the markup as HTML. The command is
shown in a separate Cloudscape container as wrapped code with a copy control.
