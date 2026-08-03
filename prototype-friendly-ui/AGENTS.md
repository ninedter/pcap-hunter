# Prototype Instructions

Run the local server yourself and open the preview in the browser available to this environment. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

Build app UI in `src/`. Keep `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs`, and `tests/sites-worker.test.mjs` intact so the same local prototype can be handed to Sites. Before a Sites handoff, run `npm run build` and `npm run test:sites`; the build must leave `dist/client/index.html`, `dist/server/index.js`, and `dist/.openai/hosting.json`.

## Selected direction and durable feedback

- Use Product Design Direction 1 as the source of truth for this prototype.
- Always show the complete PCAP Hunter brand lockup: the uncropped magnifying-glass mark and the full “PCAP Threat Hunting Workbench” wordmark.
- Include a prominent global IOC search in Findings, supporting IPs, domains, and hashes, with an evidence-type filter.
- Preserve the friendly findings-first information hierarchy while keeping Dashboard as a first-class, familiar destination alongside Analyze, Findings, Investigate, Reports, and Cases. Keep Settings secondary.
- The Dashboard must retain the existing analyst visual vocabulary: interactive world flow map, protocol distribution, flow timeline, Top 10 IP/domain views, Sankey flow, network graph, attack timeline, packet-size and inter-arrival histograms, and the traffic heatmap.
- Keep the world flow map at a stable visual proportion when destination volume grows. Aggregate endpoints by continent in the global view, by country at mid zoom, and reveal city-level endpoints close in without hiding the full endpoint inventory.
- Give the desktop world-map row enough vertical space for the destination hierarchy: scale it responsively between roughly 560 and 640 px, and scale the geographic projection with the canvas so the world fills the added area without distortion or empty bands. Keep the smaller stacked breakpoints compact.
- At close zoom, group all endpoints that resolve to the same city into one counted marker; retain individual IPs in the endpoint inventory. Never truncate the selected destination's protocol list.
- Present the destination inventory as a compact expandable hierarchy (continent → country → city → IP), with only the selected endpoint's path open by default; never render all endpoints as one long flat list.
- Keep dashboard visualizations cross-filtered with the world map as in the original application: protocol selections and timeline selections must redraw the mapped endpoints and traffic weights, expose their active state, and provide a clear reset. Chart marks must remain fully inside their containers at every responsive breakpoint.
- Every “Additional traffic views” control must open its matching Dashboard visualization, select the required visualization tab, scroll it into view, and move keyboard focus to the destination.
- Open the root workbench route on Analyze. After a capture batch is accepted, move directly to Run queue and preserve that view through a page refresh.
- Use “PCAP Hunter” as the browser document title.
- In indicator tables, show a PTR hostname as the primary label when reverse DNS succeeds while keeping the original IP visible; clicking an IP or domain must open its WHOIS/RDAP details.
- Every visible control must perform the action its label and icon promise, expose a genuine disabled/read-only state, or be rendered as non-interactive content. Never leave button-like cards, table rows, filters, exports, toggles, or chevrons inert.
- Never truncate hostnames, IPs, domains, evidence identifiers, or other investigation-critical values without an adjacent way to reveal the complete value. Prefer wrapping full values inside table rows and detail panels.
- Public documentation, design handoffs, and shared screenshots must use the opt-in privacy view and must never expose capture IPs, hostnames, case details, filenames, secrets, email addresses, local paths, or precise home-location data. Use irreversible replacement labels rather than reversible blur.
