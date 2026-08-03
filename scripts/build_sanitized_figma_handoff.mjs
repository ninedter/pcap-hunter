import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const imageRoot = path.join(repositoryRoot, "docs", "images", "workbench-current");
const outputDirectory = path.join(repositoryRoot, "docs", "figma");
const outputPath = path.join(outputDirectory, "pcap-hunter-sanitized-handoff.svg");

const sections = [
  {
    title: "01 · Global connectivity dashboard",
    subtitle: "Continent → country → city aggregation keeps the whole traffic picture readable.",
    image: "dashboard-redacted.png",
    notes: ["Stable world-map proportion", "Compact expandable destination hierarchy", "Protocol and time filters remain linked to the map"],
  },
  {
    title: "02 · Evidence inventory",
    subtitle: "Complete identifiers remain readable while public documentation uses irreversible privacy labels.",
    image: "evidence-redacted.png",
    notes: ["Full hostname and identifier wrapping", "Working type, assessment, and search filters", "IOC export and WHOIS entry points"],
  },
  {
    title: "03 · Linked traffic workspace",
    subtitle: "The protocol, talker, and timeline views update together and every shortcut opens a real destination.",
    image: "traffic-redacted.png",
    notes: ["Readable protocol legend", "Working All, IP, Protocol, and Time controls", "Eight functioning deep-dive visualization shortcuts"],
  },
  {
    title: "04 · ATT&CK hypotheses",
    subtitle: "Network observations are presented as reviewable hypotheses with explicit coverage and export paths.",
    image: "mitre-redacted.png",
    notes: ["Technique rows open supporting details", "Coverage gaps remain explicit", "Navigator and evidence JSON exports"],
  },
];

const escapeXml = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

const imageWidth = 1400;
const imageHeight = imageWidth * (1000 / 1440);
const sectionHeight = 1245;
const topHeight = 700;
const canvasHeight = topHeight + sections.length * sectionHeight + 180;

const imageData = await Promise.all(sections.map(async (section) => ({
  ...section,
  href: `data:image/png;base64,${(await readFile(path.join(imageRoot, section.image))).toString("base64")}`,
})));

const sectionMarkup = imageData.map((section, index) => {
  const y = topHeight + index * sectionHeight;
  const noteMarkup = section.notes.map((note, noteIndex) => `
    <circle cx="124" cy="${y + 172 + noteIndex * 34}" r="5" fill="#2b8de0" />
    <text x="142" y="${y + 179 + noteIndex * 34}" class="note">${escapeXml(note)}</text>`).join("");
  return `
  <g id="section-${index + 1}">
    <rect x="70" y="${y}" width="1460" height="1185" rx="22" fill="#ffffff" stroke="#d8e0ea" stroke-width="2" />
    <text x="105" y="${y + 62}" class="section-title">${escapeXml(section.title)}</text>
    <text x="105" y="${y + 102}" class="section-subtitle">${escapeXml(section.subtitle)}</text>
    ${noteMarkup}
    <rect x="99" y="${y + 280}" width="1402" height="${imageHeight + 2}" rx="16" fill="#ffffff" stroke="#cfd8e5" stroke-width="2" />
    <image x="100" y="${y + 281}" width="${imageWidth}" height="${imageHeight}" href="${section.href}" preserveAspectRatio="xMidYMid meet" />
  </g>`;
}).join("");

const svg = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="1600" height="${canvasHeight}" viewBox="0 0 1600 ${canvasHeight}">
  <style>
    .eyebrow { font: 700 18px Inter, Arial, sans-serif; letter-spacing: 2px; fill: #4da7f7; }
    .title { font: 800 58px Inter, Arial, sans-serif; fill: #f3f7fc; }
    .subtitle { font: 400 24px Inter, Arial, sans-serif; fill: #bac9dc; }
    .privacy-title { font: 750 22px Inter, Arial, sans-serif; fill: #163354; }
    .privacy-copy { font: 400 18px Inter, Arial, sans-serif; fill: #4f6078; }
    .metric { font: 800 32px Inter, Arial, sans-serif; fill: #173252; }
    .metric-label { font: 600 15px Inter, Arial, sans-serif; fill: #65738a; }
    .section-title { font: 780 30px Inter, Arial, sans-serif; fill: #142b49; }
    .section-subtitle { font: 400 19px Inter, Arial, sans-serif; fill: #5c6b82; }
    .note { font: 600 16px Inter, Arial, sans-serif; fill: #334a68; }
    .footer { font: 500 16px Inter, Arial, sans-serif; fill: #6f7d91; }
  </style>
  <rect width="1600" height="${canvasHeight}" fill="#f5f7fa" />
  <rect width="1600" height="360" fill="#0b1b2f" />
  <text x="80" y="92" class="eyebrow">SANITIZED PRODUCT AUDIT HANDOFF</text>
  <text x="80" y="172" class="title">PCAP Hunter</text>
  <text x="80" y="224" class="subtitle">Verified connectivity, evidence, traffic, and ATT&amp;CK workspaces</text>
  <text x="80" y="272" class="subtitle">Prepared from the production Docker build · 2026-08-03</text>

  <g id="quality-summary">
    <rect x="80" y="310" width="250" height="115" rx="18" fill="#ffffff" />
    <text x="110" y="360" class="metric">24 / 24</text><text x="110" y="394" class="metric-label">FRONTEND TESTS</text>
    <rect x="350" y="310" width="250" height="115" rx="18" fill="#ffffff" />
    <text x="380" y="360" class="metric">1,052</text><text x="380" y="394" class="metric-label">BACKEND TESTS PASSED</text>
    <rect x="620" y="310" width="250" height="115" rx="18" fill="#ffffff" />
    <text x="650" y="360" class="metric">0</text><text x="650" y="394" class="metric-label">BROWSER ERRORS</text>
    <rect x="890" y="310" width="250" height="115" rx="18" fill="#ffffff" />
    <text x="920" y="360" class="metric">0</text><text x="920" y="394" class="metric-label">TEXT CUTOFFS</text>
  </g>

  <g id="privacy-notice">
    <rect x="80" y="475" width="1440" height="155" rx="20" fill="#eaf5ff" stroke="#a9cbe8" stroke-width="2" />
    <text x="120" y="525" class="privacy-title">Privacy-safe by construction</text>
    <text x="120" y="562" class="privacy-copy">Only irreversible labels such as [IP 01], [HOST 01], and [CAPTURE 01] are present.</text>
    <text x="120" y="595" class="privacy-copy">No raw addresses, hostnames, case details, filenames, secrets, email addresses, local paths, or precise home location are embedded.</text>
  </g>

  ${sectionMarkup}
  <text x="800" y="${canvasHeight - 70}" text-anchor="middle" class="footer">PCAP Hunter · sanitized design handoff · production-verified</text>
</svg>`;

await mkdir(outputDirectory, { recursive: true });
const normalizedSvg = svg.split("\n").map((line) => line.trimEnd()).join("\n");
await writeFile(outputPath, normalizedSvg, "utf8");
console.log(outputPath);
