import { useEffect, useMemo, useRef, useState } from "react";
import {
  AddressBook,
  ArrowLeft,
  ArrowRight,
  ArrowsLeftRight,
  Bell,
  Brain,
  CaretDown,
  ChartLine,
  ChartPieSlice,
  Check,
  CheckCircle,
  ClockCounterClockwise,
  Code,
  Copy,
  Database,
  DownloadSimple,
  File,
  FileArrowDown,
  FileText,
  FolderSimple,
  Funnel,
  GearSix,
  GlobeHemisphereWest,
  HardDrives,
  Key,
  ListChecks,
  MagnifyingGlass,
  MapPin,
  NotePencil,
  Package,
  Play,
  Plus,
  Pulse,
  Queue,
  ShareNetwork,
  ShieldCheck,
  SlidersHorizontal,
  Sparkle,
  Target,
  Trash,
  UploadSimple,
  UserCircle,
  WarningCircle,
  Waveform,
  X,
} from "@phosphor-icons/react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Sankey,
  Scatter,
  ScatterChart,
  ZAxis,
} from "recharts";
import {
  ComposableMap,
  Geographies,
  Geography,
  Line as MapLine,
  Marker,
  ZoomableGroup,
  createCoordinates,
} from "@vnedyalk0v/react19-simple-maps";
import worldGeography from "world-atlas/countries-110m.json";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { PIPELINE_STAGES as pipelineStages, normalizeJobProgress } from "./progress.js";
import { aggregateMapFlows, buildMapFlowHierarchy, getMapAggregationLabel, getMapAggregationLevel, getNextMapZoom } from "./mapAggregation.js";
import { filterDashboardMapFlows } from "./dashboardFilters.js";
import { getDashboardViewForTarget, getTrafficViewTool, trafficViewTools } from "./trafficViews.js";
import { buildAttackNavigatorLayer, buildIocCsv, getDashboardChartExport, isPrivateAddress } from "./uiActions.js";
import { useWorkbench } from "./workbench.js";

const navigation = [
  { id: "analyze", label: "Analyze", icon: UploadSimple },
  { id: "dashboard", label: "Dashboard", icon: ChartPieSlice },
  { id: "findings", label: "Findings", icon: Target },
  { id: "investigate", label: "Investigate", icon: MagnifyingGlass },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "cases", label: "Cases", icon: FolderSimple },
];

const investigateTabs = [
  { id: "evidence", label: "Evidence", icon: MagnifyingGlass },
  { id: "traffic", label: "Traffic", icon: Waveform },
  { id: "mitre", label: "MITRE ATT&CK", icon: Target },
  { id: "intel", label: "Threat intel", icon: GlobeHemisphereWest },
  { id: "raw", label: "Raw data", icon: Database },
];

const settingsNavigation = [
  { id: "llm", label: "LLM & reports", icon: Brain },
  { id: "intel", label: "Threat intelligence", icon: GlobeHemisphereWest },
  { id: "pipeline", label: "Analysis pipeline", icon: SlidersHorizontal },
  { id: "tools", label: "Tools & YARA", icon: HardDrives },
  { id: "map", label: "Map & location", icon: MapPin },
  { id: "api", label: "API access", icon: Key },
  { id: "data", label: "Data & retention", icon: Database },
  { id: "logs", label: "Runtime logs", icon: Code },
];

const evidence = [
  { value: "192.168.1.42", type: "IP", context: "Top talker · 1.2 MB", status: "Expected", source: "hq-morning.pcap" },
  { value: "93.184.216.34", type: "IP", context: "External destination · 540 KB", status: "Expected", source: "hq-morning.pcap" },
  { value: "172.217.16.14", type: "IP", context: "External destination · 320 KB", status: "Expected", source: "branch-office.pcapng" },
  { value: "updates.example.net", type: "Domain", context: "14 DNS queries", status: "Observed", source: "Both captures" },
  { value: "58f6a4d0…8c90", type: "Hash", context: "Carved body · clean YARA", status: "Clean", source: "branch-office.pcapng" },
  { value: "72a589da5868…", type: "JA3", context: "3 TLS sessions", status: "Observed", source: "hq-morning.pcap" },
];

const protocolData = [
  { name: "TCP", value: 26, color: "#2b8de0" },
  { name: "UDP", value: 8, color: "#7d46c8" },
  { name: "DNS", value: 4, color: "#2fac55" },
];

const trafficData = [
  { time: "10:00", flows: 2 }, { time: "10:05", flows: 4 }, { time: "10:10", flows: 6 },
  { time: "10:15", flows: 5 }, { time: "10:20", flows: 3 }, { time: "10:25", flows: 5 },
  { time: "10:30", flows: 2 }, { time: "10:35", flows: 4 }, { time: "10:40", flows: 5 },
  { time: "10:45", flows: 2 }, { time: "10:50", flows: 3 }, { time: "10:55", flows: 5 },
  { time: "11:00", flows: 2 },
];

const talkerData = [
  { name: "192.168.1.42", bytes: 1200 },
  { name: "93.184.216.34", bytes: 540 },
  { name: "172.217.16.14", bytes: 320 },
];

const dashboardFlowLocations = [
  { ip: "93.184.216.34", city: "San Francisco", country: "United States", continent: "North America", coordinates: createCoordinates(-122.4194, 37.7749), packets: 1200, bytes: "540 KB", protocols: ["TCP", "TLS"], status: "Expected", color: "#47a8ff" },
  { ip: "172.217.16.14", city: "Frankfurt", country: "Germany", continent: "Europe", coordinates: createCoordinates(8.6821, 50.1109), packets: 760, bytes: "320 KB", protocols: ["TCP", "TLS"], status: "Expected", color: "#47a8ff" },
  { ip: "1.1.1.1", city: "Sydney", country: "Australia", continent: "Oceania", coordinates: createCoordinates(151.2093, -33.8688), packets: 340, bytes: "86 KB", protocols: ["UDP", "DNS"], status: "Expected", color: "#55d58a" },
  { ip: "8.8.8.8", city: "Mountain View", country: "United States", continent: "North America", coordinates: createCoordinates(-122.0839, 37.3861), packets: 180, bytes: "44 KB", protocols: ["UDP", "DNS"], status: "Expected", color: "#55d58a" },
  { ip: "45.33.32.156", city: "Tokyo", country: "Japan", continent: "Asia", coordinates: createCoordinates(139.6503, 35.6762), packets: 90, bytes: "18 KB", protocols: ["TCP"], status: "Review", color: "#ffbd59" },
];

const topIpData = [
  { name: "192.168.1.42", value: 18 },
  { name: "93.184.216.34", value: 8 },
  { name: "172.217.16.14", value: 6 },
  { name: "1.1.1.1", value: 4 },
  { name: "8.8.8.8", value: 2 },
];

const topDomainData = [
  { name: "updates.example.net", value: 14 },
  { name: "example.org", value: 8 },
  { name: "dns.google", value: 6 },
  { name: "cloudflare-dns.com", value: 5 },
  { name: "ocsp.example.net", value: 3 },
];

const sankeyData = {
  nodes: [
    { name: "192.168.1.42" }, { name: "10.40.8.12" }, { name: "443 / TLS" },
    { name: "53 / DNS" }, { name: "93.184.216.34" }, { name: "172.217.16.14" },
    { name: "1.1.1.1" }, { name: "8.8.8.8" },
  ],
  links: [
    { source: 0, target: 2, value: 18 }, { source: 1, target: 3, value: 8 },
    { source: 2, target: 4, value: 10 }, { source: 2, target: 5, value: 8 },
    { source: 3, target: 6, value: 5 }, { source: 3, target: 7, value: 3 },
  ],
};

const networkData = [
  { x: 18, y: 56, size: 180, name: "192.168.1.42" },
  { x: 42, y: 78, size: 90, name: "93.184.216.34" },
  { x: 48, y: 32, size: 72, name: "172.217.16.14" },
  { x: 72, y: 62, size: 58, name: "1.1.1.1" },
  { x: 80, y: 25, size: 42, name: "8.8.8.8" },
  { x: 64, y: 88, size: 34, name: "45.33.32.156" },
];

const packetSizeData = [
  { bucket: "64", count: 26 }, { bucket: "128", count: 18 }, { bucket: "256", count: 12 },
  { bucket: "512", count: 22 }, { bucket: "768", count: 9 }, { bucket: "1024", count: 15 },
  { bucket: "1280", count: 8 }, { bucket: "1500", count: 31 },
];

const arrivalData = [
  { bucket: ".01", count: 31 }, { bucket: ".05", count: 24 }, { bucket: ".1", count: 18 },
  { bucket: ".5", count: 12 }, { bucket: "1", count: 9 }, { bucket: "5", count: 5 },
];

const attackTimelineData = [
  { time: 5, severity: 1, size: 55, label: "DNS observation" },
  { time: 18, severity: 1, size: 44, label: "TLS session" },
  { time: 32, severity: 2, size: 65, label: "Repeated destination" },
  { time: 47, severity: 1, size: 48, label: "HTTP response" },
  { time: 58, severity: 2, size: 58, label: "Cross-file IOC" },
];

function Brand() {
  return (
    <div className="brand" aria-label="PCAP Threat Hunting Workbench">
      <img src="/assets/pcap-hunter-logo.svg" alt="PCAP Hunter magnifying-glass logo" />
      <span>PCAP Threat Hunting Workbench</span>
    </div>
  );
}

function Header({ onNavigate, workbench }) {
  const captureCount = workbench.capture_count || 0;
  const analysisReady = workbench.analysis_complete;
  return (
    <header className="app-header">
      <Brand />
      <div className="capture-status">
        <button className="capture-switcher" onClick={() => onNavigate("cases")}><File size={19} /> {captureCount} {captureCount === 1 ? "capture" : "captures"} <ArrowRight size={15} /></button>
        <span className="status-divider" />
        <span className={analysisReady ? "complete-status" : "ready-status"}>{analysisReady ? <CheckCircle size={19} weight="fill" /> : <Pulse size={19} />} {analysisReady ? "Analysis complete" : "Ready to analyze"}</span>
        <button className="icon-button" aria-label="Open settings" onClick={() => onNavigate("settings")}><GearSix size={21} /></button>
      </div>
    </header>
  );
}

function Sidebar({ active, onChange, system, version }) {
  const readyTools = (system?.tools || []).filter((tool) => tool.ready).map((tool) => tool.name);
  return (
    <aside className="sidebar">
      <nav aria-label="Primary navigation">
        {navigation.map(({ id, label, icon: Icon }) => (
          <button key={id} className={`nav-item ${active === id ? "active" : ""}`} onClick={() => onChange(id)} aria-current={active === id ? "page" : undefined}>
            <Icon size={24} weight={active === id ? "duotone" : "regular"} /><span>{label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-foot">
        <button className={`nav-item ${active === "settings" ? "active" : ""}`} onClick={() => onChange("settings")}>
          <GearSix size={24} /><span>Settings</span>
        </button>
        <div className={`system-health ${system?.healthy ? "" : "degraded"}`}><span /><div><strong>{system?.healthy ? "System healthy" : "Tool check needed"}</strong><small>{version ? `v${version} · ` : ""}{readyTools.join(" · ") || "worker starting"}</small></div></div>
      </div>
    </aside>
  );
}

function PageHeading({ title, description, actions }) {
  return <div className="page-heading"><div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

function SegmentedTabs({ items, active, onChange, label = "View" }) {
  return (
    <div className="segmented-tabs" role="tablist" aria-label={label}>
      {items.map(({ id, label: itemLabel, icon: Icon }) => (
        <button key={id} role="tab" aria-selected={active === id} className={active === id ? "active" : ""} onClick={() => onChange(id)}>
          {Icon && <Icon size={18} />}{itemLabel}
        </button>
      ))}
    </div>
  );
}

function Toggle({ checked, onChange, label, hint }) {
  return (
    <label className="toggle-row">
      <span><strong>{label}</strong>{hint && <small>{hint}</small>}</span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
    </label>
  );
}

function Notice({ children, onClose }) {
  return <div className="notice"><CheckCircle size={20} weight="fill" /><span>{children}</span>{onClose && <button onClick={onClose}><X size={17} /></button>}</div>;
}

function Analyze({ onNavigate, workbench }) {
  const inputRef = useRef(null);
  const [view, setView] = useState(() => new URLSearchParams(window.location.search).get("view") === "runs" ? "runs" : "upload");
  const [includeLlm, setIncludeLlm] = useState(true);
  const [path, setPath] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [files, setFiles] = useState([]);
  const [paths, setPaths] = useState([]);
  const queueCount = files.length + paths.length;

  const changeView = (nextView) => {
    setView(nextView);
    const url = new URL(window.location.href);
    if (nextView === "runs") url.searchParams.set("view", "runs");
    else url.searchParams.delete("view");
    window.history.replaceState({ ...window.history.state, analyzeView: nextView }, "", `${url.pathname}${url.search}${url.hash}`);
  };

  const addFiles = (selected) => {
    const rows = Array.from(selected || []).map((file) => ({ file, name: file.name, size: `${Math.max(1, Math.round(file.size / 1024 / 1024))} MB`, state: "Ready" }));
    if (rows.length) setFiles((current) => [...current, ...rows].slice(0, 50));
  };

  const startRun = async () => {
    if (!queueCount) {
      setSubmitError("Add at least one capture first.");
      return;
    }
    if (files.length && paths.length) {
      setSubmitError("Run uploaded files and container paths as separate batches so their source lineage stays clear.");
      return;
    }
    setSubmitting(true);
    setSubmitError("");
    try {
      if (files.length) await workbench.submitCaptures(files.map((row) => row.file), includeLlm);
      else await workbench.submitPaths(paths, includeLlm);
      setFiles([]);
      setPaths([]);
      setPath("");
      changeView("runs");
    } catch (error) {
      setSubmitError(error.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="screen">
      <PageHeading title="Analyze" description="Load one capture or a batch, choose what should run, and keep an eye on progress." actions={<button className="button secondary" onClick={() => changeView(view === "upload" ? "runs" : "upload")}><Queue size={18} /> {view === "upload" ? "Run queue" : "New analysis"}</button>} />
      <SegmentedTabs items={[{ id: "upload", label: "Upload & configure", icon: UploadSimple }, { id: "runs", label: "Run queue", icon: Queue }]} active={view} onChange={changeView} label="Analyze workflow" />

      {view === "upload" ? (
        <div className="analyze-layout">
          <section className="panel upload-panel">
            <div className="panel-title"><div><span className="eyebrow">Step 1</span><h2>Add PCAP files</h2><p>Batch mode turns on automatically when more than one capture is added.</p></div><span className="count-pill">{queueCount} files</span></div>
            <button className="drop-zone" onClick={() => inputRef.current?.click()}>
              <span className="upload-icon"><UploadSimple size={31} weight="duotone" /></span>
              <strong>Drop PCAP or PCAPNG files here</strong>
              <span>or choose multiple files from your computer</span>
              <small>Up to 50 files · 1 GB each · 5 GB total</small>
            </button>
            <input className="visually-hidden" ref={inputRef} type="file" multiple accept=".pcap,.pcapng" onChange={(event) => addFiles(event.target.files)} />
            <div className="path-input"><File size={19} /><input value={path} onChange={(event) => setPath(event.target.value)} placeholder="Or enter an allowed container path, e.g. /data/capture.pcap" /><button className="button secondary" disabled={!path.trim()} onClick={() => { const next = path.trim(); if (next && !paths.includes(next)) setPaths((current) => [...current, next].slice(0, 50)); setPath(""); }}>Add path</button></div>
            {submitError && <div className="error-notice"><WarningCircle size={19} /><span>{submitError}</span></div>}
            <div className="file-queue">
              {files.map((file, index) => <div className="file-row" key={`${file.name}-${index}`}><span className="file-kind"><File size={19} /></span><div><strong>{file.name}</strong><small>{file.size}</small></div><span className="ready-state"><CheckCircle size={16} weight="fill" /> {file.state}</span><button aria-label={`Remove ${file.name}`} onClick={() => setFiles(files.filter((_, rowIndex) => rowIndex !== index))}><X size={17} /></button></div>)}
              {paths.map((capturePath) => <div className="file-row" key={capturePath}><span className="file-kind"><HardDrives size={19} /></span><div><strong>{capturePath.split("/").pop()}</strong><small>{capturePath}</small></div><span className="ready-state"><CheckCircle size={16} weight="fill" /> Allowed path</span><button aria-label={`Remove ${capturePath}`} onClick={() => setPaths(paths.filter((item) => item !== capturePath))}><X size={17} /></button></div>)}
            </div>
          </section>

          <aside className="analysis-setup">
            <section className="panel">
              <div className="panel-title compact"><div><span className="eyebrow">Step 2</span><h2>Run setup</h2></div><button className="text-button" onClick={() => onNavigate("settings")}>Edit settings</button></div>
              <div className="setup-summary"><div><span>Profile</span><strong>Balanced inspection</strong></div><div><span>Pipeline</span><strong>10 of 10 stages</strong></div><div><span>OSINT</span><strong>Top 50 public IPs</strong></div><div><span>Output</span><strong>Autosave to case</strong></div></div>
              <div className="stage-chips">{pipelineStages.map((stage) => <span key={stage}><Check size={12} weight="bold" /> {stage}</span>)}</div>
              <Toggle checked={includeLlm} onChange={setIncludeLlm} label="Generate AI threat report" hint="OpenAI · gpt-4o · US English" />
              <div className="privacy-note"><ShieldCheck size={21} weight="duotone" /><span><strong>Durable background run</strong><small>Analysis survives a page reload and completed evidence is autosaved.</small></span></div>
              <button className="button primary full" disabled={submitting || !queueCount} onClick={startRun}><Play size={18} weight="fill" /> {submitting ? "Submitting…" : `Analyze ${queueCount > 1 ? `${queueCount} captures` : "capture"}`}</button>
            </section>
          </aside>
        </div>
      ) : (
        <RunQueue jobs={workbench.jobs} onNavigate={onNavigate} onRefresh={workbench.refresh} />
      )}
    </div>
  );
}

function RunQueue({ jobs, onNavigate, onRefresh }) {
  const latestCaseId = jobs[0]?.case_id;
  const visibleJobs = jobs.filter((job) => job.case_id === latestCaseId).slice(0, 50);
  const progressRows = visibleJobs.map((job) => ({ job, ...normalizeJobProgress(job) }));
  const running = visibleJobs.some((job) => job.status === "queued" || job.status === "running");
  const done = visibleJobs.length > 0 && visibleJobs.every((job) => job.status === "done");
  const progress = progressRows.length ? Math.floor(progressRows.reduce((sum, row) => sum + row.overallProgress, 0) / progressRows.length) : 0;
  return (
    <div className="run-layout">
      {done && <Notice>Analysis completed and was autosaved to its case.</Notice>}
      <section className="panel run-overview">
        <div className="run-head"><div><span className={`run-state ${done ? "complete" : "running"}`}>{done ? "Complete" : running ? "Running safely in background" : "Ready"}</span><h2>{visibleJobs.length || "No"}-capture threat hunting run</h2><p>{visibleJobs.length ? `Latest case ${visibleJobs[0].case_id}` : "Submit captures from Upload & configure"}</p></div><strong>{progress}%</strong></div>
        <div className="progress-track"><span style={{ width: `${progress}%` }} /></div>
        <p className="run-caption">{done ? "All evidence is ready across Findings, Investigate, Reports, and Cases." : running ? "You can leave this page. The worker and autosave continue independently." : "No active analysis is running."}</p>
        <div className="run-actions">{done ? <button className="button primary" onClick={() => onNavigate("findings")}>Review findings <ArrowRight size={17} /></button> : <button className="button secondary" onClick={onRefresh}>Refresh status</button>}</div>
      </section>
      <div className="run-files">
        {progressRows.map(({ job: file, activeStageIndex, completedStages, displayStage, overallProgress, stageProgress }, index) => {
          return <section className="panel run-file" key={file.id}><div className="run-file-head"><div><File size={20} /><span><strong>{index + 1}/{visibleJobs.length} — {file.name}</strong><small>{displayStage}</small></span></div><b>{overallProgress}%</b></div><div className="progress-track small"><span style={{ width: `${overallProgress}%` }} /></div>{file.status === "running" && <div className="active-stage-progress"><div><span><strong>{displayStage || "Preparing analysis"}</strong><small>{file.stage_message || "Processing this stage"}</small></span><b>{stageProgress}%</b></div><div className="stage-progress-track"><span style={{ width: `${stageProgress}%` }} /></div></div>}<div className="mini-stage-list">{pipelineStages.map((stage, stageIndex) => { const isDone = file.status === "done" || stageIndex < completedStages; const isActive = file.status === "running" && stageIndex === (activeStageIndex >= 0 ? activeStageIndex : completedStages); return <span className={isDone ? "done" : isActive ? "active" : ""} key={stage}><i>{isDone ? <Check size={12} /> : stageIndex + 1}</i><em>{stage}</em></span>; })}</div></section>;
        })}
      </div>
    </div>
  );
}

function SearchPanel({ query, setQuery, evidenceType, setEvidenceType, items = evidence, onResult }) {
  const filtered = useMemo(() => items.filter((item) => (evidenceType === "All evidence" || item.type === evidenceType) && (!query.trim() || `${item.value} ${item.context} ${item.type}`.toLowerCase().includes(query.toLowerCase()))), [items, query, evidenceType]);
  const active = query.trim() || evidenceType !== "All evidence";
  return (
    <div className="search-wrap">
      <div className={`global-search ${active ? "searching" : ""}`}><MagnifyingGlass size={22} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IPs, domains, hashes, JA3…" aria-label="Search IPs, domains, hashes, and JA3" />{query && <button className="clear-search" onClick={() => setQuery("")} aria-label="Clear search"><X size={17} /></button>}<div className="search-separator" /><Funnel size={19} /><select value={evidenceType} onChange={(event) => setEvidenceType(event.target.value)} aria-label="Evidence type">{["All evidence", "IP", "Domain", "Hash", "JA3"].map((type) => <option key={type}>{type}</option>)}</select></div>
      {active && <div className="search-results" role="status"><div className="search-results-head"><span>{filtered.length} matching {filtered.length === 1 ? "item" : "items"}</span><button onClick={() => { setQuery(""); setEvidenceType("All evidence"); }}>Clear search</button></div>{filtered.map((item) => <button className="evidence-result" key={item.value} onClick={() => onResult?.(item)} aria-label={`Open ${item.value} in the evidence workspace`}><span className="evidence-type">{item.type}</span><span className="evidence-value">{item.value}</span><span className="evidence-context">{item.context}</span><span className="evidence-status"><Check size={14} /> {item.status}</span><ArrowRight size={17} /></button>)}</div>}
    </div>
  );
}

function Findings({ onNavigate, workbench }) {
  const [query, setQuery] = useState("");
  const [evidenceType, setEvidenceType] = useState("All evidence");
  const dashboard = workbench.dashboard;
  const evidenceRows = dashboard.evidence || [];
  const summaryMetrics = [
    { label: "Packets", value: dashboard.packets, icon: Copy }, { label: "Flows", value: dashboard.flows, icon: ArrowsLeftRight },
    { label: "Indicators", value: evidenceRows.length, icon: ShieldCheck }, { label: "Alerts", value: dashboard.alerts, icon: Bell },
  ];
  return (
    <div className="screen findings-screen">
      <button className="back-button upper-layer-back" onClick={() => onNavigate("dashboard")}><ArrowLeft size={16} /> Back to Dashboard</button>
      <PageHeading title="Findings" description={`${workbench.capture_count} ${workbench.capture_count === 1 ? "capture" : "captures"} · ${workbench.analysis_complete ? "Analysis complete" : "Waiting for analysis"} · ${dashboard.stages.length} stages recorded`} actions={<button className="button secondary" onClick={() => onNavigate("reports")}><FileText size={17} /> Open report</button>} />
      <SearchPanel query={query} setQuery={setQuery} evidenceType={evidenceType} setEvidenceType={setEvidenceType} items={evidenceRows} onResult={(item) => onNavigate("investigate", { investigateTab: "evidence", evidenceQuery: item.value })} />
      <section className="risk-summary"><CheckCircle size={51} /><div><h2>{dashboard.alerts ? `${dashboard.alerts} elevated finding${dashboard.alerts === 1 ? "" : "s"} detected` : "No elevated risk detected"}</h2><p>{dashboard.packets} packets and {dashboard.flows} flows were analyzed. {dashboard.alerts ? "Review the evidence inventory and supporting traffic." : "No high-priority threats were found."}</p><button className="text-button" onClick={() => onNavigate("investigate")}>Why this verdict?</button></div><span className="coverage-badge"><Check size={14} /> {dashboard.stages.length}/10 stages recorded</span></section>
      <section className="metric-grid">{summaryMetrics.map(({ label, value, icon: Icon }) => <article className="metric" key={label}><span className="metric-icon"><Icon size={29} weight="duotone" /></span><span className="metric-value">{value}</span><span className="metric-label">{label}</span></article>)}</section>
      <section className="recommended-section"><h2>Recommended next steps</h2><div className="recommended-list">
        <article className="recommended-row"><span className="step-icon"><ChartPieSlice size={23} /></span><div className="step-copy"><h3>Review capture coverage</h3><p>Confirm the batch covers the expected time range and endpoints.</p></div><button className="button primary" onClick={() => onNavigate("investigate", { investigateTab: "mitre", mitreView: "coverage" })}>Review coverage</button></article>
        <article className="recommended-row"><span className="step-icon"><GlobeHemisphereWest size={23} /></span><div className="step-copy"><h3>Enrich the {evidenceRows.length} observed indicators</h3><p>Configured providers and missing coverage stay visibly distinct.</p></div><button className="button secondary" onClick={() => onNavigate("investigate", { investigateTab: "intel" })}>Open threat intel</button></article>
        <article className="recommended-row"><span className="step-icon"><ArrowsLeftRight size={23} /></span><div className="step-copy"><h3>Inspect cross-file traffic</h3><p>One domain and one external IP appear in both captures.</p></div><button className="button secondary" onClick={() => onNavigate("investigate", { investigateTab: "traffic" })}>Explore traffic</button></article>
      </div></section>
      <TrafficOverview data={dashboard} />
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return <div className="chart-tooltip"><strong>{label}</strong><span>{payload[0].value} flows</span></div>;
}

function TrafficOverview({ expanded = false, data, activeProtocol = "All", activeTime = "", onProtocolSelect, onTimeSelect, onClearFilters, filterTarget = "overview" }) {
  const protocols = data?.protocols ?? protocolData;
  const talkers = data?.top_talkers ?? talkerData;
  const timeline = data?.traffic ?? trafficData;
  const totalFlows = data?.flows ?? protocols.reduce((sum, row) => sum + row.value, 0);
  const selectedProtocol = protocols.find((item) => item.name === activeProtocol);
  const hasLinkedFilter = Boolean(selectedProtocol || activeTime);
  const selectProtocol = (name) => onProtocolSelect?.(activeProtocol === name ? "All" : name);
  const interactiveCopy = filterTarget === "map" ? "Click a protocol or time point to filter the world map" : "Click a protocol or time point to filter this traffic overview";
  const summaryLabel = filterTarget === "map" ? "Map" : "Traffic overview";
  return (
    <section className={`traffic-section ${expanded ? "expanded" : ""}`}><div className="section-heading"><div><h2>Traffic overview</h2><p>{onProtocolSelect || onTimeSelect ? interactiveCopy : "Protocol distribution, top talkers, and traffic volume over time."}</p></div>{expanded && <div className={`linked-filter-summary ${hasLinkedFilter ? "active" : ""}`} aria-live="polite"><Funnel size={16} />{hasLinkedFilter ? <><span>{summaryLabel} filtered by {[selectedProtocol?.name, activeTime && `${activeTime} UTC`].filter(Boolean).join(" · ")}</span><button type="button" onClick={onClearFilters}>Clear</button></> : <span>{filterTarget === "map" ? "Visualizations linked to map" : "Filters ready"}</span>}</div>}</div><div className="traffic-card">
      <div className="protocol-panel"><div className="donut-wrap" aria-label={onProtocolSelect ? "Interactive protocol distribution" : "Protocol distribution"}><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={protocols} dataKey="value" innerRadius={expanded ? 49 : 42} outerRadius={expanded ? 64 : 58} paddingAngle={1} stroke="#fff" strokeWidth={2} onClick={(entry) => entry?.name && selectProtocol(entry.name)} className={onProtocolSelect ? "interactive-donut" : undefined}>{protocols.map((entry) => <Cell key={entry.name} fill={entry.color} opacity={selectedProtocol && selectedProtocol.name !== entry.name ? 0.28 : 1} />)}</Pie></PieChart></ResponsiveContainer><span className="donut-total"><strong>{selectedProtocol?.value ?? totalFlows}</strong>{selectedProtocol?.name ?? "Flows"}</span></div><div className="legend" aria-label="Protocol flow counts">{protocols.map((item) => onProtocolSelect ? <button type="button" className={activeProtocol === item.name ? "active" : ""} aria-pressed={activeProtocol === item.name} onClick={() => selectProtocol(item.name)} key={item.name} title={`Filter the ${filterTarget === "map" ? "map" : "traffic overview"} to ${item.name}`}><span className="legend-dot" style={{ background: item.color }} /><span className="legend-name">{item.name}</span><b>{item.value}</b></button> : <div key={item.name} title={`${item.name}: ${item.value} flows`}><span className="legend-dot" style={{ background: item.color }} /><span className="legend-name">{item.name}</span><b>{item.value}</b></div>)}</div></div>
      <div className="chart-panel"><div className="chart-heading"><strong>Top talkers</strong><span>By total bytes</span></div><ResponsiveContainer width="100%" height={expanded ? 190 : 126}><BarChart data={talkers} layout="vertical" margin={{ left: 8, right: 28, top: 4, bottom: 4 }}><XAxis type="number" hide /><YAxis type="category" dataKey="name" width={104} tick={{ fill: "#66728a", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip /><Bar dataKey="bytes" fill="#3d9bea" radius={[0, 5, 5, 0]} barSize={7} /></BarChart></ResponsiveContainer></div>
      <div className={`chart-panel timeline-panel ${onTimeSelect ? "interactive-chart-panel" : ""}`} data-testid={onTimeSelect ? "traffic-timeline-chart" : undefined} role={onTimeSelect ? "group" : undefined} aria-label={onTimeSelect ? `Traffic timeline ${filterTarget === "map" ? "map" : "workspace"} filter` : undefined}><div className="chart-heading"><strong>Traffic over time</strong><span>{activeTime ? `${summaryLabel} filtered to ${activeTime} UTC · click again to clear` : onTimeSelect ? `Flows per minute · click a point to filter the ${filterTarget === "map" ? "map" : "traffic overview"}` : "Flows per minute"}</span></div><ResponsiveContainer width="100%" height={expanded ? 195 : 132}><AreaChart data={timeline} margin={{ left: -22, right: 4, top: 10, bottom: 0 }} onClick={(state) => state?.activeLabel && onTimeSelect?.(activeTime === state.activeLabel ? "" : state.activeLabel)}><CartesianGrid stroke="#eef1f6" vertical={false} /><XAxis dataKey="time" tick={{ fill: "#77839a", fontSize: 10 }} axisLine={{ stroke: "#dce2eb" }} tickLine={false} interval={2} /><YAxis allowDecimals={false} tick={{ fill: "#77839a", fontSize: 10 }} axisLine={false} tickLine={false} /><Tooltip content={<ChartTooltip />} />{activeTime && <ReferenceLine x={activeTime} stroke="#ff3942" strokeWidth={2} strokeDasharray="4 3" />}<Area type="monotone" dataKey="flows" stroke="#3d9bea" strokeWidth={2.3} fill="#e9f4fe" activeDot={{ r: 5, fill: "#ff3942", stroke: "#fff", strokeWidth: 2 }} /></AreaChart></ResponsiveContainer></div>
    </div></section>
  );
}

function FlowDestinationTree({ flows, selected, onSelect }) {
  const hierarchy = useMemo(() => buildMapFlowHierarchy(flows), [flows]);
  const [expandedGroups, setExpandedGroups] = useState(new Set());
  const selectedPath = useMemo(() => {
    if (!selected) return null;
    for (const continent of hierarchy) {
      for (const country of continent.countries) {
        for (const city of country.cities) {
          if (city.members.some((flow) => flow.ip === selected.ip)) return { continent, country, city };
        }
      }
    }
    return null;
  }, [hierarchy, selected]);

  useEffect(() => {
    if (!selectedPath) return;
    setExpandedGroups((current) => {
      const next = new Set(current);
      next.add(selectedPath.continent.key);
      next.add(selectedPath.country.key);
      if (selectedPath.city.endpointCount > 1) next.add(selectedPath.city.key);
      return next.size === current.size ? current : next;
    });
  }, [selectedPath]);

  const toggleGroup = (key) => {
    setExpandedGroups((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const groupButton = (group, depth, childLabel, children) => {
    const open = expandedGroups.has(group.key);
    return <div className="flow-tree-group" key={group.key}>
      <button className={`flow-tree-row flow-tree-group-row ${open ? "open" : ""}`} style={{ "--flow-depth": depth }} onClick={() => toggleGroup(group.key)} aria-expanded={open}>
        <CaretDown className="flow-tree-caret" size={13} weight="bold" />
        <span className="flow-tree-dot" style={{ background: group.color }} />
        <div><strong>{group.label}</strong><small>{group.endpointCount} {group.endpointCount === 1 ? "endpoint" : "endpoints"} · {childLabel}</small></div>
        <b>{group.packets.toLocaleString()}</b>
      </button>
      {open && <div className="flow-tree-children">{children}</div>}
    </div>;
  };

  const endpointButton = (flow, depth, label = flow.ip, context = flow.city) => (
    <button className={`flow-tree-row flow-tree-endpoint ${selected?.ip === flow.ip ? "active" : ""}`} style={{ "--flow-depth": depth }} key={flow.ip} onClick={() => onSelect(flow.ip)}>
      <span className="flow-tree-spacer" />
      <span className="flow-tree-dot" style={{ background: flow.color }} />
      <div><strong>{label}</strong><small>{context}</small></div>
      <b>{Number(flow.packets).toLocaleString()}</b>
    </button>
  );

  const cityRows = (country) => country.cities.map((city) => {
    if (city.endpointCount === 1) {
      const flow = city.members[0];
      return endpointButton(flow, 2, city.label, flow.ip);
    }
    return groupButton(city, 2, `${city.protocols.length} ${city.protocols.length === 1 ? "protocol" : "protocols"}`, city.members.map((flow) => endpointButton(flow, 3, flow.ip, `${flow.packets.toLocaleString()} packets`)));
  });

  const countryRows = (continent) => continent.countries.map((country) => groupButton(
    country,
    1,
    `${country.cities.length} ${country.cities.length === 1 ? "city" : "cities"}`,
    cityRows(country),
  ));

  return <div className="flow-destination-list">
    <div className="flow-list-title"><span>Destinations by region</span><b>{flows.length}</b></div>
    {hierarchy.map((continent) => groupButton(
      continent,
      0,
      `${continent.countries.length} ${continent.countries.length === 1 ? "country" : "countries"}`,
      countryRows(continent),
    ))}
  </div>;
}

function WorldFlowMap({ flows, home = { lat: 0, lon: 0, city: "Home" }, onOpenFlows }) {
  const [selectedIp, setSelectedIp] = useState(flows[0]?.ip || "");
  const [position, setPosition] = useState({ coordinates: createCoordinates(0, 8), zoom: 1 });
  const selected = flows.find((flow) => flow.ip === selectedIp) || flows[0];
  const homePoint = createCoordinates(home.lon || 0, home.lat || 0);
  const aggregationLevel = getMapAggregationLevel(position.zoom);
  const visibleMapItems = useMemo(() => aggregateMapFlows(flows, aggregationLevel), [flows, aggregationLevel]);
  const activeMapItem = visibleMapItems.find((item) => item.members.some((flow) => flow.ip === selected?.ip));

  const selectMapItem = (item) => {
    const primaryFlow = item.primaryFlow || item.members[0];
    if (primaryFlow) setSelectedIp(primaryFlow.ip);
    if (aggregationLevel !== "city") {
      setPosition({ coordinates: createCoordinates(item.coordinates[0], item.coordinates[1]), zoom: getNextMapZoom(aggregationLevel) });
    }
  };

  useEffect(() => {
    if (!flows.length) setSelectedIp("");
    else if (!flows.some((flow) => flow.ip === selectedIp)) setSelectedIp(flows[0].ip);
  }, [flows, selectedIp]);

  return (
    <section className="panel world-map-panel dashboard-view-target" id="world-flow-map" tabIndex={-1}>
      <div className="panel-title compact map-title">
        <div><h2>Global traffic origins & connectivity</h2><p>{home.city || "Home"} → public destinations · zoom reveals continent, country, then city detail</p></div>
        <div className="map-actions"><span className="live-dot">Live view</span><button className="button secondary" onClick={() => setPosition({ coordinates: createCoordinates(0, 8), zoom: 1 })}>Reset map</button></div>
      </div>
      <div className="world-map-layout">
        <div className="world-map-canvas" aria-label={`World map showing network flow paths from ${home.city || "the home location"} to ${flows.length} public destinations, ${getMapAggregationLabel(aggregationLevel).toLowerCase()}`}>
          <ComposableMap projection="geoEqualEarth" projectionConfig={{ scale: 180, center: createCoordinates(0, 1) }} width={960} height={560}>
            <ZoomableGroup center={position.coordinates} zoom={position.zoom} minZoom={1} maxZoom={4} onMoveEnd={setPosition}>
              <Geographies geography={worldGeography}>
                {({ geographies }) => geographies.map((geo) => (
                  <Geography key={geo.rsmKey} geography={geo} tabIndex={-1} style={{ default: { fill: "#132c49", stroke: "#35506c", strokeWidth: 0.45, outline: "none" }, hover: { fill: "#193b60", stroke: "#4c6c8d", strokeWidth: 0.6, outline: "none" }, pressed: { fill: "#193b60", outline: "none" } }} />
                ))}
              </Geographies>
              {visibleMapItems.map((item) => (
                <MapLine key={`line-${item.key}`} from={homePoint} to={item.coordinates} stroke={item.status === "Review" ? "#ffbd59" : "#4da7f7"} strokeWidth={Math.min(6, Math.max(1.4, item.packets / 300)) / position.zoom} strokeLinecap="round" fill="transparent" className={activeMapItem?.key === item.key ? "map-flow active" : "map-flow"} />
              ))}
              <Marker coordinates={homePoint}>
                <circle r={7 / position.zoom} fill="#ff3942" stroke="#ffffff" strokeWidth={2.5 / position.zoom} />
                <text y={-13 / position.zoom} textAnchor="middle" className="map-label home" style={{ fontSize: `${10 / position.zoom}px`, strokeWidth: 3 / position.zoom }}>{home.city || "Home"}</text>
              </Marker>
              {visibleMapItems.map((item) => {
                const isActive = activeMapItem?.key === item.key;
                const baseRadius = item.endpointCount > 1 ? Math.min(11, 7 + Math.log2(item.endpointCount)) : 5;
                const showLabel = aggregationLevel === "continent" || isActive || item.endpointCount > 1;
                return <Marker key={item.key} coordinates={item.coordinates} onClick={() => selectMapItem(item)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") selectMapItem(item); }} role="button" tabIndex={0} aria-label={`${item.label}, ${item.endpointCount} ${item.endpointCount === 1 ? "endpoint" : "endpoints"}, ${item.packets.toLocaleString()} packets`} className={isActive ? "map-marker selected" : "map-marker"}>
                  <circle r={(isActive ? baseRadius + 1.5 : baseRadius) / position.zoom} fill={item.color} stroke="#ffffff" strokeWidth={2 / position.zoom} />
                  {item.endpointCount > 1 && <text y={2.6 / position.zoom} textAnchor="middle" className="map-cluster-count" style={{ fontSize: `${7.5 / position.zoom}px` }}>{item.endpointCount}</text>}
                  {showLabel && <text y={-(baseRadius + 7) / position.zoom} textAnchor="middle" className="map-label" style={{ fontSize: `${10 / position.zoom}px`, strokeWidth: 3 / position.zoom }}>{item.label}</text>}
                </Marker>
              })}
            </ZoomableGroup>
          </ComposableMap>
          <div className="map-legend"><strong className="map-detail-label">{getMapAggregationLabel(aggregationLevel)}</strong><span><i className="map-key blue" /> Expected flow</span><span><i className="map-key amber" /> Review</span><span>Drag to pan · scroll to zoom</span></div>
        </div>
        <aside className="flow-inspector">
          <div className="flow-inspector-head"><div className="flow-inspector-kicker"><span className="eyebrow">Selected destination</span>{selected && <span className={selected.status === "Review" ? "flow-assessment review" : "flow-assessment expected"}>{selected.status}</span>}</div><strong>{selected?.city || "No match"}</strong><small>{selected ? `${selected.country} · ${selected.ip}` : "Adjust the dashboard filters"}</small></div>
          {selected ? <><div className="flow-stats"><div><span>Packets</span><strong>{selected.packets.toLocaleString()}</strong></div><div><span>Traffic</span><strong>{selected.bytes}</strong></div><div className="protocol-stat"><span>Protocols</span><strong>{selected.protocols.join(" · ")}</strong></div></div><button className="button secondary full" onClick={() => onOpenFlows?.(selected)}>Open matching flows <ArrowRight size={16} /></button></> : <div className="map-empty-copy"><GlobeHemisphereWest size={30} weight="duotone" /><strong>No public GeoIP matches</strong><span>The global canvas stays available; public destinations appear here when resolved.</span></div>}
          <FlowDestinationTree flows={flows} selected={selected} onSelect={setSelectedIp} />
        </aside>
      </div>
    </section>
  );
}

function FamiliarVisualizations({ data, focusTarget = "" }) {
  const [view, setView] = useState(() => getDashboardViewForTarget(focusTarget));
  const profileHeat = data?.heatmap || [];
  const liveSankey = data?.sankey || { nodes: [], links: [] };
  const liveNetwork = data?.network || [];
  const livePacketSizes = data?.packet_sizes || [];
  const liveArrivals = data?.inter_arrivals || [];
  const liveTimeline = data?.attack_timeline || [];
  const sankeyNames = liveSankey.nodes.map((node) => node.name);
  const exportCurrentChart = () => {
    const chartExport = getDashboardChartExport(view, data);
    downloadText(chartExport.filename, chartExport.content, "application/json");
  };
  return (
    <section className="dashboard-advanced" id="dashboard-deep-dives">
      <div className="section-heading"><div><h2>Familiar deep-dive visualizations</h2><p>The established flow, topology, timeline, and profiling views remain one click away.</p></div><button className="button secondary" onClick={exportCurrentChart}><DownloadSimple size={17} /> Export current chart</button></div>
      <SegmentedTabs items={[{ id: "paths", label: "Sankey flow", icon: ShareNetwork }, { id: "network", label: "Network graph", icon: ShareNetwork }, { id: "profile", label: "Traffic profiling", icon: Pulse }, { id: "timeline", label: "Attack timeline", icon: ClockCounterClockwise }]} active={view} onChange={setView} label="Dashboard visualization" />
      <div className="panel advanced-chart-panel">
        {view === "paths" && <div className="advanced-chart dashboard-view-target" id="sankey-flow" tabIndex={-1}><div className="chart-heading roomy"><strong>Traffic flow · client → service → server</strong><span>Width represents packet volume; hover a path for detail.</span></div>{liveSankey.links.length ? <><div className="sankey-label-grid"><div><span>Observed nodes</span><strong>{sankeyNames.slice(0, 2).join(" · ")}</strong></div><div><span>Services</span><strong>{sankeyNames.filter((name) => name.includes(" / ")).slice(0, 2).join(" · ") || "Protocol paths"}</strong></div><div><span>Destinations</span><strong>{sankeyNames.slice(-3).join(" · ")}</strong></div></div><ResponsiveContainer width="100%" height={300}><Sankey data={liveSankey} nodePadding={28} nodeWidth={12} margin={{ top: 10, right: 24, bottom: 10, left: 24 }} link={{ stroke: "#83aee0" }}><Tooltip /></Sankey></ResponsiveContainer></> : <ChartEmptyState label="No flow paths are available for this capture." />}</div>}
        {view === "network" && <div className="network-layout dashboard-view-target" id="network-graph" tabIndex={-1}><div className="advanced-chart"><div className="chart-heading roomy"><strong>Network communication graph</strong><span>Node size reflects total connections; local nodes use the red home color.</span></div>{liveNetwork.length ? <ResponsiveContainer width="100%" height={355}><ScatterChart margin={{ top: 24, right: 24, bottom: 18, left: 18 }}><CartesianGrid stroke="#edf1f6" /><XAxis type="number" dataKey="x" domain={[0, 100]} hide /><YAxis type="number" dataKey="y" domain={[0, 100]} hide /><ZAxis type="number" dataKey="size" range={[90, 1000]} /><Tooltip cursor={{ strokeDasharray: "3 3" }} /><Scatter data={liveNetwork} fill="#378fd7">{liveNetwork.map((node) => <Cell key={node.name} fill={node.private ? "#ff3942" : "#378fd7"} />)}</Scatter></ScatterChart></ResponsiveContainer> : <ChartEmptyState label="No network graph is available for this capture." />}</div><div className="network-key">{liveNetwork.map((node) => <div key={node.name}><span className={node.private ? "home" : ""} /><strong>{node.name}</strong><small>{node.size} weighted connections</small></div>)}</div></div>}
        {view === "profile" && <div className="profile-view"><div className="profile-charts"><div className="dashboard-view-target" id="packet-size-histogram" tabIndex={-1}><div className="chart-heading roomy"><strong>Packet size distribution</strong><span>Bytes per packet</span></div><ResponsiveContainer width="100%" height={245}><BarChart data={livePacketSizes}><CartesianGrid stroke="#edf1f6" vertical={false} /><XAxis dataKey="bucket" tick={{ fontSize: 10, fill: "#748096" }} /><YAxis tick={{ fontSize: 10, fill: "#748096" }} /><Tooltip /><Bar dataKey="count" fill="#378fd7" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div><div className="dashboard-view-target" id="inter-arrival-histogram" tabIndex={-1}><div className="chart-heading roomy"><strong>Inter-arrival distribution</strong><span>Seconds between packets</span></div><ResponsiveContainer width="100%" height={245}><BarChart data={liveArrivals}><CartesianGrid stroke="#edf1f6" vertical={false} /><XAxis dataKey="bucket" tick={{ fontSize: 10, fill: "#748096" }} /><YAxis tick={{ fontSize: 10, fill: "#748096" }} /><Tooltip /><Bar dataKey="count" fill="#3dbb6f" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer></div></div><div className="heatmap-wrap dashboard-view-target" id="traffic-heatmap" tabIndex={-1}><div className="chart-heading roomy"><strong>Traffic timeline heatmap · top destination IPs</strong><span>Brighter cells indicate more packets in that minute.</span></div><div className="traffic-heatmap" aria-label="Traffic timeline heatmap">{profileHeat.map((value, index) => <span key={index} data-level={value} />)}</div><div className="heatmap-axis"><span>Start</span><span>25%</span><span>50%</span><span>75%</span><span>End</span></div></div></div>}
        {view === "timeline" && <div className="advanced-chart dashboard-view-target" id="attack-timeline" tabIndex={-1}><div className="chart-heading roomy"><strong>Attack timeline</strong><span>Analytical observations ordered by capture minute and severity.</span></div>{liveTimeline.length ? <ResponsiveContainer width="100%" height={350}><ScatterChart margin={{ top: 25, right: 25, bottom: 25, left: 5 }}><CartesianGrid stroke="#edf1f6" /><XAxis type="number" dataKey="time" name="Capture minute" unit=" min" domain={[0, 60]} tick={{ fontSize: 11, fill: "#748096" }} /><YAxis type="number" dataKey="severity" name="Severity" domain={[0, 4]} ticks={[0, 1, 2, 3, 4]} tickFormatter={(value) => ["Info", "Low", "Medium", "High", "Critical"][value]} width={70} tick={{ fontSize: 11, fill: "#748096" }} /><ZAxis type="number" dataKey="size" range={[90, 360]} /><Tooltip cursor={{ strokeDasharray: "3 3" }} /><Scatter data={liveTimeline} fill="#f3aa35" /></ScatterChart></ResponsiveContainer> : <ChartEmptyState label="No attack-timeline events were detected." />}</div>}
      </div>
    </section>
  );
}

function ChartEmptyState({ label }) {
  return <div className="chart-empty-state"><ChartLine size={30} weight="duotone" /><strong>{label}</strong><span>The visualization remains available when matching evidence is present.</span></div>;
}

function Dashboard({ workbench, onNavigate }) {
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("All");
  const [timeBucket, setTimeBucket] = useState("");
  const [topMode, setTopMode] = useState("IP");
  const focusTarget = getTrafficViewTool(window.location.hash.slice(1))?.target || "";
  const dashboard = workbench.dashboard;
  const mapFlows = useMemo(() => filterDashboardMapFlows(dashboard.map_flows, { query, protocol, time: timeBucket }), [dashboard.map_flows, query, protocol, timeBucket]);
  const topData = topMode === "IP" ? dashboard.top_ips : dashboard.top_domains;
  const issueCount = dashboard.yara_issues + dashboard.cert_issues;
  const clearDashboardFilters = () => { setQuery(""); setProtocol("All"); setTimeBucket(""); };
  const exportDashboard = () => downloadText("pcap-hunter-dashboard.json", JSON.stringify({
    case_id: workbench.active_case_id,
    analysis_id: workbench.active_analysis_id,
    dashboard,
  }, null, 2), "application/json");
  const openTopItem = (row) => onNavigate("investigate", { investigateTab: "evidence", evidenceQuery: row.name });

  useEffect(() => {
    if (!focusTarget) return undefined;
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(focusTarget);
      if (!target) return;
      target.scrollIntoView({ behavior: "smooth", block: "start" });
      target.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [focusTarget]);

  return (
    <div className="screen dashboard-screen">
      <PageHeading title="Dashboard" description={`The familiar visual overview, restored for ${workbench.active_case_title || "the active capture set"}.`} actions={<><span className="coverage-badge"><Check size={14} /> {dashboard.stages.length}/10 stages recorded</span><button className="button secondary" onClick={exportDashboard}><DownloadSimple size={17} /> Export dashboard</button></>} />
      <section className="dashboard-summary">
        {[{ label: "Risk level", value: dashboard.risk, icon: ShieldCheck }, { label: "Flows", value: dashboard.flows, icon: ArrowsLeftRight }, { label: "Alerts", value: dashboard.alerts, icon: Bell }, { label: "Beacons", value: dashboard.beacons, icon: Pulse }, { label: "YARA / cert issues", value: issueCount, icon: CheckCircle }].map(({ label, value, icon: Icon }) => <article key={label}><span><Icon size={22} weight="duotone" /></span><div><small>{label}</small><strong>{value}</strong></div></article>)}
      </section>
      <div className="dashboard-filter-bar">
        <div className="dashboard-search"><MagnifyingGlass size={19} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search IPs or locations on the dashboard…" aria-label="Search dashboard IPs and locations" /></div>
        <div className="protocol-filters" aria-label="Protocol filter">{["All", "TCP", "UDP", "DNS"].map((item) => <button className={protocol === item ? "active" : ""} onClick={() => setProtocol(item)} key={item}>{item}</button>)}</div>
        <span className="public-only-note"><ShieldCheck size={15} /> Public destinations only</span>
        <button className="text-button" onClick={clearDashboardFilters}>Clear filters</button>
        <span className="filter-count">{mapFlows.length} mapped destinations · home anchor included</span>
      </div>
      <WorldFlowMap flows={mapFlows} home={dashboard.home} onOpenFlows={(flow) => onNavigate("investigate", { investigateTab: "evidence", evidenceQuery: flow?.ip || "" })} />
      <TrafficOverview expanded data={dashboard} activeProtocol={protocol} activeTime={timeBucket} onProtocolSelect={setProtocol} onTimeSelect={setTimeBucket} onClearFilters={() => { setProtocol("All"); setTimeBucket(""); }} filterTarget="map" />
      <section className="top-analysis panel dashboard-view-target" id="top-10-analysis" tabIndex={-1}>
        <div className="panel-title compact"><div><h2>Top 10 analysis</h2><p>Switch between the IP-centric and domain-centric views analysts already know.</p></div><div className="button-group"><button className={`button ${topMode === "IP" ? "primary" : "secondary"}`} onClick={() => setTopMode("IP")}>IP view</button><button className={`button ${topMode === "Domain" ? "primary" : "secondary"}`} onClick={() => setTopMode("Domain")}>Domain view</button></div></div>
        <div className="top-analysis-grid"><div><div className="chart-heading roomy"><strong>{topMode === "IP" ? "Top source & destination IPs" : "Top queried & resolved domains"}</strong><span>By flow or DNS query count</span></div><ResponsiveContainer width="100%" height={270}><BarChart data={topData} layout="vertical" margin={{ left: 18, right: 34, top: 10, bottom: 8 }}><XAxis type="number" hide /><YAxis type="category" dataKey="name" width={150} tick={{ fill: "#66728a", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip /><Bar dataKey="value" fill="#378fd7" radius={[0, 5, 5, 0]} barSize={12} /></BarChart></ResponsiveContainer></div><div className="top-table"><div className="top-table-head"><span>{topMode === "IP" ? "Endpoint" : "Domain"}</span><span>Count</span><span>Context</span></div>{topData.map((row, index) => <button key={row.name} onClick={() => openTopItem(row)} aria-label={`Open evidence for ${row.name}`}><strong>{row.name}</strong><b>{row.value}</b><span>{index === 0 ? "Top observed" : index < 3 ? "Expected traffic" : "Observed"}</span></button>)}</div></div>
      </section>
      <FamiliarVisualizations data={dashboard} focusTarget={focusTarget} />
    </div>
  );
}

function Investigate({ workbench, onOpenTrafficView }) {
  const requestedTab = window.history.state?.investigateTab;
  const [tab, setTab] = useState(investigateTabs.some((item) => item.id === requestedTab) ? requestedTab : "evidence");
  return (
    <div className="screen">
      <PageHeading title="Investigate" description="Move from the verdict into traffic, behaviors, enrichment, and underlying evidence." />
      <SegmentedTabs items={investigateTabs} active={tab} onChange={setTab} label="Investigation workspace" />
      {tab === "evidence" && <EvidenceWorkspace items={workbench.dashboard.evidence} lookupWhois={workbench.lookupWhois} initialQuery={window.history.state?.evidenceQuery || ""} />}
      {tab === "traffic" && <TrafficWorkspace data={workbench.dashboard} onOpenTrafficView={onOpenTrafficView} onChangeTab={setTab} />}
      {tab === "mitre" && <MitreWorkspace data={workbench.dashboard} initialView={window.history.state?.mitreView || "findings"} />}
      {tab === "intel" && <ThreatIntelWorkspace data={workbench.dashboard} config={workbench.config} lookupWhois={workbench.lookupWhois} />}
      {tab === "raw" && <RawWorkspace data={workbench.dashboard} />}
    </div>
  );
}

function IndicatorValue({ row }) {
  return <strong className="indicator-value"><span>{row.hostname || row.value}</span>{row.hostname && <small>{row.value} · PTR</small>}</strong>;
}

function firstWhoisValue(value) {
  if (Array.isArray(value)) return value.filter(Boolean).join(", ") || "Not available";
  return value || "Not available";
}

function WhoisDialog({ indicator, lookupWhois, onClose }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    const onKeyDown = (event) => { if (event.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKeyDown);
    lookupWhois(indicator.value)
      .then((payload) => { if (active) setResult(payload); })
      .catch((requestError) => { if (active) setError(requestError.message); });
    return () => { active = false; window.removeEventListener("keydown", onKeyDown); };
  }, [indicator.value, lookupWhois, onClose]);

  const record = result?.record || {};
  const fields = [
    ["Registrar / network", record.registrar || record.name],
    ["Organization", record.org || record.organization],
    ["Registrant", record.registrant || record.registrant_name || record.name],
    ["Country", record.country],
    ["Created", record.creation_date || record.created],
    ["Updated", record.updated_date || record.last_changed],
    ["Expires", record.expiration_date],
    ["Status", record.status],
    ["Email", record.emails || record.email],
    ["Name servers", record.name_servers],
  ];
  return <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section className="settings-modal whois-modal" role="dialog" aria-modal="true" aria-labelledby="whois-title"><div className="modal-head"><div><span className="eyebrow">WHOIS / RDAP lookup</span><h2 id="whois-title">{indicator.hostname || indicator.value}</h2><p>{indicator.hostname ? `${indicator.value} · reverse DNS result` : `${indicator.type} registration details`}</p></div><button className="icon-button" onClick={onClose} aria-label="Close WHOIS details"><X size={20} /></button></div>{!result && !error && <div className="whois-loading"><GlobeHemisphereWest size={25} weight="duotone" /><div><strong>Looking up registration data…</strong><span>This can take a few seconds.</span></div></div>}{error && <div className="error-notice"><WarningCircle size={18} /><span>{error}</span></div>}{result && <><div className="whois-grid">{fields.map(([label, value]) => <div key={label}><span>{label}</span><strong>{firstWhoisValue(value)}</strong></div>)}</div><details className="whois-raw"><summary>Full WHOIS record</summary><pre>{JSON.stringify(record, null, 2)}</pre></details></>}<div className="modal-actions"><button className="button secondary" onClick={onClose}>Close</button></div></section></div>;
}

function EvidenceWorkspace({ items = evidence, lookupWhois, initialQuery = "" }) {
  const [query, setQuery] = useState(initialQuery);
  const [type, setType] = useState("All");
  const [status, setStatus] = useState("All statuses");
  const [showFilters, setShowFilters] = useState(false);
  const [selected, setSelected] = useState(null);
  const rows = items.filter((row) => (type === "All" || row.type === type) && (status === "All statuses" || row.status === status) && `${row.value} ${row.hostname || ""}`.toLowerCase().includes(query.toLowerCase()));
  const highPriority = items.filter((row) => ["High", "Critical"].includes(row.status)).length;
  const statuses = ["All statuses", ...new Set(items.map((row) => row.status).filter(Boolean))];
  const clearFilters = () => { setQuery(""); setType("All"); setStatus("All statuses"); };
  const exportRows = () => downloadText("pcap-hunter-visible-iocs.csv", buildIocCsv(rows), "text/csv");
  return <div className="workspace-stack"><div className="investigation-search"><MagnifyingGlass size={20} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search evidence across the active batch" aria-label="Search evidence" /><select value={type} onChange={(event) => setType(event.target.value)} aria-label="Evidence type">{["All", "IP", "Domain", "Hash", "JA3", "URL"].map((item) => <option key={item}>{item}</option>)}</select></div><div className="summary-strip"><span><strong>{items.length}</strong> indicators</span><span><strong>{new Set(items.map((item) => item.value)).size}</strong> unique values</span><span><strong>{highPriority}</strong> high priority</span><button className="button secondary" onClick={exportRows}><DownloadSimple size={17} /> Export IOCs</button></div><section className="panel table-panel"><div className="panel-title compact"><div><h2>Evidence inventory</h2><p>{rows.length} visible items · resolved IPs show their full PTR hostname · click an IP or domain for WHOIS</p></div><button className="button secondary" onClick={() => setShowFilters((current) => !current)} aria-expanded={showFilters}><Funnel size={17} /> {showFilters ? "Hide filters" : "More filters"}</button></div>{showFilters && <div className="evidence-filter-panel"><label>Assessment<select value={status} onChange={(event) => setStatus(event.target.value)}>{statuses.map((item) => <option key={item}>{item}</option>)}</select></label><span>{rows.length} of {items.length} indicators shown</span><button className="text-button" onClick={clearFilters}>Clear all filters</button></div>}<div className="data-table"><div className="table-row table-head"><span>Indicator</span><span>Type</span><span>Context</span><span>Source</span><span>Assessment</span></div>{rows.map((row) => { const canLookup = ["IP", "Domain"].includes(row.type); const content = <><IndicatorValue row={row} /><span>{row.type}</span><span>{row.context}</span><span>{row.source}</span><span className="expected"><Check size={13} /> {row.status}</span></>; return canLookup ? <button className="table-row" key={`${row.type}-${row.value}`} onClick={() => setSelected(row)} aria-label={`Open WHOIS details for ${row.value}`}>{content}</button> : <div className="table-row" key={`${row.type}-${row.value}`}>{content}</div>; })}</div></section><section className="panel"><div className="panel-title compact"><div><h2>Hunting checklist</h2><p>Keep analyst verification separate from automated findings.</p></div><span className="count-pill">2 of 6 reviewed</span></div><div className="checklist-grid">{["Confirm capture scope", "Review repeated destinations", "Validate DNS anomalies", "Inspect TLS certificates", "Check carved payloads", "Document disposition"].map((item, index) => <label key={item}><input type="checkbox" defaultChecked={index < 2} /><span>{item}</span></label>)}</div></section>{selected && <WhoisDialog indicator={selected} lookupWhois={lookupWhois} onClose={() => setSelected(null)} />}</div>;
}

function TrafficWorkspace({ data, onOpenTrafficView, onChangeTab }) {
  const [filterMode, setFilterMode] = useState("all");
  const [ipQuery, setIpQuery] = useState("");
  const [protocol, setProtocol] = useState("All");
  const [timeBucket, setTimeBucket] = useState("");
  const [excludePrivate, setExcludePrivate] = useState(false);
  const protocolNames = (data.protocols || []).map((item) => item.name);
  const timeBuckets = (data.traffic || []).map((item) => item.time);
  const talkers = (data.top_talkers || []).filter((item) => (!ipQuery.trim() || item.name.toLowerCase().includes(ipQuery.toLowerCase())) && (!excludePrivate || !isPrivateAddress(item.name)));
  const filteredData = { ...data, top_talkers: talkers };
  const clearFilters = () => { setFilterMode("all"); setIpQuery(""); setProtocol("All"); setTimeBucket(""); setExcludePrivate(false); };
  const chooseMode = (nextMode) => {
    setFilterMode(nextMode);
    if (nextMode === "all") clearFilters();
  };
  const shortcuts = [
    ["Cross-file correlation", "Review shared indicators across captures", ShareNetwork, "evidence"],
    ["Beacon candidates", `${data.beacons || 0} candidate${data.beacons === 1 ? "" : "s"} detected`, Pulse, "mitre"],
    ["Flow anomalies", "Inspect exact packets, ports, and timestamps", Waveform, "raw"],
  ];
  return <div className="workspace-stack"><div className="filter-bar" aria-label="Traffic filters"><button className={`filter-chip ${filterMode === "all" ? "active" : ""}`} onClick={() => chooseMode("all")} aria-pressed={filterMode === "all"}><Funnel size={15} /> All flows</button><button className={`filter-chip ${filterMode === "ip" ? "active" : ""}`} onClick={() => chooseMode("ip")} aria-pressed={filterMode === "ip"}>IP</button><button className={`filter-chip ${filterMode === "protocol" ? "active" : ""}`} onClick={() => chooseMode("protocol")} aria-pressed={filterMode === "protocol"}>Protocol</button><button className={`filter-chip ${filterMode === "time" ? "active" : ""}`} onClick={() => chooseMode("time")} aria-pressed={filterMode === "time"}>Time range</button><label className="compact-check"><input type="checkbox" checked={excludePrivate} onChange={(event) => setExcludePrivate(event.target.checked)} /> Exclude private IPs</label><button className="text-button" onClick={clearFilters}>Clear filters</button></div>{filterMode !== "all" && <div className="traffic-filter-controls">{filterMode === "ip" && <label>Filter top talkers by IP<input value={ipQuery} onChange={(event) => setIpQuery(event.target.value)} placeholder="Enter a full or partial IP" /></label>}{filterMode === "protocol" && <label>Protocol<select value={protocol} onChange={(event) => setProtocol(event.target.value)}><option>All</option>{protocolNames.map((item) => <option key={item}>{item}</option>)}</select></label>}{filterMode === "time" && <label>Time point<select value={timeBucket} onChange={(event) => setTimeBucket(event.target.value)}><option value="">All times</option>{timeBuckets.map((item) => <option key={item}>{item}</option>)}</select></label>}<span>{talkers.length} top talker{talkers.length === 1 ? "" : "s"} shown</span></div>}<TrafficOverview expanded data={filteredData} activeProtocol={protocol} activeTime={timeBucket} onProtocolSelect={(value) => { setProtocol(value); setFilterMode(value === "All" ? "all" : "protocol"); }} onTimeSelect={(value) => { setTimeBucket(value); setFilterMode(value ? "time" : "all"); }} onClearFilters={clearFilters} filterTarget="workspace" /><div className="three-card-grid">{shortcuts.map(([title, copy, Icon, target]) => <button className="mini-card" key={title} onClick={() => onChangeTab(target)} aria-label={`${title}: open ${target === "mitre" ? "MITRE ATT&CK" : target}`}><Icon size={24} weight="duotone" /><div><h3>{title}</h3><p>{copy}</p></div><ArrowRight size={18} /></button>)}</div><section className="panel" id="additional-traffic-views"><div className="panel-title compact"><div><h2>Additional traffic views</h2><p>Open the visualization that best answers your current question.</p></div></div><div className="tool-grid">{trafficViewTools.map((tool) => <button key={tool.target} onClick={() => onOpenTrafficView(tool.target)} aria-label={`Open ${tool.label} on the dashboard`}><ChartLine size={19} />{tool.label}<ArrowRight size={16} /></button>)}</div></section></div>;
}

function MitreWorkspace({ data, initialView = "findings" }) {
  const [view, setView] = useState(["findings", "coverage", "export"].includes(initialView) ? initialView : "findings");
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const mapping = data.attack_mapping || {};
  const techniques = Array.isArray(mapping.techniques) ? mapping.techniques : [];
  const tactics = Object.keys(mapping.tactics_summary || {});
  const stages = data.stages || [];
  const exportActions = [
    {
      title: "ATT&CK Navigator layer",
      copy: "Download a Navigator-compatible layer with confidence scores, evidence, and limitations.",
      label: "Download",
      action: () => downloadText("pcap-hunter-attack-navigator.json", JSON.stringify(buildAttackNavigatorLayer(mapping), null, 2), "application/json"),
    },
    {
      title: "Technique evidence JSON",
      copy: "Export every network hypothesis with its supporting evidence and analyst caveats.",
      label: "Download",
      action: () => downloadText("pcap-hunter-attack-evidence.json", JSON.stringify(mapping, null, 2), "application/json"),
    },
  ];
  return <div className="workspace-stack"><div className="scope-banner"><WarningCircle size={21} /><div><strong>Network evidence creates ATT&CK hypotheses, not proof of endpoint execution.</strong><span>Validate raw flows and endpoint telemetry before confirming a technique.</span></div></div><div className="metric-grid five"><article><strong>{techniques.length}</strong><span>Hypotheses</span></article><article><strong>{tactics.length}</strong><span>Tactics</span></article><article><strong>{Math.max(0, 10 - stages.length)}</strong><span>Visibility gaps</span></article><article><strong>{data.flows}</strong><span>Parsed flows</span></article><article><strong>{String(mapping.overall_severity || "low").toUpperCase()}</strong><span>Mapping severity</span></article></div><SegmentedTabs items={[{ id: "findings", label: "Findings" }, { id: "coverage", label: "Coverage & gaps" }, { id: "export", label: "Exports" }]} active={view} onChange={(next) => { setView(next); setSelectedTechnique(null); }} label="MITRE view" />{view === "findings" && <section className="panel table-panel"><div className="data-table mitre-table"><div className="table-row table-head"><span>ID</span><span>Technique</span><span>Tactic</span><span>Confidence</span><span>Disposition</span></div>{techniques.length ? techniques.map((item, index) => { const id = item.technique_id || item.id || `Hypothesis ${index + 1}`; const confidence = Number(item.confidence || item.score || 0); return <button className="table-row" key={id} onClick={() => setSelectedTechnique(item)} aria-expanded={selectedTechnique === item}><strong>{id}</strong><span>{item.technique_name || item.name || "Mapped network behavior"}</span><span>{item.tactic || item.tactic_name || "Unspecified"}</span><span>{Math.round(confidence * (confidence <= 1 ? 100 : 1))}%</span><span>{item.disposition || "Unreviewed"}</span></button>; }) : <div className="empty-state-note"><CheckCircle size={17} weight="fill" /><span>No ATT&CK hypotheses were produced for this analysis.</span></div>}</div>{selectedTechnique && <div className="technique-detail" role="region" aria-live="polite"><div className="technique-detail-head"><div><span className="eyebrow">ATT&CK hypothesis</span><h3>{selectedTechnique.technique_id || selectedTechnique.id} · {selectedTechnique.technique_name || selectedTechnique.name}</h3><p>{selectedTechnique.tactic || selectedTechnique.tactic_name || "Unspecified tactic"} · {selectedTechnique.data_components?.join(" · ") || "Network evidence"}</p></div><button className="icon-button" onClick={() => setSelectedTechnique(null)} aria-label="Close technique details"><X size={18} /></button></div><div className="technique-detail-grid"><div><strong>Supporting evidence</strong><ul>{(selectedTechnique.evidence || ["No supporting evidence text was recorded."]).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul></div><div><strong>Limitations</strong><ul>{(selectedTechnique.limitations || ["No limitations were recorded."]).map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul></div></div>{selectedTechnique.references?.length > 0 && <div className="technique-references"><strong>References</strong>{selectedTechnique.references.map((item) => <a href={item} target="_blank" rel="noreferrer" key={item}>{item}</a>)}</div>}</div>}</section>}{view === "coverage" && <section className="panel"><div className="panel-title"><div><h2>Capture profile & detector coverage</h2><p>Unavailable stages are shown as visibility gaps, never clean results.</p></div></div><div className="coverage-list">{pipelineStages.map((item) => { const available = stages.some((stage) => String(stage).toLowerCase().includes(item.split(" ")[0].toLowerCase())); return <div key={item}><span>{available ? <CheckCircle size={17} weight="fill" /> : <WarningCircle size={17} />}{item}</span><strong>{available ? "Available" : "Not recorded"}</strong></div>; })}</div></section>}{view === "export" && <ExportCards items={exportActions} />}</div>;
}

function ThreatIntelWorkspace({ data, config, lookupWhois }) {
  const [domainView, setDomainView] = useState(false);
  const [selected, setSelected] = useState(null);
  const providerKeys = config.configured_providers || {};
  const providers = [["VirusTotal", "cfg_vt_key"], ["AbuseIPDB", "cfg_abuseipdb_key"], ["GreyNoise", "cfg_greynoise_key"], ["OTX", "cfg_otx_key"], ["Shodan", "cfg_shodan_key"]];
  const domainRows = (data.evidence || []).filter((item) => item.type === "Domain");
  const ipRows = data.osint_rows?.length ? data.osint_rows : (data.evidence || []).filter((item) => item.type === "IP").map((item) => ({ value: item.value, hostname: item.hostname, kind: "IP", verdict: item.status, organization: item.context, score: 0 }));
  const rows = domainView ? domainRows.map((item) => ({ value: item.value, kind: "Domain", verdict: item.status, organization: item.context, score: 0 })) : ipRows;
  return <div className="workspace-stack"><div className="provider-strip">{providers.map(([name, key]) => { const connected = Boolean(providerKeys[key]); return <span className={connected ? "connected" : ""} key={name}>{connected ? <CheckCircle size={15} weight="fill" /> : <WarningCircle size={15} />}{name}<small>{connected ? "Connected" : "Not configured"}</small></span>; })}</div><div className="section-heading"><div><h2>IOC triage</h2><p>Provider coverage and verdicts are kept distinct from “no data.” Click any indicator for WHOIS.</p></div><div className="button-group"><button className={`button ${!domainView ? "primary" : "secondary"}`} onClick={() => setDomainView(false)}>IPs</button><button className={`button ${domainView ? "primary" : "secondary"}`} onClick={() => setDomainView(true)}>Domains</button></div></div><section className="panel table-panel"><div className="data-table intel-table"><div className="table-row table-head"><span>Verdict</span><span>{domainView ? "Domain" : "IP address"}</span><span>{domainView ? "Context" : "ASN / organization"}</span><span>Score</span><span>Coverage</span></div>{rows.length ? rows.map((row) => <button className="table-row" key={row.value} onClick={() => setSelected({ ...row, type: row.kind || (domainView ? "Domain" : "IP") })}><span>{row.verdict || "Observed"}</span><IndicatorValue row={row} /><span>{row.organization || "No enrichment data"}</span><span>{row.score ? Number(row.score).toFixed(2) : "—"}</span><span>{data.osint_rows?.length ? "Enriched" : "Observed only"}</span></button>) : <div className="empty-state-note"><WarningCircle size={17} /><span>No {domainView ? "domain" : "IP"} indicators are available in the active analysis.</span></div>}</div></section>{selected && <WhoisDialog indicator={selected} lookupWhois={lookupWhois} onClose={() => setSelected(null)} />}</div>;
}

function RawWorkspace({ data }) {
  const [dataset, setDataset] = useState("flows");
  const datasets = ["flows", "dns", "tls", "ja3", "zeek", "carved", "yara"];
  const counts = { flows: data.raw_flows?.length || 0, dns: Number(data.dns_analysis?.records || 0), tls: Number(data.tls_analysis?.total_certificates || 0), ja3: (data.evidence || []).filter((item) => item.type === "JA3").length, yara: Number(data.yara_results?.matched || 0) };
  const flowRows = data.raw_flows || [];
  return <div className="workspace-stack"><div className="raw-layout"><aside className="dataset-nav"><h3>Datasets</h3>{datasets.map((item) => <button className={dataset === item ? "active" : ""} onClick={() => setDataset(item)} key={item}><Database size={17} />{item === "ja3" ? "JA3 / JA3S" : item[0].toUpperCase() + item.slice(1)}<span>{counts[item] || 0}</span></button>)}</aside><section className="panel table-panel raw-table"><div className="panel-title compact"><div><h2>{dataset === "ja3" ? "JA3 / JA3S fingerprints" : `${dataset[0].toUpperCase()}${dataset.slice(1)} data`}</h2><p>Underlying evidence with exact timestamps and source capture lineage.</p></div></div>{dataset === "flows" ? <div className="data-table"><div className="table-row table-head"><span>First seen (UTC)</span><span>Source</span><span>Destination</span><span>Protocol</span><span>Evidence</span></div>{flowRows.map((row, index) => <div className="table-row" key={`${row.first_seen}-${row.source}-${row.destination}-${index}`}><span>{row.first_seen}</span><strong>{row.source}</strong><span>{row.destination}</span><span>{row.protocol}</span><span>{row.packets} packets · {row.bytes} bytes</span></div>)}</div> : <div className="empty-state-note"><CheckCircle size={17} weight="fill" /><span>{counts[dataset] || 0} {dataset} records are summarized for the active analysis.</span></div>}</section></div></div>;
}

function downloadText(filename, content, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function Reports({ workbench }) {
  const [tab, setTab] = useState("report");
  const dashboard = workbench.dashboard;
  const config = workbench.config || {};
  const provider = config.cfg_llm_provider || "Not configured";
  const model = provider === "openai" ? config.cfg_openai_model : provider === "anthropic" ? config.cfg_anthropic_model : config.cfg_llm_model;
  const report = dashboard.report || "No AI narrative has been generated for the active analysis. Deterministic findings and exports remain available.";
  const exportPayload = JSON.stringify({ case_id: workbench.active_case_id, analysis_id: workbench.active_analysis_id, dashboard }, null, 2);
  const downloadPdf = () => {
    if (!workbench.active_case_id) return;
    const link = document.createElement("a");
    link.href = `/api/ui/cases/${workbench.active_case_id}/report.pdf`;
    link.download = `pcap-hunter-${workbench.active_case_id}.pdf`;
    document.body.appendChild(link);
    link.click();
    link.remove();
  };
  const exportItems = [
    ["PDF report with dashboard", "Download a polished report with the narrative, KPIs, protocol charts, OSINT, and detector summaries.", downloadPdf],
    ["Markdown investigation report", "Download the saved narrative exactly as generated.", () => downloadText("pcap-hunter-report.md", report, "text/markdown")],
    ["Analysis evidence · JSON", "Export dashboard metrics, evidence, flows, and detector summaries.", () => downloadText("pcap-hunter-evidence.json", exportPayload, "application/json")],
    ["IOC inventory · CSV", "Export the active evidence inventory for triage and handoff.", () => downloadText("pcap-hunter-iocs.csv", buildIocCsv(dashboard.evidence || []), "text/csv")],
  ];
  return <div className="screen"><PageHeading title="Reports" description="Turn deterministic evidence into a narrative or machine-readable handoff." actions={<span className="provider-summary"><Sparkle size={17} /> {provider} · {model || "default model"} · {config.cfg_llm_language || "US English"}</span>} /><SegmentedTabs items={[{ id: "report", label: "AI threat report", icon: Brain }, { id: "exports", label: "Exports", icon: DownloadSimple }]} active={tab} onChange={setTab} label="Report workspace" />{tab === "report" ? <div className="report-layout"><article className="panel report-document"><div className="report-head"><div><span className="eyebrow">Saved with the active analysis</span><h2>PCAP analysis report</h2><p>{workbench.capture_count} captures · {dashboard.packets} packets · {dashboard.flows} flows · {(dashboard.evidence || []).length} indicators</p></div><div className="report-actions"><button className="button secondary" onClick={workbench.refresh}><ClockCounterClockwise size={17} /> Refresh</button><button className="button primary" disabled={!workbench.active_case_id} onClick={downloadPdf}><FileArrowDown size={17} /> Download PDF</button></div></div><div className="report-body actual-report"><ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown></div></article><aside className="report-sidebar"><section className="panel"><h2>Evidence coverage</h2><div className="coverage-list">{["Traffic & flows", "DNS & TLS", "Beaconing", "YARA", "OSINT", "MITRE mapping"].map((item, index) => <div key={item}><span>{index < dashboard.stages.length ? <CheckCircle size={16} weight="fill" /> : <WarningCircle size={16} />}{item}</span><strong>{index < dashboard.stages.length ? "Included" : "Not recorded"}</strong></div>)}</div></section><section className="panel"><h2>Report configuration</h2><div className="setup-summary"><div><span>Provider</span><strong>{provider}</strong></div><div><span>Model</span><strong>{model || "Default"}</strong></div><div><span>Language</span><strong>{config.cfg_llm_language || "US English"}</strong></div><div><span>Context</span><strong>{config.cfg_llm_unlimited_context ? "Unlimited" : `${config.cfg_llm_context_window || 32000} tokens`}</strong></div></div></section></aside></div> : <div className="export-grid">{exportItems.map(([title, copy, action]) => <article className="panel export-card" key={title}><span><FileArrowDown size={25} weight="duotone" /></span><div><h2>{title}</h2><p>{copy}</p></div><button className="button secondary" onClick={action}>Download<DownloadSimple size={16} /></button></article>)}</div>}</div>;
}

function ExportCards({ items }) {
  return <div className="export-grid">{items.map((item) => <article className="panel export-card" key={item.title}><span><FileArrowDown size={25} weight="duotone" /></span><div><h2>{item.title}</h2><p>{item.copy}</p></div><button className="button secondary" onClick={item.action}>{item.label || "Download"}<DownloadSimple size={16} /></button></article>)}</div>;
}

function Cases({ workbench, onNavigate }) {
  const [detailId, setDetailId] = useState("");
  const [search, setSearch] = useState("");
  const [created, setCreated] = useState(false);
  const cases = workbench.cases || [];
  const visible = cases.filter((item) => `${item.id} ${item.title} ${item.description} ${(item.tags || []).join(" ")}`.toLowerCase().includes(search.toLowerCase()));
  if (detailId) return <CaseDetail item={cases.find((item) => item.id === detailId)} workbench={workbench} onBack={() => setDetailId("")} />;
  const totalAnalyses = cases.reduce((sum, item) => sum + item.analysis_count, 0);
  const totalIocs = cases.reduce((sum, item) => sum + item.ioc_count, 0);
  const openCases = cases.filter((item) => item.status !== "closed").length;
  const create = async () => { const result = await workbench.createCase(); setCreated(true); if (result?.id) setDetailId(result.id); };
  return <div className="screen"><PageHeading title="Cases" description="Keep captures, analyses, IOCs, and analyst notes together across sessions." actions={<><button className="button secondary" onClick={() => onNavigate("analyze")}><Copy size={17} /> Analyze into a case</button><button className="button primary" onClick={create}><Plus size={17} /> New case</button></>} />{created && <Notice onClose={() => setCreated(false)}>The new investigation case is saved and ready for notes or analyses.</Notice>}<div className="metric-grid four"><article><strong>{cases.length}</strong><span>Total cases</span></article><article><strong>{totalAnalyses}</strong><span>Analyses</span></article><article><strong>{totalIocs}</strong><span>IOCs</span></article><article><strong>{openCases}</strong><span>Open cases</span></article></div><div className="case-filter-bar"><div className="investigation-search"><MagnifyingGlass size={19} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title, description, or tag…" /></div><button className="button secondary" onClick={() => setSearch("")}><Target size={17} /> Clear search</button></div><div className="case-list">{visible.map((item) => <button className="case-row" onClick={() => setDetailId(item.id)} key={item.id}><span className="case-icon"><FolderSimple size={25} weight="duotone" /></span><div><small>{item.id}</small><h2>{item.title}</h2><p>{item.analysis_count} captures · {item.ioc_count} IOCs</p></div><span className={`severity-tag ${item.severity}`}>{item.severity}</span><span className="case-status">{item.status.replaceAll("_", " ")}</span><span className="case-updated">{new Date(item.updated_at).toLocaleDateString()}</span><ArrowRight size={19} /></button>)}{!visible.length && <div className="empty-state-note"><FolderSimple size={18} /><span>No cases match this search.</span></div>}</div></div>;
}

function CaseDetail({ item, workbench, onBack }) {
  const [tab, setTab] = useState("analyses");
  const [note, setNote] = useState("");
  if (!item) return <div className="screen"><button className="back-button" onClick={onBack}><ArrowLeft size={16} /> Back to cases</button><Notice>This case is no longer available.</Notice></div>;
  const addNote = async () => { if (!note.trim()) return; await workbench.addNote(item.id, note.trim()); setNote(""); };
  const caseEvidence = item.id === workbench.active_case_id ? workbench.dashboard.evidence : [];
  return <div className="screen"><button className="back-button upper-layer-back" onClick={onBack}><ArrowLeft size={16} /> Back to cases</button><PageHeading title={item.title} description={`${item.id} · ${item.status.replaceAll("_", " ")} · ${item.severity} severity · updated ${new Date(item.updated_at).toLocaleString()}`} /><div className="case-meta"><span><strong>{item.analysis_count}</strong> captures</span><span><strong>{item.ioc_count}</strong> IOCs</span><span><strong>{item.note_count}</strong> notes</span><span><strong>Tags</strong> {(item.tags || []).join(" · ") || "none"}</span></div><SegmentedTabs items={[{ id: "analyses", label: "Analyses" }, { id: "notes", label: "Notes" }, { id: "iocs", label: "IOCs" }]} active={tab} onChange={setTab} label="Case detail" />{tab === "analyses" && <section className="panel"><div className="panel-title"><div><h2>Saved analyses</h2><p>Every completed upload is autosaved here by the background worker.</p></div></div>{item.analyses.map((analysis) => <div className="analysis-row" key={analysis.id}><File size={21} /><div><strong>{analysis.name}</strong><span>{analysis.packet_count} packets · {analysis.flow_count} flows · analyzed {new Date(analysis.analyzed_at).toLocaleString()}</span></div><span>{analysis.ioc_count} IOCs</span></div>)}{!item.analyses.length && <div className="empty-state-note"><File size={17} /><span>No analyses have been added to this case.</span></div>}</section>}{tab === "notes" && <section className="panel notes-panel"><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Add an investigation note…" /><button className="button primary" disabled={!note.trim()} onClick={addNote}>Add note</button>{item.notes.map((entry) => <div className="note-item" key={entry.id}><strong>{new Date(entry.created_at).toLocaleString()}</strong><p>{entry.content}</p></div>)}</section>}{tab === "iocs" && <section className="panel table-panel"><div className="panel-title compact"><div><h2>Case IOCs</h2><p>{caseEvidence.length ? "Evidence from the active analysis." : "Open the active case to view its in-memory evidence inventory."}</p></div></div><div className="data-table"><div className="table-row table-head"><span>Value</span><span>Type</span><span>Context</span><span>Severity</span><span>Analysis</span></div>{caseEvidence.map((entry) => <div className="table-row" key={`${entry.type}-${entry.value}`}><strong>{entry.value}</strong><span>{entry.type}</span><span>{entry.context}</span><span>{entry.status}</span><span>{entry.source}</span></div>)}</div></section>}</div>;
}

function Settings({ workbench }) {
  const [section, setSection] = useState("llm");
  const [saved, setSaved] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [draft, setDraft] = useState(workbench.config || {});
  useEffect(() => setDraft(workbench.config || {}), [workbench.config]);
  const change = (key, value) => { setSaved(false); setDraft((current) => ({ ...current, [key]: value })); };
  const save = async () => { setSaveError(""); try { await workbench.saveSettings(draft); setSaved(true); } catch (error) { setSaveError(error.message); } };
  const loadSaved = () => { setDraft(workbench.config || {}); setSaved(false); setSaveError(""); };
  return <div className="screen settings-screen"><PageHeading title="Settings" description="Configure analysis, enrichment, reports, integrations, and stored data in one place." actions={<><button className="button secondary" onClick={loadSaved}>Load saved</button><button className="button primary" onClick={save}>Save changes</button></>} />{saved && <Notice onClose={() => setSaved(false)}>Settings saved. Sensitive provider values remain encrypted at rest.</Notice>}{saveError && <div className="error-notice"><WarningCircle size={19} /><span>{saveError}</span></div>}<div className="settings-layout"><aside className="settings-nav">{settingsNavigation.map(({ id, label, icon: Icon }) => <button className={section === id ? "active" : ""} onClick={() => setSection(id)} key={id}><Icon size={19} />{label}<ArrowRight size={15} /></button>)}</aside><div className="settings-content">{section === "llm" && <LlmSettings config={draft} onChange={change} />}{section === "intel" && <IntelSettings config={draft} onChange={change} />}{section === "pipeline" && <PipelineSettings config={draft} onChange={change} />}{section === "tools" && <ToolSettings config={draft} onChange={change} system={workbench.system} />}{section === "map" && <MapSettings config={draft} onChange={change} getGeoItems={workbench.getGeoItems} resolveGeoLocation={workbench.resolveGeoLocation} />}{section === "api" && <ApiSettings />}{section === "data" && <DataSettings cases={workbench.cases} />}{section === "logs" && <LogsSettings jobs={workbench.jobs} />}</div></div></div>;
}

function SettingsHeader({ title, description, badge }) {
  return <div className="settings-header"><div><h2>{title}</h2><p>{description}</p></div>{badge && <span className="settings-badge">{badge}</span>}</div>;
}

function LlmSettings({ config, onChange }) {
  const provider = config.cfg_llm_provider || "lmstudio";
  const providerLabel = { lmstudio: "LM Studio", openai: "OpenAI", anthropic: "Anthropic" }[provider] || "LM Studio";
  const unlimited = Boolean(config.cfg_llm_unlimited_context);
  const [tested, setTested] = useState(false);
  const endpointKey = provider === "openai" ? "cfg_openai_base_url" : "cfg_llm_endpoint";
  const modelKey = provider === "openai" ? "cfg_openai_model" : provider === "anthropic" ? "cfg_anthropic_model" : "cfg_llm_model";
  const secretKey = provider === "openai" ? "cfg_openai_cloud_key" : provider === "anthropic" ? "cfg_anthropic_key" : "cfg_openai_key";
  const configured = Boolean(config.configured_providers?.[secretKey]);
  return <div className="settings-stack"><SettingsHeader title="LLM & reports" description="Choose how the optional AI report is generated. Deterministic analysis remains available without an LLM." badge="Optional" /><section className="settings-card"><label className="field-label">Provider</label><div className="provider-choice">{[["LM Studio", "lmstudio"], ["OpenAI", "openai"], ["Anthropic", "anthropic"]].map(([label, value]) => <button className={provider === value ? "active" : ""} onClick={() => { onChange("cfg_llm_provider", value); setTested(false); }} key={value}><Brain size={20} /><span><strong>{label}</strong><small>{value === "lmstudio" ? "Local · air-gapped" : "Cloud · full context"}</small></span>{provider === value && <CheckCircle size={17} weight="fill" />}</button>)}</div><div className="form-grid two"><label>{provider === "lmstudio" ? "OpenAI-compatible base URL" : provider === "openai" ? "Base URL (optional)" : "Provider endpoint"}<input value={provider === "anthropic" ? "Managed by Anthropic SDK" : config[endpointKey] || ""} onChange={(event) => onChange(endpointKey, event.target.value)} disabled={provider === "anthropic"} /></label><label>API key<input type="password" value={config[secretKey] || ""} onChange={(event) => onChange(secretKey, event.target.value)} placeholder={configured ? "Configured · enter a new value to replace" : "Paste API key"} /></label><label>Model<input value={config[modelKey] || ""} onChange={(event) => onChange(modelKey, event.target.value)} placeholder="Model name" /></label><div className="field-actions"><button className="button secondary" onClick={() => setTested(true)}>Review configuration</button></div></div>{tested && <Notice>{providerLabel} configuration is ready to save. Connection testing occurs when a report run starts.</Notice>}</section><section className="settings-card"><h3>Report output</h3><div className="form-grid two"><label>Report language<select value={config.cfg_llm_language || "US English"} onChange={(event) => onChange("cfg_llm_language", event.target.value)}>{["US English", "Traditional Chinese (zh-tw)", "Simplified Chinese (zh-cn)", "Japanese", "Korean", "Italian", "Spanish", "French", "German"].map((lang) => <option key={lang}>{lang}</option>)}</select></label><label>Model context window<input type="number" min="10000" max="1000000" step="1000" value={config.cfg_llm_context_window || 32000} onChange={(event) => onChange("cfg_llm_context_window", Number(event.target.value))} disabled={unlimited} /></label></div><Toggle checked={unlimited} onChange={(value) => onChange("cfg_llm_unlimited_context", value)} label="No context window limit" hint="Send all available sanitized evidence in one request. The provider can still reject an oversized request." /><div className="budget-note"><ChartPieSlice size={20} /><span><strong>{unlimited ? "Unlimited sanitized input" : `${Math.round((config.cfg_llm_context_window || 32000) / 2).toLocaleString()}-token input budget`}</strong><small>{unlimited ? "Physical model limits still apply." : "Half of the selected context window is reserved for evidence."}</small></span></div></section></div>;
}

function IntelSettings({ config, onChange }) {
  const providers = [["VirusTotal", "cfg_vt_key"], ["AbuseIPDB", "cfg_abuseipdb_key"], ["GreyNoise", "cfg_greynoise_key"], ["OTX", "cfg_otx_key"], ["Shodan", "cfg_shodan_key"]];
  const connectedCount = providers.filter(([, key]) => config.configured_providers?.[key] || config[key]).length;
  return <div className="settings-stack"><SettingsHeader title="Threat intelligence" description="Connect optional enrichment providers and control how much public-IP evidence is queried." badge={`${connectedCount} of ${providers.length} connected`} /><section className="settings-card"><div className="provider-config-list">{providers.map(([name, key]) => { const connected = Boolean(config.configured_providers?.[key] || config[key]); return <div key={name}><span className={connected ? "provider-mark connected" : "provider-mark"}><GlobeHemisphereWest size={19} /></span><div><strong>{name}</strong><small>{connected ? "Configured · key stored securely" : "Not configured"}</small></div><input aria-label={`${name} API key`} type="password" value={config[key] || ""} onChange={(event) => onChange(key, event.target.value)} placeholder={connected ? "Enter a new value to replace" : "Paste API key"} /><span className={connected ? "status-good" : "status-muted"}>{connected ? "Connected" : "Optional"}</span></div>; })}</div></section><section className="settings-card"><h3>Enrichment behavior</h3><div className="form-grid two"><label>Top public IPs to enrich<input type="number" min="0" max="1000" step="5" value={config.cfg_osint_top_ips ?? 50} onChange={(event) => onChange("cfg_osint_top_ips", Number(event.target.value))} /><small>Use 0 to enrich every public IP.</small></label><label>Cache lifetime<input value="24 hours" disabled /></label></div><Toggle checked={Boolean(config.cfg_osint_cache_enabled)} onChange={(value) => onChange("cfg_osint_cache_enabled", value)} label="Enable OSINT cache" hint="Reuse recent results to protect provider quota. Clear the cache under Data & retention." /></section></div>;
}

function PipelineSettings({ config, onChange }) {
  const stages = ["Pre-count packets", "Packet parsing (tshark/PyShark)", "Zeek processing", "DNS analysis", "TLS certificate analysis", "Beaconing ranking", "HTTP body carving", "YARA scanning", "OSINT enrichment", "LLM report generation"];
  const packetLimit = Number(config.cfg_pyshark_limit ?? 200000);
  const profile = packetLimit === 0 ? "Deep inspection" : packetLimit <= 50000 ? "Fast triage" : "Balanced";
  const profiles = [
    ["Fast triage", "First 50,000 packets", 50000],
    ["Balanced", "First 200,000 packets", 200000],
    ["Deep inspection", "No packet-count limit", 0],
  ];
  return <div className="settings-stack"><SettingsHeader title="Analysis pipeline" description="Choose packet depth before a run is submitted. Every listed detector remains part of the pipeline." badge="10 stages enabled" /><section className="settings-card"><label className="field-label">Packet-depth preset</label><div className="profile-choice">{profiles.map(([name, copy, limit]) => <button className={profile === name ? "active" : ""} onClick={() => onChange("cfg_pyshark_limit", limit)} key={name} aria-pressed={profile === name}><strong>{name}</strong><small>{copy}</small>{profile === name && <CheckCircle size={17} weight="fill" />}</button>)}</div><label>PyShark packet limit <input type="number" min="0" step="10000" value={packetLimit} onChange={(event) => onChange("cfg_pyshark_limit", Number(event.target.value))} /><small>0 removes the limit. Per-flow timestamp samples remain capped at 5,000.</small></label></section><section className="settings-card"><h3>Pipeline stages</h3><p className="settings-section-copy">Stages are always enabled in this build. If a required tool or input is unavailable, the result is reported as a visibility gap.</p><div className="pipeline-stage-list">{stages.map((stage, index) => <div key={stage}><span><CheckCircle size={17} weight="fill" /><span><strong>{stage}</strong>{(index === 3 || index === 4) && <small>Requires Zeek output</small>}{index === 7 && <small>Requires carved files and YARA rules</small>}</span></span><b>Included</b></div>)}</div></section></div>;
}

function ToolSettings({ config, onChange, system }) {
  const status = Object.fromEntries((system?.tools || []).map((tool) => [tool.name.toLowerCase(), tool.ready]));
  return <div className="settings-stack"><SettingsHeader title="Tools & YARA" description="Override binary discovery and configure external analysis tools." badge={system?.healthy ? "System healthy" : "Tool check needed"} /><section className="settings-card"><h3>Binary paths</h3><div className="binary-row"><span><HardDrives size={22} /><div><strong>Zeek</strong><small>Protocol and log analysis</small></div></span><input value={config.cfg_zeek_bin || ""} onChange={(event) => onChange("cfg_zeek_bin", event.target.value)} placeholder="Auto-detect" /><b>{status.zeek ? <CheckCircle size={16} weight="fill" /> : <WarningCircle size={16} />} {status.zeek ? "Found" : "Not found"}</b></div><div className="binary-row"><span><HardDrives size={22} /><div><strong>tshark</strong><small>Packet parsing, counting, and carving</small></div></span><input value={config.cfg_tshark_bin || ""} onChange={(event) => onChange("cfg_tshark_bin", event.target.value)} placeholder="Auto-detect" /><b>{status.tshark ? <CheckCircle size={16} weight="fill" /> : <WarningCircle size={16} />} {status.tshark ? "Found" : "Not found"}</b></div></section><section className="settings-card"><h3>YARA rules</h3><label>Rules directory<input value={config.cfg_yara_rules_dir || ""} onChange={(event) => onChange("cfg_yara_rules_dir", event.target.value)} placeholder="Use the default data directory" /><small>Scanned recursively for .yar and .yara files. Leave blank to use the default data directory.</small></label></section></div>;
}

function MapSettings({ config, onChange, getGeoItems, resolveGeoLocation }) {
  const [continents, setContinents] = useState([]);
  const [countries, setCountries] = useState([]);
  const [cities, setCities] = useState([]);
  const [geoError, setGeoError] = useState("");
  const [resolving, setResolving] = useState(false);

  useEffect(() => {
    let active = true;
    getGeoItems("continents").then((items) => { if (active) setContinents(items); }).catch((error) => { if (active) setGeoError(error.message); });
    return () => { active = false; };
  }, [getGeoItems]);

  useEffect(() => {
    let active = true;
    if (!config.cfg_home_continent) { setCountries([]); return () => { active = false; }; }
    getGeoItems("countries", { continent: config.cfg_home_continent }).then((items) => { if (active) setCountries(items); }).catch((error) => { if (active) setGeoError(error.message); });
    return () => { active = false; };
  }, [config.cfg_home_continent, getGeoItems]);

  useEffect(() => {
    let active = true;
    if (!config.cfg_home_country) { setCities([]); return () => { active = false; }; }
    getGeoItems("cities", { country: config.cfg_home_country }).then((items) => { if (active) setCities(items); }).catch((error) => { if (active) setGeoError(error.message); });
    return () => { active = false; };
  }, [config.cfg_home_country, getGeoItems]);

  useEffect(() => {
    let active = true;
    if (!config.cfg_home_country || !config.cfg_home_city) return () => { active = false; };
    setResolving(true);
    setGeoError("");
    resolveGeoLocation(config.cfg_home_country, config.cfg_home_city)
      .then(({ latitude, longitude }) => {
        if (!active) return;
        onChange("cfg_home_lat", latitude);
        onChange("cfg_home_lon", longitude);
      })
      .catch((error) => { if (active) setGeoError(error.message); })
      .finally(() => { if (active) setResolving(false); });
    return () => { active = false; };
  }, [config.cfg_home_country, config.cfg_home_city, resolveGeoLocation]);

  const chooseContinent = (value) => {
    onChange("cfg_home_continent", value);
    onChange("cfg_home_country", "");
    onChange("cfg_home_city", "");
    onChange("cfg_home_lat", 0);
    onChange("cfg_home_lon", 0);
  };
  const chooseCountry = (value) => {
    onChange("cfg_home_country", value);
    onChange("cfg_home_city", "");
    onChange("cfg_home_lat", 0);
    onChange("cfg_home_lon", 0);
  };
  const coordinatesReady = Boolean(config.cfg_home_city && !resolving && !geoError);
  return <div className="settings-stack"><SettingsHeader title="Map & location" description="Choose the analyst’s home point for connection arcs on the world map. Coordinates are filled automatically." badge={coordinatesReady ? "Location resolved" : "Select a city"} /><section className="settings-card"><div className="form-grid three"><label>Continent<select value={config.cfg_home_continent || ""} onChange={(event) => chooseContinent(event.target.value)}><option value="">Select continent</option>{continents.map((item) => <option key={item}>{item}</option>)}</select></label><label>Country<select value={config.cfg_home_country || ""} onChange={(event) => chooseCountry(event.target.value)} disabled={!config.cfg_home_continent}><option value="">Select country</option>{countries.map((item) => <option key={item}>{item}</option>)}</select></label><label>City<select value={config.cfg_home_city || ""} onChange={(event) => onChange("cfg_home_city", event.target.value)} disabled={!config.cfg_home_country}><option value="">Select city</option>{cities.map((item) => <option key={item}>{item}</option>)}</select></label><label>Latitude<input className="resolved-coordinate" readOnly value={resolving ? "Resolving…" : Number(config.cfg_home_lat || 0).toFixed(6)} /><small>Filled from the selected city.</small></label><label>Longitude<input className="resolved-coordinate" readOnly value={resolving ? "Resolving…" : Number(config.cfg_home_lon || 0).toFixed(6)} /><small>Filled from the selected city.</small></label></div>{geoError && <div className="error-notice"><WarningCircle size={18} /><span>{geoError}</span></div>}<div className="location-preview"><MapPin size={28} weight="duotone" /><div><strong>{resolving ? "Resolving location…" : config.cfg_home_city || "Choose a city"}{config.cfg_home_country && !resolving ? `, ${config.cfg_home_country}` : ""}</strong><small>{coordinatesReady ? `${Number(config.cfg_home_lat).toFixed(4)}, ${Number(config.cfg_home_lon).toFixed(4)} · ready for world-map arcs` : "Complete the continent, country, and city selections to anchor local-to-external traffic arcs."}</small></div></div></section></div>;
}

function ApiSettings() {
  return <div className="settings-stack"><SettingsHeader title="API access" description="Programmatic access for PCAP submission, job polling, case retrieval, and IOC feeds." badge="Protected service · port 8000" /><section className="settings-card"><div className="retention-card"><Key size={25} weight="duotone" /><div><h3>Keys are managed by the authenticated integrations service</h3><p>Bootstrap full-scope and feed keys through the deployment environment. Secrets are never displayed or edited in this browser workbench.</p></div></div></section><section className="settings-card"><h3>Integration endpoints</h3><div className="endpoint-list"><code>POST /api/v1/pcaps</code><code>GET /api/v1/jobs/:job_id</code><code>GET /api/v1/iocs.json</code><code>GET /api/v1/iocs.csv</code><code>GET /api/v1/iocs.stix</code></div></section></div>;
}

function DataSettings({ cases = [] }) {
  const analyses = cases.reduce((sum, item) => sum + item.analysis_count, 0);
  const iocs = cases.reduce((sum, item) => sum + item.ioc_count, 0);
  return <div className="settings-stack"><SettingsHeader title="Data & retention" description="Understand what is retained by the analysis service." badge="7-day run retention" /><section className="settings-card"><div className="retention-card"><ClockCounterClockwise size={25} weight="duotone" /><div><h3>Run directories are pruned after 7 days</h3><p>Zeek logs and carved payloads live in per-run folders. Cases and cached summaries remain available in the persistent data volume.</p></div></div></section><div className="metric-grid three"><article><strong>{cases.length}</strong><span>Cases retained</span></article><article><strong>{analyses}</strong><span>Analyses retained</span></article><article><strong>{iocs}</strong><span>IOCs retained</span></article></div><section className="settings-card"><h3>Safe data management</h3><p>Destructive cleanup is intentionally kept out of the browser workbench. Use the authenticated administration API so deletion remains scoped and auditable.</p></section></div>;
}

function LogsSettings({ jobs = [] }) {
  const lines = jobs.slice(0, 50).map((job) => `${job.submitted_at}  ${job.status.toUpperCase().padEnd(9)}  ${job.name} · ${job.stage || "submitted"}${job.error ? ` · ${job.error}` : ""}`);
  return <div className="settings-stack"><SettingsHeader title="Runtime logs" description="Read-only recent analysis activity from the durable job queue." /><section className="settings-card logs-card"><div className="log-toolbar"><span>Showing {lines.length} recent queue entries</span></div><pre>{lines.length ? lines.join("\n") : "No analysis jobs have been submitted yet."}</pre></section></div>;
}

export function App() {
  const workbench = useWorkbench();
  const validScreens = ["analyze", "dashboard", "findings", "investigate", "reports", "cases", "settings"];
  const pathScreen = () => { const candidate = window.location.pathname.split("/").filter(Boolean)[0] || "analyze"; return validScreens.includes(candidate) ? candidate : "analyze"; };
  const [screen, setScreen] = useState(pathScreen);
  useEffect(() => {
    const onPopState = () => setScreen(pathScreen());
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  const navigate = (next, state = {}) => {
    if (!validScreens.includes(next)) return;
    const nextPath = next === "analyze" ? "/" : `/${next}`;
    if (window.location.pathname !== nextPath || Object.keys(state).length) window.history.pushState({ screen: next, ...state }, "", nextPath);
    setScreen(next);
  };
  const openTrafficView = (target) => {
    if (!getTrafficViewTool(target)) return;
    const nextPath = `/dashboard#${target}`;
    window.history.pushState({ screen: "dashboard", trafficView: target }, "", nextPath);
    setScreen("dashboard");
  };
  const renderScreen = () => {
    if (screen === "analyze") return <Analyze onNavigate={navigate} workbench={workbench} />;
    if (screen === "dashboard") return <Dashboard onNavigate={navigate} workbench={workbench} />;
    if (screen === "investigate") return <Investigate workbench={workbench} onOpenTrafficView={openTrafficView} />;
    if (screen === "reports") return <Reports workbench={workbench} />;
    if (screen === "cases") return <Cases onNavigate={navigate} workbench={workbench} />;
    if (screen === "settings") return <Settings workbench={workbench} />;
    return <Findings onNavigate={navigate} workbench={workbench} />;
  };
  return <div className="app-shell"><Header onNavigate={navigate} workbench={workbench} /><Sidebar active={screen} onChange={navigate} system={workbench.system} version={workbench.version} /><main className="main-content">{workbench.error && <div className="global-error"><WarningCircle size={19} /><span>{workbench.error}</span><button onClick={workbench.refresh}>Retry</button></div>}{renderScreen()}</main></div>;
}
