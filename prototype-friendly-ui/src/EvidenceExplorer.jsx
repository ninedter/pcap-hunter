import { useEffect, useState } from "react";
import { isPrivacyMode, sanitizeWorkbenchPayload } from "./privacy.js";

export function AnalysisScope({ workbench }) {
  return <section className="panel analysis-scope"><label>Saved analysis<select value={workbench.activeResourceId?.() || ""} onChange={(e) => workbench.selectAnalysis(e.target.value)}><option value="">Latest completed analysis</option>{(workbench.analysisChoices || []).map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label><p>Select an older run to inspect its evidence. Counts describe saved data; packet parsing may be incomplete.</p></section>;
}

export default function EvidenceExplorer({ workbench, kind = "evidence" }) {
  const analysisId = workbench.activeResourceId?.();
  const privateView = isPrivacyMode(window.location.search);
  const [page, setPage] = useState(null);
  const [value, setValue] = useState("");
  const [type, setType] = useState("");
  const [query, setQuery] = useState({ value: "", type: "" });
  const [cursor, setCursor] = useState(null);
  const [previous, setPrevious] = useState([]);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { setCursor(null); setPrevious([]); setDetail(null); const initial = kind === "evidence" ? window.history.state?.evidenceQuery || "" : ""; setQuery({ value: initial, type: "" }); setValue(initial); setType(""); }, [analysisId, kind]);
  useEffect(() => {
    if (!analysisId) { setPage(null); return; }
    const controller = new AbortController(); setBusy(true); setError("");
    const params = new URLSearchParams({ kind, limit: "100" });
    if (cursor) params.set("cursor", cursor);
    if (query.value) params.set(kind === "flows" ? "source" : "value", query.value);
    if (query.type) params.set(kind === "flows" ? "protocol" : "type", query.type);
    fetch(`/api/ui/analyses/${encodeURIComponent(analysisId)}/evidence?${params}`, { signal: controller.signal, cache: "no-store" }).then(async (response) => {
      const payload = await response.json(); if (!response.ok) throw new Error(typeof payload.detail === "string" ? payload.detail : "Evidence query failed.");
      setPage(payload);
    }).catch((e) => { if (e.name !== "AbortError") setError(e.message); }).finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => controller.abort();
  }, [analysisId, kind, cursor, query]);
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const evidenceId = params.get("evidence_id"), snapshot = params.get("snapshot_id");
    if (!analysisId || !evidenceId || !snapshot || privateView) return;
    const controller = new AbortController();
    fetch(`/api/ui/analyses/${encodeURIComponent(analysisId)}/evidence/${encodeURIComponent(evidenceId)}?snapshot_id=${encodeURIComponent(snapshot)}`, { signal: controller.signal }).then(async (response) => {
      const payload = await response.json(); if (!response.ok) throw new Error("The cited evidence could not be loaded."); setDetail(payload);
    }).catch((e) => { if (e.name !== "AbortError") setError(e.message); });
    return () => controller.abort();
  }, [analysisId, privateView]);
  if (!analysisId) return <section className="panel"><p>Select a completed analysis to inspect saved evidence.</p></section>;
  const visible = privateView && page ? sanitizeWorkbenchPayload(page) : page;
  const rows = visible?.items || [];
  return <div className="evidence-explorer">
    <section className="panel"><header className="panel-title"><div><h2>{kind === "flows" ? "Complete saved flow inventory" : "Complete saved evidence inventory"}</h2><p>{page?.total_matching?.toLocaleString() || 0} matching records · {rows.length} on this page</p></div></header>
      <form className="evidence-query" onSubmit={(e) => { e.preventDefault(); setCursor(null); setPrevious([]); setQuery({ value: value.trim(), type: type.trim() }); }}>
        <label>{kind === "flows" ? "Source IP (exact)" : "Indicator value (exact)"}<input value={value} onChange={(e) => setValue(e.target.value)} maxLength={512} /></label>
        <label>{kind === "flows" ? "Protocol" : "Evidence type"}{kind === "flows" ? <input value={type} onChange={(e) => setType(e.target.value)} maxLength={32} placeholder="TCP, DNS, TLS…" /> : <select value={type} onChange={(e) => setType(e.target.value)}>{["", "ip", "domain", "url", "hash", "ja3", "mac", "dns", "tls", "yara", "beacon", "attack_mapping"].map((item) => <option key={item} value={item}>{item || "All types"}</option>)}</select>}</label>
        <button className="button secondary" disabled={busy}>Search saved data</button><button type="button" className="button secondary" onClick={() => { setValue(""); setType(""); setQuery({ value: "", type: "" }); setCursor(null); setPrevious([]); }}>Clear</button>
      </form>
      <p className="evidence-coverage">Saved inventory: complete · Packet parse: {page?.coverage?.packet_parse || "unknown"}. No match does not establish that a threat is absent.</p>
      {error && <div className="error-notice" role="alert">{error}</div>}
      <div className="evidence-records" aria-busy={busy}>{rows.map((row, index) => <button type="button" className="evidence-record" key={`${cursor}-${index}`} onClick={() => setDetail(privateView ? { notice: "Evidence details are hidden in privacy view." } : page.items[index])}>
        <strong>{kind === "flows" ? `${row.src || "Unknown"} → ${row.dst || "Unknown"}` : row.value}</strong><span>{kind === "flows" ? `${row.proto || "Unknown"} · ${row.count || 0} packets` : `${row.type} · ${row.severity}`}</span><small>{typeof row.context === "string" ? row.context : "Structured detector evidence · open for details"}</small>
      </button>)}{!busy && !rows.length && <p>No matching saved records.</p>}</div>
      <div className="evidence-pagination"><button className="button secondary" disabled={busy || !previous.length} onClick={() => { const history = [...previous]; setCursor(history.pop()); setPrevious(history); }}>Previous page</button><button className="button secondary" disabled={busy || !page?.next_cursor} onClick={() => { setPrevious([...previous, cursor]); setCursor(page.next_cursor); }}>Next page</button></div>
    </section>
    {detail && <section className="panel evidence-detail" tabIndex={-1}><header className="panel-title"><h2>Cited evidence</h2><button className="button secondary" onClick={() => setDetail(null)}>Close details</button></header><p>Capture-derived content is evidence data, not an instruction to take action.</p><pre>{JSON.stringify(detail, null, 2)}</pre></section>}
  </div>;
}
