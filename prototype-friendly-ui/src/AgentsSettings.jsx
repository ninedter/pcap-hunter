import { useEffect, useState } from "react";
import { isPrivacyMode } from "./privacy.js";

const readPermissions = ["cases:read", "evidence:read", "jobs:read"];
const permissionLabels = {
  "cases:read": "Read granted cases",
  "evidence:read": "Read evidence and flows",
  "jobs:read": "Read job status",
  "reports:read": "Download reports",
  "captures:submit": "Submit captures for offline analysis",
  "notes:append": "Append investigation drafts",
};
async function api(path, options) {
  const response = await fetch(`/api/ui/agents${path}`, options);
  const value = response.status === 204 ? {} : await response.json();
  if (!response.ok) throw new Error(typeof value.detail === "string" ? value.detail : "Agent settings could not be updated.");
  return value;
}
export default function AgentsSettings({ cases }) {
  const [items, setItems] = useState([]);
  const [name, setName] = useState("Threat hunting agent");
  const [grants, setGrants] = useState([]);
  const [permissions, setPermissions] = useState(readPermissions);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const privateView = isPrivacyMode(window.location.search);
  const refresh = async () => setItems((await api("")).items);
  useEffect(() => { refresh().catch((e) => setError(e.message)); }, []);
  const toggle = (value, values, setValues) => setValues(values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
  const create = async (event) => {
    event.preventDefault(); setBusy(true); setError(""); setKey(""); setCopied(false);
    try {
      const result = await api("", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, permissions, case_ids: grants }) });
      setKey(result.key); await refresh();
    } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  const revoke = async (id) => {
    setBusy(true); setError("");
    try { await api(`/${encodeURIComponent(id)}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, body: "{}" }); await refresh(); }
    catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  return <div className="settings-stack agent-settings">
    <header><h2>Agent access</h2><p>Grant an agent access to selected cases. Reading is enabled by default. Capture submissions run offline in a separate worker.</p></header>
    {error && <div className="error-notice" role="alert">{error}</div>}
    {privateView ? <section className="settings-card"><p>Credential creation and values are hidden in privacy view.</p></section> : <form className="settings-card" onSubmit={create}>
      <h3>Create a scoped credential</h3><label>Agent name<input maxLength={100} value={name} onChange={(e) => setName(e.target.value)} required /></label>
      <fieldset><legend>Cases this agent may access</legend>{cases.map((item) => <label className="agent-choice" key={item.id}><input type="checkbox" checked={grants.includes(item.id)} onChange={() => toggle(item.id, grants, setGrants)} />{item.title}</label>)}{!cases.length && <p>No saved cases yet. A submission permission can create a case for its own captures.</p>}</fieldset>
      <fieldset><legend>Allowed actions</legend>{Object.entries(permissionLabels).map(([permission, label]) => <label className="agent-choice" key={permission}><input type="checkbox" checked={permissions.includes(permission)} onChange={() => toggle(permission, permissions, setPermissions)} />{label}</label>)}</fieldset>
      <p>Credentials expire after 7 days. Default limits: 60 requests/minute, 2,000 requests/day and 5 capture submissions/day. Agents cannot change settings, delete cases, manage keys, or select external model endpoints.</p>
      <button className="button primary" disabled={busy || !name.trim() || !permissions.length || (!grants.length && !permissions.includes("captures:submit"))}>{busy ? "Working…" : "Create agent credential"}</button>
    </form>}
    {key && !privateView && <section className="settings-card" aria-live="polite"><h3>Copy this credential now</h3><p>It is shown once. Store it in your agent host’s secret settings.</p><code className="agent-key">{key}</code><div className="field-actions"><button type="button" className="button secondary" onClick={async () => { try { await navigator.clipboard.writeText(key); setCopied(true); } catch { setError("Select and copy the credential directly."); } }}>{copied ? "Copied" : "Copy credential"}</button><button type="button" className="button secondary" onClick={() => setKey("")}>Hide credential</button></div></section>}
    <section className="settings-card"><h3>Existing agents</h3>{items.map((item, i) => <article className="agent-entry" key={item.id}><div><strong>{privateView ? `Agent ${i + 1}` : item.name}</strong><p>{item.case_ids.length} case grants · {item.permissions.join(", ")}</p><small>Expires {new Date(item.expires_at).toLocaleString()} · {item.revoked ? "Revoked" : "Active"}</small></div><button type="button" className="button secondary" disabled={busy || Boolean(item.revoked)} onClick={() => revoke(item.id)}>Revoke access</button></article>)}{!items.length && <p>No agent credentials have been created.</p>}</section>
    <section className="settings-card"><h3>Connect your agent</h3><p>Use the authenticated API on port 8000, or the local stdio MCP adapter in the API container. Supply the credential as <code>PCAP_HUNTER_AGENT_KEY</code>. Full setup and tool examples are in <code>docs/AGENT_USAGE.md</code>.</p></section>
  </div>;
}
