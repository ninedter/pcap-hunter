// Pure helpers for the feedback shown after PUT /api/ui/settings: validation
// errors (422, nothing saved) and stored keys the server cleared because a
// provider's base-URL host changed without a new key.

/** Display label and Settings section for every key the form can submit. */
export const SETTINGS_FIELDS = {
  cfg_llm_provider: { label: "LLM provider", section: "llm" },
  cfg_llm_endpoint: { label: "LM Studio base URL", section: "llm" },
  cfg_llm_model: { label: "LM Studio model", section: "llm" },
  cfg_llm_language: { label: "Report language", section: "llm" },
  cfg_llm_context_window: { label: "Model context window", section: "llm" },
  cfg_llm_unlimited_context: { label: "No context window limit", section: "llm" },
  cfg_openai_base_url: { label: "OpenAI base URL", section: "llm" },
  cfg_openai_model: { label: "OpenAI model", section: "llm" },
  cfg_anthropic_model: { label: "Anthropic model", section: "llm" },
  cfg_openai_key: { label: "LM Studio API key", section: "llm" },
  cfg_openai_cloud_key: { label: "OpenAI API key", section: "llm" },
  cfg_anthropic_key: { label: "Anthropic API key", section: "llm" },
  cfg_vt_key: { label: "VirusTotal API key", section: "intel" },
  cfg_abuseipdb_key: { label: "AbuseIPDB API key", section: "intel" },
  cfg_greynoise_key: { label: "GreyNoise API key", section: "intel" },
  cfg_otx_key: { label: "OTX API key", section: "intel" },
  cfg_shodan_key: { label: "Shodan API key", section: "intel" },
  cfg_osint_top_ips: { label: "Top public IPs to enrich", section: "intel" },
  cfg_osint_cache_enabled: { label: "OSINT cache", section: "intel" },
  cfg_pyshark_limit: { label: "PyShark packet limit", section: "pipeline" },
  cfg_zeek_bin: { label: "Zeek binary path", section: "tools" },
  cfg_tshark_bin: { label: "tshark binary path", section: "tools" },
  cfg_yara_rules_dir: { label: "YARA rules directory", section: "tools" },
  cfg_home_continent: { label: "Home continent", section: "map" },
  cfg_home_country: { label: "Home country", section: "map" },
  cfg_home_city: { label: "Home city", section: "map" },
  cfg_home_lat: { label: "Home latitude", section: "map" },
  cfg_home_lon: { label: "Home longitude", section: "map" },
};

export const CLEARED_KEY_MESSAGE = "The stored key was cleared because the API URL now points at a different host. Enter the key for the new host and save again.";

const DEFAULT_SAVE_ERROR = "Settings could not be saved.";
const DEFAULT_CLEARED_NOTICE = "A provider API URL now points at a different host, so its stored API key was cleared. Enter the key for the new host and save again.";

const text = (value) => (typeof value === "string" ? value.trim() : "");

export function settingsFieldLabel(field) {
  return SETTINGS_FIELDS[field]?.label || String(field || "");
}

const sentence = (message) => {
  const trimmed = text(message);
  return trimmed ? `${trimmed.charAt(0).toUpperCase()}${trimmed.slice(1)}${/[.!?]$/.test(trimmed) ? "" : "."}` : "";
};

/**
 * Normalize a failed settings save into something the form can render.
 *
 * Accepts the thrown request error (with `.payload`), or the raw 422 body.
 * The server sends message fragments such as "must be a whole number"; they
 * are shown beside the field as a sentence, and listed with the field label
 * in the summary so an error in a section that is not open is still visible.
 *
 * @param {Error|object} source
 * @returns {{ summary: string, fields: Record<string, string>, items: Array<{field: string, label: string, section: string, message: string}>, sections: string[] }}
 */
export function mapSettingsErrors(source) {
  const payload = source?.payload && typeof source.payload === "object" ? source.payload : source && !(source instanceof Error) ? source : {};
  const detail = text(payload?.detail) || text(source?.message) || DEFAULT_SAVE_ERROR;
  const fields = {};
  const items = [];
  for (const entry of Array.isArray(payload?.errors) ? payload.errors : []) {
    const field = text(entry?.field);
    const message = sentence(entry?.message);
    if (!field || !message || fields[field]) continue;
    fields[field] = message;
    items.push({ field, label: settingsFieldLabel(field), section: SETTINGS_FIELDS[field]?.section || "", message });
  }
  if (!items.length) return { summary: detail, fields, items, sections: [] };
  return {
    summary: `Settings were not saved. Fix ${items.length === 1 ? "this field" : `these ${items.length} fields`} and save again.`,
    fields,
    items,
    sections: [...new Set(items.map((item) => item.section).filter(Boolean))],
  };
}

/**
 * Normalize a successful settings save response.
 *
 * @param {object} payload
 * @returns {{ notice: string, clearedKeys: string[], clearedLabels: string[] }}
 */
export function parseSettingsSaveResult(payload) {
  const clearedKeys = [...new Set((Array.isArray(payload?.cleared_keys) ? payload.cleared_keys : []).map(text).filter(Boolean))];
  const notice = text(payload?.notice) || (clearedKeys.length ? DEFAULT_CLEARED_NOTICE : "");
  return { notice, clearedKeys, clearedLabels: clearedKeys.map(settingsFieldLabel) };
}

/**
 * Feedback for one field: a validation error wins, then a cleared-key prompt.
 * A cleared key stops being flagged once a replacement is typed into the draft.
 *
 * @returns {{ tone: "error"|"warning", message: string } | null}
 */
export function settingsFieldFeedback(field, { errors = {}, clearedKeys = [], draft = {} } = {}) {
  if (errors[field]) return { tone: "error", message: errors[field] };
  if (clearedKeys.includes(field) && !text(draft[field])) return { tone: "warning", message: CLEARED_KEY_MESSAGE };
  return null;
}
