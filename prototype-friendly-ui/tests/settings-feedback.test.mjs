import assert from "node:assert/strict";
import test from "node:test";

import { CLEARED_KEY_MESSAGE, SETTINGS_FIELDS, mapSettingsErrors, parseSettingsSaveResult, settingsFieldFeedback } from "../src/settingsFeedback.js";

// Shapes produced by PUT /api/ui/settings in app/web/app.py.
const validationBody = {
  detail: "Settings were not saved: cfg_llm_context_window must be a whole number; cfg_openai_base_url must be a plain http(s) API URL without credentials, query, or fragment.",
  errors: [
    { field: "cfg_llm_context_window", message: "must be a whole number" },
    { field: "cfg_openai_base_url", message: "must be a plain http(s) API URL without credentials, query, or fragment" },
  ],
};

function requestError(status, payload) {
  const error = new Error(typeof payload.detail === "string" ? payload.detail : "The workbench could not complete that request.");
  error.status = status;
  error.payload = payload;
  return error;
}

test("validation errors map to their fields with readable labels", () => {
  const mapped = mapSettingsErrors(requestError(422, validationBody));
  assert.deepEqual(mapped.fields, {
    cfg_llm_context_window: "Must be a whole number.",
    cfg_openai_base_url: "Must be a plain http(s) API URL without credentials, query, or fragment.",
  });
  assert.deepEqual(mapped.items.map((item) => item.label), ["Model context window", "OpenAI base URL"]);
  assert.deepEqual(mapped.sections, ["llm"]);
  assert.match(mapped.summary, /not saved/i);
  assert.match(mapped.summary, /2 fields/);
});

test("errors spanning sections report every section once", () => {
  const mapped = mapSettingsErrors({
    detail: "Settings were not saved: …",
    errors: [
      { field: "cfg_osint_top_ips", message: "must be between 0 and 1000" },
      { field: "cfg_vt_key", message: "is not a valid key value" },
      { field: "cfg_pyshark_limit", message: "must be a whole number" },
    ],
  });
  assert.deepEqual(mapped.sections, ["intel", "pipeline"]);
  assert.equal(mapped.fields.cfg_vt_key, "Is not a valid key value.");
});

test("a failure without per-field errors falls back to the detail string", () => {
  const mapped = mapSettingsErrors(requestError(422, { detail: "settings_object_required" }));
  assert.equal(mapped.summary, "settings_object_required");
  assert.deepEqual(mapped.fields, {});
  assert.deepEqual(mapped.items, []);
  assert.deepEqual(mapped.sections, []);

  assert.equal(mapSettingsErrors(new Error("Failed to fetch")).summary, "Failed to fetch");
  assert.equal(mapSettingsErrors({ detail: [{ loc: ["body"], msg: "bad" }] }).summary, "Settings could not be saved.");
  assert.equal(mapSettingsErrors(undefined).summary, "Settings could not be saved.");
});

test("malformed, duplicate, and unknown error entries are handled", () => {
  const mapped = mapSettingsErrors({
    detail: "Settings were not saved.",
    errors: [
      null,
      { field: "", message: "must be text" },
      { field: "cfg_zeek_bin" },
      { field: "cfg_tshark_bin", message: "must be text" },
      { field: "cfg_tshark_bin", message: "second message ignored" },
      { field: "cfg_future_option", message: "must be true or false" },
    ],
  });
  assert.deepEqual(Object.keys(mapped.fields), ["cfg_tshark_bin", "cfg_future_option"]);
  assert.equal(mapped.items[1].label, "cfg_future_option");
  assert.deepEqual(mapped.sections, ["tools"]);
  assert.match(mapped.summary, /these 2 fields/);
});

test("a plain save reports no notice and no cleared keys", () => {
  assert.deepEqual(parseSettingsSaveResult({ saved: true }), { notice: "", clearedKeys: [], clearedLabels: [] });
  assert.deepEqual(parseSettingsSaveResult(undefined), { notice: "", clearedKeys: [], clearedLabels: [] });
});

test("a save that cleared a stored key surfaces the notice and the affected fields", () => {
  const result = parseSettingsSaveResult({
    saved: true,
    cleared_keys: ["cfg_openai_cloud_key"],
    notice: "The provider API URL now points at a different host, so its stored API key was cleared. Enter the key for the new host and save again.",
  });
  assert.deepEqual(result.clearedKeys, ["cfg_openai_cloud_key"]);
  assert.deepEqual(result.clearedLabels, ["OpenAI API key"]);
  assert.match(result.notice, /stored API key was cleared/);

  // The notice must never be lost when the server omits its text.
  const withoutText = parseSettingsSaveResult({ saved: true, cleared_keys: ["cfg_openai_key", "cfg_openai_key"] });
  assert.deepEqual(withoutText.clearedKeys, ["cfg_openai_key"]);
  assert.match(withoutText.notice, /cleared/);
});

test("field feedback prefers errors, then flags cleared keys until a replacement is typed", () => {
  const context = { errors: { cfg_openai_base_url: "Must be a plain http(s) API URL." }, clearedKeys: ["cfg_openai_cloud_key"], draft: { cfg_openai_cloud_key: "" } };
  assert.deepEqual(settingsFieldFeedback("cfg_openai_base_url", context), { tone: "error", message: "Must be a plain http(s) API URL." });
  assert.deepEqual(settingsFieldFeedback("cfg_openai_cloud_key", context), { tone: "warning", message: CLEARED_KEY_MESSAGE });
  assert.equal(settingsFieldFeedback("cfg_openai_cloud_key", { ...context, draft: { cfg_openai_cloud_key: "sk-new" } }), null);
  assert.equal(settingsFieldFeedback("cfg_llm_model", context), null);
  assert.equal(settingsFieldFeedback("cfg_llm_model"), null);
});

test("every secret the server can clear has a label in the LLM section", () => {
  for (const key of ["cfg_openai_cloud_key", "cfg_openai_key"]) {
    assert.equal(SETTINGS_FIELDS[key].section, "llm");
  }
});
