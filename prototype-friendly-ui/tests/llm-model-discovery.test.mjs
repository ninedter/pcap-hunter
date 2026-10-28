import assert from "node:assert/strict";
import test from "node:test";

import {
  acceptsLlmDiscoveryResponse,
  buildLlmModelDiscoveryRequest,
  getLlmConnectionSignature,
  getLlmModelPickerState,
  nextLlmDiscoveryGeneration,
  normalizeDiscoveredLlmModels,
  shouldResetLlmDiscoveryForConfigSync,
  shouldSyncSettingsDraft,
} from "../src/workbench.js";

test("model discovery sends only configured draft connection values", () => {
  assert.deepEqual(
    buildLlmModelDiscoveryRequest({ provider: "lmstudio", baseUrl: " http://host.docker.internal:1234/v1 ", apiKey: "" }),
    { provider: "lmstudio", base_url: "http://host.docker.internal:1234/v1" },
  );
  assert.deepEqual(
    buildLlmModelDiscoveryRequest({ provider: "openai", baseUrl: "", apiKey: " replacement-key " }),
    { provider: "openai", api_key: "replacement-key" },
  );
});

test("model discovery accepts only usable, unique model names", () => {
  assert.deepEqual(
    normalizeDiscoveredLlmModels({ models: ["gpt-4.1", " gpt-4.1 ", "", null, "claude-sonnet"] }),
    ["gpt-4.1", "claude-sonnet"],
  );
  assert.deepEqual(normalizeDiscoveredLlmModels({ models: "not-a-list" }), []);
});

test("model picker keeps custom entry selected without erasing its value", () => {
  const models = ["gpt-4.1", "gpt-4.1-mini"];
  assert.deepEqual(
    getLlmModelPickerState({ models, selectedModel: "gpt-4.1", customModelMode: false }),
    { modelIsDiscovered: true, pickerValue: "gpt-4.1", showCustomInput: false },
  );
  assert.deepEqual(
    getLlmModelPickerState({ models, selectedModel: "gpt-4.1", customModelMode: true }),
    { modelIsDiscovered: true, pickerValue: "__custom__", showCustomInput: true },
  );
  assert.deepEqual(
    getLlmModelPickerState({ models, selectedModel: "local-specialist", customModelMode: false }),
    { modelIsDiscovered: false, pickerValue: "__custom__", showCustomInput: true },
  );
});

test("an explicit connection-field or load reset invalidates model responses started before it", () => {
  const requestGeneration = nextLlmDiscoveryGeneration(4);
  const resetGeneration = nextLlmDiscoveryGeneration(requestGeneration);
  assert.equal(acceptsLlmDiscoveryResponse(requestGeneration, requestGeneration), true);
  assert.equal(acceptsLlmDiscoveryResponse(requestGeneration, resetGeneration), false);
});

test("background configuration polls do not replace a dirty settings draft", () => {
  assert.equal(shouldSyncSettingsDraft(true), false);
  assert.equal(shouldSyncSettingsDraft(false), true);
});

test("saved configuration signatures ignore routine polling but detect connection changes", () => {
  const lmStudio = getLlmConnectionSignature({ cfg_llm_provider: "lmstudio", cfg_llm_endpoint: "http://host.docker.internal:1234/v1" });
  const sameLmStudio = getLlmConnectionSignature({ cfg_llm_provider: "lmstudio", cfg_llm_endpoint: " http://host.docker.internal:1234/v1 " });
  const openAi = getLlmConnectionSignature({ cfg_llm_provider: "openai", cfg_openai_base_url: "https://api.openai.com/v1" });
  assert.equal(shouldResetLlmDiscoveryForConfigSync(lmStudio, sameLmStudio), false);
  assert.equal(shouldResetLlmDiscoveryForConfigSync(lmStudio, openAi), true);
});
