import assert from "node:assert/strict";
import test from "node:test";
import { collectEvidencePages } from "../src/evidenceExport.js";

test("export follows every saved page and preserves its snapshot", async () => {
  const calls = [];
  const result = await collectEvidencePages(async (query) => {
    calls.push(query);
    return { schema_version: "1", analysis_id: "a", snapshot_id: "s", total_matching: 3, coverage: { packet_parse: "partial" },
      items: query.cursor ? [3] : [1, 2], next_cursor: query.cursor ? null : "page-two" };
  });
  assert.deepEqual(result.items, [1, 2, 3]);
  assert.equal(calls[1].snapshotId, "s");
  assert.equal(result.coverage.packet_parse, "partial");
});

test("export refuses silent truncation, repeated cursors, and an oversized result", async () => {
  const page = { analysis_id: "a", snapshot_id: "s", total_matching: 2, items: [1], next_cursor: null };
  await assert.rejects(collectEvidencePages(async () => page), /incomplete/);
  await assert.rejects(collectEvidencePages(async () => ({ ...page, next_cursor: "same" })), /did not advance/);
  await assert.rejects(collectEvidencePages(async () => page, { maxBytes: 1 }), /exceeds/);
});
