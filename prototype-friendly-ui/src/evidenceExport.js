export async function collectEvidencePages(fetchPage, { snapshotId, maxBytes = 20 * 1024 * 1024 } = {}) {
  let cursor = null, first = null, totalBytes = 0;
  const items = [], seen = new Set();
  do {
    const page = await fetchPage({ cursor, snapshotId: first?.snapshot_id || snapshotId });
    if (!first) first = page;
    if (page.snapshot_id !== first.snapshot_id || page.analysis_id !== first.analysis_id) throw new Error("Evidence changed during export. Try again.");
    totalBytes += new TextEncoder().encode(JSON.stringify(page.items)).length;
    if (totalBytes > maxBytes) throw new Error("This export exceeds the browser's 20 MiB limit. Narrow the query or use paginated API retrieval.");
    items.push(...page.items);
    cursor = page.next_cursor;
    if (cursor && seen.has(cursor)) throw new Error("Evidence pagination did not advance.");
    if (cursor) seen.add(cursor);
  } while (cursor);
  if (items.length !== first.total_matching) throw new Error("Evidence export is incomplete. Try again.");
  return { schema_version: first.schema_version, analysis_id: first.analysis_id, snapshot_id: first.snapshot_id,
    total_matching: first.total_matching, coverage: first.coverage, warnings: first.warnings, items };
}
