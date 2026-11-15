import assert from "node:assert/strict";
import test from "node:test";

import { formatFileSize, hasCaptureExtension, validateCaptureFiles } from "../src/uploads.js";

const GB = 1024 ** 3;
const file = (name, size = 2048) => ({ name, size });

test("file sizes are labelled in the unit that fits", () => {
  assert.equal(formatFileSize(0), "0 B");
  assert.equal(formatFileSize(512), "512 B");
  assert.equal(formatFileSize(20 * 1024), "20.0 KB");
  assert.equal(formatFileSize(1.5 * 1024 * 1024), "1.5 MB");
  assert.equal(formatFileSize(250 * 1024 * 1024), "250 MB");
  assert.equal(formatFileSize(GB), "1.0 GB");
  assert.equal(formatFileSize(5 * GB), "5.0 GB");
  assert.equal(formatFileSize(undefined), "0 B");
});

test("only capture extensions are accepted", () => {
  for (const name of ["a.pcap", "B.PCAPNG", "trace.2026.pcap"]) assert.equal(hasCaptureExtension(name), true, name);
  for (const name of ["a.cap", "notes.txt", "pcap", ".pcap", "a.pcap.zip", ""]) assert.equal(hasCaptureExtension(name), false, name);
});

test("valid captures are accepted without a message", () => {
  const incoming = [file("one.pcap"), file("two.pcapng")];
  const result = validateCaptureFiles(incoming);
  assert.deepEqual(result.accepted, incoming);
  assert.deepEqual(result.rejected, []);
  assert.equal(result.message, "");
  assert.deepEqual(validateCaptureFiles(undefined), { accepted: [], rejected: [], message: "" });
});

test("wrong types, empty files, and oversized files are rejected with reasons", () => {
  const result = validateCaptureFiles([file("ok.pcap"), file("readme.txt"), file("empty.pcap", 0), file("huge.pcap", GB + 1)]);
  assert.deepEqual(result.accepted.map((item) => item.name), ["ok.pcap"]);
  assert.deepEqual(result.rejected.map((item) => item.name), ["readme.txt", "empty.pcap", "huge.pcap"]);
  assert.match(result.message, /^3 files were not added:/);
  assert.match(result.message, /readme\.txt \(not a \.pcap or \.pcapng file\)/);
  assert.match(result.message, /huge\.pcap \(1\.0 GB exceeds the 1\.0 GB per-file limit\)/);
  assert.equal(validateCaptureFiles([file("exact.pcap", GB)]).accepted.length, 1);
});

test("batch count and total size limits include files already queued", () => {
  const queued = Array.from({ length: 49 }, (_, index) => file(`q${index}.pcap`));
  const overCount = validateCaptureFiles([file("a.pcap"), file("b.pcap")], queued);
  assert.deepEqual(overCount.accepted.map((item) => item.name), ["a.pcap"]);
  assert.match(overCount.message, /^1 file was not added: b\.pcap \(the batch already holds 50 files\)/);

  const overTotal = validateCaptureFiles([file("c.pcap", GB), file("d.pcap", GB), file("small.pcap", 10)], [file("x", GB), file("y", GB), file("z", GB), file("w", GB - 5)]);
  assert.deepEqual(overTotal.accepted.map((item) => item.name), ["c.pcap"]);
  assert.deepEqual(overTotal.rejected.map((item) => item.name), ["d.pcap", "small.pcap"]);
  assert.match(overTotal.message, /would exceed the 5\.0 GB batch limit/);
});
