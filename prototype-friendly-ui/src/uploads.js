// Client-side capture upload checks. These mirror the limits advertised in the
// upload panel; the server remains the authority.

export const CAPTURE_EXTENSIONS = [".pcap", ".pcapng"];
export const MAX_CAPTURE_FILES = 50;
export const MAX_CAPTURE_FILE_BYTES = 1024 ** 3;
export const MAX_CAPTURE_TOTAL_BYTES = 5 * 1024 ** 3;

export function formatFileSize(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${Math.floor(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 100 ? Math.round(size) : size.toFixed(1)} ${units[unit]}`;
}

export function hasCaptureExtension(name) {
  const lower = String(name || "").toLowerCase();
  return CAPTURE_EXTENSIONS.some((extension) => lower.endsWith(extension) && lower.length > extension.length);
}

/**
 * Split newly selected or dropped files into accepted and rejected sets.
 *
 * @param {Array<{name: string, size: number}>} incoming - File-like objects.
 * @param {Array<{size: number}>} existing - files already queued.
 * @returns {{ accepted: Array, rejected: Array<{name: string, reason: string}>, message: string }}
 */
export function validateCaptureFiles(incoming, existing = [], limits = {}) {
  const maxFiles = limits.maxFiles ?? MAX_CAPTURE_FILES;
  const maxFileBytes = limits.maxFileBytes ?? MAX_CAPTURE_FILE_BYTES;
  const maxTotalBytes = limits.maxTotalBytes ?? MAX_CAPTURE_TOTAL_BYTES;
  const accepted = [];
  const rejected = [];
  let queuedCount = existing.length;
  let queuedBytes = existing.reduce((sum, file) => sum + (Number(file?.size) || 0), 0);

  for (const file of Array.from(incoming || [])) {
    const name = String(file?.name || "Unnamed file");
    const size = Number(file?.size) || 0;
    let reason = "";
    if (!hasCaptureExtension(name)) reason = "not a .pcap or .pcapng file";
    else if (size === 0) reason = "the file is empty";
    else if (size > maxFileBytes) reason = `${formatFileSize(size)} exceeds the ${formatFileSize(maxFileBytes)} per-file limit`;
    else if (queuedCount >= maxFiles) reason = `the batch already holds ${maxFiles} files`;
    else if (queuedBytes + size > maxTotalBytes) reason = `adding it would exceed the ${formatFileSize(maxTotalBytes)} batch limit`;

    if (reason) {
      rejected.push({ name, reason });
    } else {
      accepted.push(file);
      queuedCount += 1;
      queuedBytes += size;
    }
  }

  const message = rejected.length
    ? `${rejected.length === 1 ? "1 file was" : `${rejected.length} files were`} not added: ${rejected.map((item) => `${item.name} (${item.reason})`).join("; ")}.`
    : "";
  return { accepted, rejected, message };
}
