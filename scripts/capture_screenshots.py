"""Capture real README screenshots and redact sensitive values.

Drives a headless Chromium via Playwright against a running Streamlit
instance (default http://localhost:8501), uploads ``data/sample.pcap``
by entering its path into the "type a container path" text input,
clicks Extract & Analyze, waits for the pipeline to finish, then
snapshots each tab at 1440×900.

After capture, every PNG is post-processed with Pillow to redact IPv4/IPv6
addresses, email addresses, full PCAP Hunter API keys, and user-home paths.
The primary pass extracts the exact DOM bounding boxes and draws solid pixel
rectangles. A multi-pass OCR fallback catches IPs rendered into Streamlit's
canvas-based data tables, and a final OCR audit fails the capture if a
recognizable sensitive value remains.

Usage:
    python3 scripts/capture_screenshots.py
    python3 scripts/capture_screenshots.py --base-url http://localhost:8501
    python3 scripts/capture_screenshots.py --seed-docs-key  # isolated data bind only
    python3 scripts/capture_screenshots.py --keep-ips   # skip redaction
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import time
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw
from playwright.sync_api import Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "docs" / "images"
SAMPLE_PCAP = REPO_ROOT / "data" / "sample.pcap"

# IPv4 pattern — matches anything that looks like a.b.c.d with 0-255 octets.
# We redact any IP, including RFC1918/loopback — the goal is zero IPs visible.
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b")
# Broad candidate matcher; candidates are validated with ipaddress.ip_address.
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
API_KEY_RE = re.compile(r"\bphk_[0-9a-f]{16,}\b", re.IGNORECASE)
USER_PATH_RE = re.compile(r"(?:/(?:Users|home)/|[A-Z]:\\Users\\)[^\s\"'<>]+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Playwright helpers
# ---------------------------------------------------------------------------


def wait_for_streamlit_idle(page: Page, timeout_ms: int = 30_000) -> None:
    """Wait until Streamlit's running indicator disappears."""
    # Streamlit shows a "Running..." status bar during reruns.
    page.wait_for_function(
        """() => {
            const status = document.querySelector('[data-testid="stStatusWidget"]');
            return !status || !status.innerText.match(/Running|Connecting/i);
        }""",
        timeout=timeout_ms,
    )


def click_tab(page: Page, tab_label: str) -> None:
    """Activate a tab by its visible label (e.g. 'Dashboard')."""
    page.get_by_role("tab", name=re.compile(tab_label, re.IGNORECASE)).click()
    wait_for_streamlit_idle(page)
    page.wait_for_timeout(800)  # let charts finish painting


def save_screenshot(page: Page, filename: str) -> Path:
    """Capture a tall screenshot that includes below-the-fold content.

    Streamlit wraps everything in a scrollable internal container, so
    Playwright's ``full_page=True`` alone doesn't capture overflow.
    We scroll to the bottom first (forces everything to lazy-render)
    then use full_page to stitch the view.
    """
    path = OUT_DIR / filename
    path.parent.mkdir(parents=True, exist_ok=True)

    # Force a full scroll so lazy-loaded sections render
    page.evaluate(
        r"""async () => {
            const SCROLL_SEL = [
                '[class*="stAppViewBlockContainer"]',
                '[data-testid="stAppViewContainer"]',
                'main',
            ].join(', ');
            // Scroll the main document + any inner scroll containers to the bottom
            window.scrollTo(0, document.body.scrollHeight);
            await new Promise(r => setTimeout(r, 400));
            for (const el of document.querySelectorAll(SCROLL_SEL)) {
                el.scrollTop = el.scrollHeight;
            }
            await new Promise(r => setTimeout(r, 400));
            // Back to top so the screenshot starts from the header
            window.scrollTo(0, 0);
            for (const el of document.querySelectorAll(SCROLL_SEL)) {
                el.scrollTop = 0;
            }
        }"""
    )
    page.wait_for_timeout(800)
    page.screenshot(path=str(path), full_page=True)
    print(f"  → saved {path.relative_to(REPO_ROOT)} ({path.stat().st_size:,} bytes)")
    return path


def upload_sample_pcap(page: Page, pcap_path: str) -> None:
    """Fill the 'type a container path' text input to load the sample.

    ``pcap_path`` must be valid for the SERVER process — when the app runs in
    Docker that means a container-visible path like ``data/sample.pcap``, not
    the host's absolute path.
    """
    path_input = page.get_by_label("...or type a container path (e.g., /data/capture.pcap)")
    path_input.fill(pcap_path)
    # Commit the input — on Streamlit >=1.55 Enter is the reliable commit
    # (Tab/blur alone no longer registers the value before the rerun).
    path_input.press("Enter")
    wait_for_streamlit_idle(page)
    try:
        page.get_by_text("Active Source", exact=False).first.wait_for(timeout=15_000)
    except Exception:
        # One retry with blur in case the first commit raced the rerun.
        path_input.fill(pcap_path)
        path_input.press("Enter")
        path_input.press("Tab")
        wait_for_streamlit_idle(page)
        page.get_by_text("Active Source", exact=False).first.wait_for(timeout=15_000)


def configure_local_llm(page: Page) -> None:
    """Select a model exposed by the real LM Studio endpoint, when available."""
    print("→ configuring LM Studio from the real Config screen")
    click_tab(page, "Config")
    try:
        page.get_by_role("button", name="Fetch Models", exact=True).first.click()
        wait_for_streamlit_idle(page, timeout_ms=45_000)
        page.get_by_text(re.compile(r"Found \d+ models?\.", re.IGNORECASE)).first.wait_for(timeout=45_000)
        selected = page.get_by_label("Model name").input_value()
        print(f"  model selected: {selected}")
    except Exception as exc:  # noqa: BLE001 — screenshot setup degrades to configured default
        print(f"  WARNING: live model discovery failed; using configured default ({exc})")
    click_tab(page, "Upload")


def prepare_documentation_api_key(page: Page) -> None:
    """Create a disposable example key through the real UI when the database is empty."""
    click_tab(page, "API Keys")
    if "README documentation key" not in page.inner_text("body"):
        page.get_by_label("Key Name").fill("README documentation key")
        page.get_by_role("button", name="Create Key", exact=True).click()
        wait_for_streamlit_idle(page)
    # A newly created secret is intentionally stored in session state and shown
    # once. Reload to clear that one-time value and refresh the repository list.
    page.reload(wait_until="networkidle")
    page.wait_for_timeout(2_000)
    click_tab(page, "API Keys")


def run_extract_analyze(page: Page, wait_for_llm: bool = False, timeout_s: int = 300) -> None:
    """Click the Extract & Analyze button and wait for the pipeline.

    By default we only wait for the *data* stages (packet parsing, zeek,
    dns, tls, beacon, carve, yara, osint) — not the LLM synthesis step,
    which can take minutes if LM Studio isn't responsive. The Dashboard
    tab only depends on data stages, so this is fine for screenshots.
    """
    page.get_by_role("button", name=re.compile(r"extract\s*&\s*analyze", re.IGNORECASE)).click()
    page.wait_for_timeout(2_000)
    if "Please upload a PCAP or provide a valid path" in page.inner_text("body"):
        raise RuntimeError(
            "the server rejected the pcap path — pass a path the SERVER can see "
            "(container-relative like data/sample.pcap when using Docker)"
        )
    # Record the real in-flight phase tracker while it is present. Once a run
    # completes, the Progress tab intentionally returns to its idle guidance.
    page.get_by_role("tab", name=re.compile("Progress", re.IGNORECASE)).click()
    page.wait_for_timeout(3_000)
    capture_and_redact(page, "02-progress.png", redact=True)
    print(f"  waiting for pipeline (up to {timeout_s}s)...")
    deadline = time.time() + timeout_s
    last_status = ""
    while time.time() < deadline:
        try:
            status = page.evaluate(
                r"""(waitLLM) => {
                    const bodyText = document.body.innerText;
                    const result = {done: false, llm_done: false, stage: ''};

                    // Check for LLM report markers
                    if (bodyText.match(/##\s*(Executive Summary|Key Findings|Recommended Actions)/)) {
                        result.llm_done = true;
                    }

                    // Data-stages complete: Beacon / YARA / OSINT sections appear in UI,
                    // or we see the LLM phase's "Generating AI report" caption, or LLM done.
                    const dataStageDone =
                        bodyText.match(/Generating (?:AI |LLM )?report/i) ||
                        bodyText.match(/OSINT enrichment complete/i) ||
                        bodyText.match(/Completed: LLM report/i) ||
                        bodyText.match(/Beacon candidates/i) ||
                        result.llm_done;

                    if (dataStageDone) result.done = true;
                    if (waitLLM) result.done = result.llm_done;

                    // Extract last visible caption as stage hint
                    const caps = document.querySelectorAll('p, [data-testid="caption"]');
                    for (let i = caps.length - 1; i >= 0; i--) {
                        const t = caps[i].innerText.trim();
                        if (t && t.length < 80 && !t.startsWith('##')) {
                            result.stage = t;
                            break;
                        }
                    }
                    return result;
                }""",
                wait_for_llm,
            )
            if status.get("stage") and status["stage"] != last_status:
                last_status = status["stage"]
                print(f"    · {last_status[:60]}")
            if status.get("done"):
                print(f"  pipeline finished (llm_done={status.get('llm_done')})")
                return
        except Exception:
            pass
        page.wait_for_timeout(3_000)
    print("  WARNING: pipeline timeout — taking screenshots with current state")


# ---------------------------------------------------------------------------
# IP redaction (via DOM-aware bounding box extraction)
# ---------------------------------------------------------------------------


def collect_sensitive_boxes(page: Page) -> list[dict]:
    """Return pixel boxes for visible sensitive text on the page.

    We walk text nodes, match IPv4 patterns, then use Range.getClientRects()
    to get exact pixel coordinates in the page (which equal viewport pixels
    in Playwright's full_page screenshots).
    """
    return page.evaluate(
        r"""() => {
        const sensitiveRes = [
            /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b/g,
            /[0-9A-Fa-f:]*:[0-9A-Fa-f:]+/g,
            /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
            /\bphk_[0-9a-f]{16,}\b/gi,
            /(?:\/(?:Users|home)\/|[A-Z]:\\Users\\)[^\s\"'<>]+/gi,
        ];
        const boxes = [];
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
        let node;
        while ((node = walker.nextNode())) {
            const text = node.nodeValue;
            if (!text) continue;
            const element = node.parentElement;
            if (!element || !element.checkVisibility({checkOpacity: true, checkVisibilityCSS: true})) continue;
            const panel = element.closest('[role="tabpanel"]');
            if (panel && panel.getAttribute('aria-hidden') === 'true') continue;
            for (const sensitiveRe of sensitiveRes) {
                sensitiveRe.lastIndex = 0;
                const matches = [...text.matchAll(sensitiveRe)];
                for (const m of matches) {
                    // The broad IPv6 candidate matcher also sees timestamps.
                    // Require compressed notation or at least four colons.
                    if (sensitiveRe === sensitiveRes[1]) {
                        const colonCount = (m[0].match(/:/g) || []).length;
                        if (!m[0].includes('::') && colonCount < 4) continue;
                    }
                    const range = document.createRange();
                    range.setStart(node, m.index);
                    range.setEnd(node, m.index + m[0].length);
                    const rects = range.getClientRects();
                    for (const r of rects) {
                        if (r.width > 0 && r.height > 0) {
                            boxes.push({
                                x: Math.floor(r.left + window.scrollX),
                                y: Math.floor(r.top + window.scrollY),
                                w: Math.ceil(r.width),
                                h: Math.ceil(r.height),
                                text: m[0],
                            });
                        }
                    }
                }
            }
        }
        return boxes;
    }"""
    )


def _valid_ip_octet(s: str) -> bool:
    try:
        n = int(s)
        return 0 <= n <= 255
    except ValueError:
        return False


def _valid_ipv6_values(text: str) -> list[str]:
    """Return syntactically valid IPv6 values found in OCR text."""
    values: list[str] = []
    for match in IPV6_CANDIDATE_RE.finditer(text):
        candidate = match.group(0)
        try:
            if ipaddress.ip_address(candidate).version == 6:
                values.append(candidate)
        except ValueError:
            continue
    return values


def _extract_ip_boxes_from_data(data: dict, scale: float = 1.0) -> list[dict]:
    """Three match strategies on one tesseract image_to_data result."""
    boxes: list[dict] = []
    n = len(data["text"])
    inv = 1.0 / scale  # divide coords to get back to original image space

    def _box(i: int, text: str) -> dict:
        return {
            "x": int(int(data["left"][i]) * inv),
            "y": int(int(data["top"][i]) * inv),
            "w": int(int(data["width"][i]) * inv),
            "h": int(int(data["height"][i]) * inv),
            "text": text,
        }

    # Strategy 1: per-token strict IPv4/IPv6
    for i, text in enumerate(data["text"]):
        if text and (IPV4_RE.search(text) or _valid_ipv6_values(text)):
            boxes.append(_box(i, text))

    # Strategy 2: 4-token sliding window on the same line
    for i in range(n - 3):
        line_key = (data["block_num"][i], data["par_num"][i], data["line_num"][i])
        if any(
            (data["block_num"][j], data["par_num"][j], data["line_num"][j]) != line_key for j in range(i + 1, i + 4)
        ):
            continue
        parts = [data["text"][i + k].strip(".,;: ") for k in range(4)]
        if all(_valid_ip_octet(p) for p in parts):
            left = min(int(data["left"][i + k]) for k in range(4))
            top = min(int(data["top"][i + k]) for k in range(4))
            right = max(int(data["left"][i + k]) + int(data["width"][i + k]) for k in range(4))
            bottom = max(int(data["top"][i + k]) + int(data["height"][i + k]) for k in range(4))
            boxes.append(
                {
                    "x": int(left * inv),
                    "y": int(top * inv),
                    "w": int((right - left) * inv),
                    "h": int((bottom - top) * inv),
                    "text": ".".join(parts),
                }
            )

    # Strategy 3: token cleaned to IPv4
    for i, text in enumerate(data["text"]):
        if not text:
            continue
        cleaned = re.sub(r"[^0-9.]", "", text)
        if cleaned.count(".") == 3 and all(_valid_ip_octet(p) for p in cleaned.split(".")):
            boxes.append(_box(i, cleaned))

    return boxes


def ocr_ip_boxes(png_path: Path) -> list[dict]:
    """Second-pass redaction: find IPs that DOM scanning missed.

    Streamlit's st.dataframe renders cells into a canvas; DOM walking
    can't see that text. We OCR the rendered PNG with tesseract.

    Uses a multi-pass approach for robustness with small fonts:
      - Pass A: original resolution, PSM 11 (sparse text)
      - Pass B: 2x upscaled, PSM 11 (better for small fonts)
      - Pass C: 2x upscaled, PSM 6 (uniform block; catches table rows)
      - Pass D: 2x upscaled, PSM 12 (sparse text with OSD)

    Each pass runs the three match strategies in _extract_ip_boxes_from_data.
    Overlapping redactions are fine — Pillow just draws the rectangle twice.
    """
    try:
        import pytesseract
    except ImportError as exc:
        raise RuntimeError(
            "pytesseract is required for privacy-safe screenshot capture; install requirements-docs.txt"
        ) from exc

    img = Image.open(png_path)
    img_2x = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)

    passes = [
        (img, "--psm 11", 1.0),
        (img_2x, "--psm 11", 2.0),
        (img_2x, "--psm 6", 2.0),
        (img_2x, "--psm 12", 2.0),
    ]

    all_boxes: list[dict] = []
    for pimg, config, scale in passes:
        try:
            data = pytesseract.image_to_data(
                pimg,
                config=config,
                output_type=pytesseract.Output.DICT,
            )
            all_boxes.extend(_extract_ip_boxes_from_data(data, scale=scale))
        except Exception:
            continue
    return all_boxes


def redact_png(
    png_path: Path,
    boxes: list[dict],
    dpr: float = 1.0,
    run_ocr_fallback: bool = True,
) -> int:
    """Overlay each sensitive box with a solid rectangle. Returns total redactions.

    First pass: uses the DOM-collected boxes (exact, fast).
    Second pass: OCR the saved PNG to catch IPs in canvas-rendered grids
    (Streamlit's st.dataframe).
    """
    img = Image.open(png_path).convert("RGBA")
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)
    total = 0

    def _draw_box(x: int, y: int, w: int, h: int, pad_x: int = 2, pad_y: int = 1) -> bool:
        x1 = max(0, x - pad_x)
        y1 = max(0, y - pad_y)
        x2 = min(img.width, x + w + pad_x)
        y2 = min(img.height, y + h + pad_y)
        if x2 <= x1 or y2 <= y1:
            return False
        draw.rectangle([x1, y1, x2, y2], fill=(20, 20, 20, 255))
        return True

    # Pass 1: DOM boxes
    for b in boxes:
        if _draw_box(int(b["x"] * dpr), int(b["y"] * dpr), int(b["w"] * dpr), int(b["h"] * dpr)):
            total += 1

    # We composite now so OCR sees the partially-redacted image and only
    # flags remaining IPs (avoids double-redacting the same text).
    if run_ocr_fallback:
        img_partial = Image.alpha_composite(img, overlay)
        img_partial.convert("RGB").save(png_path, format="PNG", optimize=True)
        ocr_boxes = ocr_ip_boxes(png_path)
        if ocr_boxes:
            # Draw OCR boxes on a fresh overlay applied to the partial image
            overlay2 = Image.new("RGBA", img.size, (0, 0, 0, 0))
            draw = ImageDraw.Draw(overlay2)
            for b in ocr_boxes:
                if _draw_box(b["x"], b["y"], b["w"], b["h"]):
                    total += 1
            img_partial = Image.alpha_composite(img_partial, overlay2)
        img_partial.convert("RGB").save(png_path, format="PNG", optimize=True)
    else:
        img = Image.alpha_composite(img, overlay)
        img.convert("RGB").save(png_path, format="PNG", optimize=True)

    return total


def audit_redacted_png(png_path: Path) -> list[str]:
    """Return recognizable sensitive values that remain after redaction."""
    try:
        import pytesseract
    except ImportError as exc:
        raise RuntimeError(
            "pytesseract is required for the final screenshot privacy audit; install requirements-docs.txt"
        ) from exc

    text = pytesseract.image_to_string(Image.open(png_path), config="--psm 11")
    findings: list[str] = []
    for pattern in (IPV4_RE, EMAIL_RE, API_KEY_RE, USER_PATH_RE):
        findings.extend(match.group(0) for match in pattern.finditer(text))
    findings.extend(_valid_ipv6_values(text))
    return sorted(set(findings))


def crop_trailing_blank(
    png_path: Path,
    min_blank_run: int = 300,
    blank_pixel_threshold: int = 240,
    padding: int = 40,
) -> None:
    """Trim trailing whitespace and any post-content duplicate render.

    Streamlit's full_page screenshot can include both trailing blank space
    and a duplicate header re-render below the actual page end. We scan
    rows top-to-bottom and crop at the first run of >=min_blank_run blank
    rows after content begins — that point is always the true page end.
    """
    img = Image.open(png_path)
    arr = np.array(img.convert("L"))
    h = arr.shape[0]
    non_white_frac = (arr < blank_pixel_threshold).mean(axis=1)
    is_blank = non_white_frac < 0.005
    if not (~is_blank).any():
        return
    first_content = int(np.argmax(~is_blank))
    crop_at = h
    run_start = None
    for i in range(first_content, h):
        if is_blank[i]:
            if run_start is None:
                run_start = i
            elif i - run_start + 1 >= min_blank_run:
                crop_at = run_start
                break
        else:
            run_start = None
    if crop_at >= h:
        return
    new_h = min(h, crop_at + padding)
    cropped = img.crop((0, 0, img.width, new_h))
    cropped.save(png_path, optimize=True)
    print(f"  ✂  cropped {png_path.name}: {h} → {new_h}px (saved {h - new_h}px)")


def capture_and_redact(
    page: Page,
    filename: str,
    redact: bool = True,
    dpr: float = 1.0,
) -> None:
    """Take a screenshot and immediately redact IPs in place."""
    # Collect sensitive bounding boxes BEFORE screenshot so the DOM is the same state.
    boxes = collect_sensitive_boxes(page) if redact else []
    path = save_screenshot(page, filename)
    if redact:
        n = redact_png(path, boxes, dpr=dpr, run_ocr_fallback=True)
        print(f"  ✂  redacted {n} sensitive region(s) in {filename}")
    crop_trailing_blank(path)
    if redact:
        findings = audit_redacted_png(path)
        if findings:
            raise RuntimeError(f"sensitive text remains in {filename}: {', '.join(findings)}")


# ---------------------------------------------------------------------------
# Main capture flow
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8501")
    parser.add_argument("--keep-ips", action="store_true", help="skip IP redaction")
    parser.add_argument("--skip-analysis", action="store_true", help="don't upload/analyze (just snap empty tabs)")
    parser.add_argument(
        "--seed-docs-key",
        action="store_true",
        help="create a disposable README API key; use only with an isolated data bind",
    )
    parser.add_argument(
        "--redact-only",
        action="store_true",
        help="skip capture; re-run OCR redaction on existing PNGs in docs/images/",
    )
    parser.add_argument("--width", type=int, default=1440)
    parser.add_argument(
        "--height",
        type=int,
        default=2400,
        help="viewport height — made tall so Streamlit's internal scroll container renders more content",
    )
    parser.add_argument(
        "--pcap",
        default="data/sample.pcap",
        help="pcap path AS THE SERVER SEES IT (container-relative when the app runs in Docker)",
    )
    parser.add_argument("--pipeline-timeout", type=int, default=600, help="seconds to wait for the data stages")
    args = parser.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    if args.redact_only:
        # Re-run OCR redaction on whatever is already in docs/images/.
        # Useful after tweaking the OCR logic without re-driving the browser.
        for png in sorted(OUT_DIR.glob("*.png")):
            n = redact_png(png, [], dpr=1.0, run_ocr_fallback=True)
            print(f"  ✂  redacted {n} IP region(s) in {png.name}")
            crop_trailing_blank(png)
        return 0

    if not SAMPLE_PCAP.is_file() and not args.skip_analysis:
        print(f"ERROR: {SAMPLE_PCAP} not found. Copy sample.pcap → data/ first.", file=sys.stderr)
        return 1

    redact = not args.keep_ips

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": args.width, "height": args.height},
            device_scale_factor=1.0,
        )
        page = context.new_page()

        print(f"→ opening {args.base_url}")
        page.goto(args.base_url, wait_until="networkidle")
        # Streamlit's first render after networkidle still sometimes paints late
        page.wait_for_timeout(2_000)

        # Discover the model through the actual Config UI. This keeps the LLM
        # screenshot tied to a functioning local provider instead of a mock or
        # hard-coded model name.
        if not args.skip_analysis:
            configure_local_llm(page)

        # 1. Upload tab (pre-analysis)
        print("→ tab: Upload (pre-analysis)")
        click_tab(page, "Upload")
        capture_and_redact(page, "01-upload.png", redact=redact)

        if args.skip_analysis:
            # Snap the other tabs in their empty state
            for label, filename in (
                ("Config", "08-config.png"),
                ("Cases", "07-cases.png"),
                ("API Keys", "11-api-keys.png"),
            ):
                print(f"→ tab: {label} (empty state)")
                click_tab(page, label)
                capture_and_redact(page, filename, redact=redact)
            browser.close()
            return 0

        # 2. Upload sample and kick off analysis
        print(f"→ entering pcap path: {args.pcap}")
        upload_sample_pcap(page, args.pcap)
        page.wait_for_timeout(1_000)

        print("→ clicking Extract & Analyze")
        run_extract_analyze(page, timeout_s=args.pipeline_timeout)

        # Give charts a moment to finish rendering post-pipeline
        page.wait_for_timeout(3_000)

        # 2b. Wait for the LLM report so 04-llm-analysis shows real content.
        # The report renders inside the (hidden) LLM Analysis tab panel, so we
        # must activate the tab before its text is visible to innerText.
        print("→ waiting for the LLM report (up to 7 min)…")
        click_tab(page, "LLM Analysis")
        llm_deadline = time.time() + 420
        while time.time() < llm_deadline:
            try:
                panel_text = page.inner_text("body")
            except Exception:
                panel_text = ""
            if re.search(r"Executive Summary|Risk Assessment|IOC Summary", panel_text):
                print("  LLM report rendered")
                break
            page.wait_for_timeout(5_000)
        else:
            print("  WARNING: LLM report not detected — capturing current state")

        # 2c. Expand the risk explainer so the Dashboard shot shows it.
        click_tab(page, "Dashboard")
        try:
            page.get_by_text("Why this risk level?").first.click()
            page.wait_for_timeout(1_200)
        except Exception:
            print("  (risk expander not found — continuing)")

        # 3. Capture each tab
        for label, filename in (
            ("Dashboard", "03-dashboard.png"),
            ("MITRE Analysis", "10-mitre-analysis.png"),
            ("LLM Analysis", "04-llm-analysis.png"),
            ("OSINT", "05-osint.png"),
            ("Raw Data", "06-raw-data.png"),
            ("Cases", "07-cases.png"),
            ("Config", "08-config.png"),
        ):
            print(f"→ tab: {label}")
            click_tab(page, label)
            capture_and_redact(page, filename, redact=redact)

        # 4. Create an example key in the isolated documentation database via
        # the UI, reload away the one-time secret, then capture management state.
        print("→ tab: API Keys")
        if args.seed_docs_key:
            prepare_documentation_api_key(page)
        else:
            click_tab(page, "API Keys")
        capture_and_redact(page, "11-api-keys.png", redact=redact)

        # 5. LLM Integration close-up with the Anthropic provider selected.
        # No IPs appear in this section, so no redaction pass is needed.
        print("→ provider close-up: 09-llm-providers.png")
        try:
            click_tab(page, "Config")
            page.get_by_text("Anthropic", exact=True).first.click()
            page.wait_for_timeout(2_000)
            heading = page.get_by_text("LLM Integration", exact=True).first
            box = heading.bounding_box() or {"y": 0}
            clip = {"x": 0, "y": max(box["y"] - 16, 0), "width": args.width, "height": 760}
            target = OUT_DIR / "09-llm-providers.png"
            page.screenshot(path=str(target), clip=clip)
            print(f"  → saved {target.relative_to(REPO_ROOT)} ({target.stat().st_size:,} bytes)")
        except Exception as exc:  # noqa: BLE001 — optional close-up
            print(f"  WARNING: provider close-up failed: {exc}")

        browser.close()

    print(f"\n✓ screenshots saved to {OUT_DIR.relative_to(REPO_ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
