import { createElement } from "react";

// The AI report is shaped by attacker-controlled capture strings (hostnames,
// URLs, HTTP headers). Never let it make the analyst's browser fetch a remote
// resource, and never hand a clicked link the workbench's referrer or opener.

function SafeLink({ href, title, children }) {
  return createElement("a", { href, title, target: "_blank", rel: "noreferrer noopener" }, children);
}

function ImagePlaceholder({ alt }) {
  return createElement("span", { className: "report-image-omitted" }, alt ? `[image omitted: ${alt}]` : "[image omitted]");
}

export const reportMarkdownComponents = {
  a: SafeLink,
  img: ImagePlaceholder,
};

// Raw HTML is already ignored by react-markdown; these are the remaining
// elements that could trigger a remote load if a plugin ever emitted them.
export const reportDisallowedElements = ["iframe", "object", "embed", "video", "audio", "source", "picture", "link", "script", "style"];
