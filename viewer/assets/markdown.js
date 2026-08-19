// Rendering published documentation. The parsing happened in Go, so what
// arrives here is already blocks and spans — headings, paragraphs, code, lists,
// quotes, tables — and this only decides what they look like.
//
// That is the same arrangement the diff has, for a stronger reason. A published
// document is written by the machine we distrust most (§6), and a renderer with
// no parser in it has very little to get wrong. Every node is built with
// textContent, and the only links that exist are the ones Go decided point at
// another file in the same project.

import { el, append } from "./dom.js";
import { jumpTo } from "./outline.js";

// renderDocument draws a parsed document. onLink is called with the file a link
// names and the heading anchor it asks for, if any; a link to a place in this
// document never reaches it, because there is nowhere to navigate to — the page
// scrolls and stays where it is.
export function renderDocument(page, onLink) {
  const root = el("article", "document");

  // Where each heading ended up, so that a fragment link can find it without a
  // selector: the anchor is Go's slug and could be anything a heading is.
  const anchors = new Map();
  const context = { onLink, anchors };

  for (const block of page.blocks || []) {
    const node = renderBlock(block, context);

    if (node) {
      root.append(node);
    }
  }

  if (!(page.blocks || []).length) {
    root.append(el("p", "empty", "This file is empty."));
  }

  root.jumpToAnchor = (anchor) => jumpToAnchor(anchors, anchor);

  return root;
}

// jumpToAnchor is how a document arrived at by a fragment link lands on the
// right heading, and it answers whether it found one — a fragment that names
// nothing is not worth scrolling to the top for.
function jumpToAnchor(anchors, anchor) {
  const node = anchors.get(anchor);

  if (!node) {
    return false;
  }

  jumpTo(node);

  return true;
}

function renderBlock(block, context) {
  switch (block.kind) {
    case "heading":
      return renderHeading(block, context);
    case "paragraph":
      return renderInline(el("p"), block, context);
    case "code":
      return renderCode(block);
    case "quote":
      return renderChildren(el("blockquote"), block.blocks, context);
    case "list":
      return renderList(block, context);
    case "table":
      return renderTable(block, context);
    case "rule":
      return el("hr");
    default:
      return renderInline(el("p"), block, context);
  }
}

function renderHeading(block, context) {
  const node = renderInline(
    el("h" + Math.min(block.level || 1, 6)), block, context);

  // The identifier is Go's, so every host lands on the same heading for the
  // same fragment, and the outline leaves an id that is already there alone.
  if (block.anchor) {
    node.id = block.anchor;
    context.anchors.set(block.anchor, node);
  }

  return node;
}

function renderInline(node, block, context) {
  for (const span of block.spans || []) {
    node.append(renderSpan(span, context));
  }

  return node;
}

function renderSpan(span, context) {
  switch (span.kind) {
    case "code":
      return el("code", null, span.text);
    case "strong":
      return el("strong", null, span.text);
    case "emphasis":
      return el("em", null, span.text);
    case "link":
      return renderLink(span, context);
    default:
      return el("span", null, span.text);
  }
}

// A link is a button rather than an anchor, and has no href at all. Nothing in
// a published document may navigate this window anywhere; the only things a
// link can do are ask the browser to open another file of the same project and
// scroll this one.
function renderLink(span, context) {
  const node = el("button", "doclink", span.text || span.target);

  if (!span.target) {
    // A place in this document. Go has already checked that the anchor is one
    // of this document's headings, so the only way this finds nothing is a
    // heading that was never drawn.
    node.onclick = () => jumpToAnchor(context.anchors, span.fragment);

    return node;
  }

  node.onclick = () => context.onLink(span.target, span.fragment || "");

  return node;
}

// A table is drawn as a table. The alignment is the delimiter row's, and it
// arrives as a word rather than as anything the document chose.
function renderTable(block, context) {
  const table = el("table", "doctable");
  const align = block.align || [];

  if (block.header) {
    const head = el("thead");

    head.append(renderRow(el("tr"), block.header, "th", align, context));
    table.append(head);
  }

  const body = el("tbody");

  for (const row of block.rows || []) {
    body.append(renderRow(el("tr"), row, "td", align, context));
  }

  table.append(body);

  // A wide table on a phone scrolls sideways inside its own box rather than
  // making the whole document do it, which is the difference between a table
  // that is awkward and a page that is broken.
  return append(el("div", "doctable-scroll"), table);
}

function renderRow(row, cells, tag, align, context) {
  (cells.cells || []).forEach((spans, column) => {
    const cell = el(tag, align[column] ? "align-" + align[column] : null);

    for (const span of spans || []) {
      cell.append(renderSpan(span, context));
    }

    row.append(cell);
  });

  return row;
}

function renderCode(block) {
  const pre = el("pre", "code");

  if (block.language) {
    pre.append(el("span", "language", block.language));
  }

  pre.append(el("code", null, block.text || ""));

  return pre;
}

function renderChildren(node, blocks, context) {
  for (const block of blocks || []) {
    const child = renderBlock(block, context);

    if (child) {
      node.append(child);
    }
  }

  return node;
}

function renderList(block, context) {
  const list = el(block.ordered ? "ol" : "ul");

  for (const item of block.items || []) {
    list.append(renderChildren(el("li"), item, context));
  }

  return append(list);
}
