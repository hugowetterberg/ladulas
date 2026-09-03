// Getting around the changes in a document that is being compared
// (decision AP).
//
// This is one of the two corner controls and it lists what moved, grouped by
// the heading it moved under. Its twin is the outline; the third control, which
// chooses *which version* the document is being read against, is in the top bar
// rather than here.
//
// **It was here first, and putting it here was wrong.** The version list is
// long — every commit that touched a file — so opening this panel to reach the
// changes meant scrolling past a version history, and the navigation the panel
// exists for was the part you could not see. Two questions, asked at different
// moments: which version am I reading against, and where are its changes. They
// get two controls.
//
// Everything is built with textContent, like the rest of the bundle. A heading
// and a commit subject are both the document's own text, written by the machine
// we distrust most (§6), so neither is ever markup.

import { el, append } from "./dom.js";
import { jumpTo } from "./outline.js";

// maxLineLength clips a change to one line. The panel is a way to reach a
// change, not a way to read it: the document is one tap away and is where the
// change is legible.
const maxLineLength = 90;

const headingTags = new Set(["H1", "H2", "H3", "H4", "H5", "H6"]);

// attachChanges builds the corner control for one drawn document, or returns
// null when there is nothing to navigate.
//
// Nothing to navigate is the ordinary case — a document nobody is comparing has
// no changes in it — and a button that opens an empty panel has told the reader
// nothing. The version control in the top bar is the one that is always there.
export function attachChanges(article) {
  const groups = collect(article);

  if (!groups.length) {
    return null;
  }

  const panel = el("div", "changes-panel");
  const list = el("div", "changes-list");

  const total = groups.reduce((sum, group) => sum + group.lines.length, 0);
  const changes = total === 1 ? "1 change" : total + " changes";
  const sections = groups.length === 1
    ? "1 section"
    : groups.length + " sections";

  append(panel, el("p", "changes-count", changes + " in " + sections), list);

  const toggle = el("button", "changes-toggle");
  toggle.type = "button";
  toggle.setAttribute("aria-label", "Changes in this document");

  // A plus and a minus drawn from elements, for the reason the outline's three
  // bars are: a glyph would depend on a font the platform may not have.
  append(toggle, el("span", "changes-plus"), el("span", "changes-minus"));

  let open = false;

  function setOpen(next) {
    open = next;
    panel.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  setOpen(false);

  toggle.onclick = () => setOpen(!open);

  for (const group of groups) {
    list.append(renderGroup(group, () => setOpen(false)));
  }

  return { panel, toggle };
}

// collect walks the drawn document and groups the marks by the heading they
// fall under.
//
// The walk is in document order over headings and outermost marks together,
// which is what makes the grouping fall out rather than needing a tree: a mark
// belongs to the last heading seen before it, whatever that heading's level,
// which is also how a reader would describe where it is.
function collect(article) {
  const nodes = Array.from(article.querySelectorAll(
    "h1,h2,h3,h4,h5,h6,.changed-added,.changed-removed"));

  const groups = [];
  let current = null;

  for (const node of nodes) {
    if (headingTags.has(node.tagName)) {
      current = groupForHeading(node, groups);

      continue;
    }

    // A mark inside another mark is the same change said twice: Go puts a
    // block's mark on its spans as well. Only the outermost is somewhere to go.
    if (node.parentElement && node.parentElement.closest(
      ".changed-added, .changed-removed")) {
      continue;
    }

    if (!current) {
      current = { heading: null, label: null, lines: [] };
      groups.push(current);
    }

    current.lines.push({ node, kind: kindOf(node) });
  }

  return groups.filter((group) => group.lines.length || group.changed);
}

// groupForHeading starts a group for a heading, or folds it into the one before
// it when the two are a rename.
//
// **This is the heading case that needs a decision.** A heading whose wording
// changed usually arrives refined — one heading, with its old words struck
// through and its new ones marked — and that is one group with a marked label.
// But when the old and new wording share nothing, Go cannot pair them and sends
// a removed heading followed by an added one. Drawn as two groups that reads as
// a section deleted and an unrelated section added, which is not what happened.
// So a removed heading immediately followed by an added heading of the same
// level becomes one group carrying both.
function groupForHeading(node, groups) {
  const kind = kindOf(node);
  const level = node.tagName;

  const previous = groups[groups.length - 1];

  if (kind === "added" && previous &&
    previous.kind === "removed" && previous.level === level &&
    !previous.lines.length) {
    previous.kind = "renamed";
    previous.label = renameLabel(previous.heading, node);
    previous.heading = node;

    return previous;
  }

  const group = {
    heading: node,
    level,
    kind,
    changed: Boolean(kind) || hasMarkedSpan(node),
    label: headingLabel(node),
    lines: [],
  };

  groups.push(group);

  return group;
}

// headingLabel is the heading as the document draws it, marks and all.
//
// Its own child nodes are cloned rather than its text taken, so that a heading
// whose wording changed shows the old words struck through beside the new ones
// exactly as the page does. Cloning carries no markup: these are nodes this
// bundle built out of textContent.
function headingLabel(node) {
  const label = el("span", "changes-heading");

  for (const child of node.childNodes) {
    label.append(child.cloneNode(true));
  }

  return label;
}

function renameLabel(before, after) {
  const label = el("span", "changes-heading");

  append(label,
    el("span", "changed-removed", text(before)),
    el("span", "changes-arrow", " "),
    el("span", "changed-added", text(after)));

  return label;
}

function renderGroup(group, close) {
  const node = el("div", "changes-group");

  const header = el("button", "changes-group-heading");
  header.type = "button";

  if (group.label) {
    header.append(group.label);
  } else {
    header.append(el("span", "changes-heading", "Before the first heading"));
  }

  if (group.kind) {
    header.classList.add("changes-" + group.kind);
  }

  header.onclick = () => {
    close();
    jumpTo(group.heading);
  };

  node.append(header);

  for (const line of group.lines) {
    node.append(renderLine(line, close));
  }

  return node;
}

function renderLine(line, close) {
  const node = el("button", "changes-line");
  node.type = "button";

  if (line.kind) {
    node.classList.add("changed-" + line.kind);
  }

  node.append(el("span", "changes-mark", line.kind === "removed" ? "−" : "+"));
  node.append(el("span", "changes-text", clip(text(line.node))));

  node.onclick = () => {
    close();
    jumpTo(line.node);
  };

  return node;
}

function kindOf(node) {
  if (node.classList.contains("changed-added")) {
    return "added";
  }

  if (node.classList.contains("changed-removed")) {
    return "removed";
  }

  return null;
}

// hasMarkedSpan reports whether a heading was refined — unmarked itself, with
// marks inside it. That is the ordinary shape of a renamed heading and it has
// to count as a change, or a section whose title is the only thing that moved
// would be missing from the panel.
function hasMarkedSpan(node) {
  return Boolean(node.querySelector(".changed-added, .changed-removed"));
}

function text(node) {
  return (node.textContent || "").replace(/\s+/g, " ").trim();
}

function clip(value) {
  if (value.length <= maxLineLength) {
    return value;
  }

  return value.slice(0, maxLineLength - 1) + "…";
}
