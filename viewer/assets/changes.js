// Getting around the changes in a document that has been refreshed
// (decision AP).
//
// A reader who has just been told their documentation moved on wants two
// things, and scrolling gives them neither: to know how much changed, and to
// see the changed parts without reading the whole file again. So the reader gets
// a second control in the corner a thumb reaches, above the outline's, and it
// lists every change grouped by the heading it happened under.
//
// **The groups are read out of the drawn document rather than computed again.**
// Go's Compare already decided what changed and the renderer has already put
// the marks in the page, so walking the page in document order is both the
// cheapest way to group them and the only way that cannot disagree with what
// the reader is looking at. A second pass over the block list could drift from
// what was drawn; this cannot.
//
// Everything is built with textContent, like the rest of the bundle. A heading
// is the document's own text and the document was written by the machine we
// distrust most (§6), so it is never markup — not in the page, and not in this
// panel either.

import { el, append } from "./dom.js";
import { jumpTo } from "./outline.js";

// maxLineLength clips a change to one line. The panel is a way to reach a
// change, not a way to read it: the document itself is one tap away and is
// where the change is legible.
const maxLineLength = 90;

const headingTags = new Set(["H1", "H2", "H3", "H4", "H5", "H6"]);

// attachChanges builds the control for one rendered document, or returns null
// when nothing changed — in which case there is no button, because a control
// that opens an empty panel is a control that has told the reader nothing.
export function attachChanges(article) {
  const groups = collect(article);

  if (!groups.length) {
    return null;
  }

  const panel = el("div", "changes-panel");
  const list = el("div", "changes-list");

  const total = groups.reduce((sum, group) => sum + group.lines.length, 0);

  append(panel, summaryLine(total, groups.length), list);

  for (const group of groups) {
    list.append(renderGroup(group));
  }

  const toggle = el("button", "changes-toggle");
  toggle.type = "button";
  toggle.setAttribute("aria-label", "Changes in this document");

  // A plus and a minus, as elements rather than as characters: a glyph would
  // depend on a font the platform may not have, and these two carry the whole
  // meaning of the button.
  append(toggle,
    el("span", "changes-plus"),
    el("span", "changes-minus"));

  let open = false;

  function setOpen(next) {
    open = next;
    panel.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  setOpen(false);

  toggle.onclick = () => setOpen(!open);

  // Choosing a change closes the panel. The reader asked to be taken
  // somewhere, and leaving the list over the place they were taken to would
  // mean a second tap to see it.
  panel.addEventListener("changes:chosen", () => setOpen(false));

  return { panel, toggle };
}

function summaryLine(total, groups) {
  const changes = total === 1 ? "1 change" : total + " changes";
  const where = groups === 1 ? "1 section" : groups + " sections";

  return el("p", "changes-count", changes + " in " + where);
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

    // A mark inside another mark is the same change said twice: Go puts the
    // block's mark on its spans as well, so a removed paragraph's spans are all
    // removed too. Only the outermost is a change a reader can be taken to.
    if (node.parentElement && node.parentElement.closest(
      ".changed-added, .changed-removed")) {
      continue;
    }

    if (!current) {
      // Changes before the first heading. Every document has somewhere above
      // its first heading, and a preamble that changed is still a change.
      current = { heading: null, label: null, lines: [] };
      groups.push(current);
    }

    current.lines.push({ node, kind: kindOf(node) });
  }

  // A group whose heading did not change and whose body did not either is not
  // a change. It is left in the walk above because a heading has to be seen to
  // become the current one.
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
// in the panel exactly as it does in the page. Cloning carries no markup: these
// are nodes this bundle built, out of textContent.
function headingLabel(node) {
  const label = el("span", "changes-heading");

  for (const child of node.childNodes) {
    label.append(child.cloneNode(true));
  }

  return label;
}

// renameLabel is the label for the pair Go could not refine: the old heading
// struck through, then the new one marked.
function renameLabel(before, after) {
  const label = el("span", "changes-heading");

  append(label,
    el("span", "changed-removed", text(before)),
    el("span", "changes-arrow", " "),
    el("span", "changed-added", text(after)));

  return label;
}

function renderGroup(group) {
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

  // The heading itself is somewhere to go, which matters most in the case where
  // the heading is the only thing that changed.
  header.onclick = () => choose(node, group.heading);

  node.append(header);

  for (const line of group.lines) {
    node.append(renderLine(line));
  }

  return node;
}

function renderLine(line) {
  const node = el("button", "changes-line");
  node.type = "button";

  if (line.kind) {
    node.classList.add("changed-" + line.kind);
  }

  node.append(el("span", "changes-mark", line.kind === "removed" ? "−" : "+"));
  node.append(el("span", "changes-text", clip(text(line.node))));

  node.onclick = () => choose(node, line.node);

  return node;
}

// choose takes the reader to a change and tells the panel to close.
function choose(from, target) {
  if (target) {
    jumpTo(target);
  }

  from.dispatchEvent(new CustomEvent("changes:chosen", { bubbles: true }));
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
