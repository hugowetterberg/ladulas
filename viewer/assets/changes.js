// Choosing what you are reading, and what you are reading it against
// (decision AP).
//
// The control is always in the corner, whether or not anything has changed,
// because the question it answers is not "did something change" but "which
// version am I looking at". A reader opens a document at the latest version by
// default; from here they can pick an earlier one — a working-tree state the
// publisher kept between commits, or a commit — and the document redraws with
// what changed since it marked in place.
//
// It went the other way first, and the way that failed is the argument. The
// button appeared only when a document happened to carry changes, which made
// it a thing that turned up unbidden and could not be reached on purpose: there
// was no way to ask "what changed since Tuesday" about a document that looked
// current, and no way to turn the marks off once they were there. A control the
// reader cannot summon is not a control.
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

// attachChanges builds the corner control for one drawn document.
//
// article is what was rendered; page is what the bridge answered, which says
// whether it is a comparison and against what; onCompare is called with a
// version to compare against, or null for the latest on its own.
export function attachChanges(article, page, source, onCompare) {
  const panel = el("div", "changes-panel");
  const list = el("div", "changes-list");

  const toggle = el("button", "changes-toggle");
  toggle.type = "button";
  toggle.setAttribute("aria-label", "Versions and changes");

  // A plus and a minus drawn from elements, for the reason the outline's three
  // bars are: a glyph would depend on a font the platform may not have.
  append(toggle, el("span", "changes-plus"), el("span", "changes-minus"));

  // Comparing is a state worth seeing from outside the panel — a reader who
  // left the marks on and scrolled away should be able to tell why the document
  // is striped.
  if (page.compared) {
    toggle.classList.add("comparing");
  }

  append(panel, list);

  let open = false;

  function setOpen(next) {
    open = next;
    panel.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  setOpen(false);

  toggle.onclick = () => {
    setOpen(!open);

    if (open) {
      fill(list, article, page, source, onCompare, () => setOpen(false));
    }
  };

  return { panel, toggle };
}

// fill draws the panel's contents, and asks for the version list the first time
// it is opened.
//
// Asking on open rather than on load is the whole reason the control is
// affordable: a version list is a call to the publishing machine, and drawing a
// document must not cost one for a question nobody asked.
async function fill(list, article, page, source, onCompare, close) {
  list.replaceChildren();

  append(list,
    versionRow({
      label: "Latest",
      detail: "the document as it is now",
      selected: !page.compared,
      onChoose: () => {
        close();
        onCompare(null);
      },
    }));

  // Whatever went wrong, said as it was said. A snapshot expiring is the
  // commonest reason and was once the only one this claimed — which made every
  // other failure, from a cap to an unreachable peer, read as "gone".
  if (page.compareError) {
    list.append(el("p", "changes-note",
      "Could not compare against that version: " + page.compareError));
  }

  const loading = el("p", "changes-note", "Reading the versions…");
  list.append(loading);

  let versions;

  try {
    versions = await source();
  } catch (error) {
    loading.textContent = "Could not read the versions: " + error.message;

    return;
  }

  loading.remove();

  if (!versions.live) {
    list.append(el("p", "changes-note",
      versions.error
        ? "The machine that publishes this could not be reached: " +
          versions.error
        : "The machine that publishes this could not be reached."));
  }

  for (const version of versions.versions || []) {
    list.append(versionRow({
      label: versionLabel(version),
      detail: versionDetail(version),
      selected: isSelected(page, version),
      onChoose: () => {
        close();
        onCompare(version);
      },
    }));
  }

  if (versions.truncated) {
    list.append(el("p", "changes-note",
      "Older commits are not listed."));
  }

  // The changes themselves, under the versions, and only when there are some
  // to reach.
  const groups = collect(article);

  if (groups.length) {
    list.append(changesSection(groups, close));
  }
}

// versionLabel is what a version is called in the list. A commit is its
// subject; a snapshot has none, because nobody writes a message about saving a
// file, so it is named by when it was taken.
function versionLabel(version) {
  if (version.kind === "commit") {
    return version.subject || shortCommit(version.commit);
  }

  return when(version.at) || "A saved version";
}

// versionDetail is the line under it, and says which sort it is — because one
// of them will still be there tomorrow and the other will not.
function versionDetail(version) {
  if (version.kind === "commit") {
    const parts = [shortCommit(version.commit)];

    if (version.author) {
      parts.push(version.author);
    }

    if (version.at) {
      parts.push(when(version.at));
    }

    return parts.join(" · ");
  }

  return "unsaved work, kept until the next commit";
}

function shortCommit(commit) {
  return (commit || "").slice(0, 10);
}

function when(value) {
  if (!value) {
    return "";
  }

  const at = new Date(value);

  if (Number.isNaN(at.getTime())) {
    return "";
  }

  return at.toLocaleString();
}

function isSelected(page, version) {
  const against = page.comparedTo;

  if (!page.compared || !against) {
    return false;
  }

  if (version.kind === "commit") {
    return Boolean(version.commit) && version.commit === against.commit;
  }

  return Boolean(version.digest) && version.digest === against.digest;
}

function versionRow({ label, detail, selected, onChoose }) {
  const row = el("button", "changes-version");
  row.type = "button";

  if (selected) {
    row.classList.add("selected");
    row.setAttribute("aria-current", "true");
  }

  const text = el("span", "changes-version-text");
  append(text,
    el("span", "changes-version-label", label),
    detail ? el("span", "changes-version-detail", detail) : null);

  row.append(text);

  row.onclick = onChoose;

  return row;
}

// changesSection is the list of what changed, grouped by the heading it
// happened under, for a document that is being compared.
function changesSection(groups, close) {
  const section = el("div", "changes-section");

  const total = groups.reduce((sum, group) => sum + group.lines.length, 0);
  const changes = total === 1 ? "1 change" : total + " changes";
  const where = groups.length === 1 ? "1 section" : groups.length + " sections";

  section.append(el("p", "changes-count", changes + " in " + where));

  for (const group of groups) {
    section.append(renderGroup(group, close));
  }

  return section;
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
