// Choosing which version a document is being read against (decision AP).
//
// It is a clock in the top bar rather than a panel in the corner, and the
// placement is the point. The version list is long — every commit that ever
// touched the file — so keeping it in the corner control meant that reaching
// the changes went past a history, and the navigation that control exists for
// was the part you could not see. These are two questions asked at two
// different moments: which version am I reading against, and where are its
// changes.
//
// The button says what is currently being compared with, so the answer to the
// first question is legible without opening anything.
//
// Everything is built with textContent. A commit subject is the publishing
// machine's own string (§6).

import { el, append } from "./dom.js";
import { icon } from "./ui.js";

// attachVersions builds the top-bar control.
//
// page is what the bridge answered, which says whether this is a comparison and
// against what; source is asked for the version list when the control is
// opened; onCompare is called with a version, or null for the latest alone.
export function attachVersions(page, source, onCompare) {
  const root = el("div", "versions");

  const toggle = el("button", "versions-toggle");
  toggle.type = "button";
  toggle.setAttribute("aria-label", "Compare with an earlier version");

  append(toggle,
    icon("rewind", "versions-icon"),
    el("span", "versions-current", currentLabel(page)));

  if (page.compared) {
    toggle.classList.add("comparing");
  }

  const panel = el("div", "versions-panel");
  const list = el("div", "versions-list");

  append(panel, list);
  append(root, toggle, panel);

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
      fill(list, page, source, onCompare, () => setOpen(false));
    }
  };

  return root;
}

// currentLabel is what the button says without being opened: the version being
// compared against, or that there is none.
function currentLabel(page) {
  if (!page.compared) {
    return "Latest";
  }

  const against = page.comparedTo || {};

  if (against.commit) {
    return against.commit.slice(0, 8);
  }

  return when(against.at) || "an earlier version";
}

// fill draws the list, asking for it the first time the control is opened.
//
// Asking on open rather than on load is what keeps it affordable: a version
// list is a call to the publishing machine, and drawing a document must not
// cost one for a question nobody asked.
async function fill(list, page, source, onCompare, close) {
  list.replaceChildren();

  list.append(versionRow({
    label: "Latest",
    detail: "the document as it is now",
    selected: !page.compared,
    onChoose: () => {
      close();
      onCompare(null);
    },
  }));

  if (page.compareError) {
    list.append(el("p", "versions-note",
      "Could not compare against that version: " + page.compareError));
  }

  const loading = el("p", "versions-note", "Reading the versions…");
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
    list.append(el("p", "versions-note",
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
    list.append(el("p", "versions-note", "Older commits are not listed."));
  }
}

// versionLabel is what a version is called. A commit is its subject; a snapshot
// has none, because nobody writes a message about saving a file, so it is named
// by when it was taken.
function versionLabel(version) {
  if (version.kind === "commit") {
    return version.subject || shortCommit(version.commit);
  }

  return when(version.at) || "A saved version";
}

// versionDetail says which sort it is, because one of them will still be there
// tomorrow and the other will not.
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
  const row = el("button", "versions-row");
  row.type = "button";

  if (selected) {
    row.classList.add("selected");
    row.setAttribute("aria-current", "true");
  }

  const text = el("span", "versions-row-text");

  append(text,
    el("span", "versions-row-label", label),
    detail ? el("span", "versions-row-detail", detail) : null);

  row.append(text);
  row.onclick = onChoose;

  return row;
}

// comparedBanner is the line above the document saying what its marks are
// against, with the way back to the latest version in it.
//
// It is a banner rather than a note because it describes the whole screen: a
// document with strikethrough in it is not the document, and somebody who
// scrolled down and forgot needs the answer where their eye already is. The
// button is in it for the same reason — the way out of a state belongs beside
// the statement of the state, not in a panel two taps away.
export function comparedBanner(page, onReset) {
  if (page.compareError) {
    const banner = el("div", "compare-banner warning-banner");

    append(banner,
      el("span", "compare-banner-text",
        "Showing the latest version: " + page.compareError));

    return banner;
  }

  if (!page.compared) {
    return null;
  }

  const against = page.comparedTo || {};

  const what = against.commit
    ? "the commit " + against.commit.slice(0, 10)
    : "an earlier saved version";

  const banner = el("div", "compare-banner");

  const reset = el("button", "compare-reset", "Read the latest");
  reset.type = "button";
  reset.onclick = () => onReset();

  append(banner,
    el("span", "compare-banner-text", "Marked against " + what),
    reset);

  return banner;
}
