// Diff rendering. The parsing happened in Go, so what arrives here is already
// files, hunks and typed lines — this only decides what they look like. That is
// deliberate: the diff is the most attacker-influenced thing in the whole
// prompt, and a renderer with no parser in it has very little to get wrong.

import { el, append } from "./dom.js";
import { bridge } from "./bridge.js";

const GUTTER = {
  added: "+",
  removed: "−",
  context: " ",
  note: "\\",
};

export function renderDiff(diff) {
  if (!diff) {
    return null;
  }

  const root = el("div", "diff");

  if (diff.error) {
    root.append(el("p", "note-line", "The diff was not available: " + diff.error));

    return root;
  }

  root.append(summary(diff));

  if (diff.truncationNote) {
    root.append(el("p", "note-line", diff.truncationNote));
  }

  const files = el("div", "diff-files");

  for (const file of diff.files || []) {
    files.append(renderFile(file));
  }

  if (!(diff.files || []).length) {
    files.append(el("p", "empty", "No files changed."));
  }

  root.append(files);

  return root;
}

function summary(diff) {
  const row = el("div", "diff-summary");

  row.append(el("span", "counts", filesChanged(diff)));
  row.append(el("span", "plus mono", "+" + (diff.insertions || 0)));
  row.append(el("span", "minus mono", "−" + (diff.deletions || 0)));

  if (diff.range) {
    row.append(el("span", "asserted mono", diff.range));
  }

  return row;
}

function filesChanged(diff) {
  const count = diff.filesChanged || 0;

  return count === 1 ? "1 file changed" : count + " files changed";
}

// renderFile is a collapsed file by default: the diffstat is what an approver
// reads first, and the hunks are the drill-down §5 asks for. A small change
// opens itself, because collapsing a three-line commit helps nobody.
function renderFile(file) {
  const node = el("details", "file");
  const lines = countLines(file);

  if (lines > 0 && lines <= 40) {
    node.open = true;
  }

  const head = el("summary");

  append(head,
    el("span", "path", pathOf(file)),
    el("span", "status", file.status || ""),
    stat(file));

  node.append(head);

  const hunks = el("div", "hunks");

  if (file.binary) {
    hunks.append(el("p", "note-line", "Binary file; no diff to show."));
  }

  for (const hunk of file.hunks || []) {
    hunks.append(el("div", "hunk-header", hunk.header));

    for (const line of hunk.lines || []) {
      hunks.append(renderLine(line));
    }
  }

  if (file.truncated) {
    hunks.append(el("p", "note-line",
      "This file's diff was cut short to keep the request a readable size."));
  }

  if (!file.binary && !(file.hunks || []).length && !file.truncated) {
    hunks.append(el("p", "note-line", "No textual change."));
  }

  node.append(hunks);

  return node;
}

function pathOf(file) {
  if (file.oldPath && file.newPath && file.oldPath !== file.newPath) {
    return file.oldPath + " → " + file.newPath;
  }

  return file.newPath || file.oldPath || "(unnamed)";
}

function stat(file) {
  const node = el("span", "stat");

  node.append(el("span", "plus", "+" + (file.insertions || 0)));
  node.append(document.createTextNode(" "));
  node.append(el("span", "minus", "−" + (file.deletions || 0)));

  if (file.modeChange) {
    node.append(document.createTextNode(" "));
    node.append(el("span", "asserted", file.modeChange));
  }

  return node;
}

function renderLine(line) {
  const kind = line.kind || "context";
  const node = el("div", "line " + kind);

  node.append(el("span", "gutter", GUTTER[kind] || " "));
  node.append(el("span", "text", line.text));

  return node;
}

// attachDiffFetch offers to go and get what the caps cut short (§5).
//
// The diff a request carries is capped because it travels with something
// somebody is waiting on, and to a phone as often as to a desktop. That was
// never a statement about what an approver may see, so when it was cut short
// there is a button, and pressing it asks the machine with the repository for
// the rest.
export function attachDiffFetch(node, request, diff) {
  if (!node || !diff || !diff.truncated) {
    return node;
  }

  const button = el("button", "fetch-diff", "Load the whole diff");

  button.onclick = async () => {
    button.disabled = true;
    button.textContent = "Fetching…";

    try {
      const full = await bridge.diff(request.id, "");
      const replacement = renderDiff(full);

      node.replaceWith(replacement);

      if (full.truncated) {
        replacement.append(
          el("p", "note-line", "Even the full diff was too large to send whole."),
        );
      }
    } catch (error) {
      button.disabled = false;
      button.textContent = "The rest of the diff could not be fetched: " + error.message;
    }
  };

  node.append(button);

  return node;
}

function countLines(file) {
  let total = 0;

  for (const hunk of file.hunks || []) {
    total += (hunk.lines || []).length;
  }

  return total;
}
