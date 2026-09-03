// Getting to a document by naming it.
//
// A doc browser is not a file manager. Somebody reading documentation knows
// roughly what the file is called and wants to be in it; walking a directory
// tree to get there is the interface of a program that does not know what its
// user came for. So the way through a project is one field: type a few letters
// of the path and choose from what matches.
//
// **The matching is a subsequence rather than a substring**, which is the
// difference between a picker and a search box. "dops" finds docs/ops.md
// because the letters appear in that order; a substring match finds nothing,
// and somebody who has to type the path exactly has gained nothing over reading
// the directory. The score prefers matches that start a path segment and runs
// that stay together, so the file whose name you were thinking of comes first.
//
// The list is asked for once, when the picker opens, because filtering happens
// here and a filter cannot narrow what it was never given.
//
// Everything is built with textContent. A path is the publishing machine's own
// string (§6).

import { el, append } from "./dom.js";

// maxShown bounds what is drawn, not what is matched. Every file is scored;
// this is how many of the best are put on screen, because a list longer than a
// screen is one nobody reads to the end of.
const maxShown = 40;

// attachPicker builds the field and the list for one project.
//
// current is the file being read, which the field shows when it is closed;
// source is asked once for the project's files; onPick is called with a path.
export function attachPicker(current, source, onPick) {
  const root = el("div", "picker");

  const chip = el("button", "picker-chip");
  chip.type = "button";

  append(chip,
    el("span", "picker-chip-label",
      current || "Find a document"),
    el("span", "picker-chip-hint", current ? "change" : ""));

  const panel = el("div", "picker-panel");

  const field = el("input", "picker-field");
  field.type = "search";
  field.placeholder = "Type part of a path";
  field.setAttribute("aria-label", "Find a document");
  field.autocomplete = "off";
  field.spellcheck = false;

  const results = el("div", "picker-results");
  const note = el("p", "picker-note");

  append(panel, field, note, results);
  append(root, chip, panel);

  let open = false;
  let files = null;
  let active = -1;

  function setOpen(next) {
    open = next;
    panel.classList.toggle("open", open);
    chip.setAttribute("aria-expanded", open ? "true" : "false");

    if (!open) {
      return;
    }

    field.value = "";
    field.focus();

    load();
  }

  async function load() {
    if (files) {
      draw();

      return;
    }

    note.textContent = "Reading the project…";
    results.replaceChildren();

    try {
      files = await source();
    } catch (error) {
      note.textContent = "Could not read the project: " + error.message;

      return;
    }

    draw();
  }

  function draw() {
    const matches = rank(files || [], field.value);

    note.textContent = summary(files || [], matches, field.value);

    results.replaceChildren();

    active = matches.length ? 0 : -1;

    matches.slice(0, maxShown).forEach((match, index) => {
      results.append(row(match, index === active, () => {
        setOpen(false);
        onPick(match.path);
      }));
    });
  }

  function move(by) {
    const rows = Array.from(results.children);

    if (!rows.length) {
      return;
    }

    active = (((active + by) % rows.length) + rows.length) % rows.length;

    rows.forEach((node, index) => {
      node.classList.toggle("active", index === active);
    });

    rows[active].scrollIntoView({ block: "nearest" });
  }

  chip.onclick = () => setOpen(!open);

  field.oninput = () => draw();

  field.onkeydown = (event) => {
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        move(1);

        break;
      case "ArrowUp":
        event.preventDefault();
        move(-1);

        break;
      case "Enter": {
        const rows = Array.from(results.children);

        if (active >= 0 && rows[active]) {
          event.preventDefault();
          rows[active].click();
        }

        break;
      }
      case "Escape":
        event.preventDefault();
        setOpen(false);

        break;
      default:
        break;
    }
  };

  setOpen(false);

  return root;
}

function summary(files, matches, query) {
  if (!files.length) {
    return "This project has no documents this machine will serve.";
  }

  if (!query) {
    return files.length === 1 ? "1 document" : files.length + " documents";
  }

  if (!matches.length) {
    return "Nothing matches.";
  }

  const shown = Math.min(matches.length, maxShown);

  if (shown < matches.length) {
    return "Showing " + shown + " of " + matches.length + " matches";
  }

  return matches.length === 1 ? "1 match" : matches.length + " matches";
}

// row draws one match, with the letters that matched marked so that somebody
// can see why it is in the list.
function row(match, isActive, onChoose) {
  const node = el("button", "picker-row");
  node.type = "button";

  if (isActive) {
    node.classList.add("active");
  }

  const path = el("span", "picker-row-path");

  let at = 0;

  for (const index of match.hits) {
    if (index > at) {
      path.append(el("span", null, match.path.slice(at, index)));
    }

    path.append(el("span", "picker-hit", match.path[index]));
    at = index + 1;
  }

  if (at < match.path.length) {
    path.append(el("span", null, match.path.slice(at)));
  }

  node.append(path);
  node.onclick = onChoose;

  return node;
}

// rank scores every file against the query and returns the matches, best first.
//
// An empty query is every file in the order the publisher gave them, which is
// the walk's own order: a picker opened with nothing typed should show the
// project rather than an empty box.
export function rank(files, query) {
  const wanted = (query || "").trim().toLowerCase();

  if (!wanted) {
    return files.map((path) => ({ path, hits: [], score: 0 }));
  }

  const out = [];

  for (const path of files) {
    const match = score(path, wanted);

    if (match) {
      out.push(match);
    }
  }

  // Best first, and by path when two score the same, so the order does not
  // wander between keystrokes for reasons nobody can see.
  out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));

  return out;
}

// score matches the query as a subsequence of the path and says how well.
//
// The rules, in the order they matter: a letter that starts a path segment or a
// word is worth much more than one in the middle, because that is how people
// abbreviate a path; a run of adjacent letters is worth more than the same
// letters scattered; and a shorter path wins a tie, because the file you meant
// is usually the one with less around it.
function score(path, wanted) {
  const lower = path.toLowerCase();
  const hits = [];

  let at = 0;
  let total = 0;
  let previous = -2;

  for (const letter of wanted) {
    const found = lower.indexOf(letter, at);

    if (found < 0) {
      return null;
    }

    let points = 1;

    const before = found > 0 ? lower[found - 1] : "/";

    if (before === "/" || before === "-" || before === "_" || before === ".") {
      points += 8;
    }

    if (found === previous + 1) {
      points += 5;
    }

    total += points;
    hits.push(found);

    previous = found;
    at = found + 1;
  }

  // A shorter path with the same letters is the better answer, and the base
  // name matters more than the directories above it.
  total -= path.length / 40;

  if (lower.slice(lower.lastIndexOf("/") + 1).includes(wanted)) {
    total += 10;
  }

  return { path, hits, score: total };
}
