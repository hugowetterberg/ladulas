// Getting around a long document.
//
// A published README is read on a phone as often as on a desktop, and on a
// phone the two things somebody wants — "take me to the deployment section" and
// "where does it mention the socket" — are both a long way from a scrollbar.
// So the reader gets one control in the corner a thumb reaches, and it does
// both: an outline of the headings, and a search over the whole file.
//
// Everything here is built with textContent, like the rest of the bundle. The
// document being navigated was written by the machine we distrust most (§6),
// and that goes for its headings — they are the search results and the outline
// entries, and neither is allowed to be markup.

import { el, append } from "./dom.js";

// maxResults bounds what a search draws. A query of "e" matches every line in
// the file, and a panel that tried to list them would be slower and no more
// useful than one that says how many there were.
const maxResults = 50;

// snippetPadding is how much of the line around a hit to show.
const snippetPadding = 32;

// attachOutline adds the corner control for one rendered document.
export function attachOutline(article) {
  const headings = indexHeadings(article);
  const searchable = indexBlocks(article);

  const panel = el("div", "outline-panel");
  const results = el("div", "outline-list");

  const search = el("input", "outline-search");
  search.type = "search";
  search.placeholder = "Search this document";
  search.setAttribute("aria-label", "Search this document");
  search.autocomplete = "off";
  search.spellcheck = false;

  const count = el("p", "outline-count");

  append(panel, search, count, results);

  const toggle = el("button", "outline-toggle");
  toggle.type = "button";
  toggle.setAttribute("aria-label", "Outline and search");

  // Three bars, as elements rather than as a character: a glyph would depend on
  // a font the platform may not have, and this is the one control on the
  // screen.
  for (let i = 0; i < 3; i++) {
    toggle.append(el("span", "bar"));
  }

  const root = el("div", "outline");
  append(root, panel, toggle);

  let open = false;

  // active is the row the arrow keys are on, as an index into what the panel is
  // currently listing — the results when there is a query, the headings when
  // there is not. The caret stays in the search field the whole time so that
  // narrowing the query and choosing from what is left are the same gesture, and
  // -1 is "nothing chosen yet".
  let active = -1;

  function rows() {
    return Array.from(results.children);
  }

  function clearActive() {
    for (const row of rows()) {
      row.classList.remove("active");
    }

    active = -1;
  }

  // moveActive wraps at both ends, which is also what makes the first Down and
  // the first Up useful: from nothing chosen they land on the first row and the
  // last one.
  function moveActive(by) {
    const list = rows();

    if (!list.length) {
      active = -1;

      return;
    }

    const from = active < 0 ? (by > 0 ? -1 : 0) : active;
    const at = (((from + by) % list.length) + list.length) % list.length;

    for (const row of list) {
      row.classList.remove("active");
    }

    list[at].classList.add("active");
    active = at;

    // Only the list scrolls: the panel is fixed, so the row is already in the
    // window and "nearest" leaves the document where the reader put it.
    list[at].scrollIntoView({ block: "nearest" });
  }

  function setOpen(next) {
    open = next;
    root.classList.toggle("open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");

    if (open) {
      // The field is focused only where focusing it costs nothing. On a phone
      // it summons the keyboard, and the keyboard covers the panel the tap was
      // meant to open — so the outline arrived already hidden behind it, which
      // is the opposite of what the control is for. A device with a pointer
      // fine enough to have a physical keyboard has no such trade.
      if (window.matchMedia("(hover: hover) and (pointer: fine)").matches) {
        search.focus();
      }

      return;
    }

    clearActive();

    // Leaving the panel leaves the highlighting: somebody who searched, jumped
    // and closed the panel is reading the thing they searched for, and taking
    // the marks away at that moment would be taking away the answer.
  }

  toggle.onclick = () => setOpen(!open);

  // Anywhere else closes it. A panel over a document should not need aiming at
  // to dismiss, and there is nothing in it worth protecting from a stray tap.
  document.addEventListener("pointerdown", (event) => {
    if (open && !root.contains(event.target)) {
      setOpen(false);
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && open) {
      setOpen(false);
    }
  });

  // Up, Down and Enter from the search field, which is where the caret is on a
  // desktop and where somebody who has just typed a query expects to steer from.
  //
  // Only from the field: the rows are still buttons in the tab order, and a row
  // that has the focus already answers Enter and Space by itself. Handling those
  // keys here as well would mean two rows arguing over one keypress.
  search.addEventListener("keydown", (event) => {
    switch (event.key) {
    case "ArrowDown":
      event.preventDefault();
      moveActive(1);

      break;
    case "ArrowUp":
      event.preventDefault();
      moveActive(-1);

      break;
    case "Enter": {
      // Enter with nothing chosen takes the first row, because a query typed and
      // confirmed is a person asking for the best match rather than for a list.
      const row = rows()[active < 0 ? 0 : active];

      if (row) {
        event.preventDefault();
        row.click();
      }

      break;
    }
    }
  });

  function show(query) {
    results.replaceChildren();
    active = -1;

    const trimmed = query.trim();

    if (!trimmed) {
      clearMarks(article);
      drawOutline(results, headings, () => setOpen(false));
      count.textContent = headings.length
        ? ""
        : "This document has no headings.";

      return;
    }

    const hits = search_(searchable, trimmed);
    const marked = markMatches(article, trimmed);

    count.textContent = describe(hits.length, marked);

    for (const hit of hits.slice(0, maxResults)) {
      results.append(resultRow(hit, trimmed, () => setOpen(false)));
    }
  }

  search.oninput = () => show(search.value);

  show("");

  return root;
}

function describe(blocks, occurrences) {
  if (!occurrences) {
    return "Nothing in this document matches.";
  }

  const where = blocks === 1 ? "1 place" : blocks + " places";

  return occurrences === 1
    ? "1 match, in " + where
    : occurrences + " matches, in " + where;
}

// drawOutline lists the headings, indented by level.
function drawOutline(into, headings, done) {
  if (!headings.length) {
    return;
  }

  for (const heading of headings) {
    const row = el("button", "outline-row level-" + heading.level, heading.text);
    row.type = "button";
    row.onclick = () => {
      done();
      jumpTo(heading.node);
    };

    into.append(row);
  }
}

function resultRow(hit, query, done) {
  const row = el("button", "outline-row result");
  row.type = "button";

  const where = el("span", "where", hit.heading || "");
  const text = el("span", "snippet");

  // The matched run is a child element rather than styled text, so the snippet
  // is still assembled out of textContent.
  for (const part of splitAround(hit.text, query)) {
    text.append(part.match ? el("mark", null, part.text) : document.createTextNode(part.text));
  }

  append(row, hit.heading ? where : null, text);

  row.onclick = () => {
    done();
    jumpTo(hit.node);
  };

  return row;
}

// jumpTo is exported because arriving at a heading is not only the outline's
// business any more: a fragment link inside a document lands the same way, and
// two ways of arriving that looked different would read as two features.
export function jumpTo(node) {
  node.scrollIntoView({ behavior: "smooth", block: "start" });

  // A moment of emphasis on arrival, because a smooth scroll that lands on a
  // paragraph in the middle of a page leaves nothing saying which one was
  // asked for.
  node.classList.add("outline-landed");

  setTimeout(() => node.classList.remove("outline-landed"), 1400);
}

// indexHeadings gives every heading an identifier and remembers where it is.
function indexHeadings(article) {
  const out = [];

  const found = article.querySelectorAll("h1, h2, h3, h4, h5, h6");

  found.forEach((node, index) => {
    const text = node.textContent.trim();

    if (!text) {
      return;
    }

    // A heading Go gave an anchor to keeps it: that identifier is what a
    // fragment link lands on, and renumbering it here would break the links in
    // the document this outline is of.
    if (!node.id) {
      node.id = "h" + index;
    }

    out.push({ node, text, level: Number(node.tagName.slice(1)) });
  });

  return out;
}

// indexBlocks is what a search looks through: the leaves that hold text, each
// remembering the heading it sits under so a result can say where it is.
function indexBlocks(article) {
  const out = [];

  let heading = "";

  // A cell is a leaf that holds text like any other, and a table is where a
  // document keeps the things somebody searches for by name — a flag, a port, a
  // metric. Leaving cells out made "where does it mention the socket" answer
  // "nowhere" for the paragraph that says it in a column.
  for (const node of article.querySelectorAll(
    "h1, h2, h3, h4, h5, h6, p, li, pre, blockquote, td")) {
    const text = node.textContent.trim();

    if (/^H[1-6]$/.test(node.tagName)) {
      heading = text;
    }

    if (!text) {
      continue;
    }

    // A blockquote's paragraphs are indexed on their own account; taking the
    // quote as well would list the same words twice.
    if (node.tagName === "BLOCKQUOTE" && node.querySelector("p")) {
      continue;
    }

    out.push({ node, text, heading });
  }

  return out;
}

function search_(blocks, query) {
  const needle = query.toLowerCase();

  return blocks.filter((block) => block.text.toLowerCase().includes(needle));
}

// splitAround cuts a line into matched and unmatched runs, and trims it to a
// window around the first hit so a result is one line rather than a paragraph.
function splitAround(text, query) {
  const needle = query.toLowerCase();
  const haystack = text.toLowerCase();

  let from = haystack.indexOf(needle);

  if (from < 0) {
    return [{ text: text.slice(0, snippetPadding * 2), match: false }];
  }

  const start = Math.max(0, from - snippetPadding);
  const end = Math.min(text.length, from + needle.length + snippetPadding * 2);

  const window = text.slice(start, end);
  const parts = [];

  if (start > 0) {
    parts.push({ text: "…", match: false });
  }

  let cursor = 0;
  const lower = window.toLowerCase();

  for (;;) {
    const at = lower.indexOf(needle, cursor);

    if (at < 0) {
      break;
    }

    if (at > cursor) {
      parts.push({ text: window.slice(cursor, at), match: false });
    }

    parts.push({ text: window.slice(at, at + needle.length), match: true });
    cursor = at + needle.length;
  }

  if (cursor < window.length) {
    parts.push({ text: window.slice(cursor), match: false });
  }

  if (end < text.length) {
    parts.push({ text: "…", match: false });
  }

  return parts;
}

// markMatches wraps every occurrence in the document, and returns how many
// there were.
//
// It walks text nodes and splits them rather than touching markup, because
// there is no markup to touch: assigning any in this bundle would be a way to
// run what a published document contains.
function markMatches(article, query) {
  clearMarks(article);

  const needle = query.toLowerCase();

  if (!needle) {
    return 0;
  }

  const walker = document.createTreeWalker(article, NodeFilter.SHOW_TEXT);
  const targets = [];

  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    if (node.textContent.toLowerCase().includes(needle)) {
      targets.push(node);
    }
  }

  let total = 0;

  for (const node of targets) {
    const text = node.textContent;
    const lower = text.toLowerCase();
    const pieces = document.createDocumentFragment();

    let cursor = 0;

    for (;;) {
      const at = lower.indexOf(needle, cursor);

      if (at < 0) {
        break;
      }

      if (at > cursor) {
        pieces.append(document.createTextNode(text.slice(cursor, at)));
      }

      pieces.append(el("mark", "hit", text.slice(at, at + needle.length)));
      cursor = at + needle.length;
      total++;
    }

    if (!total) {
      continue;
    }

    if (cursor < text.length) {
      pieces.append(document.createTextNode(text.slice(cursor)));
    }

    node.replaceWith(pieces);
  }

  return total;
}

function clearMarks(article) {
  for (const mark of article.querySelectorAll("mark.hit")) {
    mark.replaceWith(document.createTextNode(mark.textContent));
  }

  article.normalize();
}
