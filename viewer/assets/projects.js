// The project doc browser (§6, decision Q): what the instances that ask this
// one for approvals publish, read from those machines a directory and a page at
// a time, and kept once read.
//
// Everything on this screen is the publishing machine's account of itself and
// is labelled so. The point of it is not that it is trustworthy — it is not —
// but that "approve this commit on the build box" is a question nobody can
// answer without knowing what the build box is for.
//
// Two states run through every surface here: read from the machine just now, or
// read from it once and kept. The second is not a failure. A phone is offline
// by construction, and a browser that answered "could not connect" would be
// useless exactly when it is wanted — so what it shows instead is the pages
// that have a reader, and says that is what they are.

import { el, append, facts } from "./dom.js";
import * as ui from "./ui.js";
import { bridge } from "./bridge.js";
import { renderDocument } from "./markdown.js";
import { attachOutline } from "./outline.js";
import { attachChanges } from "./changes.js";
import { attachVersions, comparedBanner } from "./versions.js";
import { attachPicker } from "./picker.js";

// withChanges puts the change navigator above the outline's control in the
// same corner stack, when the document has changes to navigate.
//
// Prepended rather than appended because the stack runs down the screen: the
// outline's button stays where a thumb has learned to find it, and the new one
// sits above it. It returns the dock either way, so a document nobody has
// refreshed is exactly what it was.
function withChanges(dock, article) {
  const changes = attachChanges(article);

  if (changes) {
    dock.prepend(changes.panel, changes.toggle);
  }

  return dock;
}

// documentsRoute is the fragment for a place in the doc browser.
//
// The fields are the same ones projectURL puts in a query string — that is the
// host's contract and is not changed — encoded into the one segment parseRoute
// hands back, because a fingerprint is base64 and carries slashes.
export function documentsRoute(fingerprint, projectID, params) {
  const query = new URLSearchParams();

  if (fingerprint) {
    query.set("peer", fingerprint);
  }

  if (projectID) {
    query.set("project", projectID);
  }

  for (const [name, value] of Object.entries(params || {})) {
    if (value) {
      query.set(name, value);
    }
  }

  return "#/documents/" + encodeURIComponent(query.toString());
}

// projectURL is how every way in names a project: the peer that publishes it
// and the identifier both ends derive (§6). Nothing here invents a handle, so a
// card can link to a project nothing has been read of.
export function projectURL(fingerprint, projectID, params) {
  const query = new URLSearchParams({ peer: fingerprint });

  if (projectID) {
    query.set("project", projectID);
  }

  for (const [name, value] of Object.entries(params || {})) {
    if (value) {
      query.set(name, value);
    }
  }

  return "/?" + query.toString();
}

// renderProjectList is the browser's front page, and the peer's own page: the
// same list, narrowed to one machine when somebody arrived from it.
export function renderProjectList(projects, peer) {
  const root = el("div", "project-listing");

  root.append(
    el(
      "p",
      "provenance",
      "Each of these is read from the machine that publishes it, while that " +
        "machine is reachable. Nothing is checked against anything, and none " +
        "of it says anything about any signature.",
    ),
  );

  if (!(projects || []).length) {
    root.append(
      el(
        "p",
        "empty",
        "No paired instance publishes anything readable from here. On a " +
          "machine that asks this one for approvals, run `ladulas projects " +
          "publish` in a project directory — or let it publish the projects " +
          "it asks for signatures in, which it does by default.",
      ),
    );

    return root;
  }

  const list = el("div", "project-list");

  for (const project of projects) {
    list.append(projectCard(project));
  }

  root.append(list);

  return root;
}

function projectCard(project) {
  const card = el("div", "project-card");

  const open = el("button", "project-open", project.name || project.peer);
  open.disabled = !project.projectId;
  open.onclick = () => {
    location.hash = documentsRoute(project.fingerprint, project.projectId);
  };

  append(
    card,
    open,
    el("p", project.live ? "note-line" : "note-line kept", project.state),
    facts([
      { label: "Published by", value: project.peer },
      { label: "Repository", value: project.path, asserted: true, mono: true },
      { label: "Remote", value: project.originUrl, asserted: true, mono: true },
      { label: "Branch", value: project.branch, asserted: true },
      { label: "Commit", value: project.commit, asserted: true, mono: true },
    ]),
  );

  if (project.error) {
    card.append(el("p", "note-line", project.error));
  }

  return card;
}

// renderProject is one project: where you are in it, what is there, and the
// page being read.
export async function renderProject(
  fingerprint, projectID, file, fragment, from) {
  const root = el("div", "project");

  // What the (i) is looking at when somebody opens it. It is a box rather
  // than an argument because the button is built once and the page under it
  // changes every time the reader picks another file or another version —
  // and the details have to be the ones on screen, not the ones that were
  // there when the screen was drawn.
  const showing = { facts: null, file: file, page: null };

  // The list of documents, which is both what the picker filters and how the
  // default one is chosen.
  //
  // It comes from what is held here (decision AP). Asking the publisher meant
  // walking its whole project over the network before anything could be drawn,
  // which was slower than the one directory page this screen used to fetch —
  // the list is already on this machine, because the sync put it there.
  let answer;

  try {
    answer = await bridge.projectDocuments(fingerprint, projectID);
  } catch (error) {
    append(root,
      el("p", "warning", "Could not read the project: " + error.message));

    return { node: root, actions: [] };
  }

  const files = answer.documents || [];

  showing.facts = answer;

  const chosen = file || defaultDocument(files);

  const bar = el("div", "project-bar");
  const reader = el("div", "project-reader");

  append(root, bar, reader);

  if (!chosen) {
    reader.append(el("p", "empty",
      "This project has no documents this machine will serve."));

    return { node: root, actions: [detailsButton(showing, fingerprint)] };
  }

  showing.file = chosen;

  await showDocument(
    reader, bar, files, fingerprint, projectID, chosen, fragment, from, showing);

  return { node: root, actions: [detailsButton(showing, fingerprint)] };
}

// detailsButton is the (i) in the title bar, and what it opens.
//
// The provenance line used to sit above the document — "Kept here, last updated
// 3 Sep 18:22, at efbc9222c2" — where it was the first thing a reader met and
// the least interesting thing on the screen. It is not a warning and it is not
// news; it is the answer to a question somebody asks occasionally and has to be
// able to ask, which core §6 requires. So it moves to where the phone already
// puts it, beside the rest of the machine's account of itself.
//
// Two things stay out in the open, because they change what the words in front
// of the reader mean rather than describing where they came from: that the
// document was cut short, and that it is marked against another version.
function detailsButton(showing, fingerprint) {
  return ui.action("info", "Technical details",
    () => detailsSheet(showing, fingerprint));
}

function detailsSheet(showing, fingerprint) {
  const about = showing.facts || {};
  const page = showing.page || {};

  const sheet = ui.sheet("Details",
    facts([
      { label: "File", value: showing.file, mono: true },
      { label: "Project", value: about.name },
      { label: "Published by", value: about.peer },
      { label: "Repository", value: about.path, mono: true },
      { label: "Remote", value: about.originUrl, mono: true },
      { label: "Branch", value: about.branch },
      { label: "Commit", value: about.commit, mono: true },
    ]),
    ui.note("Everything here is the publishing machine's own account of "
      + "itself. Nothing is checked against anything, and none of it says "
      + "anything about any signature."));

  const body = sheet.querySelector(".sheet-body");

  body.append(ui.heading("Where this came from"));

  append(body,
    about.state ? el("p", "note-line", about.state) : null,
    page.note ? el("p", "note-line kept", page.note) : null,
    page.error ? el("p", "note-line warning", page.error) : null,
    facts([{ label: "Machine", value: fingerprint, mono: true }]));
}

// defaultDocument is what opening a project shows before anybody has chosen.
//
// README.md in the root first, because that is the document a project is
// introduced by and the one somebody who clicked the project's name meant. Then
// the first markdown file in the root, and only then further in — breadth
// first, so a README one level down beats a stray note four levels down. A
// project whose documentation is in docs/ is found on the second pass rather
// than by guessing at directory names.
export function defaultDocument(files) {
  const documents = files.filter((path) => /\.(md|markdown)$/i.test(path));

  if (!documents.length) {
    return files[0] || "";
  }

  const readme = documents.find(
    (path) => path.toLowerCase() === "readme.md");

  if (readme) {
    return readme;
  }

  // Shallowest first, then lexically, which is breadth first over a list of
  // paths without having to build the tree it came from.
  const sorted = documents.slice().sort((a, b) => {
    const depth = segments(a) - segments(b);

    return depth || a.localeCompare(b);
  });

  // A README anywhere beats a neighbour that merely sorts earlier, at the same
  // depth: it is the document its directory is introduced by.
  const shallowest = segments(sorted[0]);

  const named = sorted.find(
    (path) => segments(path) === shallowest &&
      /(^|\/)readme\.(md|markdown)$/i.test(path));

  return named || sorted[0];
}

function segments(path) {
  return path.split("/").length;
}

async function showDocument(
  reader, bar, files, fingerprint, projectID, file, fragment, from, showing) {
  // The document is redrawn in place when the reader picks a version to compare
  // against, so what changes lives in its own container — and the corner dock
  // goes inside it, which is what keeps it from outliving the screen.
  //
  // It used to be appended to document.body and taken down by hand — and that
  // worked only because leaving a document was a page load, which took the
  // whole window with it. Once leaving became a change of fragment the buttons
  // stayed behind, floating over the next screen. Nothing here removes it now:
  // it is a child of what gets replaced, so replacing that is the removal.
  //
  // It is position: fixed, and .pane sets no transform, filter, perspective or
  // contain — none of which it may grow without moving the dock into the pane's
  // corner instead of the window's.
  const body = el("div", "reader-body");
  reader.append(body);

  async function draw(compare) {
    let page;

    try {
      page = await bridge.projectFile(fingerprint, projectID, file, compare);
    } catch (error) {
      body.replaceChildren(
        el("p", "warning", "Could not read " + file + ": " + error.message));

      return;
    }

    // What the (i) reports, kept current: the reader may have switched file or
    // picked a version to compare against since the button was made.
    showing.page = page;

    // A link inside a document keeps the reader in the project, because
    // following one is reading on rather than starting again.
    const article = renderDocument(page, (target, anchor) => {
      location.hash = documentsRoute(fingerprint, projectID, {
        file: target,
        frag: anchor,
        from,
      });
    });

    // The top bar: what is being read, and what it is being read against.
    bar.replaceChildren();

    append(bar,
      attachPicker(file, async () => files, (picked) => {
        location.hash = documentsRoute(
          fingerprint, projectID, { file: picked, from });
      }),
      attachVersions(page,
        () => bridge.projectVersions(fingerprint, projectID, file),
        (version) => draw(compareOf(version))));

    body.replaceChildren();

    append(body,
      comparedBanner(page, () => draw(null)),
      truncatedBanner(page),
      article);

    body.append(withChanges(attachOutline(article), article));

    land(article, fragment);
  }

  await draw(null);
}

// truncatedBanner says the document stops before the document does.
//
// It goes above the text rather than at the end of it, where the reader is
// already lost: a document that simply runs out two thirds of the way through
// reads as one somebody never finished writing, and the whole point is to say
// that the rest exists and is on another machine.
//
// The sentence is composed in Go, like every other line of prose the reader is
// shown (pkg/bridge/projects.go).
function truncatedBanner(page) {
  if (!page.truncated || !page.truncatedNote) {
    return null;
  }

  const banner = el("div", "compare-banner truncated-banner");

  banner.append(el("span", "compare-banner-text", page.truncatedNote));

  return banner;
}

// compareOf turns a chosen version into what the file call takes, and null into
// null — which is the reader asking for the latest on its own.
function compareOf(version) {
  if (!version) {
    return null;
  }

  if (version.kind === "commit") {
    return { commit: version.commit };
  }

  return { digest: version.digest };
}

function land(article, fragment) {
  if (!fragment || !article.jumpToAnchor) {
    return;
  }

  requestAnimationFrame(() => article.jumpToAnchor(fragment));
}

// renderReader is one document and nothing else, for a host that browses the
// project itself (decision R).
//
// It is the doc-browser twin of the diff-only pane: iOS draws the directory, the
// search and the provenance natively and pushes this for the page, because a
// markdown document is the one thing here that is genuinely a document. What
// stays inside it is what belongs to the text — the note saying which reading of
// the project this is, the headings, and the search over the file — and what
// leaves is the chrome around it.
export async function renderReader(fingerprint, projectID, file, fragment) {
  const root = el("div", "reader");
  const body = el("div", "reader-body");
  root.append(body);

  async function draw(compare) {
    const page = await bridge.projectFile(
      fingerprint, projectID, file, compare);

    // A link inside the document is a file of the same project, so it opens the
    // same way this page did. The host may take it over — iOS cancels the
    // navigation and pushes a screen of its own — and where it does not, the
    // webview follows it and its back gesture is the way out.
    const article = renderDocument(page, (target, anchor) => {
      location.href = projectURL(fingerprint, projectID, {
        file: target,
        read: "1",
        frag: anchor,
      });
    });

    // The version control rides above the document here rather than in a bar of
    // its own: this mode is one document and nothing else (decision R), so
    // there is no bar, and the host draws the file browsing natively.
    const bar = el("div", "reader-bar");

    bar.append(attachVersions(page,
      () => bridge.projectVersions(fingerprint, projectID, file),
      (version) => draw(compareOf(version))));

    body.replaceChildren();

    append(body,
      bar,
      comparedBanner(page, () => draw(null)),
      truncatedBanner(page),
      page.note ? el("p", "note-line kept", page.note) : null,
      article);

    body.append(withChanges(attachOutline(article), article));

    land(article, fragment);
  }

  await draw(null);

  return root;
}
