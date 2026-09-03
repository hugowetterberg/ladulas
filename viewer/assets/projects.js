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

import { el, append, facts, section } from "./dom.js";
import { bridge } from "./bridge.js";
import { renderDocument } from "./markdown.js";
import { attachOutline } from "./outline.js";
import { attachChanges } from "./changes.js";

// withChanges puts the change navigator above the outline's control in the
// same corner stack, when the document has changes to navigate.
//
// Prepended rather than appended because the stack runs down the screen: the
// outline's button stays where a thumb has learned to find it, and the new one
// sits above it. It returns the dock either way, so a document nobody has
// refreshed is exactly what it was.
function withChanges(dock, article, page, source, onCompare) {
  const changes = attachChanges(article, page, source, onCompare);

  dock.prepend(changes.panel, changes.toggle);

  return dock;
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
    location.href = projectURL(project.fingerprint, project.projectId);
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
  fingerprint, projectID, path, file, query, fragment) {
  const listing = query
    ? await bridge.projectSearch(fingerprint, projectID, query)
    : await bridge.projectDirectory(fingerprint, projectID, path);

  const root = el("div", "project");

  root.append(header(listing, fingerprint, projectID, path, file, query));

  const body = el("div", "project-body");

  body.append(entries(listing, fingerprint, projectID, file, query));

  const reader = el("div", "project-reader");

  body.append(reader);
  root.append(body);

  if (file) {
    await showDocument(
      reader, fingerprint, projectID, file, listing.dir, query, fragment);
  } else {
    reader.append(el("p", "empty", "Choose a file to read it."));
  }

  return root;
}

function header(listing, fingerprint, projectID, path, file, query) {
  const root = el("div", "project-header");

  const back = el("button", "back", "← All documentation");
  back.onclick = () => {
    location.href = "/?projects=1";
  };

  append(
    root,
    back,
    el("h1", null, listing.name || "Documentation"),
    el(
      "p",
      listing.live ? "provenance" : "provenance kept",
      listing.state ||
        "This is the publishing machine's account of itself. Nothing here is " +
          "checked against anything.",
    ),
    facts([
      { label: "Published by", value: listing.peer },
      { label: "Repository", value: listing.path, asserted: true, mono: true },
      { label: "Branch", value: listing.branch, asserted: true },
      { label: "Commit", value: listing.commit, asserted: true, mono: true },
    ]),
    crumbs(fingerprint, projectID, path, file, query),
    search(fingerprint, projectID, query),
  );

  if (listing.note) {
    root.append(el("p", "note-line kept", listing.note));
  }

  if (listing.error) {
    root.append(el("p", "warning", listing.error));
  }

  return root;
}

// crumbs is the way back up. A directory listing without one is a browser you
// can only go deeper into.
function crumbs(fingerprint, projectID, path, file, query) {
  if (query) {
    const back = el("nav", "crumbs");
    const all = el("button", "crumb", "← Back to the files");

    all.onclick = () => {
      location.href = projectURL(fingerprint, projectID, { file });
    };

    back.append(all);

    return back;
  }

  const nav = el("nav", "crumbs");
  const parts = (path || "").split("/").filter(Boolean);

  const root = el("button", "crumb", "/");
  root.onclick = () => {
    location.href = projectURL(fingerprint, projectID, { file });
  };

  nav.append(root);

  let walked = "";

  for (const part of parts) {
    walked = walked ? walked + "/" + part : part;

    const here = walked;
    const crumb = el("button", "crumb", part);

    crumb.onclick = () => {
      location.href = projectURL(fingerprint, projectID, { path: here, file });
    };

    nav.append(el("span", "crumb-sep", "/"), crumb);
  }

  return nav;
}

// search is the question people actually have — where is the deployment runbook
// — asked of the publisher rather than of a tree walked by hand (decision Q).
function search(fingerprint, projectID, query) {
  const form = el("form", "project-search");

  const field = el("input", "search-field");
  field.type = "search";
  field.placeholder = "Find a file by name";
  field.value = query || "";

  const go = el("button", "search-go", "Search");
  go.type = "submit";

  form.onsubmit = (event) => {
    event.preventDefault();

    const wanted = field.value.trim();

    location.href = wanted
      ? projectURL(fingerprint, projectID, { q: wanted })
      : projectURL(fingerprint, projectID);
  };

  append(form, field, go);

  return form;
}

// entries is one page of a directory, or of a search.
function entries(listing, fingerprint, projectID, current, query) {
  const root = el("nav", "project-tree");

  if (!(listing.entries || []).length) {
    root.append(
      el("p", "empty", query ? "Nothing matched." : "Nothing here."),
    );

    return root;
  }

  for (const entry of listing.entries) {
    root.append(entryItem(entry, listing, fingerprint, projectID, current, query));
  }

  if (listing.total > listing.entries.length || listing.next) {
    root.append(
      el(
        "p",
        "tree-count",
        "Showing " + listing.entries.length + " of " + listing.total + ".",
      ),
    );
  }

  if (listing.next) {
    const more = el("button", "tree-more", "Show more");

    more.onclick = async () => {
      more.disabled = true;
      more.textContent = "Loading…";

      const next = query
        ? await bridge.projectSearch(fingerprint, projectID, query, listing.next)
        : await bridge.projectDirectory(
            fingerprint,
            projectID,
            listing.dir,
            listing.next,
          );

      more.remove();

      for (const entry of next.entries || []) {
        root.append(
          entryItem(entry, next, fingerprint, projectID, current, query),
        );
      }

      if (next.next) {
        root.append(more);
        more.disabled = false;
        more.textContent = "Show more";
      }
    };

    root.append(more);
  }

  if (listing.truncated) {
    root.append(
      el(
        "p",
        "tree-count",
        "The project was too large to search all of it.",
      ),
    );
  }

  return root;
}

function entryItem(entry, listing, fingerprint, projectID, current, query) {
  const label = entry.directory ? entry.name + "/" : entry.name;
  const item = el("button", "tree-item", label);

  if (entry.path === current) {
    item.className = "tree-item current";
  }

  if (entry.directory) {
    item.onclick = () => {
      location.href = projectURL(fingerprint, projectID, { path: entry.path });
    };

    return item;
  }

  // A file the publisher will not hand over is still listed — hiding it would
  // be lying about what the project contains — and says why it is not offered.
  if (!entry.readable) {
    item.className = "tree-item unreadable";
    item.disabled = true;
    item.title = entry.reason || "not offered by the publisher";

    return item;
  }

  item.onclick = () => {
    location.href = projectURL(fingerprint, projectID, {
      path: listing.dir,
      file: entry.path,
      q: query,
    });
  };

  return item;
}

async function showDocument(
  reader, fingerprint, projectID, file, path, query, fragment) {
  // The document is redrawn in place when the reader picks a version to compare
  // against, so the parts that change live in their own container and the dock
  // is tracked well enough to be replaced (decision AP).
  const body = el("div", "reader-body");
  reader.append(body);

  let dock = null;

  async function draw(compare) {
    let page;

    try {
      page = await bridge.projectFile(fingerprint, projectID, file, compare);
    } catch (error) {
      body.replaceChildren(
        el("p", "warning", "Could not read " + file + ": " + error.message));

      return;
    }

    // A link inside a document keeps the reader where they were in the project,
    // because following one is reading on rather than starting again.
    const article = renderDocument(page, (target, anchor) => {
      location.href = projectURL(fingerprint, projectID, {
        path,
        file: target,
        q: query,
        frag: anchor,
      });
    });

    body.replaceChildren();

    append(
      body,
      el("p", "path mono", page.path),
      page.note ? el("p", "note-line kept", page.note) : null,
      comparedNote(page),
      article,
    );

    if (dock) {
      dock.remove();
    }

    // The way around a long file, in the corner a thumb reaches: the headings
    // and a search over the whole of it, with the versions above them.
    dock = withChanges(
      attachOutline(article), article, page,
      () => bridge.projectVersions(fingerprint, projectID, file),
      (version) => draw(compareOf(version)));

    document.body.append(dock);

    land(article, fragment);
  }

  await draw(null);
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

// comparedNote says what the marks in a document are against, above the
// document rather than only inside the panel: a reader who scrolled away from
// the corner should still be able to tell why the page is striped.
function comparedNote(page) {
  if (page.compareError) {
    return el("p", "note-line",
      "Showing the latest version: the one you asked to compare against is no "
      + "longer there.");
  }

  if (!page.compared) {
    return null;
  }

  const against = page.comparedTo || {};

  if (against.commit) {
    return el("p", "note-line",
      "Marked against the commit " + against.commit.slice(0, 10) + ".");
  }

  return el("p", "note-line",
    "Marked against an earlier saved version.");
}

// land scrolls a document that was arrived at through a link to a place in it.
//
// It is done after the article is in the page, because scrolling to something
// that has not been laid out yet scrolls nowhere. A fragment naming a heading
// this document does not have leaves the reader at the top, which is where they
// would have been anyway.
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

  let dock = null;

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

    body.replaceChildren();

    append(body,
      page.note ? el("p", "note-line kept", page.note) : null,
      comparedNote(page),
      article);

    if (dock) {
      dock.remove();
    }

    dock = withChanges(
      attachOutline(article), article, page,
      () => bridge.projectVersions(fingerprint, projectID, file),
      (version) => draw(compareOf(version)));

    document.body.append(dock);

    land(article, fragment);
  }

  await draw(null);

  return root;
}
