// The viewer's entry point.
//
// Two things are served from here, and the query string is what tells them apart.
//
// A **pane** is one thing, opened by a host that draws everything around it: an
// approval prompt in its own popup window (/?request=<id>), that request's diff on
// its own (/?diff=<id>) for a phone that drew the card natively, one published
// document (/?peer=…&project=…&file=…&read=1) for a phone that drew the browser
// natively (decisions O and R), and the unlock panel (/?unlock=1) for a host that
// wants only that.
//
// Everything else is the **shell**: the desktop application's own window, with a
// sidebar and a screen beside it (decision AA). It reads its screen from the
// fragment, so moving around inside it is not a page load — and it keeps the doc
// browser's query parameters working, because those are how the browser's own
// links name where they are going.
//
// So a webview that can only open URLs, which is all of them, needs nothing else
// to drive the viewer.

import { el } from "./dom.js";
import { bridge } from "./bridge.js";
import { renderDiff, attachDiffFetch } from "./diff.js";
import { renderPrompt } from "./prompt.js";
import { renderReader } from "./projects.js";
import { renderUnlock } from "./lock.js";
import { runShell } from "./shell.js";

const root = document.getElementById("root");
const params = new URLSearchParams(location.search);
const requestID = params.get("request");
const diffID = params.get("diff");
const readFile = params.get("read") ? params.get("file") : null;
const peer = params.get("peer");
const projectID = params.get("project");
// The heading a link asked for. It travels as its own parameter rather than as a
// URL fragment, because the fragment of a custom-scheme URL is not something every
// host hands on — and this one has to survive the shell taking a link over and
// pushing a screen of its own (decision R).
const fragment = params.get("frag");
const unlock = params.get("unlock");

function show(...children) {
  root.className = "";
  root.replaceChildren(...children);
}

// hosted says the screen around this pane is the shell's rather than the bundle's,
// which is true of exactly the two panes a native host pushes: the diff and one
// document. It takes the page's own background away so that what shows through the
// webview is the surface the shell drew, and the two match in light and dark
// appearance without either having to know the other's colours.
function hosted() {
  document.body.classList.add("hosted");
}

function showMessage(text) {
  root.className = "loading";
  root.replaceChildren(el("p", null, text));
}

// renderPromptPane is the popup: one request, in a window of its own, which is how
// a desktop asks (decision AA). Closing it without answering is a refusal, and the
// host is the half that knows that — this is the card and the buttons.
async function renderPromptPane() {
  let request;

  try {
    request = await bridge.request(requestID);
  } catch (error) {
    showMessage(
      error.status === 404
        ? "This request is no longer waiting for an answer."
        : "The request could not be loaded: " + error.message,
    );

    return;
  }

  const prompt = renderPrompt(request, (decision, error) => {
    if (error) {
      showMessage("The answer did not go through: " + error.message);

      return;
    }

    showMessage(decision === "approve" ? "Approved." : "Denied.");
  });

  show(prompt.card);

  // The popup is the card and nothing else, and the card now ends in a footer
  // pinned to the bottom of the page. The page's own bottom padding would leave
  // that footer floating above a strip of background with the card's rounded
  // edge behind it, so here the card runs to the window's bottom and the footer
  // sits on its edge. Only this pane: everywhere else the padding is right.
  root.className = "prompt";

  // Escape denies. Closing the window without answering denies too, on the host
  // side: a request that goes unanswered is never an approval.
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      prompt.answer("deny", 0);
    }
  });

  // Focus without scrolling. The footer is pinned, so there is nothing to scroll
  // to in order to reach it — and a window that opened part-way down the commit
  // because something in it took focus is a window whose first screen was never
  // read.
  prompt.focus.focus({ preventScroll: true });
}

// renderDiffPane is the diff and nothing else — no card, no buttons.
//
// It is what a host that draws the card itself opens (decision O): iOS draws the
// request natively and pushes this for the change, because a diff is a document and
// rendering documents is what a webview is for. The parsing has already happened in
// Go either way, so both hosts are looking at the same files, hunks and typed
// lines.
async function renderDiffPane() {
  let request;

  try {
    request = await bridge.request(diffID);
  } catch (error) {
    showMessage(
      error.status === 404
        ? "This request is no longer waiting for an answer."
        : "The request could not be loaded: " + error.message,
    );

    return;
  }

  const diff = request.git && request.git.diff;

  if (!diff) {
    showMessage("This request carries no diff.");

    return;
  }

  hosted();
  root.className = "diff-only";
  root.replaceChildren(attachDiffFetch(renderDiff(diff), request, diff));
}

// renderReaderPane is one published document, for a host that draws the browser
// around it natively (decision R).
//
// It says it is reading before it starts, and takes the page's own background away
// at the same moment rather than when the document arrives. A read goes to the
// machine that publishes (decision Q), so it takes as long as that machine takes to
// wake up and answer — and until it did, this screen was the bare "Loading…" that
// index.html ships, on the bundle's own background, inside a screen the shell had
// already pushed. A wait that looks like a mistake is worse than a wait: the report
// was that tapping a file did nothing.
async function renderReaderPane() {
  hosted();
  showMessage("Reading " + readFile + "…");

  try {
    const article = await renderReader(peer, projectID, readFile, fragment);

    root.className = "document-only";
    root.replaceChildren(article);
  } catch (error) {
    showMessage("Could not read " + readFile + ": " + error.message);
  }
}

async function renderUnlockPane() {
  try {
    show(renderUnlock(await bridge.lockState(), () => {
      location.href = "/";
    }));
  } catch (error) {
    showMessage("The store could not be reached: " + error.message);
  }
}

if (unlock) {
  renderUnlockPane();
} else if (requestID) {
  renderPromptPane();
} else if (diffID) {
  renderDiffPane();
} else if (peer && projectID && readFile) {
  renderReaderPane();
} else {
  runShell(root);
}
