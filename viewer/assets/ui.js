// The furniture the desktop shell is built out of, and the one place its idiom
// is decided: a card, a section heading, a state pill, an avatar, a row that is
// a button, and the small stroked icons beside them.
//
// It is the iOS app's shared furniture, in a stylesheet instead of a
// ButtonStyle. The two apps look alike because they are the same handful of
// shapes over the same JSON — a card with a title, a secondary line and a pill
// in its corner; a heading with a count beside it; a fingerprint that is never
// cut through the middle — and keeping the shapes in one module is what stops
// the fourth screen inventing a fifth kind of row.
//
// Everything here builds nodes and sets textContent, like the rest of the
// bundle: a peer's name, a grant's description and a key's comment are all text
// somebody else chose (viewer/viewer_test.go asserts there is no other way).

import { el, append } from "./dom.js";

// The icons, as the path data of a 24-unit stroked drawing. Stroked rather than
// filled because they sit beside 13px text at 16px, where a filled glyph reads
// as a blob; and inline SVG rather than an image because the colour has to
// follow the text — a nav item that is selected, a warning that is amber.
const ICONS = {
  home: ["M3 9.5 12 3l9 6.5V20a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z", "M9.5 21v-7h5v7"],
  key: [
    "M10.6 13.4a4.6 4.6 0 1 0-6.5 6.5 4.6 4.6 0 0 0 6.5-6.5z",
    "M10.6 13.4 20 4m-2.6 2.6 2.4 2.4M14.4 9.6l2.4 2.4",
  ],
  clock: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 7.5V12l3.5 2"],
  // A clock with its arc left open and an arrow sweeping back into it: the
  // version this document is being read against (decision AP).
  rewind: [
    "M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8",
    "M3 3v5h5",
    "M12 7.5V12l3.5 2",
  ],
  book: ["M4 19.5A2.5 2.5 0 0 1 6.5 17H20", "M6.5 3H20v18H6.5A2.5 2.5 0 0 1 4 18.5v-13A2.5 2.5 0 0 1 6.5 3z"],
  gear: [
    "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
    "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z",
  ],
  machine: ["M3 4.5h18v11H3z", "M8.5 21h7M12 15.5V21"],
  sign: ["M20.5 3.5a2.1 2.1 0 0 1 0 3L8 19l-4.5 1.5L5 16z", "M14.5 6 18 9.5"],
  terminal: ["M4.5 8.5 8 12l-3.5 3.5", "M12 15.5h7.5", "M2.5 3.5h19v17h-19z"],
  link: [
    "M10 13.5a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.5 1.5",
    "M14 10.5a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.5-1.5",
  ],
  list: ["M8 6h12M8 12h12M8 18h12M3.5 6h.01M3.5 12h.01M3.5 18h.01"],
  question: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M9.4 9.2a2.7 2.7 0 0 1 5.2.9c0 1.8-2.6 2.4-2.6 3.9", "M12 17.3h.01"],
  info: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M12 11.2v5.3", "M12 7.6h.01"],
  approved: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M8 12.3l2.8 2.7L16 9.5"],
  denied: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z", "M9 9l6 6M15 9l-6 6"],
  given: ["M17 7 7 17", "M17 16.5V7H7.5"],
  taken: ["M7 17 17 7", "M7 7.5V17h9.5"],
  chevron: ["m9.5 6 6 6-6 6"],
  plus: ["M12 5.5v13M5.5 12h13"],
  close: ["M6.5 6.5l11 11M17.5 6.5l-11 11"],
  warning: ["M12 3.5 22 20H2z", "M12 9.5v4.5M12 17h.01"],
};

// icon builds one. A name nothing is drawn for returns null rather than a blank
// box, so a kind of request nobody has drawn an icon for yet is a row with no
// icon rather than a row with a hole in it.
export function icon(name, className) {
  const paths = ICONS[name];

  if (!paths) {
    return null;
  }

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");

  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.6");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("class", className ? "icon " + className : "icon");

  for (const data of paths) {
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");

    path.setAttribute("d", data);
    svg.append(path);
  }

  return svg;
}

// action is a button in the pane's title bar: an icon, and the word it means in
// a tooltip rather than beside it (decision AF).
//
// It is where a screen puts the thing it can *start*, as opposed to the things
// it lists. A form that is on the screen is a form that is in the way of the
// screen — the Keys pane led with an empty text box above the keys somebody had
// come to look at — and a title bar is the one place a desktop application has
// always kept "and one more of these".
export function action(iconName, label, onClick) {
  const button = el("button", "action");

  button.title = label;
  button.setAttribute("aria-label", label);
  button.append(icon(iconName));
  button.onclick = onClick;

  return button;
}

// clockValue is a length of time as a time input reads one: hours and minutes,
// and never past the day it would wrap at.
//
// It is here rather than in the screen that first needed it because two screens
// now ask for a length on a clock — how long a promise runs (decision V) and
// how long a signing request waits (§9) — and a second copy of this is a second
// place for the padding and the clamp to be got slightly differently.
export function clockValue(seconds) {
  const bounded = Math.max(60, Math.min(seconds, 23 * 3600 + 59 * 60));
  const pad = (n) => String(n).padStart(2, "0");

  return pad(Math.floor(bounded / 3600)) + ":" + pad(Math.floor((bounded % 3600) / 60));
}

// clockSeconds is the other direction: what a time input holds, as a length.
export function clockSeconds(value) {
  const [hours, minutes] = String(value || "").split(":").map(Number);

  return (hours || 0) * 3600 + (minutes || 0) * 60;
}

// duration says a length the way the core's HumanDuration does, because a
// button, the promise it makes and the log line it ends up in should all read
// alike.
export function duration(seconds) {
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const count = (n, word) => n + " " + word + (n === 1 ? "" : "s");

  if (!hours) {
    return count(minutes, "minute");
  }

  if (!minutes) {
    return count(hours, "hour");
  }

  return count(hours, "hour") + " " + count(minutes, "minute");
}

// sheet is a modal over the pane: what an action in the title bar opens.
//
// It is a `dialog` rather than a pane of its own, and that is what buys the
// three things a form needs and a screen cannot give it — Escape closes it, the
// rest of the window is inert while it is up, and it lives outside the pane, so
// the four-second poll repainting the screen underneath does not empty a box
// somebody is halfway through typing into (§12). The Keys screen was taken out
// of the redrawn set for exactly that reason and is back in it now.
//
// The node is thrown away when it closes: a sheet holds a form and a form holds
// what was typed, and reopening one is asking to start again.
export function sheet(title, ...children) {
  const root = document.createElement("dialog");

  root.className = "sheet";

  const close = el("button", "sheet-close");

  close.title = "Close";
  close.setAttribute("aria-label", "Close");
  close.append(icon("close"));
  close.onclick = () => root.close();

  append(root,
    append(el("header", "sheet-head"), el("h2", null, title), close),
    append(el("div", "sheet-body"), ...children));

  root.addEventListener("close", () => root.remove());

  document.body.append(root);

  // showModal is what makes the rest of the window inert and Escape close it.
  // A host whose webview does not have it gets a dialog that is merely on top,
  // which is worse in every way except the one that matters: the form works.
  if (typeof root.showModal === "function") {
    root.showModal();
  } else {
    root.setAttribute("open", "");
  }

  return root;
}

// card is the panel everything sits in.
export function card(className, ...children) {
  return append(el("div", className ? "card " + className : "card"), ...children);
}

// heading is the small label above a group, with the count beside it when there
// is more than nothing to count. An empty group still gets its heading: "no live
// grants" is worth saying, and a heading that appears and disappears is a page
// that moves under the reader.
export function heading(text, count) {
  const root = el("div", "section-label");

  root.append(el("span", null, text));

  if (count) {
    root.append(el("span", "count", String(count)));
  }

  return root;
}

// The states a pill knows a colour for. The words are the core's — peerState,
// the trust summaries, a borrowed key's availability — and this only decides
// what colour each one is. Anything it has not been told about is grey, which is
// the right answer for a state nobody has thought about yet.
const PILL = {
  ok: [
    "connected", "online", "reached", "available", "unlocked", "attached",
    "held here too", "in the agent", "signs locally",
  ],
  warn: [
    "connecting", "pairing", "waiting for you", "waiting for the other side",
    "locked", "pending revoke",
  ],
  bad: ["unreachable", "offline", "sealed", "not attached", "not running"],
};

function pillKind(state) {
  for (const [kind, words] of Object.entries(PILL)) {
    if (words.some((word) => state.startsWith(word))) {
      return kind;
    }
  }

  return "idle";
}

// pill says what state something is in: a dot in the colour of it and the core's
// own word beside it.
export function pill(state) {
  if (!state) {
    return null;
  }

  const root = el("span", "pill " + pillKind(state));

  root.append(el("span", "dot"), el("span", null, state));

  return root;
}

// avatar is the picture that goes beside a fingerprint (§7), drawn by the bridge
// from the fingerprint itself. It is the same drawing the phone shows for the
// same machine, which is the whole point of it: two machines are told apart by a
// picture and a name long before anybody compares the characters.
export function avatar(seed, size) {
  if (!seed) {
    // Nothing to draw yet: the drawing is a pure function of the fingerprint, so
    // an instance that has not said what its own is — a sealed one, at the moment
    // the window opens — would otherwise ask the bridge to draw nothing and get a
    // broken image in the corner of the window back.
    //
    // The placeholder is an SVG rather than a styled span because its size is an
    // attribute there. The stylesheet is a file the policy allows and a style
    // attribute is not (viewer.ContentSecurityPolicy), and a placeholder is not a
    // reason to find out which of the two the CSSOM counts as.
    const blank = document.createElementNS("http://www.w3.org/2000/svg", "svg");

    blank.setAttribute("class", "avatar blank");
    blank.setAttribute("width", String(size));
    blank.setAttribute("height", String(size));
    blank.setAttribute("aria-hidden", "true");

    return blank;
  }

  const image = document.createElement("img");

  image.className = "avatar";
  image.width = size;
  image.height = size;
  image.alt = "";
  image.src = "/api/v1/avatar?seed=" + encodeURIComponent(seed);

  return image;
}

// fingerprint draws the characters somebody is actually meant to compare.
//
// Never cut through the middle: an ellipsis through the part that differs is the
// one thing this text must not do. Shortened, it keeps the front of the key —
// where two fingerprints differ first — and drops the algorithm prefix every one
// of them shares.
export function fingerprint(value, full) {
  const text = full ? value : shortFingerprint(value);
  const node = el("span", "fingerprint", text);

  node.title = value || "";

  return node;
}

export function shortFingerprint(value) {
  const body = String(value || "").split(":").pop();

  return body.length > 20 ? body.slice(0, 20) + "…" : body;
}

// row is a card that is a button: the whole thing is the target, and the chevron
// on the right says so. Every list on every screen is made of these, which is
// why "does this row do anything" never has to be guessed at.
export function row(className, onClick, ...children) {
  const node = el("button", className ? "row " + className : "row");

  append(node, ...children);

  if (!onClick) {
    node.classList.add("static");
    node.disabled = true;

    return node;
  }

  node.onclick = onClick;
  node.append(icon("chevron", "chevron"));

  return node;
}

// title and sub are the two lines inside a row: what it is, and what about it.
export function title(text) {
  return el("div", "row-title", text);
}

export function sub(text) {
  return el("div", "row-sub", text);
}

// stack is the middle of a row: the lines, taking the space the icon and the
// pill leave.
export function stack(...children) {
  return append(el("div", "row-stack"), ...children);
}

// empty says why a list has nothing in it, and what to do about it. Both halves:
// a bare "nothing here" leaves somebody wondering whether they are looking at
// the wrong screen.
export function empty(what, why) {
  return card("empty-card", el("div", "row-title", what), el("p", "hint", why));
}

// note is a line of explanation under something, in the core's words where there
// are any.
export function note(text) {
  return el("p", "hint", text);
}

// warning is a line meant to be read before whatever is under it.
export function warning(text, danger) {
  const root = el("div", danger ? "banner danger" : "banner");

  append(root, icon("warning"), el("span", null, text));

  return root;
}

// ago is how long since an instant, in words, for the one field the core sends
// as a timestamp rather than a sentence: how long a request has been waiting.
// Everything else — when a grant runs out, when a key was last offered — is
// already a sentence written in Go, and rewording it here would be two surfaces
// saying the same thing differently.
export function ago(stamp, now) {
  const at = Date.parse(stamp || "");

  if (Number.isNaN(at)) {
    return "";
  }

  const seconds = Math.max(0, Math.round(((now || Date.now()) - at) / 1000));

  if (seconds < 60) {
    return seconds + "s ago";
  }

  if (seconds < 3600) {
    return Math.floor(seconds / 60) + "m ago";
  }

  if (seconds < 86400) {
    return Math.floor(seconds / 3600) + "h ago";
  }

  return Math.floor(seconds / 86400) + "d ago";
}

// ticking keeps every "4s ago" on a screen honest without the screen being
// redrawn to do it: the nodes are collected once and only their text is written
// again. A rebuilt row loses a click that lands mid-rebuild, which is the bug
// the phone spent a milestone on (§12) — so nothing here rebuilds anything.
export function ticking(node, stamp) {
  node.dataset.since = stamp;

  return node;
}

export function startTicking(root) {
  const tick = () => {
    const now = Date.now();

    for (const node of root.querySelectorAll("[data-since]")) {
      node.textContent = ago(node.dataset.since, now);
    }
  };

  tick();

  return setInterval(tick, 1000);
}
