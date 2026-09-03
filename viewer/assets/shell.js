// The desktop shell: a sidebar, and one screen beside it (decision AA).
//
// It is the phone's app in a window. The phone has four tabs and puts the paired
// machines on its home screen because a tab bar holds four things; a window has a
// side to put a list down, so the machines are in it, one entry each, and "this
// phone" becomes Settings at the bottom. Everything else is the same screens over
// the same JSON, which is what makes a fix to one of them a fix to both.
//
// What it replaced was one long scrolling pane of tables — keys, peers, grants,
// activity and the lock buttons, in that order, every five seconds — reached
// through a tray menu that opened a new window each time it was clicked. Nothing
// in it was wrong and none of it was findable.
//
// The rules it follows, all three of them learned on the phone (§12):
//
//   * A poll that found nothing new redraws nothing. The instance is re-read
//     every few seconds to keep a countdown honest, and a pane rebuilt under
//     somebody's cursor loses the click that was landing on it.
//   * A screen that has to ask another machine says so before it starts asking,
//     and draws the answer when it arrives.
//   * Nothing navigates on its own. A request that arrives while somebody is
//     reading one screen appears in the sidebar's count and nowhere else.

import { el, append } from "./dom.js";
import { bridge } from "./bridge.js";
import * as ui from "./ui.js";
import * as screens from "./screens.js";
import { renderPrompt } from "./prompt.js";
import {
  renderProject, renderProjectList, documentsRoute,
} from "./projects.js";
import { renderUnlock, lockControls } from "./lock.js";
import { addMachine } from "./pairing.js";

// How often the instance is re-read. It is the timer the countdowns and the
// waiting-request count live on, and a poll that finds the same answer costs one
// comparison and no repaint.
const REFRESH_MS = 4000;

// The screens the poll may redraw under the reader. The rest own data they went
// and fetched — a document read from another machine, a request card, one
// decision out of the log — and redrawing those would throw away what somebody is
// looking at to show them the same thing again.
//
// Keys is among them again. It was taken out when the "make a new key" form was
// on the screen: a name is typed a character at a time, any decision anywhere
// changes the instance payload, and a poll four seconds later emptied the box
// somebody was halfway through filling. The form is a sheet now (decision AF)
// and sheets live outside the pane, so there is no box under the poll to empty
// — and the screen has something that has to arrive on its own again, which is
// a key a paired machine has handed this one (decision S). What must not come
// back is a text field drawn into a screen in this set.
const LIVE = new Set(["home", "keys", "activity", "settings"]);

// What each live screen actually draws.
//
// The poll used to compare the whole instance and repaint when any byte of it
// moved, which is how a peer's last-seen ticking redrew the Keys screen — a
// screen that does not mention peers. With a link flapping, as one does
// whenever a machine is asleep or a route is blackholed, that is a repaint
// every few seconds: the pane is replaced, and what goes with it is the scroll
// position, the focus, and any panel somebody had open. The flash is the
// visible half of it and the lost state is the worse half.
//
// So a screen is repainted when what it draws has changed. A name missing from
// here is compared whole, which is the safe way round: a new screen redraws too
// often rather than not at all, and the fix is to add its fields.
//
// Keep this next to the screens. A screen that grows a field and is not added
// here stops updating for it, which is the one failure this arrangement has.
const DRAWS = {
  home: [
    "delegations", "grants", "offers", "pairings", "peers", "pending",
  ],
  keys: ["borrowed", "endorsements", "keys", "offers", "retractions"],
  activity: ["recent"],
  settings: ["fingerprint", "locations", "lock", "name", "settings"],
};

// screenStamp is what one screen draws, as something comparable.
function screenStamp(name, instance) {
  const fields = DRAWS[name];

  if (!fields) {
    return JSON.stringify(instance);
  }

  const drawn = {};

  for (const field of fields) {
    drawn[field] = instance[field];
  }

  return JSON.stringify(drawn);
}

// The store states that leave nothing else worth drawing (§10). A locked store
// still has its keys, still lists its peers and can still be approved for by a
// paired approver, so it is an ordinary screen with an Unlock button on it; these
// three are a gate.
const GATES = new Set(["sealed", "not running", "not created yet"]);

export function runShell(root) {
  const shell = new Shell(root);

  shell.start();

  return shell;
}

class Shell {
  constructor(root) {
    this.root = root;
    this.instance = null;
    // stamp is the last instance payload, so that a poll which found nothing new
    // can be recognised and ignored.
    this.stamp = "";
    this.route = { name: "home", id: "" };
    this.drawn = null;
    this.error = null;
    this.clock = 0;

    document.body.classList.add("app");

    this.sidebar = el("nav", "sidebar");
    // A section rather than a `main`, and that is not a nitpick: index.html's
    // own `#root` is the `main` — one per document — and the stylesheet's rule
    // for it was landing on this one too, capping the pane at 900px, centring it
    // and padding it 20px away from the top. The pane's header is the width of
    // its container, so what showed was a heading that stopped short of the pane
    // it belonged to and sat below its top edge.
    this.pane = el("section", "pane");

    root.replaceChildren(append(el("div", "shell"), this.sidebar, this.pane));
  }

  async start() {
    this.route = parseRoute();

    // The first paint has nothing to draw with, and a blank window that turns
    // into an application half a second later is worse than a window that says
    // it is starting.
    this.pane.replaceChildren(el("p", "starting", "Asking the daemon…"));

    await this.poll(true);

    window.addEventListener("hashchange", () => {
      const next = parseRoute();

      if (next.name === this.route.name && next.id === this.route.id) {
        return;
      }

      this.route = next;
      this.paintSidebar();
      this.paintPane();
    });

    setInterval(() => this.poll(false), REFRESH_MS);
  }

  // poll re-reads the instance and redraws what the answer changed.
  async poll(first) {
    let instance;

    try {
      instance = await bridge.instance();
    } catch (error) {
      // The bridge is this window's own handler, so a failure here is not a
      // daemon that is down — that arrives as a lock state (decision Z) — it is
      // this window's own half being broken, which is worth saying out loud.
      this.error = error.message;

      if (first) {
        this.paintPane();
      }

      return;
    }

    this.error = null;

    const stamp = JSON.stringify(instance);

    if (stamp === this.stamp && !first) {
      return;
    }

    this.stamp = stamp;
    this.instance = instance;

    // The sidebar is drawn from the lock, the waiting requests and the
    // machines, and is small enough that redrawing it whenever any of them
    // moves costs nothing anybody can see.
    this.paintSidebar();

    if (first) {
      this.paintPane();

      return;
    }

    if (!LIVE.has(this.route.name)) {
      return;
    }

    if (screenStamp(this.route.name, instance) === this.painted) {
      return;
    }

    this.paintPane();
  }

  // The handle the screens are given: what to draw from, and the few things they
  // may ask the shell to do.
  get state() {
    return {
      instance: this.instance || {},
      attached: this.attached,
      refresh: () => this.poll(true),
      complain: (message) => {
        this.error = message;
        this.paintPane();
      },
      lockControls: () => lockControls(
        (this.instance || {}).lock, () => this.poll(true)),
    };
  }

  get attached() {
    const lock = (this.instance || {}).lock || {};

    return lock.state !== "not running";
  }

  go(route) {
    location.hash = "#/" + route;
  }

  paintSidebar() {
    const instance = this.instance || {};
    const lock = instance.lock || {};
    const pending = (instance.pending || []).length;

    const identity = el("button", "identity");

    identity.onclick = () => this.go("settings");

    append(identity,
      ui.avatar(instance.fingerprint, 34),
      append(el("div", "identity-lines"),
        el("div", "identity-name", instance.name || "Ladulås"),
        el("div", "identity-state", lock.state || "…")),
      ui.icon("gear", "identity-gear"));

    const items = el("div", "nav");

    append(items,
      this.navItem("home", "Home", "home", pending),
      // A key a paired machine has handed this one waits on the Keys screen and
      // is counted here, the way a request waiting for an answer is counted on
      // Home: it is the only part of a handover this end can do, and until the
      // count was on the sidebar there was nothing anywhere to say one had
      // arrived (decision S).
      this.navItem("keys", "Keys", "key", (instance.offers || []).length),
      this.navItem("activity", "Activity", "clock"),
      this.navItem("documents", "Documents", "book"));

    const machines = el("div", "nav");
    const peers = instance.peers || [];

    if (peers.length) {
      machines.append(ui.heading("Machines", peers.length));

      for (const peer of peers) {
        machines.append(this.peerItem(peer));
      }
    }

    // Adding one lives with the list of them, and is here rather than only on
    // the home screen because an instance with no peers at all is exactly the
    // one whose owner is looking for it (§7).
    machines.append(this.navItem("pair", "Add a machine", "link"));

    const footer = el("div", "nav footer");

    footer.append(this.navItem("settings", "Settings", "gear"));

    this.sidebar.replaceChildren(identity, items, machines, footer);
  }

  navItem(name, label, iconName, count) {
    const item = el("button", "nav-item");

    if (this.route.name === name) {
      item.classList.add("current");
    }

    append(item,
      ui.icon(iconName),
      el("span", "nav-label", label),
      count ? el("span", "count", String(count)) : null);

    item.onclick = () => this.go(name);

    return item;
  }

  // One machine, which is a nav item with a face on it. The picture is what tells
  // two of them apart at a glance; the dot is whether reaching for it would get
  // anywhere right now.
  peerItem(peer) {
    const item = el("button", "nav-item peer-item");
    const route = "peer/" + encodeURIComponent(peer.fingerprint);

    if (this.route.name === "peer" && this.route.id === peer.fingerprint) {
      item.classList.add("current");
    }

    append(item,
      ui.avatar(peer.fingerprint, 22),
      el("span", "nav-label", peer.name),
      ui.pill(peer.state));

    item.onclick = () => this.go(route);

    return item;
  }

  async paintPane() {
    const token = {};

    this.drawing = token;

    // What this paint is of, so that the next poll can tell whether anything
    // it draws has moved. Recorded here rather than in poll because a route
    // change paints without going through one.
    this.painted = screenStamp(this.route.name, this.instance || {});

    if (this.clock) {
      clearInterval(this.clock);
      this.clock = 0;
    }

    let screen;

    try {
      screen = await this.screen();
    } catch (error) {
      screen = {
        title: "Something went wrong here",
        body: [ui.empty("This window could not draw that", error.message)],
      };
    }

    // A screen that took a moment to fetch and lost the race to a click is not
    // drawn: what is on screen is what was asked for last.
    if (this.drawing !== token) {
      return;
    }

    const head = el("header", "pane-head");

    if (screen.back) {
      const back = el("button", "back", "← " + screen.back.label);

      back.onclick = () => this.go(screen.back.route);
      head.append(back);
    }

    head.append(el("h1", null, screen.title));

    // What the screen can start, or take apart, in the corner a desktop
    // application has always kept it in (decision AF).
    if (screen.actions && screen.actions.length) {
      head.append(append(el("div", "pane-actions"), ...screen.actions));
    }

    const body = append(
      el("div", screen.wide ? "pane-body wide" : "pane-body"), ...screen.body);

    if (this.error) {
      body.prepend(ui.warning(this.error, true));
    }

    this.pane.replaceChildren(head, body);
    this.pane.scrollTop = 0;

    this.clock = ui.startTicking(this.pane);
  }

  // screen is the route as a title and a list of nodes.
  screen() {
    const state = this.state;
    const lock = (this.instance || {}).lock || {};

    // A store with no key in it cannot answer for anything, and every screen
    // would be empty lists and a countdown to nothing. So the gate is the whole
    // pane wherever the reader happens to be standing, and the sidebar stays so
    // that the window still looks like the application it is.
    if (GATES.has(lock.state)) {
      return this.gate();
    }

    const go = (route) => this.go(route);

    switch (this.route.name) {
      case "keys":
        return screens.keys(state);
      case "activity":
        return this.route.id
          ? decisionScreen(state, this.route.id)
          : screens.activity(state, go);
      case "peer":
        return peerScreen(state, this.route.id, go);
      case "pair":
        return pairScreen(state);
      case "documents":
        return documentsScreen(this.route);
      case "settings":
        return screens.settings(state);
      case "request":
        return requestScreen(state, this.route.id, go);
      default:
        return screens.home(state, go);
    }
  }

  // gate is the unlock panel, which is the shared one every host shows (§10). The
  // passphrase goes to the daemon, which is the only thing that can check it.
  async gate() {
    const state = await bridge.lockState();

    return {
      title: state.state === "not running" ? "Nothing is running" : "Locked away",
      body: [renderUnlock(state, (next) => {
        if (next && next.state === "unlocked") {
          this.poll(true);
        }
      })],
    };
  }
}

async function decisionScreen(state, id) {
  const screen = await screens.decision(state, id);

  return { ...screen, back: { label: "Activity", route: "activity" } };
}

async function peerScreen(state, fingerprint, go) {
  const screen = await screens.peer(state, fingerprint, go);

  return { ...screen, back: { label: "Home", route: "home" } };
}

// pairScreen is starting a pairing (§7). It is not in LIVE: it holds a choice
// somebody is halfway through making and a code they are halfway through
// typing, and a poll that redrew it would take both away.
async function pairScreen(state) {
  const screen = await addMachine(state);

  return { ...screen, back: { label: "Home", route: "home" } };
}

// requestScreen is one waiting request, answered here rather than in its own
// popup: the popup is what a person is shown when it arrives, and this is where
// the one they closed, or never saw, can still be answered.
async function requestScreen(state, id, go) {
  let request;

  try {
    request = await bridge.request(id);
  } catch (error) {
    return {
      title: "Not waiting any more",
      back: { label: "Home", route: "home" },
      body: [ui.empty(
        error.status === 404 ? "Already answered" : "Could not be read",
        error.status === 404
          ? "This request is no longer waiting for an answer. What was decided "
            + "is in the activity list."
          : error.message)],
    };
  }

  const prompt = renderPrompt(request, (decision, error) => {
    if (error) {
      state.complain("The answer did not go through: " + error.message);

      return;
    }

    state.refresh();
    go("home");
  });

  return {
    title: request.title,
    back: { label: "Home", route: "home" },
    body: [prompt.card],
  };
}

// documentsScreen is the doc browser, in the pane rather than in a window of its
// own (§6, decision Q).
//
// **Where it is lives in the fragment**, like every other screen's does, and
// that is what makes leaving it free.
//
// It used to live in the query string, on the reasoning that a project is named
// the way the browser's own links name it. What that cost was the one thing
// nobody would have chosen: a query string cannot be left without loading the
// page, so going from a document to Home or Keys tore the whole application
// down and built it again — half a second of "Asking the daemon…" for a move
// that is instant from anywhere else. A fragment carries the same three fields
// and changes in place.
//
// A query string still works, because it is the host's: /?peer=…&project=… is
// how iOS pushes a screen and how an external link names one, and both of those
// are a load whatever this does.
//
// The browser is still not a screen the poll may redraw — a repaint while
// somebody is reading would put them back at the front page.
async function documentsScreen(route) {
  const params = documentParams(route);
  const peer = params.get("peer");
  const projectID = params.get("project");

  if (peer && projectID) {
    return {
      title: "Documentation",
      wide: true,
      body: [await renderProject(
        peer,
        projectID,
        params.get("file"),
        params.get("frag"),
      )],
    };
  }

  return {
    title: "Documentation",
    body: [renderProjectList(await bridge.projects(peer), peer)],
  };
}

// documentParams is where the doc browser is, from the fragment when the shell
// put it there and from the query string when a host or an external link did.
function documentParams(route) {
  if (route && route.id) {
    return new URLSearchParams(route.id);
  }

  return new URLSearchParams(location.search);
}

// parseRoute reads the screen out of the address.
//
// The fragment is the shell's, and the query string is the host's: /?diff=<id> is
// a pane a phone pushed and /?peer=…&project=… is the doc browser's own way of
// naming where it is. A fingerprint is base64 and carries slashes, so the
// identifier is whatever follows the first one and is percent-encoded on the way
// in.
export function parseRoute() {
  const params = new URLSearchParams(location.search);

  if (params.get("projects") || params.get("peer")) {
    return { name: "documents", id: "" };
  }

  const raw = location.hash.replace(/^#\/?/, "");
  const cut = raw.indexOf("/");
  const name = cut < 0 ? raw : raw.slice(0, cut);
  const id = cut < 0 ? "" : decode(raw.slice(cut + 1));

  switch (name) {
    case "keys":
    case "activity":
    case "documents":
    case "settings":
    case "peer":
    case "pair":
    case "request":
      return { name, id };
    default:
      return { name: "home", id: "" };
  }
}

function decode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
