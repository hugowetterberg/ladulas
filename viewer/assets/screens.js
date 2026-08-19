// The shell's screens: what is in the pane beside the sidebar, one function per
// entry in it (decision AA).
//
// Every one of them returns a title and a list of nodes, and none of them knows
// what the window is or how it navigates — shell.js draws the heading and hands
// them a `go`. That is the same seam internal/frontend has on the Go side, and it
// is what let the iOS app be written against the screens rather than against the
// pane: the shape of each of these is one of its views (HomeView, KeysView,
// ActivityListView, PeerDetailView, SettingsView), over the same JSON.

import { el, append, facts } from "./dom.js";
import { bridge } from "./bridge.js";
import * as ui from "./ui.js";
import { renderDecision } from "./prompt.js";
import { projectURL } from "./projects.js";

// The icon a waiting request gets, by kind. The same mapping the phone's home
// screen uses.
const KIND_ICONS = {
  "git-sign": "sign",
  "ssh-auth": "terminal",
  pairing: "link",
  "key-list": "list",
};

// home is what is happening now: anything waiting for an answer, the machines
// this instance is paired with, and the promises that are still running.
//
// Anything waiting is at the top and is a row rather than a card that opens
// itself. A prompt arrives as its own popup; this is the list of what is still
// waiting after one has been closed or missed, which on a desktop is the thing
// that used to be impossible to find.
export function home(state, go) {
  const body = [];
  const instance = state.instance;

  const pending = instance.pending || [];

  body.push(ui.heading("Waiting for you", pending.length));

  if (!pending.length) {
    body.push(ui.empty("Nothing is waiting",
      "A signature or a pairing that needs an answer opens a window of its "
      + "own, and is listed here until it is answered."));
  }

  for (const item of pending) {
    body.push(ui.row("wants-answer",
      () => go("request/" + encodeURIComponent(item.id)),
      ui.icon(KIND_ICONS[item.kind] || "question", "kind"),
      ui.stack(
        ui.title(item.title),
        item.subject ? ui.sub(item.subject) : null),
      ui.ticking(el("span", "when"), item.since)));
  }

  // A pairing this side has already answered has no card and never will: what it
  // is waiting for is a person at the other machine. Without a row here there
  // would be no way to see one, let alone call it off (§7).
  const pairings = instance.pairings || [];

  if (pairings.length) {
    body.push(ui.heading("Pairings under way", pairings.length));

    for (const item of pairings) {
      const call = el("button", "danger small", "Call off");

      call.onclick = () => {
        call.disabled = true;

        bridge
          .withdrawPairing(item.session)
          .then(() => state.refresh())
          .catch((error) => {
            call.disabled = false;
            state.complain(error.message);
          });
      };

      body.push(ui.card("pairing",
        ui.avatar(item.fingerprint, 40),
        ui.stack(
          ui.title(item.name || "A machine"),
          ui.sub(item.direction ? item.state + " — " + item.direction : item.state),
          ui.fingerprint(item.fingerprint)),
        item.url
          ? answerLink(item.url)
          : null,
        call));
    }
  }

  const peers = instance.peers || [];

  body.push(ui.heading("Paired instances", peers.length));

  if (!peers.length && !pairings.length) {
    body.push(ui.empty("No machines yet",
      "A paired machine can approve for this one, or ask it to approve. "
      + "Adding one displays a code the other machine reads."));
  }

  for (const peer of peers) {
    body.push(peerRow(peer, go));
  }

  body.push(ui.row("add",
    () => go("pair"),
    ui.icon("link", "kind"),
    ui.stack(
      ui.title("Add a machine"),
      ui.sub("Display a pairing code for a phone, a laptop or a server"))));

  const grants = instance.grants || [];

  body.push(ui.heading("Live grants", grants.length));

  if (!grants.length) {
    body.push(ui.empty("No live grants",
      "Approving something “for a while” makes one, and everything it "
      + "covers is listed under it until it runs out."));
  }

  for (const grant of grants) {
    body.push(grantCard(grant, state));
  }

  // The promises somebody else made about this instance, which it keeps for
  // itself (decision P). They only get a heading when there are some: an empty
  // list on a machine that never asked anybody for one would be a heading about
  // a mechanism rather than about this instance.
  const delegations = instance.delegations || [];

  if (delegations.length) {
    body.push(ui.heading("Given to this instance", delegations.length));

    for (const item of delegations) {
      body.push(delegationCard(item));
    }
  }

  return { title: "Home", body };
}

// answerLink is the way into a pairing that still needs answering here. It is a
// link out of the shell and into the card, which is the one thing on this screen
// that is a question rather than a fact.
function answerLink(url) {
  const open = el("button", "small", "Answer");

  open.onclick = () => {
    location.href = url;
  };

  return open;
}

function peerRow(peer, go) {
  return ui.row("peer",
    () => go("peer/" + encodeURIComponent(peer.fingerprint)),
    ui.avatar(peer.fingerprint, 40),
    ui.stack(
      ui.title(peer.name),
      ui.sub(peer.summary || peer.direction)),
    ui.pill(peer.state));
}

// One grant, with what it has covered folded up behind it.
//
// A signature a delegation allowed is something the grant did rather than an
// event of its own, so the card carries a count and the individual uses are
// behind a disclosure — a grant used two hundred times is one line that says two
// hundred (decision P).
function grantCard(grant, state) {
  // A grant revoked here and not yet delivered is still being kept on the machine
  // holding it, which is the one state this list must not round off in either
  // direction: dropping the row would say the signing had stopped, and showing it
  // unmarked would say it was still wanted.
  const root = ui.card(grant.revokePending ? "grant-card pending" : "grant-card");

  const head = el("div", "card-head");

  append(head,
    ui.icon(grant.delegated ? "given" : "clock", "kind"),
    ui.stack(
      ui.title(grant.description),
      ui.sub(grant.delegated
        ? grant.expires + " · on " + (grant.delegate || "a paired machine")
        : grant.expires)),
    grant.useCount ? el("span", "count", String(grant.useCount)) : null,
    grant.revokePending ? ui.pill("pending revoke") : null);

  root.append(head);

  if (grant.revokePending) {
    root.append(ui.note(
      (grant.delegate || "The machine holding it")
      + " has not been reached, so it is still signing. It stops the moment "
      + "this instance gets through."));
  }

  const uses = grant.uses || [];

  if (uses.length) {
    const details = el("details", "uses");

    details.append(el("summary", null,
      grant.useCount === 1 ? "What it covered" : "What it covered (" + grant.useCount + ")"));

    for (const use of uses) {
      details.append(el("div", "use",
        use.when + " · " + use.kind + (use.subject ? " · " + use.subject : "")));
    }

    // What the requester says it did, not what this instance decided. The
    // distinction is §18's and is worth keeping on screen.
    if (grant.delegated) {
      details.append(ui.note("Reported by the machine that holds the delegation."));
    }

    root.append(details);
  } else if (grant.useCount) {
    root.append(ui.note("Nothing has been reported in detail yet."));
  }

  if (!grant.revokePending) {
    const revoke = el("button", "danger small", "Revoke");

    revoke.onclick = () => {
      revoke.disabled = true;

      bridge
        .revokeGrant(grant.id)
        .then(() => state.refresh())
        .catch((error) => {
          revoke.disabled = false;
          state.complain(error.message);
        });
    };

    root.append(append(el("div", "card-actions"), revoke));
  }

  return root;
}

// A standing permission somebody else made about this instance: what it covers,
// how long is left, and who to ask to end it.
//
// It reads like a grant because it is the same promise from the other end, and it
// has no revoke because that is the difference that matters: this side can let one
// run out and nothing more.
function delegationCard(item) {
  const root = ui.card("grant-card");

  append(root, append(el("div", "card-head"),
    ui.icon("taken", "kind"),
    ui.stack(
      ui.title(item.description),
      ui.sub(item.expires + " · from " + item.approver)),
    item.useCount ? el("span", "count", String(item.useCount)) : null));

  // A machine that has been out of touch owes an account rather than having done
  // anything wrong, and the card says which it is.
  if (item.unreported) {
    root.append(ui.note(item.unreported
      + " of those have not been reported to " + item.approver + " yet."));
  }

  return root;
}

// grouped is the locations with a repeated label said once.
//
// The peer channel binds every private address it finds, and each of them is a
// row of its own with the same label on it — fifteen lines reading "Peer channel"
// on a machine with a tailnet and a few docker bridges, which is most of them.
// The label belongs to the group and the addresses under it, the way the peer
// screen already lists a machine's addresses.
function grouped(locations) {
  const rows = [];
  let last = "";

  for (const location of locations) {
    rows.push({
      label: location.label === last ? "" : location.label,
      value: location.path,
      mono: true,
    });

    last = location.label;
  }

  return rows;
}

// keys is what this instance can sign with: what it holds, and what it can reach
// for on a machine that holds it instead (§10, decision N).
export function keys(state) {
  const body = [];
  const instance = state.instance;
  const held = instance.keys || [];

  body.push(ui.heading("In this instance's store", held.length));

  if (!held.length) {
    body.push(ui.empty("No keys",
      "Making one below puts it in the daemon's store. This window shows "
      + "keys and never holds one."));
  }

  for (const key of held) {
    body.push(ui.card("key-card",
      append(el("div", "card-head"),
        ui.icon("key", "kind"),
        ui.stack(
          ui.title(key.label),
          key.comment ? ui.sub(key.comment) : null),
        key.algorithm ? el("span", "algorithm", key.algorithm) : null),
      ui.fingerprint(key.fingerprint, true)));
  }

  body.push(newKeyCard(state));

  // Every key a peer offers is listed whether or not its holder is there, which
  // is the whole point of remembering them: a phone is out of reach most of the
  // time by construction, and a list that showed only what could be signed with
  // this second said a phone held nothing almost always — which is how somebody
  // comes to believe a key was lost rather than that a screen is off.
  const borrowed = instance.borrowed || [];

  body.push(ui.heading("Lent by paired machines", borrowed.length));

  if (!borrowed.length) {
    body.push(ui.empty("Nothing lent",
      "A paired machine that holds keys and lets this one use them lists them "
      + "here, reachable or not."));
  }

  for (const key of borrowed) {
    body.push(ui.card("key-card",
      append(el("div", "card-head"),
        ui.icon("key", "kind"),
        ui.stack(
          ui.title(key.label),
          ui.sub("Held by " + key.peer)),
        key.algorithm ? el("span", "algorithm", key.algorithm) : null,
        ui.pill(borrowedState(key))),
      ui.fingerprint(key.fingerprint, true),
      !key.available && key.lastSeen
        ? ui.note("Last offered " + key.lastSeen)
        : null));
  }

  return { title: "Keys", body };
}

// newKeyCard makes a key in the daemon's store.
//
// A name and, optionally, the comment that rides along in the public half —
// which is what an `authorized_keys` line says the key is, so it is worth
// filling in and is nobody's secret. Importing an existing key is not here:
// that is a file to pick and a passphrase to type into a webview, and `ladulas
// keys import` is where both belong (decision S).
function newKeyCard(state) {
  const label = field("Name", "work", "text");
  const comment = field("Comment", "hugo@guppy", "text");
  const make = el("button", "primary", "Generate a key");
  const said = ui.note("");

  said.hidden = true;

  make.onclick = () => {
    make.disabled = true;
    said.hidden = true;

    bridge
      .generateKey(label.input.value, comment.input.value)
      .then((key) => {
        label.input.value = "";
        comment.input.value = "";
        said.textContent = key.label + " — " + key.fingerprint;
        said.hidden = false;
        make.disabled = false;

        state.refresh();
      })
      .catch((error) => {
        make.disabled = false;
        said.textContent = error.message;
        said.hidden = false;
      });
  };

  return ui.card("new-key",
    ui.heading("Make a new key"),
    label.root,
    comment.root,
    ui.note("An ed25519 key, generated by the daemon and kept in its "
      + "encrypted store. Nothing offers it to an agent or lends it to a "
      + "paired machine until you say so."),
    append(el("div", "card-actions"), make),
    said);
}

// field is a labelled input. The label is a real one rather than a placeholder:
// a placeholder is gone the moment somebody types, which is the moment they
// want to check what the box was for.
function field(text, placeholder, type) {
  const root = el("label", "field");
  const input = document.createElement("input");

  input.type = type;
  input.placeholder = placeholder;

  append(root, el("span", "field-label", text), input);

  return { root, input };
}

function borrowedState(key) {
  // A copy in this instance's own store is what signs, so the row is about where
  // else the key lives rather than about reaching for it.
  if (key.heldHere) {
    return "held here too";
  }

  return key.available ? "available" : "unreachable";
}

// activity is what has been decided lately, which is a different question from
// the home screen's: that one is what is true now, and this is what was agreed
// to — and it is the only place an auto-approval, which never raised a card at
// all, is visible (§9).
export function activity(state, go) {
  const body = [];
  const recent = state.instance.recent || [];

  if (!recent.length) {
    body.push(ui.empty("Nothing yet",
      "Requests this instance has answered show up here, including the ones a "
      + "live grant answered without asking."));
  }

  // A row opens the card that was answered, when the log has it. One the log has
  // not been told about yet is still a row — it says what happened — it just has
  // nowhere to go.
  for (const item of recent) {
    body.push(ui.row("decision",
      item.id ? () => go("activity/" + encodeURIComponent(item.id)) : null,
      ui.icon(outcomeIcon(item.outcome), "kind " + outcomeKind(item.outcome)),
      ui.stack(
        ui.title(item.title),
        ui.sub(item.outcome)),
      el("span", "when", item.when)));
  }

  return { title: "Activity", body };
}

function outcomeKind(outcome) {
  const word = (outcome || "").toLowerCase();

  if (word.includes("den") || word.includes("refus")) {
    return "bad";
  }

  return word.includes("approv") ? "ok" : "idle";
}

function outcomeIcon(outcome) {
  return outcomeKind(outcome) === "bad" ? "denied" : "approved";
}

// decision is one of those rows opened again (§18).
export async function decision(state, id) {
  let detail;

  try {
    detail = await bridge.activity(id);
  } catch (error) {
    return {
      title: "Decision",
      body: [ui.empty(
        error.status === 404 ? "Not in the log" : "Could not be read",
        error.status === 404
          ? "This instance's log does not go back to that decision."
          : error.message)],
    };
  }

  return { title: detail.title, body: [renderDecision(detail)] };
}

// peer is one paired instance: who it is, what the pairing allows, the keys it
// lends this one, and what it publishes.
//
// The projects are read from that machine when the screen opens, because browsing
// is a pull (decision Q) — so a machine that is asleep says so here, which is
// where it belongs.
export async function peer(state, fingerprint, go) {
  const found = (state.instance.peers || [])
    .find((item) => item.fingerprint === fingerprint);

  if (!found) {
    return {
      title: "Machine",
      body: [ui.empty("Not paired",
        "This instance is not paired with that machine, or the pairing has "
        + "been revoked since this window last looked.")],
    };
  }

  const body = [];

  body.push(ui.card("peer-card",
    append(el("div", "card-head"),
      ui.avatar(found.fingerprint, 56),
      ui.stack(
        ui.title(found.name),
        ui.sub(found.direction)),
      ui.pill(found.state))));

  // What "not connected" means depends on which side does the dialling, and a
  // pill has no room to say so. A machine listens, so no link means it is not
  // there; a phone listens to nothing and reaches this machine when somebody
  // opens it or a push wakes it, so no link is the ordinary state of a phone in
  // a pocket and says nothing about whether it can be asked (§11, decision T).
  if (!found.dialable) {
    body.push(ui.card("reach",
      ui.icon(found.state === "connected" ? "link" : "question", "kind"),
      ui.stack(
        ui.title(found.state === "connected"
          ? "Connected to this machine now"
          : found.lastSeen
            ? "Last connected " + found.lastSeen
            // Not "never": what this machine knows about a device that comes to
            // it is forgotten when the daemon restarts, so the claim it can
            // make is about itself.
            : "Has not been in touch since this machine started"),
        ui.sub(found.name + " has no address to dial. It reaches this machine "
          + "— when somebody opens it, when a push wakes it — so not being "
          + "connected is not the same as not being available."))));
  }

  body.push(ui.heading("The pairing"));
  body.push(ui.card(null, facts([
    { label: "Fingerprint", value: found.fingerprint, mono: true },
    { label: "May use keys", value: keyAccess(found) },
    ...(found.addresses || []).map((address, index) => ({
      label: index === 0 ? "Addresses" : "",
      value: address,
      mono: true,
    })),
    // Only for a peer this instance dials: for one that dials in, the card above
    // has already said it, in a sentence rather than as a row.
    found.dialable
      ? { label: "Last connected", value: found.lastSeen }
      : null,
  ]),
  ui.note("The fingerprint is what the two machines compared when they "
    + "paired.")));

  const borrowed = (state.instance.borrowed || [])
    .filter((key) => key.peer === found.name);

  if (borrowed.length) {
    body.push(ui.heading("Keys it lends this instance", borrowed.length));

    for (const key of borrowed) {
      body.push(ui.card("key-card",
        append(el("div", "card-head"),
          ui.icon("key", "kind"),
          ui.stack(ui.title(key.label)),
          ui.pill(borrowedState(key))),
        ui.fingerprint(key.fingerprint, true)));
    }
  }

  body.push(ui.heading("Published projects"));
  body.push(ui.note("Read from " + found.name + " just now, or read from it once "
    + "and kept. Nothing here is checked against anything, and none of it says "
    + "anything about any signature."));

  const projects = el("div", "cards");

  projects.append(ui.empty("Asking " + found.name + "…",
    "Documentation is read from the machine that publishes it, so this takes as "
    + "long as that machine takes to answer."));

  body.push(projects);

  // The list arrives after the screen does. A pane that waited on a sleeping
  // build box before drawing anything is a pane that looks broken, which is the
  // lesson the phone's reader already learned (§12).
  bridge
    .projects(found.fingerprint)
    .then((list) => {
      projects.replaceChildren();

      if (!(list || []).length) {
        projects.append(ui.empty(found.name + " publishes nothing readable",
          "On that machine, run `ladulas projects publish` in a project "
          + "directory — or let it publish the projects it asks for signatures "
          + "in, which it does by default."));

        return;
      }

      for (const project of list) {
        projects.append(projectRow(project));
      }
    })
    .catch((error) => {
      projects.replaceChildren(
        ui.empty("Could not ask " + found.name, error.message));
    });

  body.push(ui.heading("End the pairing"));
  body.push(revokeCard(found, state, go));

  return { title: found.name, body };
}

// revokeCard forgets a machine, and asks twice before it does.
//
// Twice because this is the one thing on any of these screens that cannot be
// undone by doing it again: it drops the direction, the keys the pairing lent,
// the promises made under it and the connection it is holding, and getting any
// of it back means pairing from scratch at both machines. The second press is
// what a stray click cannot produce.
function revokeCard(peer, state, go) {
  const revoke = el("button", "danger", "Revoke this pairing");
  const sure = ui.note("");

  sure.hidden = true;

  let asked = false;

  revoke.onclick = () => {
    if (!asked) {
      asked = true;
      revoke.textContent = "Forget " + peer.name + " — this cannot be undone";
      sure.textContent = "Press again to forget it. This side alone decides; "
        + peer.name + " is not asked and finds out by being dropped.";
      sure.hidden = false;

      return;
    }

    revoke.disabled = true;

    bridge
      .revokePeer(peer.fingerprint)
      .then(() => {
        state.refresh();
        go("home");
      })
      .catch((error) => {
        revoke.disabled = false;
        state.complain(error.message);
      });
  };

  return ui.card(null,
    ui.note("Revoking takes back everything this pairing granted: the "
      + "direction, any keys it lends, any promise made under it, and the "
      + "connection it is holding. What it is for cannot be changed — pairing "
      + "again is how that is done."),
    append(el("div", "card-actions"), revoke),
    sure);
}

function keyAccess(peer) {
  if (peer.keyAccess) {
    return peer.keyAccess;
  }

  return peer.mayUseKeys ? "all of them" : "none";
}

function projectRow(project) {
  return ui.row(project.live ? "project" : "project kept",
    project.projectId
      ? () => {
          location.href = projectURL(project.fingerprint, project.projectId);
        }
      : null,
    ui.icon("book", "kind"),
    ui.stack(
      ui.title(project.name || project.peer),
      ui.sub(project.state),
      project.error ? el("div", "row-warn", project.error) : null));
}

// settings is this instance: who it is to everything else, where its files are,
// and the two things that can be done to the store from here.
//
// Its own fingerprint is on this screen because a pairing is confirmed by
// comparing two of them and the other machine is showing this one. It is the only
// screen where somebody reads their own — which is why it is here rather than on
// the home screen, the way the phone puts it under "This phone".
export function settings(state) {
  const body = [];
  const instance = state.instance;
  const lock = instance.lock || {};

  body.push(ui.card("identity",
    append(el("div", "card-head"),
      ui.avatar(instance.fingerprint, 56),
      ui.stack(
        ui.title(instance.name || "This machine"),
        ui.sub("This is the machine you are looking at")),
      ui.pill(state.attached ? lock.state || "" : "not attached"))));

  body.push(ui.heading("Identity"));
  body.push(ui.card(null,
    ui.fingerprint(instance.fingerprint, true),
    ui.note("The other machine shows this when you pair. They have to match.")));

  body.push(ui.heading("The store"));
  body.push(ui.card(null,
    el("div", "row-title", lock.reason
      ? (lock.state || "") + " — " + lock.reason
      : lock.state || "unknown"),
    ui.note("Locking suspends approving here without forgetting anything, and a "
      + "paired approver can still answer for this machine. Sealing wipes the "
      + "key from memory: the agent offers nothing until it is unlocked."),
    state.lockControls()));

  const locations = instance.locations || [];

  if (locations.length) {
    body.push(ui.heading("Where things are"));
    body.push(ui.card(null, facts(grouped(locations))));
  }

  body.push(ui.heading("The daemon"));

  const reload = el("button", null, "Reload the store and the policy");
  const reloaded = ui.note("");
  reloaded.hidden = true;

  reload.onclick = () => {
    reload.disabled = true;

    bridge
      .reload()
      .then(() => {
        reload.disabled = false;
        reloaded.textContent = "Re-read from disk.";
        reloaded.hidden = false;
      })
      .catch((error) => {
        reload.disabled = false;
        reloaded.textContent = error.message;
        reloaded.hidden = false;
      });
  };

  body.push(ui.card(null,
    ui.note("This window draws what the daemon says and answers for it; the "
      + "keys, the agent socket and the approval engine are its."),
    append(el("div", "card-actions"), reload),
    reloaded));

  return { title: "Settings", body };
}
