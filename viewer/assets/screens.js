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
import { documentsRoute } from "./projects.js";

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

  // A key a paired machine has handed this one is waiting for somebody here too,
  // and it is the half of a handover that this end alone can finish (decision
  // S). It is not in the section above because that one is approval requests,
  // each with a card and a popup of its own; this has neither and would
  // otherwise be visible only on the Keys screen. Drawn only when there is one.
  const offers = instance.offers || [];

  if (offers.length) {
    body.push(ui.heading("Keys handed to this instance", offers.length));

    for (const offer of offers) {
      body.push(offerRow(offer, state));
    }
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
  const offers = instance.offers || [];

  // A key a paired machine has handed this one is the only thing on this screen
  // that is a question rather than a fact, so it is above the answers (§12,
  // decision S). The section is drawn only when there is one: an instance
  // nobody has ever sent a key would otherwise carry a heading about a
  // mechanism instead of about itself.
  if (offers.length) {
    body.push(ui.heading("Handed to this instance", offers.length));
    body.push(ui.note("A paired machine has copied a key here. It is not in "
      + "the store, signs nothing and is offered to no agent until somebody "
      + "at this end accepts it."));

    for (const offer of offers) {
      body.push(offerRow(offer, state));
    }
  }

  body.push(ui.heading("In this instance's store", held.length));

  if (!held.length) {
    body.push(ui.empty("No keys",
      "The + above makes one in the daemon's store. This window shows keys "
      + "and never holds one."));
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

  // What other holders of a key have promised about a machine, and what this
  // instance is therefore signing without asking (decision AG).
  //
  // Listed whether or not this instance acts on it, and the reason it does not
  // is a line on the row rather than a reason to leave the row out. An
  // endorsement is carried by the requester and honoured by any holder, so a
  // screen that showed only the live ones would be a window unable to answer
  // "what is this machine signing under" — and a promise nobody can see is a
  // promise nobody can take back.
  const endorsements = instance.endorsements || [];
  const retractions = instance.retractions || [];

  if (endorsements.length || retractions.length) {
    body.push(ui.heading("Promises about these keys", endorsements.length));

    if (!endorsements.length) {
      body.push(ui.empty("Nothing standing",
        "Everything promised about these keys has been taken back or has run "
        + "out."));
    }

    for (const item of endorsements) {
      body.push(endorsementCard(item, state));
    }

    for (const item of retractions) {
      body.push(retractionCard(item));
    }
  }

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

  return {
    title: "Keys",
    actions: [ui.action("plus", "Make a new key", () => newKeySheet(state))],
    body,
  };
}

// endorsementCard is one promise another holder of a key has made about a
// machine (decision AG).
//
// It leads with who promised what to whom, because those are the three facts
// somebody reading this screen is checking — and it carries the reason this
// instance would not act on it, when it would not, since a copy carried to
// present elsewhere and a promise being kept here look identical otherwise.
function endorsementCard(item, state) {
  // A promise this instance does not act on is not a warning and is not drawn
  // as one: a copy carried to present elsewhere is inert here by construction,
  // and the pill already says which it is.
  const root = ui.card("grant-card");

  append(root, append(el("div", "card-head"),
    ui.icon("taken", "kind"),
    ui.stack(
      ui.title(item.description || "A promise about a key"),
      ui.sub(item.expires + " · from " + item.issuer
        + " · for " + item.requester)),
    item.useCount ? el("span", "count", String(item.useCount)) : null,
    ui.pill(item.live ? "signing" : "not applied here")));

  root.append(ui.fingerprint(item.key, true));

  if (!item.live) {
    root.append(ui.note(capitalise(item.inertBecause) + "."));
  } else if (!item.published) {
    // Worth saying out loud. A promise that arrived on the request that spent
    // it was never visible before it was spent, which is the state publishing
    // exists to avoid and cannot always reach.
    root.append(ui.note("This arrived with a request rather than being "
      + "published ahead of one, so it was first seen as it was first used."));
  }

  if (item.unreported) {
    root.append(ui.note(item.unreported + " of those have not been reported "
      + "to " + item.issuer + " yet."));
  }

  root.append(append(el("div", "card-actions"), retractButton(item, state)));

  return root;
}

// retractButton takes one back, and asks twice.
//
// Twice for the reason revoking a pairing does: what it cannot do is reach the
// holders it could not reach, so a retraction is a thing that half-happens and
// then has to be understood. It is not the press that is dangerous — it is
// believing it finished.
function retractButton(item, state) {
  const button = el("button", "danger small", "Take it back");

  let asked = false;

  button.onclick = () => {
    if (!asked) {
      asked = true;
      button.textContent = "Take it back from every holder that answers";

      return;
    }

    button.disabled = true;
    button.textContent = "Telling the holders…";

    bridge
      .retractEndorsement(item.id, item.key, "taken back at the desktop")
      .then((result) => {
        state.refresh();
        retractionResult(item, result, state);
      })
      .catch((error) => {
        button.disabled = false;
        asked = false;
        button.textContent = "Take it back";
        state.complain(error.message);
      });
  };

  return button;
}

// retractionResult says what actually happened, which is not always what was
// asked for.
//
// A holder that could not be reached goes on honouring the promise until it
// expires or until somebody gets through — and it is told by any holder that
// has the retraction, not only by this one, because retractions gossip. Saying
// "done" over that would be the one wrong claim available here.
function retractionResult(item, result, state) {
  const told = (result && result.told) || [];
  const unreached = (result && result.unreached) || [];

  const sheet = ui.sheet("Taken back",
    ui.note("It is gone from this machine, and " + item.requester
      + " cannot spend it here again whatever it presents."));

  const body = sheet.querySelector(".sheet-body");

  if (told.length) {
    body.append(ui.heading("Told", told.length));

    for (const holder of told) {
      body.append(ui.card(null, ui.fingerprint(holder, true)));
    }
  }

  if (unreached.length) {
    body.append(ui.heading("Could not be reached", unreached.length));

    for (const holder of unreached) {
      body.append(ui.card(null, ui.fingerprint(holder, true)));
    }

    body.append(ui.warning("Those are still honouring it. The retraction "
      + "reaches them when they are next in touch — with this machine or with "
      + "any other holder that has it — and the promise runs out on its own "
      + "whether or not anybody gets through.", true));
  }

  if (!told.length && !unreached.length) {
    body.append(ui.note("No other holder of that key is known here, so there "
      + "was nobody to tell."));
  }

  state.refresh();
}

// retractionCard is a promise that has been taken back, kept on screen until
// what it took back would have expired anyway.
//
// It is on this screen rather than tidied away because an endorsement is
// carried by the requester: the machine will present the promise again, and the
// only reason that presentation does nothing is this record.
function retractionCard(item) {
  return ui.card("grant-card",
    append(el("div", "card-head"),
      ui.icon("denied", "kind bad"),
      ui.stack(
        ui.title("Taken back: " + item.target),
        ui.sub("by " + item.issuer + (item.reason ? " — " + item.reason : ""))),
      ui.pill("retracted")),
    ui.fingerprint(item.key, true),
    ui.note("Remembered until " + item.until + ", so that a copy presented "
      + "after this is refused rather than honoured."));
}

function capitalise(text) {
  const value = String(text || "");

  return value.charAt(0).toUpperCase() + value.slice(1);
}

// offerRow is one key waiting to be answered, and answering it is a sheet
// rather than two buttons on the row.
//
// Accepting is the one thing this window does that puts key material into the
// store, and what makes it safe to do is comparing the fingerprint with the
// machine that sent it — which is not something a row has room for. The sheet
// is where the fingerprint, the sender and what accepting costs are all on
// screen at the moment the button is pressed.
function offerRow(offer, state) {
  return ui.row("wants-answer",
    () => offerSheet(offer, state),
    ui.icon("taken", "kind"),
    ui.stack(
      ui.title(offer.label || "A key"),
      ui.sub("From " + offer.peer)),
    ui.ticking(el("span", "when"), offer.receivedAt));
}

// offerSheet takes a key into the store, or forgets it (decision S).
//
// Both answers are final in their own direction and the sheet says so rather
// than asking twice: accepting means the key exists on two machines from then
// on and there is no un-sending it, and refusing keeps nothing here — the
// sender is not told, still holds the key, and would have to send it again.
//
// The name is a field because the store refuses a label it already holds, and
// the sender chose this one on a machine that could not know what is here. It
// starts as the sender's, which is what the command line does when nobody says
// otherwise.
function offerSheet(offer, state) {
  const name = field("Name here", offer.label || "a key", "text");

  name.input.value = offer.label || "";

  const accept = el("button", "primary", "Accept the key");
  const refuse = el("button", "danger", "Refuse and forget it");
  const said = ui.note("");

  said.hidden = true;

  const sheet = ui.sheet("A key from " + offer.peer,
    ui.card("key-card",
      append(el("div", "card-head"),
        ui.icon("key", "kind"),
        ui.stack(
          ui.title(offer.label || "A key"),
          offer.comment ? ui.sub(offer.comment) : null),
        offer.algorithm ? el("span", "algorithm", offer.algorithm) : null),
      ui.fingerprint(offer.fingerprint, true)),
    ui.note("Compare that fingerprint with the machine that sent it. Nothing "
      + "else about this key was checked: the transfer proves which paired "
      + "machine it came from and not which key was meant."),
    facts([
      { label: "Sent by", value: offer.peer },
      { label: "Its fingerprint", value: offer.peerFingerprint, mono: true },
      { label: "Arrived", value: offer.received },
    ]),
    ui.heading("Accepting"),
    name.root,
    ui.note("Accepting copies the private half into this instance's store, "
      + "where it signs like any other key. The key then exists on both "
      + "machines and nothing can take it back — a key sent to the wrong "
      + "machine has to be rotated, exactly like one that leaked. Refusing "
      + "keeps nothing here; " + offer.peer + " is not told and still holds "
      + "it."),
    append(el("div", "card-actions"), accept, refuse),
    said);

  const answer = (yes) => {
    accept.disabled = true;
    refuse.disabled = true;
    said.hidden = true;

    bridge
      .answerKeyOffer(offer.id, yes, yes ? name.input.value : "")
      .then(() => {
        sheet.close();
        state.refresh();
      })
      .catch((error) => {
        accept.disabled = false;
        refuse.disabled = false;
        said.textContent = error.message;
        said.hidden = false;
      });
  };

  accept.onclick = () => answer(true);
  refuse.onclick = () => answer(false);

  name.input.focus();
}

// newKeySheet makes a key in the daemon's store, behind the + in the title bar
// (decision AF).
//
// A name and, optionally, the comment that rides along in the public half —
// which is what an `authorized_keys` line says the key is, so it is worth
// filling in and is nobody's secret. Importing an existing key is not here:
// that is a file to pick and a passphrase to type into a webview, and `ladulas
// keys import` is where both belong (decision S).
//
// It used to be a card on the screen, above the keys. Two things were wrong
// with that and only one of them was the clutter: an empty form is not what
// somebody who opened Keys came to read, and a text box on a screen the poll
// repaints is a box that empties itself, which is why Keys had to be taken out
// of the redrawn set to hold it (shell.js).
function newKeySheet(state) {
  const label = field("Name", "work", "text");
  const comment = field("Comment", "hugo@guppy", "text");
  const make = el("button", "primary", "Generate a key");
  const said = ui.note("");

  said.hidden = true;

  const sheet = ui.sheet("Make a new key",
    label.root,
    comment.root,
    ui.note("An ed25519 key, generated by the daemon and kept in its "
      + "encrypted store. Nothing offers it to an agent or lends it to a "
      + "paired machine until you say so."),
    append(el("div", "card-actions"), make),
    said);

  make.onclick = () => {
    make.disabled = true;
    said.hidden = true;

    bridge
      .generateKey(label.input.value, comment.input.value)
      .then(() => {
        // The confirmation is the key itself, at the bottom of the list the
        // sheet was covering — so this closes rather than reporting a
        // fingerprint nobody can compare with anything yet.
        sheet.close();
        state.refresh();
      })
      .catch((error) => {
        make.disabled = false;
        said.textContent = error.message;
        said.hidden = false;
      });
  };

  label.input.focus();
}

// signTimeoutCard is how long somebody has to answer a signing request, and the
// way to change it (§9).
//
// It is a fact with a button rather than a box on the screen, because the pane
// is repainted every four seconds and a repaint empties a field somebody is
// halfway through (decision AF). The form is in a sheet, where the poll cannot
// reach it.
function signTimeoutCard(state, settings) {
  const change = el("button", null, "Change");

  change.onclick = () => signTimeoutSheet(state, settings);

  const card = ui.card(null,
    el("div", "row-title",
      "Signing requests wait up to " + ui.duration(settings.signTimeoutSeconds)),
    ui.note("How long git and ssh-keygen block while somebody answers. It is "
      + "meant to be long: a request that gives up costs the commit, and the "
      + "person answering may be in another room. An SSH login keeps its own "
      + "much shorter budget, because the server at the other end is counting "
      + "too."),
    append(el("div", "card-actions"), change));

  if (settings.policyPath) {
    card.append(ui.note("Kept in " + settings.policyPath + "."));
  }

  return card;
}

// signTimeoutSheet asks for the length on a clock, the way a promise is asked
// for (decision V) — the two are the same question about the same kind of
// thing, and a second idiom for it would be a second thing to learn.
function signTimeoutSheet(state, settings) {
  const clock = document.createElement("input");

  clock.type = "time";
  clock.step = 60;
  clock.min = ui.clockValue(settings.minSignTimeoutSeconds);
  clock.max = ui.clockValue(settings.maxSignTimeoutSeconds);
  clock.value = ui.clockValue(settings.signTimeoutSeconds);

  const save = el("button", "primary", "");
  const said = ui.note("");
  const quick = el("div", "card-actions");

  said.hidden = true;

  function chosen() {
    return ui.clockSeconds(clock.value);
  }

  function refresh() {
    const seconds = chosen();

    save.textContent = "Wait up to " + ui.duration(seconds);
    save.disabled =
      seconds < settings.minSignTimeoutSeconds ||
      seconds > settings.maxSignTimeoutSeconds;
  }

  clock.oninput = refresh;

  // The lengths worth one tap, including the one it goes back to. A default
  // offered as a number nobody has to know is the difference between putting a
  // setting back and guessing at what it was.
  const suggestions = [300, 900, 3600, 4 * 3600];

  if (!suggestions.includes(settings.defaultSignTimeoutSeconds)) {
    suggestions.push(settings.defaultSignTimeoutSeconds);
  }

  suggestions.sort((a, b) => a - b);

  for (const seconds of suggestions) {
    if (seconds < settings.minSignTimeoutSeconds ||
        seconds > settings.maxSignTimeoutSeconds) {
      continue;
    }

    const label = seconds === settings.defaultSignTimeoutSeconds
      ? ui.duration(seconds) + " (the default)"
      : ui.duration(seconds);

    const button = el("button", null, label);

    button.onclick = () => {
      clock.value = ui.clockValue(seconds);
      refresh();
    };

    quick.append(button);
  }

  const sheet = ui.sheet("How long a signing request waits",
    append(el("label", "field"),
      el("span", "field-label", "Hours and minutes"), clock),
    quick,
    ui.note("Requests already waiting keep the length they started with. "
      + "This is for the next one."),
    append(el("div", "card-actions"), save),
    said);

  save.onclick = () => {
    save.disabled = true;
    said.hidden = true;

    bridge
      .setSignTimeout(chosen())
      .then(() => {
        sheet.close();
        state.refresh();
      })
      .catch((error) => {
        save.disabled = false;
        said.textContent = error.message;
        said.hidden = false;
      });
  };

  refresh();
  clock.focus();
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

  return {
    title: found.name,
    actions: [ui.action("gear", "The pairing",
      () => pairingSheet(found, state, go))],
    body,
  };
}

// pairingSheet is what the cog on the peer screen opens (decision AF): what the
// pairing is, and the one way to end it.
//
// Both were down the screen, under everything a peer is *for* — the keys it
// lends and what it publishes — and they belong together rather than apart. The
// facts are read once, when two machines are being compared or somebody is
// working out why a peer cannot be reached; ending the pairing is read once
// ever. What a person opens a peer for is what it does, and neither of these
// is that.
function pairingSheet(peer, state, go) {
  const sheet = ui.sheet("Paired with " + peer.name,
    ui.card(null, facts([
      { label: "Fingerprint", value: peer.fingerprint, mono: true },
      { label: "May use keys", value: keyAccess(peer) },
      ...(peer.addresses || []).map((address, index) => ({
        label: index === 0 ? "Addresses" : "",
        value: address,
        mono: true,
      })),
      // Only for a peer this instance dials: for one that dials in, the screen
      // behind this has already said it, in a sentence rather than as a row.
      peer.dialable
        ? { label: "Last connected", value: peer.lastSeen }
        : null,
    ]),
    ui.note("The fingerprint is what the two machines compared when they "
      + "paired.")),
    ui.heading("End the pairing"),
    revokeCard(peer, state, () => {
      sheet.close();
      go("home");
    }));

  return sheet;
}

// revokeCard forgets a machine, and asks twice before it does.
//
// Twice because this is the one thing on any of these screens that cannot be
// undone by doing it again: it drops the direction, the keys the pairing lent,
// the promises made under it and the connection it is holding, and getting any
// of it back means pairing from scratch at both machines. The second press is
// what a stray click cannot produce.
function revokeCard(peer, state, done) {
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
        done();
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
          // From here, leaving a document goes back to this machine rather
          // than to the Documents section (readerBack in shell.js).
          location.hash = documentsRoute(
            project.fingerprint, project.projectId, { from: "peer" });
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

  if (instance.settings) {
    body.push(ui.heading("Approvals"));
    body.push(signTimeoutCard(state, instance.settings));
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
