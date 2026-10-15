// Adding a machine: the question a pairing asks, and the code that answers it.
//
// Pairing was a command line and nothing else until this screen. The window
// listed what was under way and could call one off, which is the half that has
// no card — but starting one meant a terminal, on a machine whose whole point is
// that the person using it is sitting in front of a window (§14).
//
// The screen is in two states and never both. First the question: what is this
// pairing for (decision AD), asked here because this is the side displaying the
// code and that side decides for both. Then the invitation: the six-digit PIN
// and the QR side by side (decision AV), and the full code under them to copy.
// Another desktop or a headless box types the PIN with the address; a phone
// points a camera at the picture; a window that cannot reach this one pastes
// the full code. For one release an older version still types the ten
// characters, labelled for what it is.
//
// The invitation is read again every couple of seconds while it is on screen,
// because what happens to a PIN while it is up is the thing worth seeing: each
// failed attempt, with where it came from, and — when the attempts are spent —
// that something is guessing, with a new PIN one press away.

import { el, append } from "./dom.js";
import { bridge } from "./bridge.js";
import * as ui from "./ui.js";

// The three intents, worded as what the pairing does rather than as which flag
// it sets. The words on the left are the core's (`trust.Intent`), and the
// sentence under each is what the other machine will be told it agreed to.
const INTENTS = [
  {
    value: "approver",
    icon: "approved",
    title: "It approves for this machine",
    detail:
      "Signing here asks that machine. Pair a phone or a desktop this way "
      + "so it can answer for this one.",
  },
  {
    value: "requester",
    icon: "sign",
    title: "This machine approves for it",
    detail:
      "That machine's signing asks this one. Pair a build box or a server "
      + "this way so its requests come here.",
  },
  {
    value: "mutual",
    icon: "link",
    title: "Both",
    detail: "Either machine can ask the other. Two machines you sit at.",
  },
];

// addMachine is the screen. It reads whether a code is already on display, so
// that leaving and coming back shows the code somebody is halfway through using
// rather than spending a second one on them.
export async function addMachine(state) {
  const panel = el("div", "cards");

  let live = null;

  try {
    live = await bridge.invitation();
  } catch (error) {
    if (error.status !== 404) {
      state.complain(error.message);
    }
  }

  let shown = null;

  const show = (invitation) => {
    shown = invitation;
    panel.replaceChildren(...invitation
      ? displayed(invitation, () => show(null), show, state)
      : chooser(show, state));
  };

  show(live);

  // What changes while a code is up is what knocked at it, whether it was
  // withdrawn, and whether it is still there at all. Anything else is the same
  // screen, and redrawing it would only take a half-finished copy away.
  const shape = (invitation) => invitation
    ? [invitation.pin, invitation.ended, (invitation.attempts || []).length].join("|")
    : "";

  const timer = setInterval(() => {
    if (!panel.isConnected) {
      clearInterval(timer);

      return;
    }

    if (!shown) {
      return;
    }

    bridge
      .invitation()
      .then((now) => {
        if (shape(now) !== shape(shown)) {
          show(now);
        }
      })
      .catch((error) => {
        if (error.status === 404) {
          show(null);
        }
      });
  }, 2000);

  return { title: "Add a machine", body: [panel] };
}

// chooser is the question, asked before anything is displayed.
function chooser(show, state) {
  const nodes = [ui.heading("What is this pairing for?")];
  const options = [];

  let chosen = "";

  const start = el("button", "primary", "Show a PIN");

  start.disabled = true;

  for (const intent of INTENTS) {
    const option = ui.row(
      "intent",
      () => {
        chosen = intent.value;
        start.disabled = false;

        for (const other of options) {
          other.setAttribute(
            "aria-pressed", other === option ? "true" : "false");
        }
      },
      ui.icon(intent.icon, "kind"),
      ui.stack(ui.title(intent.title), ui.sub(intent.detail)));

    option.setAttribute("aria-pressed", "false");

    options.push(option);
    nodes.push(option);
  }

  nodes.push(ui.card(null,
    ui.note("Whichever you choose settles both machines: the one that joins "
      + "is shown what it means and either agrees or does not. Changing it "
      + "afterwards means removing the machine and pairing again."),
    append(el("div", "card-actions"), start)));

  start.onclick = () => {
    start.disabled = true;

    bridge
      .invite(chosen)
      .then(show)
      .catch((error) => {
        start.disabled = false;
        state.complain(error.message);
      });
  };

  nodes.push(ui.heading("Or join a machine that is showing a PIN"));
  nodes.push(joinCard(state));

  return nodes;
}

// joinCard is the other end of the screen above: the PIN from a machine that
// has already answered the question, typed here with its address, or its full
// code pasted. It asks nothing about what the pairing is for, because that side
// decided (decision AD) — what this side agreed to is on the card that follows,
// beside the fingerprint to compare.
//
// One press is one attempt (decision AV). A refusal is shown and nothing is
// retried: each try is a guess the other machine counts, and trying the same
// PIN somewhere else would be a guess at a machine nobody picked.
function joinCard(state) {
  const code = field("PIN", "the six digits, or the full code", "text");
  const address = field("Address", "host:port — not needed for a full code", "text");
  const join = el("button", "primary", "Join");
  const said = ui.note("");

  said.hidden = true;

  join.onclick = () => {
    join.disabled = true;
    said.hidden = true;

    bridge
      .join(code.input.value, address.input.value)
      .then((joined) => {
        // The card is the confirmation, and it arrives the way every request
        // does; this only says to look for it. The fields are left as they
        // were, because a dial that worked is not a code to spend again.
        said.textContent = (joined && joined.message)
          || "The other machine answered. Compare the fingerprints on the card.";
        said.hidden = false;
        state.refresh();
      })
      .catch((error) => {
        join.disabled = false;
        said.textContent = error.message;
        said.hidden = false;
      });
  };

  return ui.card(null,
    code.root,
    address.root,
    ui.note("Type the PIN the other machine is showing and the address under "
      + "it. The full code — the long string under the PIN on the other "
      + "machine — carries its address and identity instead, so there is "
      + "nothing else to type. Either way both machines then show the same two "
      + "fingerprints, and somebody at each has to agree they match."),
    append(el("div", "card-actions"), join),
    said);
}

// field is a labelled input, the shape screens.js draws its sheets with.
function field(text, placeholder, type) {
  const root = el("label", "field");
  const input = document.createElement("input");

  input.type = type;
  input.placeholder = placeholder;

  append(root, el("span", "field-label", text), input);

  return { root, input };
}

// displayed is the PIN on screen, with the other ways to use it under it — or,
// when the attempts were spent, the sentence saying so and a new PIN.
function displayed(invitation, stopped, show, state) {
  if (invitation.ended) {
    return ended(invitation, stopped, show, state);
  }

  const nodes = [];

  // The PIN and the QR side by side, because they are the two ways in that a
  // person looks at (decision AE keeps the QR out from behind a disclosure —
  // it is the phone's only path).
  const pin = append(el("div", "pin-side"),
    el("div", "field-label", "PIN"),
    el("div", "code", invitation.pin || invitation.code),
    ui.note(invitation.expiresAt
      ? "Good until " + clockTime(invitation.expiresAt)
      + ", once, and then it is spent."
      : "Good once, and then it is spent."));

  const pair = append(el("div", "pairing-pair"), pin);

  if (invitation.qr) {
    const picture = document.createElement("img");

    picture.className = "qr";
    picture.alt = "The pairing code, as a QR for a phone camera";
    picture.src = invitation.qr;

    append(pair, append(el("div", "qr-side"), picture,
      ui.note("Scan it in the Ladulås app.")));
  }

  const code = ui.card("pairing-code", pair);

  // The full code under them: what a window that cannot see this one pastes,
  // and what the phone scans, as a string.
  append(code,
    ui.note("Or copy the full code into the other machine. It carries this "
      + "instance's identity and addresses, so nothing else needs typing."),
    ui.copyable(invitation.fullCode));

  // The ten characters, for one release, for the one kind of machine that
  // still needs them (decision AV).
  if (invitation.code && invitation.pin) {
    append(code,
      append(el("div", "older-code"),
        el("span", "field-label", "For older versions of Ladulås"),
        el("span", "mono", invitation.code)));
  }

  nodes.push(code);

  nodes.push(ui.card(null,
    el("div", "row-title", "The machine that joins " + invitation.direction),
    ui.note("Both machines will show the same two fingerprints, and somebody "
      + "at each of them has to agree they match. Nothing is written down "
      + "until then.")));

  const attempts = invitation.attempts || [];

  if (attempts.length > 0) {
    nodes.push(ui.heading("Failed attempts", attempts.length));
    nodes.push(ui.card(null,
      ui.warning("Somebody tried this code and got it wrong. If that was not "
        + "the machine you are pairing, look closely at the name on the card "
        + "that arrives."),
      ...attempts.map((attempt) => el("div", "mono address",
        (attempt.at ? clockTime(attempt.at) + "  " : "")
        + attempt.source + " — " + attempt.outcome))));
  }

  nodes.push(ui.heading("From a terminal"));
  nodes.push(ui.card(null,
    ui.copyable(invitation.join),
    ui.note("The address is the one this machine thinks is most likely to "
      + "work; the rest are below.")));

  if (invitation.olderJoin) {
    nodes.push(ui.card(null,
      ui.copyable(invitation.olderJoin),
      ui.note("The same from an older version of Ladulås, which cannot take a "
        + "PIN.")));
  }

  if ((invitation.addresses || []).length > 1) {
    nodes.push(ui.heading("This machine is reachable at"));
    nodes.push(ui.card(null, ...invitation.addresses.map(
      (address) => el("div", "mono address", address))));
  }

  const stop = el("button", "danger small", "Stop showing this PIN");

  stop.onclick = () => {
    stop.disabled = true;

    bridge
      .stopPairing()
      .then(stopped)
      // A code that could not be withdrawn is one still on offer, and saying
      // it stopped would be the one wrong thing to say about a live secret.
      .catch(() => {
        stop.disabled = false;
        stop.textContent = "It is still on offer — try again";
      });
  };

  nodes.push(append(el("div", "card-actions"), stop));

  return nodes;
}

// ended is a code withdrawn because its attempts were spent (decision AV). It
// says so rather than closing quietly, and the way on is a new PIN for the same
// pairing — the question was answered, and nothing about guessing changes it.
function ended(invitation, stopped, show, state) {
  const again = el("button", "primary", "Show a new PIN");
  const done = el("button", "small", "Stop");

  again.onclick = () => {
    again.disabled = true;

    bridge
      .invite(invitation.intent)
      .then(show)
      .catch((error) => {
        again.disabled = false;
        state.complain(error.message);
      });
  };

  done.onclick = () => {
    bridge.stopPairing().then(stopped, stopped);
  };

  const attempts = invitation.attempts || [];

  return [ui.card(null,
    ui.warning(invitation.ended, true),
    ...attempts.map((attempt) => el("div", "mono address",
      attempt.source + " — " + attempt.outcome)),
    append(el("div", "card-actions"), again, done))];
}

// clockTime is when a code stops working, in the reader's own locale. It is the
// one time this bundle formats rather than being handed as a sentence, because
// what it means is "look at the clock on the wall".
function clockTime(stamp) {
  const at = new Date(stamp);

  if (Number.isNaN(at.getTime())) {
    return "";
  }

  return at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
