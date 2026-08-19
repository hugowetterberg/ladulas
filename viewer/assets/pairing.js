// Adding a machine: the question a pairing asks, and the code that answers it.
//
// Pairing was a command line and nothing else until this screen. The window
// listed what was under way and could call one off, which is the half that has
// no card — but starting one meant a terminal, on a machine whose whole point is
// that the person using it is sitting in front of a window (§14).
//
// The screen is in two states and never both. First the question: what is this
// pairing for (decision AD), asked here because this is the side displaying the
// code and that side decides for both. Then the invitation: the code itself, and
// the three ways into it, which are one secret seen by three kinds of machine —
// a terminal types the command, another window pastes the full string, a phone
// points a camera at the picture.

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

  const show = (invitation) => {
    panel.replaceChildren(...invitation
      ? displayed(invitation, () => show(null))
      : chooser(show, state));
  };

  show(live);

  return { title: "Add a machine", body: [panel] };
}

// chooser is the question, asked before anything is displayed.
function chooser(show, state) {
  const nodes = [ui.heading("What is this pairing for?")];
  const options = [];

  let chosen = "";

  const start = el("button", "primary", "Show a pairing code");

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

  return nodes;
}

// displayed is the code on screen, with the three ways to use it under it.
function displayed(invitation, stopped) {
  const nodes = [];

  nodes.push(ui.card("pairing-code",
    el("div", "code", invitation.code),
    ui.note(invitation.expiresAt
      ? "Good until " + clockTime(invitation.expiresAt)
      + ", once, and then it is spent."
      : "Good once, and then it is spent.")));

  nodes.push(ui.card(null,
    el("div", "row-title", "The machine that joins " + invitation.direction),
    ui.note("Both machines will show the same two fingerprints, and somebody "
      + "at each of them has to agree they match. Nothing is written down "
      + "until then.")));

  nodes.push(ui.heading("From a terminal"));
  nodes.push(ui.card(null,
    copyable(invitation.join),
    ui.note("The address is the one this machine thinks is most likely to "
      + "work; the rest are below.")));

  nodes.push(ui.heading("From another Ladulås window"));
  nodes.push(ui.card(null,
    ui.note("Paste this into the other machine's own Add a machine screen. It "
      + "carries this instance's identity, so that side has nothing left to "
      + "compare by hand."),
    copyable(invitation.fullCode)));

  if (invitation.qr) {
    nodes.push(ui.heading("From a phone"));

    const picture = document.createElement("img");

    picture.className = "qr";
    picture.alt = "The pairing code, as a QR for a phone camera";
    picture.src = invitation.qr;

    nodes.push(ui.card("qr-card", picture,
      ui.note("Scan it in the Ladulås app. It is the same code as above.")));
  }

  if ((invitation.addresses || []).length > 1) {
    nodes.push(ui.heading("This machine is reachable at"));
    nodes.push(ui.card(null, ...invitation.addresses.map(
      (address) => el("div", "mono address", address))));
  }

  const stop = el("button", "danger small", "Stop showing this code");

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

// copyable is a string somebody has to get onto another machine: selectable,
// and with a button for the case where the window is not where they are typing.
function copyable(text) {
  const root = el("div", "copyable");
  const button = el("button", "small", "Copy");

  button.onclick = () => {
    navigator.clipboard.writeText(text).then(
      () => {
        button.textContent = "Copied";
      },
      () => {
        // Some hosts have no clipboard to write to. The text is selectable
        // either way, which is what the button was a shortcut for.
        button.textContent = "Select it instead";
      },
    );
  };

  append(root, el("code", "mono", text), button);

  return root;
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
