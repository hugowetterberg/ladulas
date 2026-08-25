// One request, with the buttons that answer it.
//
// It is a module rather than part of the popup because the popup is not the only
// place a request is answered any more: the desktop shell's home screen lists
// what is waiting and opens the same card in its pane (decision AA), and the
// popup opens it on its own. Two renderings of a question that is being answered
// under a signature would be exactly the drift §5 exists to prevent — so there
// is one, and the host says what happens after the answer.

import { el, append, facts } from "./dom.js";
import { bridge } from "./bridge.js";
import { renderCard } from "./cards.js";
import { icon } from "./ui.js";

// renderPrompt draws the card and the answer. `done` is called with the decision
// once the instance has taken it, which is where a host decides what a window
// that has served its purpose should do.
export function renderPrompt(request, done) {
  const card = renderCard(request);
  const actions = el("div", "actions");
  const buttons = [];

  function answer(decision, grantSeconds, grantScope) {
    for (const button of buttons) {
      button.disabled = true;
    }

    bridge
      .answer(request.id, decision, grantSeconds, grantScope)
      .then(() => done(decision, null))
      .catch((error) => done(decision, error));
  }

  // A pairing is answered once and for good, so it is worded as what it does
  // rather than as an approval with a length left off. There is no offer under
  // it either — the core sends none for a kind nothing can be promised about
  // (§9) — and "approve once" beside no "approve for a while" reads as a
  // choice somebody made rather than the only answer there is.
  const pairing = request.kind === "pairing";

  const approve = el("button", "approve", pairing ? "Pair" : "Approve once");
  approve.onclick = () => answer("approve", 0);

  const deny = el("button", "deny", pairing ? "Don’t pair" : "Deny");
  deny.onclick = () => answer("deny", 0);

  buttons.push(approve, deny);
  actions.append(approve, deny);

  // The answer sits in a footer that stays at the bottom of whatever is
  // scrolling the card, because a card is as long as the diff in it and the
  // buttons used to be underneath that: on any commit worth reading, answering
  // meant scrolling past the whole change first, and the one thing a prompt
  // must never be is hard to say no to. Sticky rather than fixed, so it belongs
  // to the card wherever the card is drawn — the popup, where the page scrolls,
  // and the shell's pane, where the pane does (decision AA).
  const footer = el("div", "answer");

  footer.append(actions);

  if (request.grant) {
    const offer = grantOffer(request.grant, answer, buttons);

    // The trust note stays in the body rather than riding along in the footer.
    // It is prose to be read before making a promise (decision X), not a
    // control, and a footer that grows a paragraph is a footer that eats the
    // card it is pinned to. It is still the last thing above the choices.
    if (offer.trust) {
      card.append(offer.trust);
    }

    footer.append(offer.controls);
  }

  card.append(footer);

  return { card, approve, deny, answer };
}

// grantOffer is "approve for a while", asked as the two questions it is
// (decision V): who the promise is made to, and then how long it runs.
//
// It used to be four buttons whose labels answered both at once, which meant the
// wider promise could not be offered at all and the lengths were whatever
// somebody had written down. Here the reach is a choice — the session the request
// came from, or the machine it came from — and the length is a clock bounded by
// what the instance will promise.
//
// It returns the two halves apart, because they are drawn in different places:
// the controls go in the pinned footer with the other buttons, and the trust
// note stays in the body above it.
function grantOffer(offer, answer, buttons) {
  const root = el("div", "grant-offer");
  const choices = el("div", "actions");
  const picker = el("div", "grant-picker");

  const clock = document.createElement("input");
  clock.type = "time";
  clock.step = 60;
  clock.min = "00:01";
  clock.max = clockValue(offer.maxSeconds);
  clock.value = clockValue(Math.min(3600, offer.maxSeconds));

  const confirm = el("button", "grant", "");
  const promise = el("p", "promise", "");

  let scope = null;

  function chosen() {
    const [hours, minutes] = clock.value.split(":").map(Number);

    return (hours || 0) * 3600 + (minutes || 0) * 60;
  }

  function refresh() {
    const seconds = chosen();

    confirm.textContent = "Approve for " + humanDuration(seconds);
    confirm.disabled = seconds < 60 || seconds > offer.maxSeconds;
  }

  clock.oninput = refresh;

  confirm.onclick = () => answer("approve", chosen(), scope);

  // The wider reach is worded as the session being dropped, not as a place being
  // opened up. It said "anywhere on guppy", and that was read as a promise about
  // the machine — where the scope keeps the repository, the destination host and
  // the user name it was made under, and only stops asking which window the
  // request came from. "Anywhere" named the one part of the scope that does not
  // widen, which on a commit is the part that matters most.
  for (const choice of [
    offer.session ? { scope: "session", label: offer.session } : null,
    { scope: "machine", label: "any session on " + offer.machine },
  ]) {
    if (!choice) {
      continue;
    }

    // The clock is the shell's drawn one rather than the ⏲ character it used to
    // be. A glyph is whatever font the system substitutes for it, and the one
    // this box picks draws a shape a few pixels across inside its em box — so
    // raising the font size raised the space around it and not the clock. A
    // stroked icon is sized by its box, takes the button's colour, and is the
    // same clock the sidebar and the activity list already use.
    const button = el("button", "grant");

    append(button, icon("clock"), el("span", "grant-label", choice.label));

    button.onclick = () => {
      scope = choice.scope;
      promise.textContent = "Approve everything like this from " + choice.label + " for:";
      picker.hidden = false;

      for (const other of choices.children) {
        other.setAttribute("aria-pressed", other === button ? "true" : "false");
      }

      refresh();
      clock.focus();
    };

    buttons.push(button);
    choices.append(button);
  }

  buttons.push(confirm);
  picker.append(promise, clock, confirm);
  picker.hidden = true;

  root.append(choices, picker);

  // The trust note comes before the choices: what a timed promise leans on is
  // worth reading before deciding to make one, not after (decision X). It is
  // returned rather than nested so that the caller can leave it in the scrolling
  // body while the choices go in the footer, which keeps that order on screen.
  return { trust: offer.trust ? grantTrust(offer.trust) : null, controls: root };
}

// grantTrust is the note a timed promise carries when its scope would pin
// something the requesting machine only asserted (decision X): the facts it
// would take on the peer's word, a line saying so, and the fuller explanation
// behind a disclosure — the same (i) idiom the rest of the card uses for what a
// reader asks after the fact.
function grantTrust(trust) {
  const root = el("div", "grant-trust");

  const list = facts(trust.facts);
  if (list) {
    root.append(list);
  }

  root.append(el("p", "note", trust.note));

  if (trust.detail) {
    const more = el("details", "grant-trust-more");
    more.append(el("summary", null, "What a timed promise trusts"));
    more.append(el("p", null, trust.detail));
    root.append(more);
  }

  return root;
}

// clockValue is a length of time as the input reads one: hours and minutes, and
// never past the day it would wrap at.
function clockValue(seconds) {
  const bounded = Math.max(60, Math.min(seconds, 23 * 3600 + 59 * 60));
  const pad = (n) => String(n).padStart(2, "0");

  return pad(Math.floor(bounded / 3600)) + ":" + pad(Math.floor((bounded % 3600) / 60));
}

// humanDuration says a length the way the core says it, because the button and
// the grant it creates should read alike.
function humanDuration(seconds) {
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

// renderDecision is a decision already made: the card that was answered, what
// was done about it, and no buttons under it (§18).
//
// It is the same renderCard the prompt uses, over a request read back out of the
// log rather than one still waiting. Two renderers would drift, and a record of
// what somebody was shown that does not look like what they were shown is not
// much of a record.
export function renderDecision(detail) {
  const card = renderCard(detail.request);

  // What happened goes in the card, in the card's own vocabulary, rather than in
  // a second panel above it. The row that was clicked already said the outcome;
  // what this screen is for is the card under it.
  append(card, el("h2", null, "Decision"), facts([
    { label: "Outcome", value: detail.outcome },
    { label: "When", value: detail.whenAt || detail.when },
    { label: "Decided", value: detail.decided },
    { label: "Reason", value: detail.reason },
  ]));

  // The log's own line, under the card that says the same things better. It is
  // the text this instance committed to having put on screen, so it is here to
  // be read rather than taken on trust.
  if (detail.prompt) {
    append(card,
      el("h2", null, "What the log recorded"),
      el("pre", "message", detail.prompt));
  }

  return card;
}
