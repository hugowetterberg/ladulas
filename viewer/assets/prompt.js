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

  const approve = el("button", "approve", "Approve once");
  approve.onclick = () => answer("approve", 0);

  const deny = el("button", "deny", "Deny");
  deny.onclick = () => answer("deny", 0);

  buttons.push(approve, deny);
  actions.append(approve, deny);

  card.append(actions);

  if (request.grant) {
    card.append(grantOffer(request.grant, answer, buttons));
  }

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

  for (const choice of [
    offer.session ? { scope: "session", label: offer.session } : null,
    { scope: "machine", label: "anywhere on " + offer.machine },
  ]) {
    if (!choice) {
      continue;
    }

    const button = el("button", "grant", "⏲ " + choice.label);

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

  // The trust note comes before the choices: what a timed promise leans on is
  // worth reading before deciding to make one, not after (decision X).
  if (offer.trust) {
    root.append(grantTrust(offer.trust));
  }

  root.append(choices, picker);

  return root;
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
