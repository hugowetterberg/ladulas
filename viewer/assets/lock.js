// The unlock panel, and the lock buttons that go with it (§10).
//
// A host opens /?unlock=1 when its store is sealed and there is a screen to ask
// on. The panel is deliberately plain: one field, one button, and a sentence
// saying what state the store is in and what that means — because the person
// reading it has just found that their agent stopped working and wants to know
// why before they want to know anything else.

import { el, append } from "./dom.js";
import { bridge } from "./bridge.js";

const UNINITIALISED = "not created yet";
// The desktop application is a client of a daemon (decision Z), so "there is
// nothing to be in a state" is a state it can be in — at login, before the user
// unit is up, and for as long as somebody has stopped it.
const NOT_RUNNING = "not running";

const WORDS = {
  sealed: "The store is sealed. Its key is not in memory: the agent offers no " +
    "keys, and paired instances cannot reach this one.",
  locked: "The store is locked. The keys are still here and a paired approver " +
    "can still answer for this machine; nothing here can.",
  unlocked: "The store is unlocked.",
  [UNINITIALISED]: "This instance has no store yet. `ladulas init` creates " +
    "one, and the instance picks it up without restarting.",
  [NOT_RUNNING]: "No Ladulås daemon is listening on this machine. The desktop " +
    "application draws what a daemon tells it and answers for it; it does not " +
    "hold the keys itself. Start one with `systemctl --user start ladulas`, " +
    "and this window attaches to it on its own.",
};

function heading(state) {
  if (state === UNINITIALISED) {
    return "No store yet";
  }

  if (state === NOT_RUNNING) {
    return "Nothing is running";
  }

  return state === "locked" ? "Locked" : "Sealed";
}

export function renderUnlock(state, onDone) {
  const root = el("div", "card unlock");

  append(root,
    el("h1", null, heading(state.state)),
    el("p", null, WORDS[state.state] || ""));

  if (state.state === "unlocked") {
    append(root, el("p", "empty", "Nothing to unlock."));

    return root;
  }

  // There is nothing to type a passphrase into before there is a store to wrap
  // with one — or when there is no daemon holding one — so the panel says what
  // to do instead of offering a field that could only ever fail.
  if (state.state === UNINITIALISED || state.state === NOT_RUNNING) {
    return root;
  }

  const message = el("p", "warning");
  message.hidden = true;

  const field = document.createElement("input");
  field.type = "password";
  field.className = "passphrase";
  field.autocomplete = "current-password";
  field.placeholder = "Store passphrase";

  const actions = el("div", "actions");
  const unlock = el("button", "approve", "Unlock");

  function submit(passphrase) {
    unlock.disabled = true;
    message.hidden = true;

    bridge
      .unlock(passphrase)
      .then((next) => {
        field.value = "";

        if (typeof onDone === "function") {
          onDone(next);
        }
      })
      .catch((error) => {
        unlock.disabled = false;
        message.textContent = error.message;
        message.hidden = false;
        field.select();
      });
  }

  unlock.onclick = () => submit(field.value);

  field.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      submit(field.value);
    }
  });

  actions.append(unlock);

  // An instance that unlocks at login has a second way in that needs nothing
  // typed, and offering it is the whole of what the enrolment bought.
  if (state.keyringEnrolled) {
    const keychain = el("button", "grant", "Unlock from the keychain");
    keychain.onclick = () => submit("");

    actions.append(keychain);
  }

  append(root, field, actions, message);

  if (!state.passphrase && !state.keyringEnrolled) {
    append(root, el("p", "warning danger",
      "This store has no passphrase wrapping and no keychain entry. " +
      "It cannot be opened here."));
  }

  field.focus();

  return root;
}

// lockControls are the buttons on the status pane: lock, seal, or unlock,
// depending on where the store is now.
export function lockControls(state, onDone) {
  if (!state || state.state === UNINITIALISED) {
    return null;
  }

  const actions = el("div", "actions");

  function run(promise) {
    promise
      .then((next) => {
        if (typeof onDone === "function") {
          onDone(next);
        }
      })
      .catch(() => {});
  }

  if (state.state === "unlocked") {
    const lock = el("button", "grant", "Lock");
    lock.onclick = () => run(bridge.lock(false));

    actions.append(lock);
  }

  if (state.state !== "sealed" && state.state !== NOT_RUNNING) {
    const seal = el("button", "deny", "Seal");
    seal.onclick = () => run(bridge.lock(true));

    actions.append(seal);
  }

  return actions;
}
