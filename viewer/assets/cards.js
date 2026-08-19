// Request cards. Every kind of request the approval engine produces has one,
// and the git card is the reason M2 exists: repository, branch, author, the
// whole message, the diffstat, and the diff behind it.
//
// The card's job beyond showing the facts is showing where they came from. The
// commit is derived from the bytes being signed and is provable; the repository,
// the branch and the diff are the requesting machine's word for it. §5 says the
// UI has to say which is which, and that is what the provenance line does.

import { el, append, facts, warnings, section } from "./dom.js";
import { renderDiff, attachDiffFetch } from "./diff.js";
import { projectURL } from "./projects.js";

export function renderCard(request) {
  const root = el("div", "card");

  append(root,
    el("h1", null, request.title),
    request.subject ? el("p", "subject", request.subject) : null);

  for (const node of warnings(request.warnings, request.danger)) {
    root.append(node);
  }

  // A body may return nodes, or {nodes, trailing} when it has something that
  // belongs below the key and the program — the diff, which is long and is the
  // last thing anyone reads.
  const body = (BODIES[request.kind] || renderGeneric)(request) || [];
  const nodes = body.nodes ? body.nodes : [].concat(body);

  append(root, ...nodes);
  append(root, facts(commonFacts(request)));
  append(root, ...(body.trailing || []));

  return root;
}

const BODIES = {
  "git-sign": renderGitSign,
  "ssh-auth": renderSSHAuth,
  sshsig: renderSshsig,
  "opaque-sign": renderOpaque,
  pairing: renderPairing,
  "key-list": renderGeneric,
};

function commonFacts(request) {
  const rows = [];

  if (request.key) {
    rows.push({ label: "Key", value: keyLabel(request.key) });
    rows.push({ label: "Fingerprint", value: request.key.fingerprint, mono: true });
  }

  if (request.requester) {
    if (request.requester.program) {
      rows.push({ label: "Program", value: request.requester.program, mono: true });
    }

    // Who asked, rather than which helper they asked through: ssh and
    // ladulas-sign read the same whoever ran them, and the session does not.
    if (request.requester.asker) {
      rows.push({ label: "Asked by", value: request.requester.asker });
    }

    if (request.requester.chain) {
      rows.push({ label: "Started by", value: request.requester.chain, mono: true });
    }

    if (!request.requester.local) {
      rows.push({ label: "Requested by", value: request.requester.name });
    }
  }

  return rows;
}

function keyLabel(key) {
  if (key.comment) {
    return key.label + " (" + key.comment + ")";
  }

  return key.label || key.fingerprint;
}

// The git card ------------------------------------------------------------

function renderGitSign(request) {
  const git = request.git;

  if (!git) {
    // A signature that came through the plain agent socket: the agent only ever
    // saw a digest, which is exactly why ladulas-sign exists (§5).
    return facts([
      { label: "Digest", value: request.sshsig && request.sshsig.digest, mono: true },
      { label: "Namespace", value: request.sshsig && request.sshsig.namespace },
    ]);
  }

  const nodes = [];

  nodes.push(provenance(git));

  nodes.push(facts([
    { label: "Repository", value: git.repository, asserted: true, mono: true },
    { label: "Remote", value: git.originUrl, asserted: true, mono: true },
    { label: "Branch", value: git.branch, asserted: true },
    { label: "Author", value: identity(git.author) },
    { label: "Committer", value: differentCommitter(git) },
    { label: "Tagger", value: identity(git.tagger) },
    { label: "Tag", value: git.tag },
    { label: "Tagged object", value: git.taggedObject, mono: true },
    { label: "Tree", value: git.tree, mono: true },
    { label: "Parents", value: (git.parents || []).join(", "), mono: true },
  ]));

  if (git.message) {
    nodes.push(el("pre", "message", git.message));
  }

  for (const header of git.extraHeaders || []) {
    nodes.push(el("p", "note-line",
      "The object carries a " + header.name + " header."));
  }

  const project = renderProjectNote(request.project);

  if (project) {
    nodes.push(project);
  }

  const trailing = git.diff
    ? section("Changes", attachDiffFetch(renderDiff(git.diff), request, git.diff))
    : [];

  return { nodes, trailing };
}

// renderProjectNote ties the request to the project it belongs to, and says how
// far the two have drifted apart (§6).
//
// It offers the way in whether or not anything has been read here. Browsing is
// a pull (decision Q), so the link works exactly when the machine that asked is
// reachable — and it is asking for a signature, so it is awake. The staleness
// label is the other half: pages read at one commit and a change built on
// another is the ordinary case, and an approver reading them to decide should
// know which state they describe.
function renderProjectNote(project) {
  if (!project || !project.projectId) {
    return null;
  }

  const node = el("p", project.stale ? "provenance stale" : "provenance");

  const open = el(
    "button",
    "doclink",
    project.known
      ? "Read the documentation for " + project.name
      : "Read what this machine publishes about it",
  );

  open.onclick = () => {
    location.href = projectURL(project.fingerprint, project.projectId);
  };

  node.append(open);
  node.append(el("span", "note-line", " " + project.note));

  return node;
}

// provenance is the sentence that keeps the whole rich prompt honest.
function provenance(git) {
  if (!git.verified) {
    return el("p", "warning danger",
      git.verificationError ||
        "The commit shown here was not checked against the payload being signed.");
  }

  const what = git.objectType === "tag" ? "tag" : "commit";

  return el("p", "provenance verified",
    "The " + what + " below was checked against the bytes being signed: the " +
      "message, author and timestamps are what the signature covers. The " +
      "repository, branch and diff are the requesting machine's account of " +
      "itself and are marked as such.");
}

function identity(who) {
  if (!who) {
    return "";
  }

  const parts = [];

  if (who.name && who.email) {
    parts.push(who.name + " <" + who.email + ">");
  } else if (who.name || who.email) {
    parts.push(who.name || who.email);
  }

  if (who.time) {
    parts.push(who.time + (who.timezone ? " " + who.timezone : ""));
  }

  return parts.join(", ");
}

function differentCommitter(git) {
  const committer = identity(git.committer);

  return committer === identity(git.author) ? "" : committer;
}

// The other cards ---------------------------------------------------------

function renderSSHAuth(request) {
  const auth = request.sshAuth || {};

  return facts([
    { label: "Destination", value: auth.destination },
    { label: "Host key", value: auth.hostKey, mono: true },
    { label: "Known hosts", value: auth.knownHosts },
    { label: "User name", value: auth.username },
    { label: "Path", value: (auth.path || []).join(" → ") },
  ]);
}

function renderSshsig(request) {
  const sig = request.sshsig || {};

  return facts([
    { label: "Namespace", value: sig.namespace },
    { label: "Hash", value: sig.hashAlgorithm },
    { label: "Digest", value: sig.digest, mono: true },
  ]);
}

function renderOpaque(request) {
  const opaque = request.opaque || {};

  return facts([
    { label: "Reason", value: opaque.reason },
    { label: "Length", value: opaque.length ? opaque.length + " bytes" : "" },
    { label: "Digest", value: opaque.digest, mono: true },
  ]);
}

// The pairing card shows both fingerprints, because that is the whole of what
// makes trust on first use trustworthy: the two machines display the same pair
// and their users agree that they match. A card showing only the other side's
// would be asking the user to confirm something with nothing to check it
// against (§7).
function renderPairing(request) {
  const pairing = request.pairing || {};
  const nodes = [];

  nodes.push(
    el(
      "p",
      "provenance",
      pairing.initiatedLocally
        ? "You started this pairing. Both machines should now be showing the same two fingerprints."
        : "This machine was asked to pair. Both machines should be showing the same two fingerprints.",
    ),
  );

  nodes.push(
    facts([
      { label: "This instance", value: pairing.localName },
      { label: "Its fingerprint", value: pairing.localFingerprint, mono: true },
      { label: "The other instance", value: pairing.name },
      { label: "Its fingerprint", value: pairing.fingerprint, mono: true },
      { label: "Connected from", value: pairing.address, mono: true },
      { label: "Reachable at", value: (pairing.addresses || []).join(", "), mono: true },
      // One sentence rather than two yes/no rows: what a pairing is for is a
      // single decision, taken on the machine that displayed the code, and the
      // wording is the core's so that every surface says it the same way.
      { label: "This pairing", value: pairing.direction },
    ]),
  );

  // Where that decision was taken, which is the half a reader cannot work out
  // from the sentence. The machine displaying the code chooses for both sides,
  // so on the side that used one there is nothing to change here — only a
  // pairing to decline and ask for again.
  nodes.push(
    el(
      "p",
      "provenance",
      pairing.initiatedLocally
        ? (pairing.name || "The other machine")
          + " chose what this pairing is for when it displayed the code. Changing it means pairing again."
        : "You chose what this pairing is for when you displayed the code.",
    ),
  );

  if (pairing.keyFromCode) {
    nodes.push(
      el(
        "p",
        "provenance",
        "The pairing code carried the other instance's identity, so its fingerprint has already been checked against the code.",
      ),
    );
  }

  return nodes;
}

function renderGeneric(request) {
  return facts(
    (request.details || []).map((detail) => ({
      label: detail.label,
      value: detail.value,
      asserted: detail.asserted,
    })),
  );
}
