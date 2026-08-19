// The bridge is the only thing the viewer talks to, and it is always the page's
// own origin: on the desktop that is Wails serving an in-process handler, on
// iOS a WKWebView scheme handler and on Android a WebView asset loader, each
// handing the same method, path and body to the same Go code. The viewer does
// not know or care which — that is what makes one bundle serve every host.

const base = "/api/v1";

async function call(method, path, body) {
  const options = { method, headers: { Accept: "application/json" } };

  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }

  const response = await fetch(base + path, options);

  if (response.status === 204) {
    return null;
  }

  const text = await response.text();
  let payload = null;

  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const error = new Error((payload && payload.error) || response.statusText);
    error.status = response.status;
    throw error;
  }

  return payload;
}

// encodePassphrase turns the typed passphrase into what a Go []byte field
// expects, which is base64. TextEncoder gives the UTF-8 bytes; btoa needs them
// one per character.
function encodePassphrase(passphrase) {
  const bytes = new TextEncoder().encode(passphrase || "");
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

export const bridge = {
  request: (id) => call("GET", "/requests/" + encodeURIComponent(id)),
  requests: () => call("GET", "/requests"),
  // A promise is a length and a reach, and the reach is sent because the
  // narrower of the two is what leaving it out means (decision V).
  answer: (id, decision, grantSeconds, grantScope) =>
    call("POST", "/requests/" + encodeURIComponent(id) + "/answer", {
      decision,
      grantSeconds: grantSeconds || 0,
      grantScope: grantScope || "",
    }),
  instance: () => call("GET", "/instance"),
  // One past decision, out of the audit log: the card that was answered, and
  // what was done about it (§18).
  activity: (entry) => call("GET", "/activity/" + encodeURIComponent(entry)),
  // Calling a pairing off, for the half of one that has no card: answering a
  // pairing is a request like any other, and this is the side that is waiting
  // for somebody at the other machine (§7).
  withdrawPairing: (session) =>
    call("POST", "/pairings/" + encodeURIComponent(session) + "/withdraw"),
  reload: () => call("POST", "/reload"),

  // The two things that can be done to a promise already made (decision P):
  // take it back, or give it longer. Revoking a delegated grant stops it when
  // its holder is next reached rather than at once, which is what the row that
  // offers this has to keep saying.
  revokeGrant: (id) =>
    call("POST", "/grants/" + encodeURIComponent(id) + "/revoke"),
  extendGrant: (id, seconds) =>
    call("POST", "/grants/" + encodeURIComponent(id) + "/extend", {
      seconds: seconds || 0,
    }),

  // The lock states (§10). An empty passphrase means "use the keychain", on an
  // instance that has enrolled one.
  lockState: () => call("GET", "/lock"),
  unlock: (passphrase) =>
    call("POST", "/lock/unlock", { passphrase: encodePassphrase(passphrase) }),
  lock: (seal) => call("POST", "/lock/lock", { seal: Boolean(seal) }),

  // The rest of a diff the request only carried part of (§5). An empty path
  // asks for the whole thing; a path asks for one file of it.
  diff: (id, path) =>
    call("POST", "/requests/" + encodeURIComponent(id) + "/diff", {
      path: path || "",
    }),

  // The doc browser (§6, decision Q). A project is named by the peer that
  // publishes it and the identifier both ends derive, in the query rather than
  // the path: a fingerprint carries slashes, and a path segment that has to be
  // escaped to hold one is a trap for whichever host forgets to.
  projects: (fingerprint) =>
    call("GET", "/projects" + (fingerprint ? where({ peer: fingerprint }) : "")),
  projectDirectory: (fingerprint, projectID, path, token) =>
    call(
      "GET",
      "/projects/directory" +
        where({ peer: fingerprint, project: projectID, path, token }),
    ),
  projectSearch: (fingerprint, projectID, query, token) =>
    call(
      "GET",
      "/projects/search" +
        where({ peer: fingerprint, project: projectID, q: query, token }),
    ),
  projectFile: (fingerprint, projectID, path) =>
    call(
      "GET",
      "/projects/file" +
        where({ peer: fingerprint, project: projectID, path }),
    ),
};

function where(params) {
  const query = new URLSearchParams();

  for (const [name, value] of Object.entries(params)) {
    if (value) {
      query.set(name, value);
    }
  }

  return "?" + query.toString();
}
