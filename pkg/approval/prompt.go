package approval

import (
	"fmt"
	"strings"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// Detail is one labelled line of a prompt.
type Detail struct {
	Label string
	Value string
	// Asserted marks context that comes from the requesting machine and has not
	// been verified — the machine we distrust, when it is a headless one (§5).
	Asserted bool
}

// Prompt is a request rendered for a human. It is structured rather than a
// string so the tray app, a console approver and the M2 webview viewer can all
// present the same facts in their own way, and so the audit log can record the
// text that was actually on screen.
type Prompt struct {
	// Title is the one-line "what is being asked".
	Title string
	// Subject is the thing being acted on — the destination, the repository.
	Subject string
	Details []Detail
	// Warnings are the things that should make someone look twice.
	Warnings []string
}

// Text renders the prompt as plain text, which is what goes into the audit log
// as "what was shown".
func (p Prompt) Text() string {
	var b strings.Builder

	b.WriteString(p.Title)

	if p.Subject != "" {
		b.WriteString(" — ")
		b.WriteString(p.Subject)
	}

	for _, d := range p.Details {
		b.WriteString("\n  ")
		b.WriteString(d.Label)
		b.WriteString(": ")
		b.WriteString(d.Value)

		if d.Asserted {
			b.WriteString(" (reported by the requester, unverified)")
		}
	}

	for _, w := range p.Warnings {
		b.WriteString("\n  ! ")
		b.WriteString(w)
	}

	return b.String()
}

// RenderPrompt turns a request into something worth reading. The whole point of
// the design is that a prompt says where a signature is going and why, so this
// is where the session-bind context and the request classification earn their
// keep (§4, §5).
func RenderPrompt(req *ladulasv1.ApprovalRequest) Prompt {
	p := Prompt{Title: "Signing request"}

	switch req.GetKind() {
	case ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH:
		renderSSHAuth(&p, req)
	case ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN:
		renderGitSign(&p, req)
	case ladulasv1.RequestKind_REQUEST_KIND_SSHSIG:
		p.Title = "Signature request"
		p.Subject = fmt.Sprintf("namespace %q", req.GetSshsig().GetNamespace())
	case ladulasv1.RequestKind_REQUEST_KIND_OPAQUE_SIGN:
		p.Title = "Unrecognised signing request"
		p.Subject = "the payload is neither an SSH login nor a signature"
		p.Warnings = append(p.Warnings, req.GetOpaqueSign().GetReason())
	case ladulasv1.RequestKind_REQUEST_KIND_PAIRING:
		p.Title = "Pairing request"
		p.Subject = req.GetPairing().GetPeerName()
	case ladulasv1.RequestKind_REQUEST_KIND_KEY_LIST:
		p.Title = "Key listing request"
	case ladulasv1.RequestKind_REQUEST_KIND_UNSPECIFIED:
		p.Title = "Unclassified request"
	}

	if key := req.GetKey(); key != nil {
		label := key.GetLabel()
		if comment := key.GetComment(); comment != "" {
			label = fmt.Sprintf("%s (%s)", label, comment)
		}

		p.Details = append(p.Details,
			Detail{Label: "Key", Value: label},
			Detail{Label: "Fingerprint", Value: key.GetFingerprint()})
	}

	renderRequester(&p, req.GetRequester())

	return p
}

func renderSSHAuth(p *Prompt, req *ladulasv1.ApprovalRequest) {
	auth := req.GetSshAuth()

	p.Title = "SSH login"

	if auth.GetUsername() != "" {
		p.Title = "SSH login as " + auth.GetUsername()
	}

	// A request asking for a promise ahead of the login wears the login's kind,
	// so it would otherwise be drawn as a login that is happening — and it is
	// not: nothing is waiting to connect, and saying yes signs nothing. The card
	// has to say which of the two it is, because the answers differ. The wording
	// carries it rather than a note, because the other half is the buttons: a
	// grant request has no plain approval on it, only a length (decision AO).
	if req.GetGrantOnly() {
		p.Title = "Allow SSH logins"

		if auth.GetUsername() != "" {
			p.Title = "Allow SSH logins as " + auth.GetUsername()
		}
	}

	p.Subject = auth.GetDestinationLabel()

	if host := auth.GetDestination(); host != nil {
		value := host.GetFingerprint()

		if host.GetKnown() {
			value += ", matched in known_hosts"
		} else {
			value += ", not in known_hosts"
		}

		// Where the host key came from is worth a few words to somebody deciding
		// on another device: one that is inside the payload is part of what the
		// signature will cover, and cannot be a story the asking machine told
		// (§4, §15).
		//
		// A grant request has no payload, so the same sentence would be a lie —
		// the fingerprint is one this machine read off the server and checked
		// against known_hosts, which is a weaker thing and has to read as one.
		// What makes it safe rather than merely disclosed is the other end: the
		// promise is spent only against a host key proven inside a real login's
		// signature, so a wrong fingerprint here yields a promise that covers no
		// login rather than one that covers the wrong login (decision AO).
		if payload := auth.GetPayloadDestination(); payload != nil &&
			payload.GetFingerprint() == host.GetFingerprint() {
			if req.GetGrantOnly() {
				value += "; read from the server now, and matched against " +
					"the signed payload when a login actually happens"
			} else {
				value += "; named in the signed payload"
			}
		}

		p.Details = append(p.Details, Detail{Label: "Host key", Value: value})
	}

	// Both, when both are true. They used to be arms of one switch, so a
	// forwarded request that also named no destination said only the first —
	// and the card that made up the difference by listing "Agent: forwarded"
	// among its rows no longer lists rows (decision W). A forwarded request
	// always needs confirmation (§4), which is not a thing to leave to a fact
	// somebody has to open an (i) to find.
	if !auth.GetBound() && auth.GetPayloadDestination() == nil {
		p.Warnings = append(p.Warnings,
			"the client did not say where it is connecting, so the destination is unknown")
	}

	if auth.GetForwarded() {
		p.Warnings = append(p.Warnings, fmt.Sprintf(
			"this request arrived through %s and always needs confirmation",
			pluralHops(auth.GetForwardedHops())))
	}

	if chain := auth.GetBindingChain(); len(chain) > 1 {
		var hops []string

		for _, binding := range chain {
			hops = append(hops, DisplayHost(binding.GetHostKey()))
		}

		p.Details = append(p.Details, Detail{
			Label: "Path",
			Value: strings.Join(hops, " → "),
		})
	}
}

func renderGitSign(p *Prompt, req *ladulasv1.ApprovalRequest) {
	p.Title = "Git signature"

	git := req.GetSshsig().GetGitContext()
	if git == nil {
		// A plain agent only ever sees the digest; the rich context arrives with
		// ladulas-sign in M2 (§5).
		p.Subject = "a git object"
		p.Details = append(p.Details, Detail{
			Label: "Digest",
			Value: shortHex(req.GetSshsig().GetMessageDigest()),
		})

		return
	}

	object := git.GetParsed()

	if object.GetType() == "tag" {
		p.Title = "Git tag signature"
	}

	p.Subject = object.GetSubject()

	// The object is provable and the environment is not, so the two are labelled
	// differently even though they sit in the same list (§5).
	proven := !git.GetVerifiedAgainstPayload()

	details := []Detail{
		{Label: "Repository", Value: git.GetRepositoryPath(), Asserted: true},
		{Label: "Branch", Value: git.GetBranch(), Asserted: true},
		{Label: "Author", Value: GitIdentityString(object.GetAuthor()), Asserted: proven},
		{Label: "Committer", Value: committerIfDifferent(object), Asserted: proven},
		{Label: "Tagger", Value: GitIdentityString(object.GetTagger()), Asserted: proven},
		{Label: "Tag", Value: object.GetTag(), Asserted: proven},
		{Label: "Changes", Value: DiffSummary(git.GetDiff()), Asserted: true},
	}

	for _, d := range details {
		if d.Value != "" {
			p.Details = append(p.Details, d)
		}
	}

	if problem := git.GetVerificationError(); problem != "" {
		p.Warnings = append(p.Warnings, problem)
	} else if !git.GetVerifiedAgainstPayload() {
		p.Warnings = append(p.Warnings,
			"the commit shown was not checked against the payload being signed")
	}
}

// GitIdentityString renders an author, committer or tagger line for a prompt.
func GitIdentityString(id *ladulasv1.GitIdentity) string {
	if id == nil {
		return ""
	}

	who := id.GetName()

	if email := id.GetEmail(); email != "" {
		if who == "" {
			who = email
		} else {
			who = fmt.Sprintf("%s <%s>", who, email)
		}
	}

	if id.GetTime() == nil {
		return who
	}

	when := id.GetTime().AsTime().Format("2006-01-02 15:04:05")

	if tz := id.GetTimezone(); tz != "" {
		when += " " + tz
	}

	if who == "" {
		return when
	}

	return who + ", " + when
}

// committerIfDifferent only reports the committer when it is not the author,
// because on an ordinary commit repeating the same line twice is noise, and on
// a rebased or applied patch the difference is the interesting part.
func committerIfDifferent(object *ladulasv1.GitObject) string {
	committer := GitIdentityString(object.GetCommitter())
	if committer == GitIdentityString(object.GetAuthor()) {
		return ""
	}

	return committer
}

// DiffSummary is the one-line "N files changed, N insertions, N deletions".
func DiffSummary(diff *ladulasv1.GitDiff) string {
	if diff == nil {
		return ""
	}

	if problem := diff.GetError(); problem != "" {
		return "not available: " + problem
	}

	if diff.GetFilesChanged() == 0 {
		return "no files changed"
	}

	summary := fmt.Sprintf("%s, %s, %s",
		plural(diff.GetFilesChanged(), "file", "files")+" changed",
		plural(diff.GetInsertions(), "insertion", "insertions"),
		plural(diff.GetDeletions(), "deletion", "deletions"))

	if diff.GetTruncated() {
		summary += " (truncated)"
	}

	return summary
}

func plural(n int32, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}

	return fmt.Sprintf("%d %s", n, many)
}

func renderRequester(p *Prompt, requester *ladulasv1.RequesterInfo) {
	if requester == nil {
		return
	}

	if !requester.GetLocal() {
		name := requester.GetName()
		if name == "" {
			name = requester.GetInstanceId()
		}

		p.Details = append(p.Details, Detail{Label: "Requested by", Value: name})

		return
	}

	proc := requester.GetProcess()
	if proc == nil {
		return
	}

	value := proc.GetExecutable()
	if value == "" {
		value = fmt.Sprintf("pid %d", proc.GetPid())
	} else {
		value = fmt.Sprintf("%s (pid %d)", value, proc.GetPid())
	}

	p.Details = append(p.Details, Detail{Label: "Program", Value: value})

	// The program is a helper and the same one every time; who is asking is the
	// session it belongs to, and the chain is how somebody checks that claim
	// (decision U).
	if asker := AskerDetail(proc); asker != "" {
		p.Details = append(p.Details, Detail{Label: "Asked by", Value: asker})
	}

	if chain := AskerChain(proc); chain != "" {
		p.Details = append(p.Details, Detail{Label: "Started by", Value: chain})
	}
}

// DisplayHost is the short name for a host key in a prompt.
func DisplayHost(host *ladulasv1.HostKey) string {
	if host == nil {
		return "unknown"
	}

	if names := host.GetKnownHostsNames(); len(names) > 0 {
		return names[0]
	}

	return host.GetFingerprint()
}

func pluralHops(hops int32) string {
	if hops == 1 {
		return "1 forwarded agent hop"
	}

	return fmt.Sprintf("%d forwarded agent hops", hops)
}

func shortHex(b []byte) string {
	const shown = 8

	if len(b) > shown {
		return fmt.Sprintf("%x…", b[:shown])
	}

	return fmt.Sprintf("%x", b)
}
