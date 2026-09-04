package frontend

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	"github.com/hugowetterberg/ladulas/pkg/bridge"
	"github.com/hugowetterberg/ladulas/pkg/keystore"
	"github.com/hugowetterberg/ladulas/pkg/project"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/trust"
)

// Everything the status pane and the cards read, over the socket (decision Z).
//
// The shapes are the ones an instance handed the viewer in-process, built from
// what the daemon answers rather than from a store. Two habits run through it.
// A listing that cannot be fetched is empty rather than an error: the status
// pane is one of the things somebody opens to find out why nothing works, and a
// page that refused to render would take that away. And nothing here caches an
// answer beyond a few hundred milliseconds — what a front end shows should be
// what the daemon says, not what it said.

// call is a context for one short call made on a viewer's behalf.
func call() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), callTimeout)
}

// status is the instance's own account of itself, reused briefly.
func (f *Frontend) status() (*ladulasv1.StatusResponse, error) {
	f.mu.Lock()

	if f.lastSeen != nil && time.Since(f.seenAt) < statusTTL {
		cached := f.lastSeen

		f.mu.Unlock()

		return cached, nil
	}

	f.mu.Unlock()

	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.Status(ctx,
		connect.NewRequest(&ladulasv1.StatusRequest{}))
	if err != nil {
		return nil, fmt.Errorf("ask the instance how it is: %w", err)
	}

	f.mu.Lock()
	f.lastSeen = resp.Msg
	f.seenAt = time.Now()
	f.mu.Unlock()

	// The identity and the paths are the daemon's to state, and both arrive
	// with every status: an instance that was sealed when the window opened
	// knows its own name as soon as somebody unlocks it (§10).
	f.session.SetInstance(instanceName(resp.Msg), resp.Msg.GetFingerprint())
	f.session.SetLocations(locations(resp.Msg))

	return resp.Msg, nil
}

// instanceName is what to call the machine before it can say. A sealed store
// holds the instance name, so there is nothing to show until it opens.
func instanceName(status *ladulasv1.StatusResponse) string {
	if name := status.GetInstanceName(); name != "" {
		return name
	}

	return "Ladulås"
}

func locations(status *ladulasv1.StatusResponse) []bridge.Location {
	where := status.GetLocations()
	if where == nil {
		return nil
	}

	// The peer channel's addresses are not here: they are the listen
	// view's, which says what was bound, what peers are told to dial and
	// what was passed over, and lets it be changed.
	return []bridge.Location{
		{Label: "Agent socket", Path: where.GetAgentSocket()},
		{Label: "Signing socket", Path: where.GetControlSocket()},
		{Label: "Policy", Path: where.GetPolicy()},
		{Label: "Audit log", Path: where.GetAuditLog()},
		{Label: "Published docs", Path: where.GetProjectsDir()},
	}
}

func (f *Frontend) keys() []*ladulasv1.KeyRef {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListStoredKeys(ctx,
		connect.NewRequest(&ladulasv1.ListStoredKeysRequest{}))
	if err != nil {
		f.log.Debug("could not list the keys", "error", err.Error())

		return nil
	}

	out := make([]*ladulasv1.KeyRef, 0, len(resp.Msg.GetKeys()))

	for _, key := range resp.Msg.GetKeys() {
		out = append(out, keyRef(key))
	}

	return out
}

func (f *Frontend) borrowed() []*ladulasv1.BorrowedKeyStatus {
	status, err := f.status()
	if err != nil {
		return nil
	}

	return status.GetBorrowedKeys()
}

// keyOffers and answerKeyOffer are the receiving half of decision S over the
// socket: what paired machines have handed this instance, and taking one into
// the store or forgetting it.
//
// A sealed instance has nothing to list rather than a failure to report, which
// is what the keys listing above already does — the window is one of the things
// somebody opens to find out why nothing works.
func (f *Frontend) keyOffers() []*ladulasv1.KeyOfferInfo {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListKeyOffers(ctx,
		connect.NewRequest(&ladulasv1.ListKeyOffersRequest{}))
	if err != nil {
		f.log.Debug("could not list the key offers", "error", err.Error())

		return nil
	}

	return resp.Msg.GetOffers()
}

func (f *Frontend) answerKeyOffer(
	ctx context.Context, id string, accept bool, label string,
) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := f.client.AnswerKeyOffer(ctx, connect.NewRequest(
		&ladulasv1.AnswerKeyOfferRequest{
			Id:     id,
			Accept: accept,
			Label:  label,
		}))
	if err != nil {
		if accept {
			return fmt.Errorf("accept the key: %w", err)
		}

		return fmt.Errorf("refuse the key: %w", err)
	}

	return nil
}

func (f *Frontend) grants() ([]*ladulasv1.Grant, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListGrants(ctx,
		connect.NewRequest(&ladulasv1.ListGrantsRequest{}))
	if err != nil {
		// A sealed instance has no grants to list rather than a failure to
		// report, which is the same answer an in-process host gave.
		return nil, nil //nolint:nilerr // see above
	}

	return resp.Msg.GetGrants(), nil
}

func (f *Frontend) revokeGrant(ctx context.Context, id string) error {
	_, err := f.client.RevokeGrant(ctx,
		connect.NewRequest(&ladulasv1.RevokeGrantRequest{GrantId: id}))
	if err != nil {
		return grantFailure(err)
	}

	return nil
}

func (f *Frontend) extendGrant(
	ctx context.Context, id string, extra time.Duration,
) error {
	_, err := f.client.ExtendGrant(ctx, connect.NewRequest(
		&ladulasv1.ExtendGrantRequest{
			GrantId:  id,
			ExtendBy: durationpb.New(extra),
		}))
	if err != nil {
		return grantFailure(err)
	}

	return nil
}

// grantFailure keeps the three answers about a promise apart across the socket.
//
// The bridge documents them as different errors because the surfaces word them
// differently: an identifier nobody knows, a length past what this instance
// promises, and a machine that could not be told. Connect carries the code, and
// the code is what says which of the three this was — without this they would
// all arrive as "it did not work".
func grantFailure(err error) error {
	switch connect.CodeOf(err) {
	case connect.CodeNotFound:
		return fmt.Errorf("%w: %w", bridge.ErrNoSuchGrant, err)
	case connect.CodeInvalidArgument:
		return fmt.Errorf("%w: %w", bridge.ErrGrantTooLong, err)
	default:
		return err
	}
}

func (f *Frontend) delegations() ([]bridge.Delegation, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListDelegations(ctx,
		connect.NewRequest(&ladulasv1.ListDelegationsRequest{}))
	if err != nil {
		return nil, nil //nolint:nilerr // sealed: nothing to list, as above
	}

	held := resp.Msg.GetDelegations()
	out := make([]bridge.Delegation, 0, len(held))

	for _, item := range held {
		view := bridge.Delegation{
			Delegation: item.GetDelegation(),
			UseCount:   int(item.GetUseCount()),
			Unreported: int(item.GetUnreportedUses()),
		}

		if received := item.GetReceivedAt(); received != nil {
			view.ReceivedAt = received.AsTime()
		}

		out = append(out, view)
	}

	return out, nil
}

func (f *Frontend) peers() []bridge.PeerView {
	status, err := f.status()
	if err != nil {
		return nil
	}

	var out []bridge.PeerView

	for _, peer := range status.GetPeers() {
		out = append(out, bridge.PeerView{
			Name:        peer.GetName(),
			Fingerprint: peer.GetFingerprint(),
			Direction: trust.Describe(
				peer.GetMayApprove(), peer.GetMayRequest()),
			Summary: trust.DescribeShort(
				peer.GetMayApprove(), peer.GetMayRequest()),
			State:      peerState(peer),
			Dialable:   len(peer.GetAddresses()) > 0,
			LastSeen:   peerLastSeen(peer),
			Addresses:  peer.GetAddresses(),
			MayUseKeys: peer.GetAllKeys(),
			KeyAccess:  keyAccessWord(peer),
		})
	}

	return out
}

// keyAccessWord says how much of this instance's key set a peer may use, in the
// words a listing uses rather than as two fields (decision T).
func keyAccessWord(peer *ladulasv1.PeerStatus) string {
	switch {
	case peer.GetAllKeys():
		return "all"
	case len(peer.GetAllowedKeys()) == 0:
		return "none"
	default:
		return fmt.Sprintf("%d", len(peer.GetAllowedKeys()))
	}
}

// lastSeenOf is the peer's last contact as a time, and the zero time when there
// has been none. It is not `AsTime()` on its own: a nil timestamp turns into the
// epoch there, which reads as 1970 rather than as nothing.
func lastSeenOf(peer *ladulasv1.PeerStatus) time.Time {
	if peer.GetLastSeenAt() == nil {
		return time.Time{}
	}

	return peer.GetLastSeenAt().AsTime()
}

// peerLastSeen is when a peer that is not connected last was, on the clock. It
// is empty for one that is connected now, which is what the state already says.
func peerLastSeen(peer *ladulasv1.PeerStatus) string {
	if peer.GetOnline() || peer.GetLastSeenAt() == nil {
		return ""
	}

	return peer.GetLastSeenAt().AsTime().Local().Format(time.RFC1123)
}

// peerState is trust.DescribeState over the wire type, so that this window and
// the command line say the same thing about the same peer.
func peerState(peer *ladulasv1.PeerStatus) string {
	return trust.DescribeState(
		peer.GetOnline(),
		peer.GetAddresses(),
		peer.GetMayApprove(),
		peer.GetLastError(),
		lastSeenOf(peer),
		time.Now(),
	)
}

// pairings and withdrawPairing are the desktop's half of §7's promise that a
// pending pairing is answerable on every surface. Answering one is a card like
// any other; what this adds is the row for a pairing this side has already
// agreed to, which has no card and would otherwise be invisible here.
func (f *Frontend) pairings() []bridge.PairingSummaryView {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListPendingPairings(ctx,
		connect.NewRequest(&ladulasv1.ListPendingPairingsRequest{}))
	if err != nil {
		return nil
	}

	return bridge.PairingSummaries(resp.Msg.GetPairings())
}

func (f *Frontend) withdrawPairing(session string) error {
	// Telling the other side is a call over the peer channel, so this is the one
	// place a front end waits longer than a screen ordinarily should.
	ctx, cancel := context.WithTimeout(
		context.Background(), pairingWithdrawTimeout)
	defer cancel()

	_, err := f.client.WithdrawPairing(ctx, connect.NewRequest(
		&ladulasv1.WithdrawPairingRequest{
			Pairing: session,
			Reason:  "called off at the desktop",
		}))
	if err != nil {
		return fmt.Errorf("withdraw the pairing: %w", err)
	}

	return nil
}

// pairingWithdrawTimeout bounds telling the other side. Failing to tell it is
// not a failure to withdraw.
const pairingWithdrawTimeout = 15 * time.Second

// revokePeer forgets a paired machine and drops what it is holding.
//
// Unlike withdrawing a pairing, nothing here waits on the peer: revoking is
// unilateral and the peer is not asked, so this is a short local call like the
// rest of them (§7).
func (f *Frontend) revokePeer(ctx context.Context, peer string) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	_, err := f.client.RevokePeer(ctx,
		connect.NewRequest(&ladulasv1.RevokePeerRequest{Peer: peer}))
	if err != nil {
		return fmt.Errorf("revoke the pairing: %w", err)
	}

	return nil
}

// fetchDiff asks the daemon to ask the requester (§5). The request is named by
// its identifier: the connection to whoever asked is the daemon's, and this
// process has never had one.
func (f *Frontend) fetchDiff(
	ctx context.Context, req *approval.Request, path string,
) (*ladulasv1.GitDiff, error) {
	resp, err := f.client.FetchRequestDiff(ctx, connect.NewRequest(
		&ladulasv1.FetchRequestDiffRequest{
			RequestId: req.Msg.GetRequestId(),
			Path:      path,
		}))
	if err != nil {
		return nil, fmt.Errorf("fetch the rest of the diff: %w", err)
	}

	return resp.Msg.GetDiff(), nil
}

// history is the audit log, read as a file.
//
// It is the one thing here that does not go over the socket, and deliberately:
// the log lives outside the store on purpose and is a plain file read for
// everything else too (§14). The path is the daemon's, so a front end reads the
// log of the instance it is attached to rather than of the one it would have
// started itself.
func (f *Frontend) history(limit int) ([]*ladulasv1.AuditEntry, error) {
	status, err := f.status()
	if err != nil {
		return nil, err
	}

	path := status.GetLocations().GetAuditLog()
	if path == "" {
		return nil, errors.New("the instance did not say where its audit log is")
	}

	entries, err := approval.ReadAuditLog(path, limit*auditEntriesPerDecision)
	if err != nil {
		return nil, fmt.Errorf("read the audit log: %w", err)
	}

	return entries, nil
}

// settings is the policy a settings screen draws (§9). It is asked for on every
// paint of the instance view, like everything else on it, and is cheap: the
// daemon reads it out of the policy it already has loaded.
func (f *Frontend) settings() (bridge.SettingsView, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.Settings(ctx,
		connect.NewRequest(&ladulasv1.SettingsRequest{}))
	if err != nil {
		return bridge.SettingsView{}, fmt.Errorf("ask for the settings: %w", err)
	}

	return settingsView(resp.Msg), nil
}

// setSignTimeout writes the signing budget through the daemon, which is the
// only process that touches the policy document (decision L).
func (f *Frontend) setSignTimeout(d time.Duration) error {
	ctx, cancel := call()
	defer cancel()

	_, err := f.client.SetSignTimeout(ctx,
		connect.NewRequest(&ladulasv1.SetSignTimeoutRequest{
			SignTimeout: durationpb.New(d),
		}))
	if err != nil {
		return fmt.Errorf("set how long a signing request waits: %w", err)
	}

	return nil
}

// settingsView is the one conversion, so that the screen and anything else
// reading this are looking at the same seconds.
func settingsView(msg *ladulasv1.SettingsResponse) bridge.SettingsView {
	seconds := func(d *durationpb.Duration) int64 {
		return int64(d.AsDuration() / time.Second)
	}

	return bridge.SettingsView{
		SignTimeoutSeconds:        seconds(msg.GetSignTimeout()),
		DefaultSignTimeoutSeconds: seconds(msg.GetDefaultSignTimeout()),
		MinSignTimeoutSeconds:     seconds(msg.GetMinSignTimeout()),
		MaxSignTimeoutSeconds:     seconds(msg.GetMaxSignTimeout()),
		PolicyPath:                msg.GetPolicyPath(),
		MaxGrantSeconds:           seconds(msg.GetMaxGrantTtl()),
	}
}

func (f *Frontend) reload() error {
	ctx, cancel := call()
	defer cancel()

	if _, err := f.client.Reload(ctx,
		connect.NewRequest(&ladulasv1.ReloadRequest{})); err != nil {
		return fmt.Errorf("reload the store and the policy: %w", err)
	}

	return nil
}

// lockControl is the unlock panel's half of §10 over the socket.
type lockControl struct {
	front *Frontend
}

var _ bridge.Lock = (*lockControl)(nil)

func (l *lockControl) State() bridge.LockView {
	status, err := l.front.status()
	if err != nil {
		// Not a lock state: there is no instance whose state it could be. The
		// panel says what to start rather than offering a passphrase field with
		// nothing behind it (decision Z).
		return bridge.LockView{State: bridge.StateNotRunning}
	}

	return bridge.LockView{
		State:           bridge.StateWord(status.GetLockState()),
		Reason:          status.GetStateReason(),
		Passphrase:      status.GetPassphraseWrapping(),
		KeyringEnrolled: status.GetKeyringEnrolled(),
	}
}

// Unlock hands the passphrase to the daemon, which is the only thing that can
// check it: the key encryption key is derived where the wrapping is (§14).
func (l *lockControl) Unlock(passphrase []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
	defer cancel()

	msg := &ladulasv1.UnlockRequest{Passphrase: passphrase}

	// The buffer this call was handed is wiped by its caller; the copy the
	// message holds is this package's to clear.
	defer keystore.Wipe(msg.GetPassphrase())

	if _, err := l.front.client.Unlock(ctx, connect.NewRequest(msg)); err != nil {
		return fmt.Errorf("unlock the store: %w", err)
	}

	l.front.forgetStatus()

	return nil
}

func (l *lockControl) Lock(seal bool) error {
	ctx, cancel := call()
	defer cancel()

	_, err := l.front.client.Lock(ctx,
		connect.NewRequest(&ladulasv1.LockRequest{Seal: seal}))
	if err != nil {
		return fmt.Errorf("lock the store: %w", err)
	}

	l.front.forgetStatus()

	return nil
}

// unlockTimeout is longer than an ordinary call because unlocking derives a key
// encryption key from a passphrase, and scrypt is slow on purpose.
const unlockTimeout = 30 * time.Second

// forgetStatus drops the cached answer after something that changed it, so that
// the panel that just unlocked the store does not draw itself sealed once more
// before it believes it.
func (f *Frontend) forgetStatus() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.lastSeen = nil
}

// projects is the doc browser over the socket (§6, decision Q).
type projects struct {
	front *Frontend
}

var _ bridge.Projects = (*projects)(nil)

func (p *projects) List(
	ctx context.Context, fingerprint string,
) ([]*project.Overview, error) {
	resp, err := p.front.client.ListPeerProjects(ctx, connect.NewRequest(
		&ladulasv1.ListPeerProjectsRequest{Fingerprint: fingerprint}))
	if err != nil {
		return nil, fmt.Errorf("list what the peers publish: %w", err)
	}

	out := make([]*project.Overview, 0, len(resp.Msg.GetProjects()))

	for _, wire := range resp.Msg.GetProjects() {
		out = append(out, project.OverviewFromWire(wire))
	}

	return out, nil
}

// Kept is what is held here, drawn before the daemon has asked anybody. The
// context is the socket round trip's: the daemon does not dial for this.
func (p *projects) Kept(
	ctx context.Context, fingerprint string,
) ([]*project.Overview, error) {
	resp, err := p.front.client.ListPeerProjects(ctx, connect.NewRequest(
		&ladulasv1.ListPeerProjectsRequest{
			Fingerprint: fingerprint,
			KeptOnly:    true,
		}))
	if err != nil {
		return nil, fmt.Errorf("list what is held of the peers' projects: %w", err)
	}

	out := make([]*project.Overview, 0, len(resp.Msg.GetProjects()))

	for _, wire := range resp.Msg.GetProjects() {
		out = append(out, project.OverviewFromWire(wire))
	}

	return out, nil
}

func (p *projects) Open(
	ctx context.Context, fingerprint, projectID string,
) (*project.Overview, error) {
	resp, err := p.front.client.OpenPeerProject(ctx, connect.NewRequest(
		&ladulasv1.OpenPeerProjectRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
		}))
	if err != nil {
		return nil, fmt.Errorf("open the project: %w", err)
	}

	return project.OverviewFromWire(resp.Msg.GetProject()), nil
}

func (p *projects) Directory(
	ctx context.Context, fingerprint, projectID, path, filter, token string,
	size int,
) (*project.Listing, error) {
	resp, err := p.front.client.ListPeerDirectory(ctx, connect.NewRequest(
		&ladulasv1.ListPeerDirectoryRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
			Path:        path,
			Filter:      filter,
			Token:       token,
			Size:        int32(size), //nolint:gosec // a page size
		}))
	if err != nil {
		return nil, fmt.Errorf("read the directory: %w", err)
	}

	return project.ListingFromWire(resp.Msg.GetListing()), nil
}

func (p *projects) KeptDirectory(
	ctx context.Context, fingerprint, projectID, path, filter string,
) (*project.Listing, error) {
	resp, err := p.front.client.ListPeerDirectory(ctx, connect.NewRequest(
		&ladulasv1.ListPeerDirectoryRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
			Path:        path,
			Filter:      filter,
			KeptOnly:    true,
		}))
	if err != nil {
		return nil, fmt.Errorf("read what is held of the directory: %w", err)
	}

	return project.ListingFromWire(resp.Msg.GetListing()), nil
}

func (p *projects) Search(
	ctx context.Context, fingerprint, projectID, query, token string, size int,
) (*project.Listing, error) {
	resp, err := p.front.client.SearchPeerProject(ctx, connect.NewRequest(
		&ladulasv1.SearchPeerProjectRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
			Query:       query,
			Token:       token,
			Size:        int32(size), //nolint:gosec // a page size
		}))
	if err != nil {
		return nil, fmt.Errorf("search the project: %w", err)
	}

	return project.ListingFromWire(resp.Msg.GetListing()), nil
}

func (p *projects) File(
	ctx context.Context, fingerprint, projectID, path string,
) (*project.Page, error) {
	resp, err := p.front.client.ReadPeerPage(ctx, connect.NewRequest(
		&ladulasv1.ReadPeerPageRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
			Path:        path,
		}))
	if err != nil {
		return nil, fmt.Errorf("read the page: %w", err)
	}

	return project.PageFromWire(resp.Msg.GetPage()), nil
}

// Versions is what one document has been (decision AP). The daemon does the
// reaching; this is a socket round trip.
func (p *projects) Versions(
	ctx context.Context, fingerprint, projectID, path string, limit int,
) (*project.VersionList, error) {
	resp, err := p.front.client.PeerDocumentVersions(ctx, connect.NewRequest(
		&ladulasv1.PeerDocumentVersionsRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
			Path:        path,
			CommitLimit: int32(limit), //nolint:gosec // a caller's page size
		}))
	if err != nil {
		return nil, fmt.Errorf("read the versions: %w", err)
	}

	return &project.VersionList{
		Versions:      resp.Msg.GetVersions(),
		Head:          resp.Msg.GetHead(),
		CurrentDigest: resp.Msg.GetCurrentDigest(),
		Truncated:     resp.Msg.GetTruncated(),
		Live:          resp.Msg.GetLive(),
		Err:           resp.Msg.GetError(),
	}, nil
}

// Read is one document, with what changed since a named version marked in it.
//
// The daemon fetches both pages, because reaching a publisher needs the
// identity key it holds (decision Z); the parsing and the comparison happen
// here, through the same Composed the in-process browser uses.
func (p *projects) Read(
	ctx context.Context, fingerprint, projectID, path string,
	digest []byte, commit string,
) (*project.DocumentAt, error) {
	resp, err := p.front.client.ReadPeerPage(ctx, connect.NewRequest(
		&ladulasv1.ReadPeerPageRequest{
			Fingerprint:   fingerprint,
			ProjectId:     projectID,
			Path:          path,
			CompareDigest: digest,
			CompareCommit: commit,
		}))
	if err != nil {
		return nil, fmt.Errorf("read the page: %w", err)
	}

	page := project.PageFromWire(resp.Msg.GetPage())

	var before *project.Page

	if wire := resp.Msg.GetComparedTo(); wire != nil {
		before = project.PageFromWire(wire)
	}

	out := project.Composed(path, page, before)
	out.Against = resp.Msg.GetVersion()

	if detail := resp.Msg.GetCompareError(); detail != "" {
		return out, errors.New(detail)
	}

	return out, nil
}

// Documents is the picker's list, and is answered out of what the daemon has
// already read rather than by asking anybody (decision AP).
//
// It goes through ListPublications rather than a control call of its own,
// because that answer already carries the cached projects and their pages —
// the daemon holds the cache and the window does not, and one round trip over a
// unix socket is what stands between them.
func (p *projects) Documents(fingerprint, projectID string) []string {
	ctx, cancel := call()
	defer cancel()

	resp, err := p.front.client.ListPublications(ctx, connect.NewRequest(
		&ladulasv1.ListPublicationsRequest{}))
	if err != nil {
		return nil
	}

	for _, cached := range resp.Msg.GetCached() {
		if cached.GetPeerFingerprint() != fingerprint {
			continue
		}

		if cached.GetProject().GetProjectId() != projectID {
			continue
		}

		out := make([]string, 0, len(cached.GetFiles()))

		for _, file := range cached.GetFiles() {
			out = append(out, file.GetPath())
		}

		sort.Strings(out)

		return out
	}

	return nil
}

// Cached is what a card asks: somebody is waiting in front of it, so it is
// answered from what has been read here and nobody is dialled (decision Q).
//
// It takes no context because the in-process browser needed none. Here it costs
// a socket round trip, which is the same order as the map lookup it replaced
// next to what a card does anyway.
func (p *projects) Cached(fingerprint, projectID string) (*project.Overview, bool) {
	ctx, cancel := call()
	defer cancel()

	resp, err := p.front.client.OpenPeerProject(ctx, connect.NewRequest(
		&ladulasv1.OpenPeerProjectRequest{
			Fingerprint: fingerprint,
			ProjectId:   projectID,
			CachedOnly:  true,
		}))
	if err != nil || !resp.Msg.GetFound() {
		return nil, false
	}

	return project.OverviewFromWire(resp.Msg.GetProject()), true
}

// endorsements and retractEndorsement are decision AG over the socket: the
// promises other holders of a key have made about a machine, and taking one
// back.
//
// The listing is not filtered here and must not be. An endorsement is carried
// by the requester and honoured whether or not this instance was told, so a
// window that showed only the live ones would be a machine unable to say what
// it is signing under — and a promise nobody can see is a promise nobody can
// retract.
func (f *Frontend) endorsements() ([]bridge.Endorsement, []bridge.Retraction, error) {
	ctx, cancel := call()
	defer cancel()

	resp, err := f.client.ListEndorsements(ctx,
		connect.NewRequest(&ladulasv1.ListEndorsementsRequest{}))
	if err != nil {
		// A sealed instance has nothing to list rather than a failure to
		// report, which is what every other listing here answers.
		return nil, nil, nil //nolint:nilerr // see above
	}

	held := resp.Msg.GetEndorsements()
	out := make([]bridge.Endorsement, 0, len(held))

	for _, item := range held {
		view := bridge.Endorsement{
			Endorsement:  item.GetEndorsement(),
			Published:    item.GetPublished(),
			InertBecause: item.GetInertBecause(),
			UseCount:     int(item.GetUseCount()),
			Unreported:   int(item.GetUnreportedUses()),
		}

		if received := item.GetReceivedAt(); received != nil {
			view.ReceivedAt = received.AsTime()
		}

		out = append(out, view)
	}

	taken := resp.Msg.GetRetractions()
	back := make([]bridge.Retraction, 0, len(taken))

	for _, item := range taken {
		view := bridge.Retraction{Retraction: item.GetRetraction()}

		if received := item.GetReceivedAt(); received != nil {
			view.ReceivedAt = received.AsTime()
		}

		back = append(back, view)
	}

	return out, back, nil
}

func (f *Frontend) retractEndorsement(
	ctx context.Context, endorsementID, keyFingerprint, reason string,
) (told, unreached []string, err error) {
	// Longer than an ordinary call: retracting means dialling every holder that
	// can be reached, and the point of the answer is which of them were. It is
	// the same reason withdrawing a pairing waits longer than a screen
	// ordinarily should.
	ctx, cancel := context.WithTimeout(ctx, retractTimeout)
	defer cancel()

	resp, err := f.client.RetractEndorsement(ctx, connect.NewRequest(
		&ladulasv1.RetractEndorsementRequest{
			EndorsementId:  endorsementID,
			KeyFingerprint: keyFingerprint,
			Reason:         reason,
		}))
	if err != nil {
		return nil, nil, fmt.Errorf("retract the endorsement: %w", err)
	}

	return resp.Msg.GetTold(), resp.Msg.GetUnreached(), nil
}

// retractTimeout bounds telling the holders. Failing to tell one is not a
// failure to retract — the promise is dropped here whatever happened on the
// wire, and the holders that were not reached come back in the answer.
const retractTimeout = 30 * time.Second
