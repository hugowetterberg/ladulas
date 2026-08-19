package project

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// The browser's answers on a wire, for a front end that is not in the daemon's
// process (decision Z, §14).
//
// Both directions live here, next to the types they carry, so that the two ends
// of the control socket cannot drift into disagreeing about what a listing is.
// Nothing is dropped in either direction: the provenance fields — Live,
// Withdrawn, Err — are the whole point of the types (§6, decision Q), and a
// conversion that let one of them fall out would turn "what was read of this
// once" into a claim about what the publisher says now.

// OverviewWire is one project as a browser lists it, for the socket.
func OverviewWire(overview *Overview) *ladulasv1.PeerProject {
	if overview == nil {
		return nil
	}

	wire := &ladulasv1.PeerProject{
		Fingerprint: overview.Fingerprint,
		Peer:        overview.Peer,
		Project:     overview.Project,
		Live:        overview.Live,
		Withdrawn:   overview.Withdrawn,
		Kept:        int32(overview.Kept), //nolint:gosec // a page count
		Error:       overview.Err,
	}

	if !overview.Read.IsZero() {
		wire.Read = timestamppb.New(overview.Read)
	}

	return wire
}

// OverviewFromWire reads one back.
func OverviewFromWire(wire *ladulasv1.PeerProject) *Overview {
	if wire == nil {
		return nil
	}

	return &Overview{
		Fingerprint: wire.GetFingerprint(),
		Peer:        wire.GetPeer(),
		Project:     wire.GetProject(),
		Live:        wire.GetLive(),
		Withdrawn:   wire.GetWithdrawn(),
		Kept:        int(wire.GetKept()),
		Read:        wireTime(wire.GetRead()),
		Err:         wire.GetError(),
	}
}

// ListingWire is one directory or one search, for the socket.
func ListingWire(listing *Listing) *ladulasv1.PeerListing {
	if listing == nil {
		return nil
	}

	return &ladulasv1.PeerListing{
		Path:      listing.Path,
		Entries:   listing.Entries,
		Next:      listing.Next,
		Total:     int32(listing.Total), //nolint:gosec // an entry count
		Truncated: listing.Truncated,
		Live:      listing.Live,
		Error:     listing.Err,
		Publisher: OverviewWire(listing.Publisher),
	}
}

// ListingFromWire reads one back.
func ListingFromWire(wire *ladulasv1.PeerListing) *Listing {
	if wire == nil {
		return nil
	}

	return &Listing{
		Path:      wire.GetPath(),
		Entries:   wire.GetEntries(),
		Next:      wire.GetNext(),
		Total:     int(wire.GetTotal()),
		Truncated: wire.GetTruncated(),
		Live:      wire.GetLive(),
		Err:       wire.GetError(),
		Publisher: OverviewFromWire(wire.GetPublisher()),
	}
}

// PageWire is one document, for the socket.
func PageWire(page *Page) *ladulasv1.PeerPage {
	if page == nil {
		return nil
	}

	wire := &ladulasv1.PeerPage{
		Path:    page.Path,
		Content: page.Content,
		Commit:  page.Commit,
		Live:    page.Live,
		Error:   page.Err,
	}

	if !page.Modified.IsZero() {
		wire.Modified = timestamppb.New(page.Modified)
	}

	if !page.ReadAt.IsZero() {
		wire.ReadAt = timestamppb.New(page.ReadAt)
	}

	return wire
}

// PageFromWire reads one back.
func PageFromWire(wire *ladulasv1.PeerPage) *Page {
	if wire == nil {
		return nil
	}

	return &Page{
		Path:     wire.GetPath(),
		Content:  wire.GetContent(),
		Modified: wireTime(wire.GetModified()),
		ReadAt:   wireTime(wire.GetReadAt()),
		Commit:   wire.GetCommit(),
		Live:     wire.GetLive(),
		Err:      wire.GetError(),
	}
}

// wireTime keeps an unset timestamp unset rather than turning it into the epoch,
// which every view here renders as a date in 1970 rather than as nothing.
func wireTime(stamp *timestamppb.Timestamp) time.Time {
	if stamp == nil {
		return time.Time{}
	}

	return stamp.AsTime()
}
