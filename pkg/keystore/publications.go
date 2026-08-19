package keystore

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

// What this instance publishes lives in the store document beside the trust
// records (§6). Only the record does — the documentation itself is bulk content
// and is sealed separately — but the record is small, is configuration rather
// than cache, and belongs where the peers it was sent to are.

// ErrNoSuchPublication is returned when a name or project id matches nothing.
var ErrNoSuchPublication = fmt.Errorf("keystore: no such publication")

// Publications returns what this instance publishes.
func (v *Vault) Publications() []*ladulasv1.Publication {
	v.mu.RLock()
	defer v.mu.RUnlock()

	out := make([]*ladulasv1.Publication, 0, len(v.doc.GetPublications()))
	for _, publication := range v.doc.GetPublications() {
		out = append(out, proto.CloneOf(publication))
	}

	return out
}

// Publication finds one by project id or by name.
func (v *Vault) Publication(ref string) (*ladulasv1.Publication, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, publication := range v.doc.GetPublications() {
		if matchesPublication(publication, ref) {
			return proto.CloneOf(publication), true
		}
	}

	return nil, false
}

// PutPublication records a publication, replacing any for the same project.
//
// Replacement rather than refusal: republishing a project after its docs have
// changed is the ordinary thing to do, and the derived project id is what says
// it is the same project.
func (v *Vault) PutPublication(publication *ladulasv1.Publication) error {
	if publication.GetProjectId() == "" {
		return fmt.Errorf("keystore: a publication needs a project id")
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	stored := proto.CloneOf(publication)

	for i, existing := range v.doc.GetPublications() {
		if existing.GetProjectId() == publication.GetProjectId() {
			v.doc.Publications[i] = stored

			return v.save()
		}
	}

	v.doc.Publications = append(v.doc.GetPublications(), stored)

	return v.save()
}

// RemovePublication forgets a publication and reports what it forgot, so the
// caller can go and tell the peers that hold it.
func (v *Vault) RemovePublication(ref string) (*ladulasv1.Publication, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	kept := make([]*ladulasv1.Publication, 0, len(v.doc.GetPublications()))

	var removed *ladulasv1.Publication

	for _, publication := range v.doc.GetPublications() {
		if removed == nil && matchesPublication(publication, ref) {
			removed = proto.CloneOf(publication)

			continue
		}

		kept = append(kept, publication)
	}

	if removed == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchPublication, ref)
	}

	v.doc.Publications = kept

	if err := v.save(); err != nil {
		return nil, err
	}

	return removed, nil
}

// AutoPublish reports whether a project this instance asks for a signature in
// is published on the way past (decision Q).
//
// Unset means yes. The moment an approver most wants a project's documentation
// is while it is being asked to sign something in it, and an instance that has
// never been asked the question should behave as though it said the useful
// thing.
func (v *Vault) AutoPublish() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.doc.AutoPublish == nil {
		return true
	}

	return v.doc.GetAutoPublish()
}

// SetAutoPublish records the answer either way, including the one that matches
// the default: a machine whose owner has said "no" should not start publishing
// again because a later version changed its mind about defaults.
func (v *Vault) SetAutoPublish(enabled bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.doc.AutoPublish = &enabled

	return v.save()
}

func matchesPublication(publication *ladulasv1.Publication, ref string) bool {
	return publication.GetProjectId() == ref ||
		strings.EqualFold(publication.GetName(), ref) ||
		publication.GetPath() == ref
}
