// Package tunnel wires the tailcat engine in pkg/tunnel into the daemon's
// instance (docs/architecture.md §8, decisions AX and BA).
//
// The engine is public so that a phone can carry it as a client; this
// package is the one piece that needs internal/app, and so the one piece
// that stays here.
package tunnel

import (
	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/pkg/peer"
	engine "github.com/hugowetterberg/ladulas/pkg/tunnel"
)

// Factory is what a daemon binary hands its instance so that the instance can
// build a tunnel whenever the upgrade is on: at unseal, and when it is turned
// on at runtime. Nil in a build without tailcat, which an instance takes to
// mean that it has no tunnel to offer.
//
// It lives here rather than in internal/app so that internal/app never imports
// tailcat: the binaries choose to carry it, and everything else built from
// internal/app — the tests, an embedder — does not (decision AX).
func Factory() app.TunnelFactory {
	if !engine.Available {
		return nil
	}

	return func(spec app.TunnelSpec) (peer.Tunnel, error) {
		return engine.Open(engine.Options{
			ServerKey:    spec.ServerKey,
			PresharedKey: spec.PresharedKey,
			ClientKey:    spec.ClientKey,
			Region:       spec.Region,
			DERPMapURL:   spec.DERPMapURL,
			OnRegion:     spec.OnRegion,
			Logger:       spec.Logger,
		})
	}
}
