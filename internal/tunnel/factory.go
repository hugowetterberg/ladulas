package tunnel

import (
	"github.com/hugowetterberg/ladulas/internal/app"
	"github.com/hugowetterberg/ladulas/pkg/peer"
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
	if !Available {
		return nil
	}

	return func(spec app.TunnelSpec) (peer.Tunnel, error) {
		return newTunnel(Options{
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
