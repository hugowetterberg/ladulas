package keystore_test

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/hugowetterberg/ladulas/pkg/keystore"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/storepb"
)

// A route survives a restart, which is the reason it is written down at all: a
// phone announces once and is then unreachable for hours, so a requester that
// kept the route in memory would forget how to wake its approver every time the
// daemon restarted — and would go on not knowing until the phone was picked up,
// which is precisely the moment it was meant to save (§11).
func TestWakeupRoutesSurviveTheStore(t *testing.T) {
	vault, opts := newVault(t)

	err := vault.PutPeerWakeup(&storepb.PeerWakeup{
		PeerFingerprint: "SHA256:phone",
		Route: &ladulasv1.WakeupRoute{
			Kind:       ladulasv1.WakeupKind_WAKEUP_KIND_RELAY,
			RelayUrl:   "https://relay.example.com",
			InstanceId: "opaque-1",
		},
		AnnouncedAt: timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("store a route: %v", err)
	}

	reopened, err := keystore.Open(opts)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	route, ok := reopened.PeerWakeup("SHA256:phone")
	if !ok {
		t.Fatal("the route did not survive")
	}

	if route.GetRoute().GetInstanceId() != "opaque-1" {
		t.Fatalf("the route came back as %+v", route.GetRoute())
	}

	dropped, err := reopened.DropPeerWakeup("SHA256:phone")
	if err != nil {
		t.Fatalf("drop: %v", err)
	}

	if !dropped {
		t.Fatal("dropping a route that was there reported nothing")
	}

	if _, held := reopened.PeerWakeup("SHA256:phone"); held {
		t.Fatal("the route is still there")
	}
}

// The identifier is what every requester holds, so a new one means every
// requester's route is dead until the next announcement. It therefore survives
// the token changing and wake-ups being switched off and on again, and is
// replaced only when the relay is — an identifier means nothing at a relay that
// never issued it.
func TestTheWakeupIdentifierOutlivesEverythingButTheRelay(t *testing.T) {
	vault, _ := newVault(t)

	if err := vault.SetWakeupSettings(&storepb.WakeupSettings{
		Enabled:     true,
		RelayUrl:    "https://relay.example.com",
		Platform:    ladulasv1.PushPlatform_PUSH_PLATFORM_APNS,
		DeviceToken: "first-token",
	}); err != nil {
		t.Fatalf("settings: %v", err)
	}

	first := vault.WakeupSettings().GetInstanceId()
	if first == "" {
		t.Fatal("no identifier was minted")
	}

	// A reissued token, and then wake-ups switched off and on: the same phone
	// at the same relay throughout.
	for _, settings := range []*storepb.WakeupSettings{
		{
			Enabled:     true,
			RelayUrl:    "https://relay.example.com",
			DeviceToken: "second-token",
		},
		{RelayUrl: "https://relay.example.com"},
		{
			Enabled:     true,
			RelayUrl:    "https://relay.example.com",
			DeviceToken: "second-token",
		},
	} {
		if err := vault.SetWakeupSettings(settings); err != nil {
			t.Fatalf("settings: %v", err)
		}

		if got := vault.WakeupSettings().GetInstanceId(); got != first {
			t.Fatalf("the identifier became %q", got)
		}
	}

	if err := vault.SetWakeupSettings(&storepb.WakeupSettings{
		Enabled:     true,
		RelayUrl:    "https://another.example.com",
		DeviceToken: "second-token",
	}); err != nil {
		t.Fatalf("settings: %v", err)
	}

	if got := vault.WakeupSettings().GetInstanceId(); got == first {
		t.Fatal("the identifier followed the phone to another relay")
	}
}

// A sealed instance has no routes, for the same reason it has no trust records:
// they are in the document, and the document is shut.
func TestAnUnconfiguredInstanceHasNoWakeups(t *testing.T) {
	vault, _ := newVault(t)

	if vault.WakeupSettings().GetEnabled() {
		t.Fatal("wake-ups were on before anybody asked for them")
	}

	if len(vault.PeerWakeups()) != 0 {
		t.Fatal("there are routes nobody announced")
	}
}
