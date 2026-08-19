package approval_test

import (
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/hugowetterberg/ladulas/pkg/approval"
	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
)

func sshAuthRequest(destination, username string, bound, forwarded bool) *ladulasv1.ApprovalRequest {
	auth := &ladulasv1.SshAuthRequest{
		Username:         username,
		Service:          "ssh-connection",
		Bound:            bound,
		Forwarded:        forwarded,
		DestinationLabel: destination,
		Destination: &ladulasv1.HostKey{
			Fingerprint:     hostFingerprint(destination),
			KnownHostsNames: []string{destination},
			Known:           destination != "",
		},
	}

	// A hostbound login carries the server's key inside the signed bytes, and
	// that proven key is what a grant is matched on (M2). The fingerprint tracks
	// the destination, so two named hosts are two scopes and an unbound login
	// carries none.
	if bound {
		auth.PayloadDestination = &ladulasv1.HostKey{
			Fingerprint: hostFingerprint(destination),
			Algorithm:   "ssh-ed25519",
		}
	}

	return &ladulasv1.ApprovalRequest{
		RequestId: "req",
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH,
		Key: &ladulasv1.KeyRef{
			Fingerprint: "SHA256:workkey",
			Label:       "work",
			Algorithm:   "ssh-ed25519",
		},
		Requester: &ladulasv1.RequesterInfo{
			InstanceId: "SHA256:instance",
			Local:      true,
			Process:    &ladulasv1.ClientProcess{Pid: 42, Executable: "/usr/bin/ssh"},
		},
		Operation: &ladulasv1.ApprovalRequest_SshAuth{SshAuth: auth},
	}
}

// hostFingerprint is a stand-in for the fingerprint of a host's key, distinct
// per destination so a test can tell two hosts apart the way a scope now does.
func hostFingerprint(destination string) string {
	if destination == "" {
		return "SHA256:hostkey"
	}

	return "SHA256:host-" + destination
}

func gitSignRequest() *ladulasv1.ApprovalRequest {
	return &ladulasv1.ApprovalRequest{
		RequestId: "req",
		Kind:      ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN,
		Key: &ladulasv1.KeyRef{
			Fingerprint: "SHA256:workkey",
			Label:       "work",
		},
		Requester: &ladulasv1.RequesterInfo{InstanceId: "SHA256:instance", Local: true},
		Operation: &ladulasv1.ApprovalRequest_Sshsig{
			Sshsig: &ladulasv1.SshsigRequest{
				Namespace:     "git",
				HashAlgorithm: "sha512",
				MessageDigest: []byte("digest"),
			},
		},
	}
}

func TestDefaultPolicyPrompts(t *testing.T) {
	policy := approval.DefaultPolicy()

	for _, req := range []*ladulasv1.ApprovalRequest{
		sshAuthRequest("github.com", "git", true, false),
		gitSignRequest(),
	} {
		if got := policy.Evaluate(req); got.Action != ladulasv1.Action_ACTION_PROMPT {
			t.Errorf("%v: action %v, want PROMPT", req.GetKind(), got.Action)
		}
	}
}

func TestPolicyFirstMatchWins(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{
			{
				Name:   "never for the bastion",
				Action: ladulasv1.Action_ACTION_DENY,
				Match: &ladulasv1.Match{
					Destinations: []string{"bastion.example.net"},
				},
			},
			{
				Name:   "github is fine",
				Action: ladulasv1.Action_ACTION_APPROVE,
				Match: &ladulasv1.Match{
					Kinds:        []ladulasv1.RequestKind{ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH},
					Destinations: []string{"*.github.com", "github.com"},
				},
			},
		},
	})

	for _, tc := range []struct {
		destination string
		want        ladulasv1.Action
		wantRule    string
	}{
		{destination: "bastion.example.net", want: ladulasv1.Action_ACTION_DENY, wantRule: "never for the bastion"},
		{destination: "github.com", want: ladulasv1.Action_ACTION_APPROVE, wantRule: "github is fine"},
		{destination: "ssh.github.com", want: ladulasv1.Action_ACTION_APPROVE, wantRule: "github is fine"},
		{destination: "somewhere.else", want: ladulasv1.Action_ACTION_PROMPT, wantRule: "default"},
	} {
		t.Run(tc.destination, func(t *testing.T) {
			got := policy.Evaluate(sshAuthRequest(tc.destination, "git", true, false))

			if got.Action != tc.want {
				t.Errorf("action %v, want %v", got.Action, tc.want)
			}

			if got.Rule != tc.wantRule {
				t.Errorf("rule %q, want %q", got.Rule, tc.wantRule)
			}
		})
	}
}

// Host names are matched case insensitively, because nobody types them
// consistently.
func TestPolicyDestinationMatchingIsCaseInsensitive(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{{
			Name:   "github",
			Action: ladulasv1.Action_ACTION_APPROVE,
			Match:  &ladulasv1.Match{Destinations: []string{"GitHub.com"}},
		}},
	})

	got := policy.Evaluate(sshAuthRequest("github.com", "git", true, false))

	if got.Action != ladulasv1.Action_ACTION_APPROVE {
		t.Errorf("action %v", got.Action)
	}
}

func TestPolicyTristates(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{{
			Name:   "deny forwarded",
			Action: ladulasv1.Action_ACTION_DENY,
			Match:  &ladulasv1.Match{Forwarded: ladulasv1.Tristate_TRISTATE_TRUE},
		}},
	})

	forwarded := policy.Evaluate(sshAuthRequest("host", "hugo", true, true))
	if forwarded.Action != ladulasv1.Action_ACTION_DENY {
		t.Errorf("forwarded request: %v", forwarded.Action)
	}

	direct := policy.Evaluate(sshAuthRequest("host", "hugo", true, false))
	if direct.Action != ladulasv1.Action_ACTION_PROMPT {
		t.Errorf("direct request: %v", direct.Action)
	}
}

// An unbound request has no destination, so a rule that names one must not
// match it. Otherwise a client that simply declines to say where it is going
// would inherit the permissions of somewhere it is not.
func TestPolicyDestinationRuleDoesNotMatchUnboundRequests(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{{
			Name:   "github",
			Action: ladulasv1.Action_ACTION_APPROVE,
			Match:  &ladulasv1.Match{Destinations: []string{"github.com"}},
		}},
	})

	req := sshAuthRequest("", "git", false, false)

	got := policy.Evaluate(req)
	if got.Action != ladulasv1.Action_ACTION_PROMPT {
		t.Errorf("action %v, want PROMPT", got.Action)
	}

	if got.Rule != "default for unbound SSH authentication" {
		t.Errorf("rule %q", got.Rule)
	}
}

func TestPolicyUnboundDefault(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Defaults: &ladulasv1.Defaults{
			UnboundSshAuth: ladulasv1.Action_ACTION_DENY,
		},
	})

	got := policy.Evaluate(sshAuthRequest("", "hugo", false, false))
	if got.Action != ladulasv1.Action_ACTION_DENY {
		t.Errorf("action %v, want DENY", got.Action)
	}
}

func TestPolicyMatchesExecutableAndKeyLabel(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{{
			Name:   "ssh with the work key",
			Action: ladulasv1.Action_ACTION_APPROVE,
			Match: &ladulasv1.Match{
				Executables: []string{"/usr/bin/ssh"},
				KeyLabels:   []string{"work"},
			},
		}},
	})

	if got := policy.Evaluate(sshAuthRequest("host", "hugo", true, false)); got.Action !=
		ladulasv1.Action_ACTION_APPROVE {
		t.Errorf("action %v", got.Action)
	}

	other := sshAuthRequest("host", "hugo", true, false)
	other.Requester.Process.Executable = "/usr/bin/curl"

	if got := policy.Evaluate(other); got.Action != ladulasv1.Action_ACTION_PROMPT {
		t.Errorf("a different program matched the rule: %v", got.Action)
	}
}

func TestPolicyNotifyDefaultsToOn(t *testing.T) {
	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{
			{Name: "loud", Action: ladulasv1.Action_ACTION_APPROVE},
		},
	})

	if !policy.Evaluate(gitSignRequest()).Notify {
		t.Error("an auto-approving rule should notify unless it says otherwise")
	}

	quiet := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Rules: []*ladulasv1.Rule{
			{Name: "quiet", Action: ladulasv1.Action_ACTION_APPROVE, Notify: boolPtr(false)},
		},
	})

	if quiet.Evaluate(gitSignRequest()).Notify {
		t.Error("notify: false was ignored")
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestPolicyTimeouts(t *testing.T) {
	policy := approval.DefaultPolicy()

	if got := policy.Timeout(ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH); got !=
		approval.DefaultSSHAuthTimeout {
		t.Errorf("ssh auth timeout %s", got)
	}

	if got := policy.Timeout(ladulasv1.RequestKind_REQUEST_KIND_GIT_SIGN); got !=
		approval.DefaultSignTimeout {
		t.Errorf("sign timeout %s", got)
	}

	custom := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Defaults: &ladulasv1.Defaults{
			SshAuthTimeout: durationpb.New(30 * time.Second),
			SignTimeout:    durationpb.New(2 * time.Minute),
		},
	})

	if got := custom.Timeout(ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH); got !=
		30*time.Second {
		t.Errorf("custom ssh auth timeout %s", got)
	}
}

func TestPolicyRoundTripsThroughDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")

	policy := approval.NewPolicy(&ladulasv1.PolicyDocument{
		Version: 1,
		Defaults: &ladulasv1.Defaults{
			Fallback:       ladulasv1.Action_ACTION_PROMPT,
			SshAuthTimeout: durationpb.New(45 * time.Second),
		},
		Rules: []*ladulasv1.Rule{{
			Name:        "github",
			Description: "GitHub is asked for a signature on every push",
			Action:      ladulasv1.Action_ACTION_APPROVE,
			Match:       &ladulasv1.Match{Destinations: []string{"github.com"}},
		}},
	})

	if err := policy.Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := approval.LoadPolicy(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	got := loaded.Evaluate(sshAuthRequest("github.com", "git", true, false))
	if got.Action != ladulasv1.Action_ACTION_APPROVE || got.Rule != "github" {
		t.Errorf("policy did not survive the round trip: %+v", got)
	}

	if loaded.Timeout(ladulasv1.RequestKind_REQUEST_KIND_SSH_AUTH) != 45*time.Second {
		t.Error("timeout did not survive the round trip")
	}
}

func TestLoadPolicyOfMissingFileIsTheDefault(t *testing.T) {
	policy, err := approval.LoadPolicy(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if got := policy.Evaluate(gitSignRequest()); got.Action != ladulasv1.Action_ACTION_PROMPT {
		t.Errorf("action %v", got.Action)
	}
}

func durationProto(d time.Duration) *durationpb.Duration {
	return durationpb.New(d)
}
