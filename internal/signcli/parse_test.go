package signcli

import (
	"errors"
	"testing"
)

// These are the command lines git 2.55 actually builds for gpg.ssh.program,
// captured by pointing gpg.ssh.program at a script that logged its argv.
func TestParsesTheCommandLinesGitBuilds(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args     []string
		agent    bool
		keyFile  string
		fileName string
	}{
		"literal key through the agent": {
			args: []string{
				"-Y", "sign", "-n", "git",
				"-f", "/tmp/.git_signing_key_tmpx8vEuK",
				"-U",
				"/tmp/.git_signing_buffer_tmpsmslOE",
			},
			agent:    true,
			keyFile:  "/tmp/.git_signing_key_tmpx8vEuK",
			fileName: "/tmp/.git_signing_buffer_tmpsmslOE",
		},
		"private key file": {
			args: []string{
				"-Y", "sign", "-n", "git",
				"-f", "/home/hugo/.ssh/id_ed25519",
				"/tmp/.git_signing_buffer_tmpmdtUmw",
			},
			keyFile:  "/home/hugo/.ssh/id_ed25519",
			fileName: "/tmp/.git_signing_buffer_tmpmdtUmw",
		},
	} {
		operation, ok := operationOf(tc.args)
		if !ok || operation != "sign" {
			t.Fatalf("%s: operation is %q, %v", name, operation, ok)
		}

		inv, err := parseSign(tc.args)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if inv.namespace != "git" {
			t.Errorf("%s: namespace is %q", name, inv.namespace)
		}

		if inv.keyFile != tc.keyFile {
			t.Errorf("%s: key file is %q", name, inv.keyFile)
		}

		if inv.useAgent != tc.agent {
			t.Errorf("%s: useAgent is %v", name, inv.useAgent)
		}

		if len(inv.files) != 1 || inv.files[0] != tc.fileName {
			t.Errorf("%s: files are %v", name, inv.files)
		}
	}
}

// The verification command lines have to be recognised as not-ours without
// being understood, since git runs the same program for them.
func TestVerificationInvocationsAreNotSigning(t *testing.T) {
	t.Parallel()

	for name, args := range map[string][]string{
		"find-principals": {
			"-Y", "find-principals",
			"-f", "/home/hugo/allowed_signers",
			"-s", "/tmp/.git_vtag_tmpuiHAyP",
			"-Overify-time=20260808191413",
		},
		"verify": {
			"-Y", "verify", "-n", "git",
			"-f", "/home/hugo/allowed_signers",
			"-I", "hugo@example.test",
			"-s", "/tmp/.git_vtag_tmpuiHAyP",
			"-Overify-time=20260808191413",
		},
		"check-novalidate": {
			"-Y", "check-novalidate", "-n", "git",
			"-s", "/tmp/.git_vtag_tmpuiHAyP",
		},
	} {
		operation, ok := operationOf(args)
		if !ok {
			t.Fatalf("%s: no -Y found", name)
		}

		if operation == "sign" {
			t.Errorf("%s: read as a signing invocation", name)
		}
	}
}

func TestParseAcceptsAttachedValues(t *testing.T) {
	t.Parallel()

	// OpenSSH's getopt allows -Ysign and -ngit as much as -Y sign and -n git.
	inv, err := parseSign([]string{"-Ysign", "-ngit", "-f/tmp/key", "-U", "/tmp/payload"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if inv.namespace != "git" || inv.keyFile != "/tmp/key" || !inv.useAgent {
		t.Errorf("parsed to %+v", inv)
	}
}

func TestParseRejectsWhatItDoesNotUnderstand(t *testing.T) {
	t.Parallel()

	for name, args := range map[string][]string{
		"unknown flag": {"-Y", "sign", "-n", "git", "-f", "/k", "-Z", "/p"},
		"no namespace": {"-Y", "sign", "-f", "/k", "/p"},
		"no key":       {"-Y", "sign", "-n", "git", "/p"},
		"signing options": {
			"-Y", "sign", "-n", "git", "-f", "/k",
			"-Ohashalg=sha256", "/p",
		},
		"another operation": {"-Y", "verify", "-n", "git", "-f", "/k"},
	} {
		if _, err := parseSign(args); !errors.Is(err, ErrUnsupportedInvocation) {
			t.Errorf("%s: error is %v, want ErrUnsupportedInvocation", name, err)
		}
	}
}

func TestParseDefaultsToStandardInput(t *testing.T) {
	t.Parallel()

	inv, err := parseSign([]string{"-Y", "sign", "-n", "git", "-f", "/k"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(inv.files) != 1 || inv.files[0] != "-" {
		t.Errorf("files are %v, want standard input", inv.files)
	}
}

// A command line with no -Y in it is not one git built (decision AI). The
// second result is what says so, and a trailing -Y with nothing after it is
// still git's shape — malformed, and ssh-keygen's to complain about.
func TestOperationOfSeparatesGitsCommandLinesFromTypedOnes(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		args   []string
		want   string
		gitish bool
	}{
		"sign":         {[]string{"-Y", "sign", "-n", "git"}, "sign", true},
		"attached":     {[]string{"-Ysign"}, "sign", true},
		"verify":       {[]string{"-Y", "verify"}, "verify", true},
		"dangling -Y":  {[]string{"-n", "git", "-Y"}, "", true},
		"help":         {[]string{"-h"}, "", false},
		"generation":   {[]string{"-t", "ed25519", "-f", "/k"}, "", false},
		"nothing":      {nil, "", false},
		"after a dash": {[]string{"--", "-Y", "sign"}, "", false},
	} {
		operation, gitish := operationOf(tc.args)

		if gitish != tc.gitish {
			t.Errorf("%s: carries an operation = %v, want %v", name, gitish, tc.gitish)
		}

		if operation != tc.want {
			t.Errorf("%s: operation %q, want %q", name, operation, tc.want)
		}
	}
}
