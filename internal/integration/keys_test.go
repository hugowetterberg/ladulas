package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hugowetterberg/ladulas/internal/testutil"
)

// The key verbs against a running daemon, which is the case §14 calls feature
// parity for a headless box: SSH in, run the CLI, add a key.
//
// They used to open the store themselves, so on a box whose daemon was already
// unlocked they asked for a passphrase there was no terminal to type — the one
// answer a management command must never give. Everything here is driven
// through the real command line against an instance that holds the store, and
// none of it involves the CLI process opening a store of its own.

func TestKeyVerbsGoThroughTheRunningDaemon(t *testing.T) {
	cli := buildCLI(t)

	box := startPeerInstance(t, "headless")

	// Listing is a read, and reads go through the daemon too: the CLI has no
	// passphrase and needs none, because the daemon was given one already.
	listed := mustLadulas(t, cli, box, "", "keys", "list")
	if !strings.Contains(listed, "work") {
		t.Fatalf("keys list did not show the instance's key:\n%s", listed)
	}

	generated := mustLadulas(t, cli, box, "", "keys", "generate", "deploy",
		"--comment", "deploy@example.test")
	if !strings.Contains(generated, "Generated SHA256:") {
		t.Fatalf("keys generate said nothing about a key:\n%s", generated)
	}

	// The daemon that made the key is the daemon serving the agent, so the new
	// key is offered immediately rather than at the next restart. That is the
	// other half of what going through the socket buys.
	if keys := agentKeys(t, box); len(keys) != 2 {
		t.Errorf("the agent offers %d keys after generating one", len(keys))
	}

	if got := len(box.app.Vault().Keys()); got != 2 {
		t.Errorf("the running instance holds %d keys", got)
	}

	// Importing takes a file, and the bytes go over the socket.
	imported := mustLadulas(t, cli, box, "", "keys", "import",
		writeTestKey(t), "--label", "borrowed")
	if !strings.Contains(imported, "borrowed") {
		t.Fatalf("keys import said nothing about the key:\n%s", imported)
	}

	public := mustLadulas(t, cli, box, "", "keys", "public", "deploy")
	if !strings.Contains(public, "ssh-ed25519 ") {
		t.Errorf("keys public printed no authorized_keys line:\n%s", public)
	}

	disabled := mustLadulas(t, cli, box, "", "keys", "disable", "deploy")
	if !strings.Contains(disabled, "disabled deploy") {
		t.Errorf("keys disable said nothing:\n%s", disabled)
	}

	// A disabled key is one the agent stops offering, and the running instance
	// is the thing that had to be told: three keys in the store, one of them
	// disabled, two offered.
	if keys := agentKeys(t, box); len(keys) != 2 {
		t.Errorf("the agent offers %d of the three keys with one disabled",
			len(keys))
	}

	mustLadulas(t, cli, box, "", "keys", "enable", "deploy")
	mustLadulas(t, cli, box, "", "keys", "remove", "deploy")

	if got := len(box.app.Vault().Keys()); got != 2 {
		t.Errorf("the running instance holds %d keys after a removal", got)
	}

	listed = mustLadulas(t, cli, box, "", "keys", "list")
	if strings.Contains(listed, "deploy") {
		t.Errorf("the removed key is still listed:\n%s", listed)
	}

	if !strings.Contains(listed, "borrowed") {
		t.Errorf("the imported key is not listed:\n%s", listed)
	}
}

// A sealed daemon refuses the key verbs and says why, rather than sending the
// CLI off to open the store behind its back.
func TestKeyVerbsRefuseASealedDaemon(t *testing.T) {
	cli := buildCLI(t)

	box := startPeerInstance(t, "headless")

	mustLadulas(t, cli, box, "", "lock", "--seal")

	out, err := ladulas(t, cli, box, "", "keys", "list")
	if err == nil {
		t.Fatalf("a sealed instance listed its keys:\n%s", out)
	}

	if !strings.Contains(out, "sealed") {
		t.Errorf("the refusal does not say the store is sealed:\n%s", out)
	}

	if out, err := ladulas(t, cli, box, "", "keys", "generate", "deploy"); err == nil {
		t.Errorf("a sealed instance generated a key:\n%s", out)
	}
}

// writeTestKey makes an unencrypted OpenSSH private key to import, the way a
// 1Password export arrives.
func writeTestKey(t *testing.T) string {
	t.Helper()

	keygen := testutil.RequireTool(t, "ssh-keygen")

	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519")

	testutil.Run(t, dir, keygen,
		"-t", "ed25519", "-N", "", "-C", "imported@example.test", "-f", path)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("ssh-keygen wrote no key: %v", err)
	}

	return path
}
