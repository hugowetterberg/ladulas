package keystore

import (
	"bytes"
	"testing"
)

// Wipe zeros the private material the vault holds before it is dropped on seal
// (M5). This reaches inside the package to prove the backing arrays are actually
// cleared, which is the whole point — dropping the reference is what it replaces.
func TestWipeZerosPrivateMaterial(t *testing.T) {
	opts := Options{
		Dir:              t.TempDir(),
		Keyring:          &MemoryKeyring{},
		Passphrase:       func(string, bool) ([]byte, error) { return []byte("correct horse battery staple"), nil },
		InstanceName:     "test-desktop",
		ScryptWorkFactor: 10,
	}

	v, err := Create(opts)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	if _, err := v.GenerateKey("work", "hugo@example.com"); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Hold on to the backing arrays before Wipe drops the document, so the test
	// can see whether they were cleared rather than merely unreferenced.
	identity := v.doc.GetIdentityKey()
	if len(identity) == 0 {
		t.Fatal("the desktop store has no identity key to wipe")
	}

	var keyMaterial []byte
	for _, key := range v.doc.GetKeys() {
		if len(key.GetPrivateKey()) > 0 {
			keyMaterial = key.GetPrivateKey()
		}
	}

	if keyMaterial == nil {
		t.Fatal("the generated key left no private material to wipe")
	}

	v.Wipe()

	if !allZero(identity) {
		t.Error("the identity key was not zeroed")
	}

	if !allZero(keyMaterial) {
		t.Error("the key's private material was not zeroed")
	}

	if v.doc != nil || v.dek != nil || v.identity != nil {
		t.Error("Wipe left a reference to the store behind")
	}
}

func allZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}
