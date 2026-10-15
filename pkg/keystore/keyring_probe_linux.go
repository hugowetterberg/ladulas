package keystore

import (
	"fmt"

	ss "github.com/zalando/go-keyring/secret_service"
)

// probe answers Has on the Secret Service by searching the login collection
// rather than reading from it.
//
// A read is not merely more expensive here, it can be unanswerable. go-keyring
// unlocks the collection before every lookup, and unlocking a locked one opens
// a prompt and then waits for its Completed signal with no timeout. On a
// session with no prompter — a window manager that never started one, a login
// that did not unlock the keyring through PAM — that signal never comes, and
// the daemon's Status handler, which asks Has every time it is called once the
// store is open, parked forever. Every `ladulas status` and every redraw of the
// lock panel hung from the moment the store was unlocked.
//
// SearchItems on a collection returns locked items as well as unlocked ones and
// never prompts, so it answers "is there an entry to try" honestly without
// asking anybody anything. Whether the entry still unlocks is the read's
// question, and only an unlock that wants the key asks it.
func probe(name string) (bool, error) {
	svc, err := ss.NewSecretService()
	if err != nil {
		return false, fmt.Errorf("reach the secret service: %w", err)
	}

	// The attributes go-keyring files an entry under.
	results, err := svc.SearchItems(svc.GetLoginCollection(), map[string]string{
		"username": name,
		"service":  keyringService,
	})
	if err != nil {
		return false, fmt.Errorf("search the keyring: %w", err)
	}

	return len(results) > 0, nil
}
