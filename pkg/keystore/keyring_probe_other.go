//go:build !linux

package keystore

import "errors"

// probe answers Has by reading, which on the remaining desktop keychains costs
// no prompt. See the Linux version for why the Secret Service cannot.
func probe(name string) (bool, error) {
	_, err := SystemKeyring{}.Get(name)

	switch {
	case errors.Is(err, ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}
