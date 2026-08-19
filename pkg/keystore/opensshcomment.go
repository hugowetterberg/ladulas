package keystore

import (
	"encoding/binary"
	"encoding/pem"
)

const openSSHMagic = "openssh-key-v1\x00"

// keyComment recovers the comment from an unencrypted OpenSSH private key.
//
// x/crypto parses these keys but does not hand back the comment, and the
// comment is where 1Password puts the key's email address — worth having in a
// prompt. Encrypted keys keep the comment inside the encrypted section, so this
// returns "" for those and the caller falls back to the label.
func keyComment(keyPEM []byte) string {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return ""
	}

	body := block.Bytes

	if len(body) < len(openSSHMagic) || string(body[:len(openSSHMagic)]) != openSSHMagic {
		return ""
	}

	rest := body[len(openSSHMagic):]

	cipherName, rest, ok := readString(rest)
	if !ok || string(cipherName) != "none" {
		return ""
	}

	// kdfName, kdfOptions.
	for range 2 {
		if _, rest, ok = readString(rest); !ok {
			return ""
		}
	}

	if len(rest) < 4 {
		return ""
	}

	numKeys := binary.BigEndian.Uint32(rest)
	rest = rest[4:]

	if numKeys != 1 {
		return ""
	}

	// The public key blob, then the private section.
	if _, rest, ok = readString(rest); !ok {
		return ""
	}

	priv, _, ok := readString(rest)
	if !ok || len(priv) < 8 {
		return ""
	}

	// Skip the two check integers. Everything after them is a sequence of
	// length-prefixed strings for every key type OpenSSH supports — mpints are
	// length-prefixed too — ending with the comment, followed by 1,2,3,…
	// padding. So the last string that parses cleanly is the comment.
	fields := priv[8:]

	var last []byte

	for {
		field, remainder, ok := readString(fields)
		if !ok {
			break
		}

		last, fields = field, remainder
	}

	if !validPadding(fields) {
		return ""
	}

	return string(last)
}

// validPadding checks the 1,2,3,… tail OpenSSH appends to round the private
// section up to the cipher block size. Anything else means the parse walked off
// the rails and the "comment" is really key material.
func validPadding(pad []byte) bool {
	if len(pad) >= 8 {
		return false
	}

	for i, b := range pad {
		if int(b) != i+1 {
			return false
		}
	}

	return true
}

func readString(b []byte) (value, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}

	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, b, false
	}

	return b[4 : 4+n], b[4+n:], true
}
