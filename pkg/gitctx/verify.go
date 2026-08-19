package gitctx

import (
	"crypto/subtle"
	"errors"
	"fmt"

	ladulasv1 "github.com/hugowetterberg/ladulas/pkg/protocol/ladulasv1"
	"github.com/hugowetterberg/ladulas/pkg/sshsig"
)

// ErrContextMismatch is returned when a request's context describes a different
// object from the one the signature would cover. It is the attack the check
// exists for: a compromised requester showing an innocuous commit while asking
// for a signature over something else.
var ErrContextMismatch = errors.New(
	"gitctx: the commit shown is not the one being signed")

// Verify checks a git context against the payload it accompanies and records
// the outcome in the context itself (§5).
//
// The SSHSIG payload commits to a digest of the message, so the check is simply
// whether the object in the context hashes to that digest. When it does, the
// message, author and timestamps the prompt shows are provably the ones the
// signature covers — the one part of a git prompt that survives a compromised
// requester.
//
// A context with no object is not a mismatch; it is a plain agent request,
// which has no object to check and is prompted with the digest alone.
func Verify(git *ladulasv1.GitContext, hashAlgorithm string, digest []byte) error {
	if git == nil {
		return nil
	}

	git.VerifiedAgainstPayload = false
	git.VerificationError = ""

	object := git.GetObject()
	if len(object) == 0 {
		return nil
	}

	if len(digest) == 0 {
		git.VerificationError = "there was no payload digest to check the commit against"

		return fmt.Errorf("%w: no digest", ErrContextMismatch)
	}

	computed, err := sshsig.Hash(hashAlgorithm, object)
	if err != nil {
		git.VerificationError = "the commit could not be checked against the payload: " +
			err.Error()

		return fmt.Errorf("%w: %w", ErrContextMismatch, err)
	}

	if subtle.ConstantTimeCompare(computed, digest) != 1 {
		git.VerificationError = "the commit shown is not the one that would be signed"

		return ErrContextMismatch
	}

	// Parsing after the digest matches means the prompt shows a parse of the
	// exact bytes being signed, and never a parse of something else.
	if err := Describe(git); err != nil {
		git.VerificationError = "the payload does not parse as a git object: " + err.Error()

		return fmt.Errorf("%w: %w", ErrContextMismatch, err)
	}

	git.VerifiedAgainstPayload = true

	return nil
}

// VerifyRequest applies Verify to an approval request, if it is a git signing
// request carrying a context. It returns a description of the problem for the
// audit log and the prompt, or an empty string when there is nothing wrong.
func VerifyRequest(req *ladulasv1.ApprovalRequest) string {
	sig := req.GetSshsig()
	if sig == nil {
		return ""
	}

	git := sig.GetGitContext()
	if git == nil {
		return ""
	}

	if err := Verify(git, sig.GetHashAlgorithm(), sig.GetMessageDigest()); err != nil {
		if problem := git.GetVerificationError(); problem != "" {
			return problem
		}

		return err.Error()
	}

	return ""
}
