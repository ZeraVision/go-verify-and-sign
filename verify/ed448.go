package verify

import (
	////"github.com/ZeraVision/go-verify-and-sign/hash"
	"github.com/cloudflare/circl/sign/ed448"
)

// VerifySignature verifies the signature of the given message using the provided public key and context.
func VerifyEd448Signature(publicKey ed448.PublicKey, message []byte, signature []byte, ctx string) bool {
	return ed448.Verify(publicKey, message, signature, ctx) // ctx is "" for network communications
}
