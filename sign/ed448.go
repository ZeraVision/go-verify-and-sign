package sign

import (
	"github.com/cloudflare/circl/sign/ed448"
)

// SignMessage signs the given message using the provided private key and context.
func SignEd448Message(privateKey ed448.PrivateKey, message []byte, ctx string) []byte {
	return ed448.Sign(privateKey, message, ctx)
}
