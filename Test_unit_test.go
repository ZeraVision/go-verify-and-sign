package main

import (
	"crypto/rand"
	"testing"

	"github.com/ZeraVision/go-verify-and-sign/create_keys"
	"github.com/ZeraVision/go-verify-and-sign/keys"
	"github.com/ZeraVision/go-verify-and-sign/sign"
	"github.com/ZeraVision/go-verify-and-sign/verify"
)

// go test ./... -v

func TestEd25519(t *testing.T) {
	message := []byte("Hello, Ed25519!")

	// Testing Ed25519
	t.Run("Ed25519 Create No Seed", func(t *testing.T) {
		// Without seed
		pubKey, privKey := create_keys.CreateEd25519KeyPair()
		signature := sign.SignEd25519Message(privKey, message)
		if !verify.VerifyEd25519Signature(pubKey, message, signature) {
			t.Error("Failed to verify Ed25519 signature without seed")
		}
	})

	t.Run("Ed25519 Create With Seed", func(t *testing.T) {
		// With seed
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		pubKey, privKey := keys.CreateEd25519KeyPair(seed)
		signature := sign.SignEd25519Message(privKey, message) // ed25519.Sign(privKey1Seed, message)
		if !verify.VerifyEd25519Signature(pubKey, message, signature) {
			t.Error("Failed to verify Ed25519 signature with seed")
		}
	})

	t.Run("Ed25519 Create From Import r_b_", func(t *testing.T) {
		pubKeyStr := "r_b_AGUsFXWrQWHX1y8nb3jN3eX5zLeftM8KnEYpWPU4yrri"
		priKeyStr := "3MgNpq75ZEEbaESm74HEjKVgAH1qHArXHtotVmFkTtMEkdhHvEwUhav9vr5Y8V4QouGGuSTMhcvv3jLH5eNJ5FTC"

		pubKey, priKey, err := keys.ImportEd25519KeyPair(pubKeyStr, priKeyStr)

		if err != nil {
			t.Error("Failed to decode r_b_ keys: " + err.Error())
		}

		signature := sign.SignEd25519Message(priKey, message) // ed25519.Sign(privKey1Seed, message)
		if !verify.VerifyEd25519Signature(pubKey, message, signature) {
			t.Error("Failed to verify Ed25519 signature for import r_b_")
		}
	})

	t.Run("Ed25519 Create From Import b_", func(t *testing.T) {
		pubKeyStr := "b_AGUsFXWrQWHX1y8nb3jN3eX5zLeftM8KnEYpWPU4yrri"
		priKeyStr := "3MgNpq75ZEEbaESm74HEjKVgAH1qHArXHtotVmFkTtMEkdhHvEwUhav9vr5Y8V4QouGGuSTMhcvv3jLH5eNJ5FTC"

		pubKey, priKey, err := keys.ImportEd25519KeyPair(pubKeyStr, priKeyStr)

		if err != nil {
			t.Error("Failed to decode b_ keys: " + err.Error())
		}

		signature := sign.SignEd25519Message(priKey, message) // ed25519.Sign(privKey1Seed, message)
		if !verify.VerifyEd25519Signature(pubKey, message, signature) {
			t.Error("Failed to verify Ed25519 signature for import b_")
		}
	})
}

func TestEd448(t *testing.T) {
	// Test seed for demonstration; in real applications, ensure it has enough entropy

	message := []byte("Hello, Ed448!")
	ctx := ""
	// Testing Ed448
	t.Run("Ed448", func(t *testing.T) {
		// Without seed
		pubKey2, privKey2 := create_keys.CreateEd448KeyPair()

		signature := sign.SignEd448Message(privKey2, message, ctx)

		if !verify.VerifyEd448Signature(pubKey2, message, signature, ctx) {
			t.Error("Failed to verify Ed448 signature with seed")
		}

		// With seed
		seed := make([]byte, 57)
		_, _ = rand.Read(seed)
		pubKey2Seed, privKey2Seed := create_keys.CreateEd448KeyPair(seed) //circlEd448.NewKeyFromSeed(seed)

		signatureSeed := sign.SignEd448Message(privKey2Seed, message, ctx) // circlEd448.Sign(privKey2Seed, message, ctx)

		if !verify.VerifyEd448Signature(pubKey2Seed, message, signatureSeed, ctx) {
			t.Error("Failed to verify Ed448 signature with seed")
		}

	})

	t.Run("Ed448 Create From Import r_c_", func(t *testing.T) {
		pubKeyStr := "r_c_GANesfzDnNDfpHeB3UteRRCsCGiUE6yH1BC1zXSqys4gghSU4UfRs2HQixsr4myFAyeY4dP7gcSscK"
		priKeyStr := "WKMbk1M9bRYbHsRLVjpEdRHsmfBxC199WhbnZJbKeCkFZz9E7f9G7aEyDCv6Mr255gEA3Gy1ZXKAdu"

		pubKey, priKey, err := keys.ImportEd448KeyPair(pubKeyStr, priKeyStr)

		if err != nil {
			t.Error("Failed to decode r_c_ keys: " + err.Error())
		}

		signature := sign.SignEd448Message(priKey, message, ctx)
		if !verify.VerifyEd448Signature(pubKey, message, signature, ctx) {
			t.Error("Failed to verify Ed448 signature for import r_c_")
		}
	})

	t.Run("Ed448 Create From Import c_", func(t *testing.T) {
		pubKeyStr := "c_GANesfzDnNDfpHeB3UteRRCsCGiUE6yH1BC1zXSqys4gghSU4UfRs2HQixsr4myFAyeY4dP7gcSscK"
		priKeyStr := "WKMbk1M9bRYbHsRLVjpEdRHsmfBxC199WhbnZJbKeCkFZz9E7f9G7aEyDCv6Mr255gEA3Gy1ZXKAdu"

		pubKey, priKey, err := keys.ImportEd448KeyPair(pubKeyStr, priKeyStr)

		if err != nil {
			t.Error("Failed to decode c_ keys: " + err.Error())
		}

		signature := sign.SignEd448Message(priKey, message, ctx) // ed25519.Sign(privKey1Seed, message)
		if !verify.VerifyEd448Signature(pubKey, message, signature, ctx) {
			t.Error("Failed to verify Ed448 signature for import c_")
		}
	})

}
