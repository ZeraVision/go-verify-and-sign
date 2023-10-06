package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"signature/create_keys"
	"signature/sign"
	"signature/verify"
	"testing"
)

func TestCreationVerifySign(t *testing.T) {
	// Test seed for demonstration; in real applications, ensure it has enough entropy

	// Testing Ed25519
	t.Run("Ed25519", func(t *testing.T) {
		// Without seed
		pubKey1, privKey1 := create_keys.CreateEd25519KeyPair()
		message := []byte("Hello, Ed25519!")
		signature := sign.SignEd25519Message(privKey1, message)
		if !verify.VerifyEd25519Signature(pubKey1, message, signature) {
			t.Error("Failed to verify Ed25519 signature without seed")
		}

		// With seed
		seed := make([]byte, 32)
		_, _ = rand.Read(seed)
		privKey1Seed := ed25519.NewKeyFromSeed(seed)
		pubKey1Seed := privKey1Seed.Public().(ed25519.PublicKey)
		signatureSeed := sign.SignEd25519Message(privKey1Seed, message) // ed25519.Sign(privKey1Seed, message)
		if !verify.VerifyEd25519Signature(pubKey1Seed, message, signatureSeed) {
			t.Error("Failed to verify Ed25519 signature with seed")
		}
	})

	// Testing Ed448
	t.Run("Ed448", func(t *testing.T) {
		// Without seed
		pubKey2, privKey2 := create_keys.CreateEd448KeyPair()
		message := []byte("Hello, Ed448!")
		ctx := ""

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
}
