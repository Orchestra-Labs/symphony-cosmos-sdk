// Package ethsecp256k1 implements the Ethereum secp256k1 key type for use
// with the Cosmos SDK. It differs from the standard secp256k1 key in:
//   - Signing: uses keccak256 hash (not SHA256)
//   - Signature format: 65 bytes [R(32) | S(32) | V(1)] with recovery bit
//   - Address derivation: keccak256(uncompressed_pubkey[1:])[12:] (Ethereum address)
//   - Public key storage: compressed (33 bytes)
//
// This key type is used for EVM-compatible accounts on Symphony. The Cosmos
// bech32 address is derived from the same underlying 20-byte Ethereum address.
package ethsecp256k1

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"

	"github.com/cometbft/cometbft/crypto"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"

	errorsmod "cosmossdk.io/errors"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types/errors"
)

var (
	_ cryptotypes.PrivKey  = &PrivKey{}
	_ codec.AminoMarshaler = &PrivKey{}
	_ cryptotypes.PubKey   = &PubKey{}
	_ codec.AminoMarshaler = &PubKey{}
)

const (
	// PrivKeySize is 32 bytes — the length of a secp256k1 private key scalar.
	PrivKeySize = 32
	// PubKeySize is 33 bytes — compressed secp256k1 public key.
	PubKeySize = 33
	// SigSize is 65 bytes — Ethereum compact signature [R|S|V].
	SigSize = 65

	keyType     = "eth_secp256k1"
	PrivKeyName = "ethermint/PrivKeyEthSecp256k1"
	PubKeyName  = "ethermint/PubKeyEthSecp256k1"
)

// --------------------------------------------------------------------------
// Keccak256 helpers (using golang.org/x/crypto/sha3, no go-ethereum dep)
// --------------------------------------------------------------------------

// keccak256 computes the Ethereum keccak256 hash of input bytes.
func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, b := range data {
		h.Write(b)
	}
	return h.Sum(nil)
}

// --------------------------------------------------------------------------
// PrivKey
// --------------------------------------------------------------------------

// Bytes returns the raw 32-byte private key scalar.
func (privKey *PrivKey) Bytes() []byte {
	return privKey.Key
}

// PubKey derives the compressed secp256k1 public key from the private key.
func (privKey *PrivKey) PubKey() cryptotypes.PubKey {
	priv := secp256k1.PrivKeyFromBytes(privKey.Key)
	return &PubKey{Key: priv.PubKey().SerializeCompressed()}
}

// Equals returns true when the keys have the same bytes.
func (privKey *PrivKey) Equals(other cryptotypes.LedgerPrivKey) bool {
	return privKey.Type() == other.Type() &&
		subtle.ConstantTimeCompare(privKey.Bytes(), other.Bytes()) == 1
}

// Type identifies this key as eth_secp256k1.
func (privKey *PrivKey) Type() string { return keyType }

// Sign signs msg using the Ethereum signing convention:
//   - hash = keccak256(msg)
//   - signature = ECDSA-sign(hash) using secp256k1
//   - returns 65 bytes: [R(32) | S(32) | V(1)]  where V ∈ {0, 1}
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	hash := keccak256(msg)
	priv := secp256k1.PrivKeyFromBytes(privKey.Key)

	// SignCompact returns [recoveryCode(1) | R(32) | S(32)] in Bitcoin format
	// where recoveryCode = 27 + recID (uncompressed) or 31 + recID (compressed).
	// We use compressed=true here so recoveryCode = 31 + recID.
	compact := secp256k1ecdsa.SignCompact(priv, hash, true)

	// Convert Bitcoin compact → Ethereum format [R|S|V]:
	// compact[0] = 31 + recID  →  V = compact[0] - 31
	v := compact[0] - 31
	sig := make([]byte, SigSize)
	copy(sig[0:32], compact[1:33]) // R
	copy(sig[32:64], compact[33:]) // S
	sig[64] = v                    // V (recovery id, 0 or 1)

	return sig, nil
}

// MarshalAmino overrides Amino binary marshaling.
func (privKey PrivKey) MarshalAmino() ([]byte, error) {
	return privKey.Key, nil
}

// UnmarshalAmino overrides Amino binary marshaling.
func (privKey *PrivKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PrivKeySize {
		return fmt.Errorf("invalid ethsecp256k1 privkey size: got %d want %d", len(bz), PrivKeySize)
	}
	privKey.Key = bz
	return nil
}

// MarshalAminoJSON overrides Amino JSON marshaling.
func (privKey PrivKey) MarshalAminoJSON() ([]byte, error) { return privKey.MarshalAmino() }

// UnmarshalAminoJSON overrides Amino JSON marshaling.
func (privKey *PrivKey) UnmarshalAminoJSON(bz []byte) error { return privKey.UnmarshalAmino(bz) }

// GenPrivKey generates a new eth_secp256k1 private key using OS randomness.
func GenPrivKey() *PrivKey {
	return &PrivKey{Key: genPrivKey(crypto.CReader())}
}

// genPrivKey generates a valid secp256k1 private key scalar from rand.
func genPrivKey(rand io.Reader) []byte {
	var privKeyBytes [PrivKeySize]byte
	d := new(big.Int)
	for {
		privKeyBytes = [PrivKeySize]byte{}
		if _, err := io.ReadFull(rand, privKeyBytes[:]); err != nil {
			panic(err)
		}
		d.SetBytes(privKeyBytes[:])
		isValidFieldElement := 0 < d.Sign() && d.Cmp(secp256k1.S256().N) < 0
		if isValidFieldElement {
			break
		}
	}
	return privKeyBytes[:]
}

// GenPrivKeyFromSecret generates a deterministic private key from a secret.
func GenPrivKeyFromSecret(secret []byte) *PrivKey {
	// Use keccak256 for Ethereum-compatible derivation.
	hash := keccak256(secret)
	var privKeyBytes [PrivKeySize]byte

	one := new(big.Int).SetInt64(1)
	fe := new(big.Int).SetBytes(hash)
	n := new(big.Int).Sub(secp256k1.S256().N, one)
	fe.Mod(fe, n)
	fe.Add(fe, one)

	feB := fe.Bytes()
	copy(privKeyBytes[32-len(feB):32], feB)
	return &PrivKey{Key: privKeyBytes[:]}
}

// --------------------------------------------------------------------------
// PubKey
// --------------------------------------------------------------------------

// Address returns the Ethereum-style address derived from this public key:
//
//	addr = keccak256(uncompressed_pubkey[1:])[12:]
//
// The resulting 20-byte address is identical to the underlying Ethereum address,
// and also forms the last 20 bytes of the bech32 Symphony address.
func (pubKey *PubKey) Address() crypto.Address {
	if len(pubKey.Key) != PubKeySize {
		panic("ethsecp256k1: invalid pubkey length")
	}
	pk, err := secp256k1.ParsePubKey(pubKey.Key)
	if err != nil {
		panic(fmt.Sprintf("ethsecp256k1: failed to parse pubkey: %v", err))
	}
	// Uncompressed = 0x04 || X(32) || Y(32) — strip the 0x04 prefix before hashing
	uncompressed := pk.SerializeUncompressed()[1:] // 64 bytes
	return crypto.Address(keccak256(uncompressed)[12:])
}

// Bytes returns the compressed (33-byte) public key.
func (pubKey *PubKey) Bytes() []byte { return pubKey.Key }

// String returns a hex representation of the public key.
func (pubKey *PubKey) String() string { return fmt.Sprintf("PubKeyEthSecp256k1{%X}", pubKey.Key) }

// Type identifies this key as eth_secp256k1.
func (pubKey *PubKey) Type() string { return keyType }

// Equals returns true if two public keys have identical bytes.
func (pubKey *PubKey) Equals(other cryptotypes.PubKey) bool {
	return pubKey.Type() == other.Type() && bytes.Equal(pubKey.Bytes(), other.Bytes())
}

// VerifySignature verifies a 65-byte Ethereum-format signature [R|S|V].
// It recovers the public key from the signature and compares it.
func (pubKey *PubKey) VerifySignature(msg, sig []byte) bool {
	if len(sig) != SigSize {
		return false
	}

	hash := keccak256(msg)

	// Convert Ethereum format [R|S|V] → Bitcoin compact [recoveryCode|R|S]
	// V ∈ {0,1} → recoveryCode = V + 31 (compressed)
	v := sig[64]
	if v > 1 {
		// Some callers pass V=27 or V=28 (old Ethereum style); normalise.
		if v < 27 {
			return false
		}
		v -= 27
		if v > 1 {
			return false
		}
	}
	compact := make([]byte, SigSize)
	compact[0] = v + 31
	copy(compact[1:33], sig[0:32]) // R
	copy(compact[33:65], sig[32:64]) // S

	recovered, _, err := secp256k1ecdsa.RecoverCompact(compact, hash)
	if err != nil {
		return false
	}
	return bytes.Equal(recovered.SerializeCompressed(), pubKey.Key)
}

// MarshalAmino overrides Amino binary marshaling.
func (pubKey PubKey) MarshalAmino() ([]byte, error) { return pubKey.Key, nil }

// UnmarshalAmino overrides Amino binary marshaling.
func (pubKey *PubKey) UnmarshalAmino(bz []byte) error {
	if len(bz) != PubKeySize {
		return errorsmod.Wrap(errors.ErrInvalidPubKey,
			fmt.Sprintf("invalid ethsecp256k1 pubkey size: got %d want %d", len(bz), PubKeySize))
	}
	pubKey.Key = bz
	return nil
}

// MarshalAminoJSON overrides Amino JSON marshaling.
func (pubKey PubKey) MarshalAminoJSON() ([]byte, error) { return pubKey.MarshalAmino() }

// UnmarshalAminoJSON overrides Amino JSON marshaling.
func (pubKey *PubKey) UnmarshalAminoJSON(bz []byte) error { return pubKey.UnmarshalAmino(bz) }

// EthAddress returns the standard 20-byte Ethereum address (common.Address equivalent)
// as a raw byte slice. This is the same value as Address() but without bech32 encoding.
func (pubKey *PubKey) EthAddress() []byte {
	return []byte(pubKey.Address())
}

