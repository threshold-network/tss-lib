// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package ckd_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	. "github.com/bnb-chain/tss-lib/crypto/ckd"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec/v2"
)

func TestLegacyPublicDerivationHierarchy(t *testing.T) {
	// Captured with btcec at c26ffa870fd8. Pin both the serialized xpub and
	// the accumulated scalar used to adjust existing signing shares.
	const master = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	const wantChild = "xpub6CYmVEgeUykCausT5DuGF88T5ygofv63uKA287sVoASqgavVhNXxVWCrGQQReXBjyMGkURetqftCVhMrAzLoCUcbP46o4sibtt3LisHMKkC"
	const wantDelta = "5cf748ee8bf3158bd5f642c0cab22fbf9e3148181497b3e85386ebe4d4819620"
	curve := tss.S256()
	root, err := NewExtendedKeyFromString(master, curve)
	if err != nil {
		t.Fatal(err)
	}
	if root.PublicKey.Curve != curve || !curve.IsOnCurve(root.X, root.Y) {
		t.Fatal("parsed key did not preserve the ECDSA public key contract")
	}
	curveCopy := *btcec.S256()
	withCurveCopy, err := NewExtendedKeyFromString(master, &curveCopy)
	if err != nil {
		t.Fatal(err)
	}
	if withCurveCopy.Curve != &curveCopy || withCurveCopy.String() != master {
		t.Fatal("parsed key did not retain the supplied curve instance")
	}
	delta, child, err := DeriveChildKeyFromHierarchy([]uint32{12, 209, 3}, root, curve.Params().N, curve)
	if err != nil {
		t.Fatal(err)
	}
	if child.String() != wantChild || delta.Text(16) != wantDelta {
		t.Fatalf("hierarchy differs from legacy output: child %s, delta %x", child, delta)
	}
}

func TestPublicDerivation(t *testing.T) {
	// port from https://github.com/btcsuite/btcutil/blob/master/hdkeychain/extendedkey_test.go
	// The public extended keys for test vectors in [BIP32].
	testVec1MasterPubKey := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	testVec2MasterPubKey := "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"

	tests := []struct {
		name    string
		master  string
		path    []uint32
		wantPub string
	}{
		// Test vector 1
		{
			name:    "test vector 1 chain m",
			master:  testVec1MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		},
		{
			name:    "test vector 1 chain m/0",
			master:  testVec1MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
		},
		{
			name:    "test vector 1 chain m/0/1",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1},
			wantPub: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
		},
		{
			name:    "test vector 1 chain m/0/1/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2},
			wantPub: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2},
			wantPub: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
		},
		{
			name:    "test vector 1 chain m/0/1/2/2/1000000000",
			master:  testVec1MasterPubKey,
			path:    []uint32{0, 1, 2, 2, 1000000000},
			wantPub: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
		},

		// Test vector 2
		{
			name:    "test vector 2 chain m",
			master:  testVec2MasterPubKey,
			path:    []uint32{},
			wantPub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		},
		{
			name:    "test vector 2 chain m/0",
			master:  testVec2MasterPubKey,
			path:    []uint32{0},
			wantPub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		},
		{
			name:    "test vector 2 chain m/0/2147483647",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647},
			wantPub: "xpub6ASAVgeWMg4pmutghzHG3BohahjwNwPmy2DgM6W9wGegtPrvNgjBwuZRD7hSDFhYfunq8vDgwG4ah1gVzZysgp3UsKz7VNjCnSUJJ5T4fdD",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1},
			wantPub: "xpub6CrnV7NzJy4VdgP5niTpqWJiFXMAca6qBm5Hfsry77SQmN1HGYHnjsZSujoHzdxf7ZNK5UVrmDXFPiEW2ecwHGWMFGUxPC9ARipss9rXd4b",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646},
			wantPub: "xpub6FL2423qFaWzHCvBndkN9cbkn5cysiUeFq4eb9t9kE88jcmY63tNuLNRzpHPdAM4dUpLhZ7aUm2cJ5zF7KYonf4jAPfRqTMTRBNkQL3Tfta",
		},
		{
			name:    "test vector 2 chain m/0/2147483647/1/2147483646/2",
			master:  testVec2MasterPubKey,
			path:    []uint32{0, 2147483647, 1, 2147483646, 2},
			wantPub: "xpub6H7WkJf547AiSwAbX6xsm8Bmq9M9P1Gjequ5SipsjipWmtXSyp4C3uwzewedGEgAMsDy4jEvNTWtxLyqqHY9C12gaBmgUdk2CGmwachwnWK",
		},
	}

tests:
	for i, test := range tests {
		extKey, err := NewExtendedKeyFromString(test.master, btcec.S256())
		if err != nil {
			t.Errorf("NewKeyFromString #%d (%s): unexpected error "+
				"creating extended key: %v", i, test.name,
				err)
			continue
		}

		for _, childNum := range test.path {
			var err error
			_, extKey, err = DeriveChildKey(childNum, extKey, btcec.S256())
			if err != nil {
				t.Errorf("err: %v", err)
				continue tests
			}
		}

		pubStr := extKey.String()
		if pubStr != test.wantPub {
			t.Errorf("Derive #%d (%s): mismatched serialized "+
				"public extended key -- got: %s, want: %s", i,
				test.name, pubStr, test.wantPub)
			continue
		}
	}
}

// koblitzShim is a non-btcec elliptic.Curve value with the secp256k1 domain
// parameters. Its IsOnCurve always reports failure, so the stdlib point
// decoding path would reject every key.
type koblitzShim struct {
	elliptic.Curve
}

func (koblitzShim) IsOnCurve(x, y *big.Int) bool {
	return false
}

// TestNewExtendedKeyFromStringParsesByCurveParameters covers a non-btcec
// secp256k1 curve value: the parser must be selected by the curve's domain
// parameters, so a key that the stdlib decode path would silently mangle (nil
// coordinates) still parses successfully.
func TestNewExtendedKeyFromStringParsesByCurveParameters(t *testing.T) {
	const master = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	inner := btcec.S256()
	shim := koblitzShim{Curve: inner}

	key, err := NewExtendedKeyFromString(master, &shim)
	if err != nil {
		t.Fatalf("NewExtendedKeyFromString with a secp256k1-parameters shim curve: %v", err)
	}
	if key.X == nil || key.Y == nil {
		t.Fatal("parsed key has nil coordinates on a secp256k1-parameters curve")
	}
	if !inner.IsOnCurve(key.X, key.Y) {
		t.Fatal("parsed key coordinates are not on secp256k1")
	}
	if key.Curve != &shim {
		t.Fatal("parsed key did not retain the supplied curve instance")
	}
	if got, want := key.String(), master; got != want {
		t.Fatalf("parsed key serializes to %q, want %q", got, want)
	}
}

// TestNewExtendedKeyFromStringRejectsUnparseableCurve covers a curve that
// cannot decode the key data: 33 bytes is not a compressed P-521 point, so
// the function must return an error instead of a key with nil coordinates.
func TestNewExtendedKeyFromStringRejectsUnparseableCurve(t *testing.T) {
	const master = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	_, err := NewExtendedKeyFromString(master, elliptic.P521())
	if err == nil {
		t.Fatal("NewExtendedKeyFromString must fail when the curve cannot parse the key data")
	}
}

// TestNewExtendedKeyFromStringRoundTripsP256 covers the non-secp256k1 parse
// path with a curve that fits the 33-byte compressed key field: a P-256 key
// serialized by String must parse back to the same point.
func TestNewExtendedKeyFromStringRoundTripsP256(t *testing.T) {
	curve := elliptic.P256()
	x, y := curve.ScalarBaseMult(big.NewInt(0x5eed).Bytes())
	key := &ExtendedKey{
		PublicKey:  ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		Depth:      1,
		ChildIndex: 7,
		ChainCode:  bytes.Repeat([]byte{0x42}, 32),
		ParentFP:   []byte{1, 2, 3, 4},
		Version:    []byte{0x04, 0x88, 0xb2, 0x1e},
	}
	encoded := key.String()

	parsed, err := NewExtendedKeyFromString(encoded, curve)
	if err != nil {
		t.Fatalf("NewExtendedKeyFromString on a P-256 key: %v", err)
	}
	if parsed.X.Cmp(x) != 0 || parsed.Y.Cmp(y) != 0 {
		t.Fatal("parsed P-256 key does not match the serialized point")
	}
	if parsed.Curve != curve {
		t.Fatal("parsed key did not retain the supplied curve instance")
	}
	if parsed.String() != encoded {
		t.Fatal("parsed P-256 key does not serialize back to the same string")
	}
}
