package crypto_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

// These ordinary public-point outputs were captured with the legacy btcec
// dependency at c26ffa870fd8 before migrating to btcec/v2.
func TestSecp256k1LegacyPointCompatibility(t *testing.T) {
	curve := tss.S256()
	point := crypto.ScalarBaseMult(curve, big.NewInt(42))
	added, err := point.Add(crypto.ScalarBaseMult(curve, big.NewInt(17)))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		point *crypto.ECPoint
		x, y  string
	}{
		{"base multiply", point, "fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af", "7b158f244cd0de2134ac7c1d371cffbfae4db40801a2572e531c573cda9b5b4"},
		{"add", added, "7635ca72d7e8432c338ec53cd12220bc01c48685e24f7dc8c602a7746998e435", "91b649609489d613d1d5e590f78e6d74ecfc061d57048bad9e76f302c5b9c61"},
		{"multiply", point.ScalarMult(big.NewInt(17)), "13a5fa6920629fd9f14541b803f64baa67f043fbc883ea787722de0f68d8fbe5", "76cd800492f816f4b7b8c2c55d3a4022d9498094932406fc6d2159c7eb06ac70"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.point == nil || test.point.X().Text(16) != test.x || test.point.Y().Text(16) != test.y {
				t.Fatal("point differs from legacy output")
			}
			pub := test.point.ToECDSAPubKey()
			if pub.Curve != curve || pub.X.Cmp(test.point.X()) != 0 || pub.Y.Cmp(test.point.Y()) != 0 {
				t.Fatal("ECDSA public key conversion changed")
			}
		})
	}

	const legacyJSON = `{"Curve":"secp256k1","Coords":[115136800820456833737994126771386015026287095034625623644186278108926690779567,3479535755779840016334846590594739014278212596066547564422106861430200972724]}`
	const legacyGob = "2100000002fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af210000000207b158f244cd0de2134ac7c1d371cffbfae4db40801a2572e531c573cda9b5b4"
	encoded, err := json.Marshal(point)
	if err != nil || string(encoded) != legacyJSON {
		t.Fatalf("JSON differs from legacy output: %s, %v", encoded, err)
	}
	var fromJSON crypto.ECPoint
	if err := json.Unmarshal([]byte(legacyJSON), &fromJSON); err != nil || !point.Equals(&fromJSON) {
		t.Fatalf("legacy JSON could not be restored: %v", err)
	}
	encoded, err = point.GobEncode()
	if err != nil || hex.EncodeToString(encoded) != legacyGob {
		t.Fatalf("Gob differs from legacy output: %x, %v", encoded, err)
	}
	legacyBytes, err := hex.DecodeString(legacyGob)
	if err != nil {
		t.Fatal(err)
	}
	var fromGob crypto.ECPoint
	if err := fromGob.GobDecode(legacyBytes); err != nil || !point.Equals(&fromGob) {
		t.Fatalf("legacy Gob could not be restored: %v", err)
	}
}
