package keygen_test

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestLegacySaveDataSerialization(t *testing.T) {
	point := crypto.ScalarBaseMult(tss.S256(), big.NewInt(42))
	want := keygen.LocalPartySaveData{
		Ks: []*big.Int{big.NewInt(1)}, BigXj: []*crypto.ECPoint{point}, ECDSAPub: point,
	}
	legacyJSON, err := ioutil.ReadFile("testdata/save_data_legacy_btcec.json")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(want)
	if err != nil || !bytes.Equal(encoded, bytes.TrimSpace(legacyJSON)) {
		t.Fatalf("save-data JSON differs from legacy output: %v", err)
	}
	legacyHex, err := ioutil.ReadFile("testdata/save_data_legacy_btcec.gob.hex")
	if err != nil {
		t.Fatal(err)
	}
	legacyGob, err := hex.DecodeString(string(bytes.TrimSpace(legacyHex)))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "gob"} {
		t.Run(format, func(t *testing.T) {
			var restored keygen.LocalPartySaveData
			var err error
			if format == "json" {
				err = json.Unmarshal(legacyJSON, &restored)
			} else {
				err = gob.NewDecoder(bytes.NewReader(legacyGob)).Decode(&restored)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(restored.Ks) != 1 || restored.Ks[0].Cmp(big.NewInt(1)) != 0 ||
				len(restored.BigXj) != 1 || !point.Equals(restored.BigXj[0]) || !point.Equals(restored.ECDSAPub) {
				t.Fatal("restored save data differs from legacy output")
			}
			if !tss.SameCurve(restored.BigXj[0].Curve(), tss.S256()) || !tss.SameCurve(restored.ECDSAPub.Curve(), tss.S256()) {
				t.Fatal("restored save-data points lost their curve registration")
			}
			if format == "gob" {
				var buf bytes.Buffer
				if err := gob.NewEncoder(&buf).Encode(restored); err != nil {
					t.Fatal(err)
				}
				var roundTrip keygen.LocalPartySaveData
				if err := gob.NewDecoder(&buf).Decode(&roundTrip); err != nil || !point.Equals(roundTrip.ECDSAPub) {
					t.Fatalf("save-data Gob round trip failed: %v", err)
				}
			}
		})
	}
}
