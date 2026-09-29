// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestBuildLocalSaveDataSubsetCopiesLocalSecrets(t *testing.T) {
	for _, mutateSource := range []bool{false, true} {
		name := "mutate subset"
		if mutateSource {
			name = "mutate source"
		}
		t.Run(name, func(t *testing.T) {
			source, ids := saveDataSubsetFixture()
			subset := BuildLocalSaveDataSubset(source, ids)
			if source.Xi == subset.Xi || source.ShareID == subset.ShareID {
				t.Fatal("local secrets must have independent pointers")
			}
			assert.Equal(t, source.Xi, subset.Xi)
			assert.Equal(t, source.ShareID, subset.ShareID)

			mutated, unchanged := &subset, &source
			if mutateSource {
				mutated, unchanged = &source, &subset
			}
			mutated.Xi.SetInt64(202)
			mutated.ShareID.SetInt64(3)
			assert.Equal(t, int64(101), unchanged.Xi.Int64())
			assert.Equal(t, int64(2), unchanged.ShareID.Int64())
		})
	}
}

func TestBuildLocalSaveDataSubsetPreservesNilSecrets(t *testing.T) {
	for _, secrets := range []LocalSecrets{
		{},
		{Xi: big.NewInt(0)},
		{ShareID: big.NewInt(0)},
	} {
		source, ids := saveDataSubsetFixture()
		source.LocalSecrets = secrets
		subset := BuildLocalSaveDataSubset(source, ids)
		assert.Equal(t, source.Xi, subset.Xi)
		assert.Equal(t, source.ShareID, subset.ShareID)
		if source.Xi != nil && source.Xi == subset.Xi {
			t.Error("present Xi must be copied")
		}
		if source.ShareID != nil && source.ShareID == subset.ShareID {
			t.Error("present ShareID must be copied")
		}
	}
}

func TestBuildLocalSaveDataSubsetRetainsSelectedSharedData(t *testing.T) {
	source, ids := saveDataSubsetFixture()
	subset := BuildLocalSaveDataSubset(source, tss.SortedPartyIDs{ids[0], ids[2]})
	assert.Len(t, subset.Ks, 2)
	if subset.LocalPreParams != source.LocalPreParams || subset.ECDSAPub != source.ECDSAPub {
		t.Error("pre-parameters and aggregate public key pointers must be retained")
	}
	for j, savedIdx := range []int{0, 2} {
		if subset.Ks[j] != source.Ks[savedIdx] ||
			subset.NTildej[j] != source.NTildej[savedIdx] ||
			subset.H1j[j] != source.H1j[savedIdx] ||
			subset.H2j[j] != source.H2j[savedIdx] ||
			subset.BigXj[j] != source.BigXj[savedIdx] ||
			subset.PaillierPKs[j] != source.PaillierPKs[savedIdx] {
			t.Errorf("subset entry %d does not retain saved entry %d", j, savedIdx)
		}
	}
	// Replacing a slice entry must not replace the source's entry.
	subset.Ks[0], subset.NTildej[0], subset.H1j[0], subset.H2j[0] = nil, nil, nil, nil
	subset.BigXj[0], subset.PaillierPKs[0] = nil, nil
	if source.Ks[0] == nil || source.NTildej[0] == nil || source.H1j[0] == nil ||
		source.H2j[0] == nil || source.BigXj[0] == nil || source.PaillierPKs[0] == nil {
		t.Error("subset slices must have independent backing arrays")
	}
}

func TestBuildLocalSaveDataSubsetReportsMalformedInputs(t *testing.T) {
	t.Run("nil saved key", func(t *testing.T) {
		source, ids := saveDataSubsetFixture()
		source.Ks[1] = nil
		assertSaveDataSubsetPanic(t, "BuildLocalSaveDataSubset: a saved party key is nil", func() {
			BuildLocalSaveDataSubset(source, ids)
		})
	})
	for _, tc := range []struct {
		name string
		id   *tss.PartyID
	}{
		{name: "nil party"},
		{name: "missing party content", id: &tss.PartyID{Index: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, _ := saveDataSubsetFixture()
			assertSaveDataSubsetPanic(t, "BuildLocalSaveDataSubset: a party in the given roster has no PartyID content", func() {
				BuildLocalSaveDataSubset(source, tss.SortedPartyIDs{tc.id})
			})
		})
	}
	t.Run("unknown key", func(t *testing.T) {
		source, _ := saveDataSubsetFixture()
		unknown := tss.NewPartyID("unknown", "unknown", big.NewInt(4))
		assertSaveDataSubsetPanic(t, "BuildLocalSaveDataSubset: unable to find a signer party in the local save data", func() {
			BuildLocalSaveDataSubset(source, tss.SortedPartyIDs{unknown})
		})
	})
}

func assertSaveDataSubsetPanic(t *testing.T, expected string, build func()) {
	t.Helper()
	defer func() {
		recovered := recover()
		err, ok := recovered.(error)
		if !ok || err.Error() != expected {
			t.Errorf("expected panic %q, got %v", expected, recovered)
		}
	}()
	build()
}

func saveDataSubsetFixture() (LocalPartySaveData, tss.SortedPartyIDs) {
	source := NewLocalPartySaveData(3)
	source.LocalSecrets = LocalSecrets{Xi: big.NewInt(101), ShareID: big.NewInt(2)}
	source.LocalPreParams = LocalPreParams{
		PaillierSK: &paillier.PrivateKey{},
		NTildei:    big.NewInt(11),
		H1i:        big.NewInt(12),
		H2i:        big.NewInt(13),
		Alpha:      big.NewInt(14),
		Beta:       big.NewInt(15),
		P:          big.NewInt(16),
		Q:          big.NewInt(17),
	}
	source.ECDSAPub = &crypto.ECPoint{}
	ids := make(tss.UnSortedPartyIDs, 3)
	for j := range ids {
		source.Ks[j] = big.NewInt(int64(j + 1))
		source.NTildej[j] = big.NewInt(int64(20 + j))
		source.H1j[j] = big.NewInt(int64(30 + j))
		source.H2j[j] = big.NewInt(int64(40 + j))
		source.BigXj[j] = &crypto.ECPoint{}
		source.PaillierPKs[j] = &paillier.PublicKey{N: big.NewInt(int64(50 + j))}
		ids[j] = tss.NewPartyID(source.Ks[j].String(), "", source.Ks[j])
	}
	return source, tss.SortPartyIDs(ids)
}
