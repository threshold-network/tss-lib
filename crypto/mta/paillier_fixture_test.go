// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

// mtaFixturePaillierSK mirrors the committed keygen fixture format
// (test/_ecdsa_fixtures/keygen_data_*.json). The mta package is an internal
// test, so it cannot import the paillier package's test-only loader; reading
// the JSON directly here is the sanctioned small-helper path.
type mtaFixturePaillierSK struct {
	N, LambdaN, PhiN *big.Int
}

// loadPaillierKeyFixture reads the pre-generated 2048-bit Paillier key pair
// committed for keygen party `index` under test/_ecdsa_fixtures, so the mta
// tests do not pay for fresh safe-prime generation on every run.
// TestShareProtocol remains the single mta test that still generates a key
// inline, keeping the generator path covered.
func loadPaillierKeyFixture(index int) (sk *paillier.PrivateKey, pk *paillier.PublicKey, err error) {
	_, fileName, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(fileName), "../../test/_ecdsa_fixtures")
	path := filepath.Join(fixtureDir, fmt.Sprintf("keygen_data_%d.json", index))

	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open Paillier key fixture for party %d at %s: %w", index, path, err)
	}
	var fixture struct {
		PaillierSK mtaFixturePaillierSK
	}
	if err := json.Unmarshal(bz, &fixture); err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal Paillier key fixture for party %d at %s: %w", index, path, err)
	}
	if fixture.PaillierSK.N == nil || fixture.PaillierSK.LambdaN == nil || fixture.PaillierSK.PhiN == nil {
		return nil, nil, fmt.Errorf("incomplete Paillier key fixture for party %d at %s", index, path)
	}

	sk = &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{N: fixture.PaillierSK.N},
		LambdaN:   fixture.PaillierSK.LambdaN,
		PhiN:      fixture.PaillierSK.PhiN,
	}
	return sk, &sk.PublicKey, nil
}
