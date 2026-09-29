// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
)

// PaillierSK mirrors the committed keygen fixture format
// (test/_ecdsa_fixtures/keygen_data_*.json), which stores the party's
// 2048-bit Paillier key material alongside the ceremony's other state.
type fixturePaillierSK struct {
	N, LambdaN, PhiN *big.Int
}

// loadFixturePaillierKey reads the pre-generated 2048-bit Paillier key pair
// committed for keygen party `index` under test/_ecdsa_fixtures. This keeps
// the keygen tests from paying for fresh safe-prime generation on every run;
// the generator itself stays covered by TestGenerateKeyPair.
func loadFixturePaillierKey(index int) (sk *PrivateKey, pk *PublicKey, err error) {
	_, fileName, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(fileName), "../../test/_ecdsa_fixtures")
	path := filepath.Join(fixtureDir, fmt.Sprintf("keygen_data_%d.json", index))

	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("could not open Paillier key fixture for party %d at %s: %w", index, path, err)
	}
	var fixture struct {
		PaillierSK fixturePaillierSK
	}
	if err := json.Unmarshal(bz, &fixture); err != nil {
		return nil, nil, fmt.Errorf("could not unmarshal Paillier key fixture for party %d at %s: %w", index, path, err)
	}
	if fixture.PaillierSK.N == nil || fixture.PaillierSK.LambdaN == nil || fixture.PaillierSK.PhiN == nil {
		return nil, nil, fmt.Errorf("incomplete Paillier key fixture for party %d at %s", index, path)
	}

	sk = &PrivateKey{
		PublicKey: PublicKey{N: fixture.PaillierSK.N},
		LambdaN:   fixture.PaillierSK.LambdaN,
		PhiN:      fixture.PaillierSK.PhiN,
	}
	return sk, &sk.PublicKey, nil
}
