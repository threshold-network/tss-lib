package keygen

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestUnmarshalVSSCommitmentPartCount(t *testing.T) {
	ec := tss.S256()
	points := []*crypto.ECPoint{
		crypto.ScalarBaseMult(ec, big.NewInt(1)),
		crypto.ScalarBaseMult(ec, big.NewInt(2)),
	}
	coordinates := []*big.Int{points[0].X(), points[0].Y(), points[1].X(), points[1].Y()}
	for _, test := range []struct {
		name        string
		coordinates []*big.Int
		valid       bool
	}{
		{"no points", nil, false},
		{"one point", coordinates[:2], false},
		{"partial point", coordinates[:3], false},
		{"expected points", coordinates, true},
		{"extra point", append(append([]*big.Int{}, coordinates...), points[0].X(), points[0].Y()), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			commitment := commitments.NewHashCommitmentWithRandomness(big.NewInt(7), test.coordinates...)
			got, err := unmarshalVSSCommitment(ec, 1, commitment.C, commitment.D)
			if !test.valid {
				if err == nil || got != nil {
					t.Fatalf("incorrect part count accepted: got=%v err=%v", got, err)
				}
				return
			}
			if err != nil || len(got) != len(points) {
				t.Fatalf("correct part count rejected: got=%v err=%v", got, err)
			}
			for i, point := range got {
				if point.X().Cmp(points[i].X()) != 0 || point.Y().Cmp(points[i].Y()) != 0 {
					t.Fatalf("point %d changed", i)
				}
			}
		})
	}
}
