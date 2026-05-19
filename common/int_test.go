package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

func TestMarshalSigned(t *testing.T) {
	assert := assert.New(t)

	assert.Equal([]byte{0}, common.MarshalSigned(nil), "Nil should marshal to 0x00")
	assert.Equal([]byte{0}, common.MarshalSigned(big.NewInt(0)), "0 should marshal to 0x00")
	assert.Equal([]byte{0, 1}, common.MarshalSigned(big.NewInt(1)), "1 should marshal to 0x0001")
	assert.Equal([]byte{0, 1, 1}, common.MarshalSigned(big.NewInt(257)), "257 should marshal to 0x000101")
	assert.Equal([]byte{1, 1}, common.MarshalSigned(big.NewInt(-1)), "-1 should marshal to 0x0101")
}

func TestInt(t *testing.T) {
	assert := assert.New(t)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	four := big.NewInt(4)
	five := big.NewInt(5)
	six := big.NewInt(6)
	seven := big.NewInt(7)

	minusOne := big.NewInt(-1)
	minusTwo := big.NewInt(-2)

	assert.True(common.Eq(one, one))
	assert.False(common.Eq(zero, one))
	assert.False(common.Eq(minusOne, one))

	assert.Equal(seven, common.AddMul(one, two, three))

	mod7 := common.ModInt(seven)

	assert.Equal(six, mod7.Neg(one))

	assert.True(common.Eq(zero, mod7.Add(one, six)))
	assert.Equal(two, mod7.Add(four, five))
	assert.Equal(six, mod7.Add(zero, minusOne))

	assert.Equal(two, mod7.Sub(five, three))
	assert.Equal(six, mod7.Sub(one, two))

	assert.Equal(two, mod7.Div(six, three))
	assert.Equal(one, mod7.Div(five, three))
	assert.Equal(two, mod7.Div(big.NewInt(81), big.NewInt(9)))
	assert.Equal(three, mod7.Div(four, minusOne))

	assert.Equal(six, mod7.Mul(two, three))
	assert.Equal(two, mod7.Mul(three, three))
	assert.Equal(three, mod7.Mul(big.NewInt(8), big.NewInt(10)))
	assert.Equal(three, mod7.Mul(four, minusOne))

	assert.Equal(two, mod7.Exp(three, two))
	assert.Equal(four, mod7.Exp(two, two))
	// 2 is the multiplicative inverse of 4 mod 7
	assert.Equal(four, mod7.Exp(four, minusTwo))

	// 4 * 3^2 = 36 == 1 mod 7
	assert.Equal(one, mod7.MulExp(four, three, two))
	// 2^2 * 3^2 = 36 == 1 mod 7
	assert.Equal(one, mod7.ExpMulExp(two, two, three, two))

	assert.Equal(two, mod7.ModInverse(four))
}

func TestUnmarshalSigned(t *testing.T) {
	assert := assert.New(t)

	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{})) == 0,
		"empty array should unmarshal to 0",
	)

	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{0})) == 0,
		"0x00 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{1})) == 0,
		"0x01 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{255})) == 0,
		"0xff should unmarshal to 0",
	)

	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{0, 0})) == 0,
		"0x0000 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{1, 0})) == 0,
		"0x0100 should unmarshal to 0",
	)
	assert.True(
		big.NewInt(0).Cmp(common.UnmarshalSigned([]byte{255, 0})) == 0,
		"0xff00 should unmarshal to 0",
	)

	assert.True(
		big.NewInt(1).Cmp(common.UnmarshalSigned([]byte{0, 1})) == 0,
		"0x0001 should unmarshal to 1",
	)
	assert.True(
		big.NewInt(-1).Cmp(common.UnmarshalSigned([]byte{1, 1})) == 0,
		"0x0101 should unmarshal to -1",
	)
	assert.True(
		big.NewInt(-1).Cmp(common.UnmarshalSigned([]byte{255, 1})) == 0,
		"0xff01 should unmarshal to -1",
	)

	assert.True(
		big.NewInt(255).Cmp(common.UnmarshalSigned([]byte{0, 255})) == 0,
		"0x00ff should unmarshal to 255",
	)
	assert.True(
		big.NewInt(-255).Cmp(common.UnmarshalSigned([]byte{1, 255})) == 0,
		"0x01ff should unmarshal to -255",
	)
	assert.True(
		big.NewInt(-255).Cmp(common.UnmarshalSigned([]byte{255, 255})) == 0,
		"0xffff should unmarshal to -255",
	)
}

func TestAnyIsNil(t *testing.T) {
	assert := assert.New(t)

	assert.True(common.AnyIsNil(nil))
	assert.False(common.AnyIsNil(big.NewInt(1)))

	assert.True(common.AnyIsNil(big.NewInt(1), nil))
	assert.True(common.AnyIsNil(nil, big.NewInt(2)))
	assert.False(common.AnyIsNil(big.NewInt(1), big.NewInt(2)))
}

// TestAppendUint64ToBytesSlice_PartyContextSeparation pins the invariant that
// per-party Fiat-Shamir context derivation depends on: appending a party index
// (including 0) must always produce a value distinct from the bare SSID, and
// distinct party indices must produce distinct contexts. If this invariant
// regresses (e.g. via a future "skip leading zeros" optimization), party 0's
// proof transcripts would collapse back to the untagged SSID.
func TestAppendUint64ToBytesSlice_PartyContextSeparation(t *testing.T) {
	assert := assert.New(t)

	ssid := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	ctx0 := common.AppendUint64ToBytesSlice(ssid, 0)
	ctx1 := common.AppendUint64ToBytesSlice(ssid, 1)
	ctx256 := common.AppendUint64ToBytesSlice(ssid, 256)

	assert.NotEqual(ssid, ctx0, "party-0 context must not collapse to bare SSID")
	assert.NotEqual(ctx0, ctx1, "party-0 and party-1 contexts must differ")
	assert.NotEqual(ctx0, ctx256, "party-0 and party-256 contexts must differ")
	assert.NotEqual(ctx1, ctx256, "party-1 and party-256 contexts must differ")

	assert.Equal(len(ssid)+8, len(ctx0), "appended index must be a fixed 8 bytes")
	assert.Equal(len(ssid)+8, len(ctx1), "appended index must be a fixed 8 bytes")
	assert.Equal(ssid, ctx0[:len(ssid)], "SSID prefix must be preserved")

	expectedCtx0 := append(append([]byte{}, ssid...), 0, 0, 0, 0, 0, 0, 0, 0)
	assert.Equal(expectedCtx0, ctx0, "party-0 must append 8 zero bytes (big-endian uint64)")

	// nil and empty SSID must still yield distinct, non-collapsing contexts.
	emptyCtx0 := common.AppendUint64ToBytesSlice(nil, 0)
	emptyCtx1 := common.AppendUint64ToBytesSlice(nil, 1)
	assert.Equal(8, len(emptyCtx0), "empty SSID + index 0 must still produce 8 bytes")
	assert.NotEqual(emptyCtx0, emptyCtx1, "indices must differ even with empty SSID")
}
