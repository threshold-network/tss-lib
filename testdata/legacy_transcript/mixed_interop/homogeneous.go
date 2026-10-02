package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

// runHomogeneousControl drives the identical ceremony shape through round 8
// with two current-implementation parties and no historical subprocess at
// all, to demonstrate the default legacy path is otherwise fully functional
// and that "reject" above is specific to the historical witness range.
func runHomogeneousControl() (*scenarioResult, error) {
	restore := fixedRandom("homogeneous-control")
	defer restore()

	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		return nil, fmt.Errorf("load keygen fixtures: %w", err)
	}
	ec := tss.S256()

	msg := new(big.Int)
	msg.SetString(fixedMessageHex, 16)
	msgBytes, _ := hex.DecodeString(fixedMessageHex)

	ctx := tss.NewPeerContext(partyIDs)
	outCh := make(chan tss.Message, 32)
	endCh := make(chan *common.SignatureData, 2)

	parties := make([]tss.Party, 2)
	for i := range parties {
		params := tss.NewParameters(ec, ctx, partyIDs[i], 2, 1)
		params.SetProtocolMode(tss.ProtocolModeLegacy)
		parties[i] = signing.NewLocalParty(msg, params, keys[i], outCh, endCh, len(msgBytes))
	}

	for _, p := range parties {
		if err := p.Start(); err != nil {
			return nil, fmt.Errorf("homogeneous start: %w", err)
		}
	}

	result := &scenarioResult{Name: "homogeneous-control"}

pump:
	for {
		// Same termination rule as runMixedScenario: stop only after BOTH
		// parties have emitted their first round-8-or-later message. Each
		// such message is captured as per-actor evidence and dropped (never
		// forwarded), and lower-round messages keep flowing until both
		// sides have emitted round 8 — so this minimal 2-of-20 fixture
		// subset can never cascade into round 9.
		if result.round8BothReached() {
			break pump
		}
		select {
		case m := <-outCh:
			if roundNumberOf(m) >= 8 {
				// Per-actor boundary evidence: capture which party emitted
				// the round-8-or-later message and drop it.
				if m.GetFrom().Index == partyIDs[0].Index {
					result.AliceReachedRound8 = true
				} else {
					result.BobReachedRound8 = true
				}
				break
			}
			wireBytes, _, wErr := m.WireBytes()
			if wErr != nil {
				return nil, fmt.Errorf("homogeneous wire bytes: %w", wErr)
			}
			dest := m.GetTo()
			if dest == nil {
				for _, p := range parties {
					if p.PartyID().Index == m.GetFrom().Index {
						continue
					}
					if _, uErr := p.UpdateFromBytes(wireBytes, m.GetFrom(), true); uErr != nil {
						return nil, fmt.Errorf("homogeneous update: %w", uErr)
					}
				}
			} else {
				if _, uErr := parties[dest[0].Index].UpdateFromBytes(wireBytes, m.GetFrom(), false); uErr != nil {
					return nil, fmt.Errorf("homogeneous update: %w", uErr)
				}
			}
		case <-endCh:
			result.Completed = true
		}
	}

	return result, nil
}
