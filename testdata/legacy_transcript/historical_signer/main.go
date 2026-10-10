// Command historical_signer drives a single historical (threshold-network/tss-lib@2e712689)
// ECDSA signing party (index 1, the fixed "peer" role) through a live signing
// ceremony, exchanging real GG18/GG20 round messages with a host process over
// a bounded, newline-delimited JSON protocol on stdin/stdout.
//
// This file is compiled only inside the pinned historical module set up by
// verify_mixed_interop.sh (go.mod.fixture replaces github.com/bnb-chain/tss-lib
// with the exact threshold-network/tss-lib@2e712689 commit). It is never part
// of the current module's build graph.
//
// Protocol (one JSON object per line):
//
//	host -> signer: {"cmd":"init","seed":"<label>","message_hex":"<hex>"}
//	host -> signer: {"cmd":"deliver","is_broadcast":bool,"wire_hex":"<hex>"}
//	host -> signer: {"cmd":"quit"}
//
//	signer -> host: {"event":"message","is_broadcast":bool,"wire_hex":"<hex>"}
//	signer -> host: {"event":"signature","r_hex":"<hex>","s_hex":"<hex>"}
//	signer -> host: {"event":"error","message":"<diagnostic text, not asserted on>"}
//	signer -> host: {"event":"turn_done"}
//
// The signer always plays party index 1 in a fixed 2-signer subset built from
// the existing test/_ecdsa_fixtures/keygen_data_{0,1}.json fixtures (byte
// identical between this historical commit and current dev), so both sides
// derive identical PartyIDs and key material independently without needing to
// serialize either over the wire.
package main

import (
	"bufio"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

// deterministicReader replays a fixed SHA-512 keystream derived from a label
// so the historical prover's witness sampling (including the MtA blinding
// value that becomes the Bob/BobWC T1 witness) is reproducible across runs.
type deterministicReader struct {
	seed    []byte
	mu      sync.Mutex
	counter uint64
	buffer  []byte
}

// Read is safe for concurrent use: signing round 2 draws fresh MtA blinding
// randomness for the Bob and BobWC proofs from two goroutines running
// concurrently, both against the process-global crypto/rand.Reader this
// function replaces. Serializing access to the counter/buffer keystream
// state avoids torn reads that would otherwise corrupt both goroutines'
// values.
func (r *deterministicReader) Read(output []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(output)
	for len(output) > 0 {
		if len(r.buffer) == 0 {
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, r.counter)
			digest := sha512.Sum512(append(append([]byte{}, r.seed...), counter...))
			r.buffer = digest[:]
			r.counter++
		}
		copied := copy(output, r.buffer)
		output = output[copied:]
		r.buffer = r.buffer[copied:]
	}
	return total, nil
}

func fixedRandom(label string) {
	cryptorand.Reader = &deterministicReader{seed: []byte("mixed-interop/" + label)}
}

type command struct {
	Cmd         string `json:"cmd"`
	Seed        string `json:"seed,omitempty"`
	MessageHex  string `json:"message_hex,omitempty"`
	IsBroadcast bool   `json:"is_broadcast,omitempty"`
	WireHex     string `json:"wire_hex,omitempty"`
}

type event struct {
	Event       string `json:"event"`
	IsBroadcast bool   `json:"is_broadcast,omitempty"`
	WireHex     string `json:"wire_hex,omitempty"`
	Message     string `json:"message,omitempty"`
	RHex        string `json:"r_hex,omitempty"`
	SHex        string `json:"s_hex,omitempty"`
}

type signer struct {
	out    chan tss.Message
	end    chan common.SignatureData
	party  tss.Party
	peerID *tss.PartyID
	writer *bufio.Writer
	enc    *json.Encoder
}

func (s *signer) emit(e event) {
	if err := s.enc.Encode(e); err != nil {
		panic(err)
	}
	s.writer.Flush()
}

// drain flushes every currently-buffered outbound message and, if the
// ceremony has finished, the resulting signature, as protocol events.
func (s *signer) drain() {
	for {
		select {
		case msg := <-s.out:
			wire, _, err := msg.WireBytes()
			if err != nil {
				s.emit(event{Event: "error", Message: err.Error()})
				continue
			}
			s.emit(event{Event: "message", IsBroadcast: msg.IsBroadcast(), WireHex: hex.EncodeToString(wire)})
		case <-s.end:
			// Unreachable in this harness's driven scenarios (the host
			// deliberately never delivers enough rounds to reach
			// completion; see mixed_interop/main.go's doc comment), kept
			// only as a defensive completion signal. Not binding the
			// received value avoids copying common.SignatureData (a
			// protobuf message embedding a sync.Mutex) by value, matching
			// this repository's own ecdsa/signing test convention of
			// `case <-endCh:`.
			s.emit(event{Event: "signature"})
		default:
			return
		}
	}
}

func main() {
	reader := bufio.NewScanner(os.Stdin)
	reader.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	writer := bufio.NewWriter(os.Stdout)
	s := &signer{writer: writer, enc: json.NewEncoder(writer)}

	// Restore the original entropy source on exit; only this process's
	// signing-round randomness is made deterministic, and only for the
	// lifetime of this subprocess.
	origRand := cryptorand.Reader
	defer func() { cryptorand.Reader = origRand }()

	for reader.Scan() {
		line := reader.Bytes()
		if len(line) == 0 {
			continue
		}
		var cmd command
		if err := json.Unmarshal(line, &cmd); err != nil {
			s.emit(event{Event: "error", Message: "invalid command json: " + err.Error()})
			continue
		}
		switch cmd.Cmd {
		case "init":
			s.handleInit(cmd)
			s.emit(event{Event: "turn_done"})
		case "deliver":
			s.handleDeliver(cmd)
			s.emit(event{Event: "turn_done"})
		case "quit":
			return
		default:
			s.emit(event{Event: "error", Message: "unknown command: " + cmd.Cmd})
			s.emit(event{Event: "turn_done"})
		}
	}
}

func (s *signer) handleInit(cmd command) {
	fixedRandom(cmd.Seed)

	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		s.emit(event{Event: "error", Message: "load keygen fixtures: " + err.Error()})
		return
	}
	s.peerID = partyIDs[0]

	msg := new(big.Int)
	if _, ok := msg.SetString(cmd.MessageHex, 16); !ok {
		s.emit(event{Event: "error", Message: "invalid message hex"})
		return
	}

	ctx := tss.NewPeerContext(partyIDs)
	params := tss.NewParameters(tss.S256(), ctx, partyIDs[1], 2, 1)

	s.out = make(chan tss.Message, 16)
	s.end = make(chan common.SignatureData, 1)
	s.party = signing.NewLocalParty(msg, params, keys[1], s.out, s.end)

	if pErr := s.party.Start(); pErr != nil {
		s.emit(event{Event: "error", Message: pErr.Error()})
		return
	}
	s.drain()
}

func (s *signer) handleDeliver(cmd command) {
	if s.party == nil {
		s.emit(event{Event: "error", Message: "deliver before init"})
		return
	}
	wireBytes, err := hex.DecodeString(cmd.WireHex)
	if err != nil {
		s.emit(event{Event: "error", Message: "invalid wire hex: " + err.Error()})
		return
	}
	if _, pErr := s.party.UpdateFromBytes(wireBytes, s.peerID, cmd.IsBroadcast); pErr != nil {
		s.emit(event{Event: "error", Message: pErr.Error()})
		return
	}
	s.drain()
}
