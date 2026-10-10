package tss

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBasePartyLatchesLifecycleFailures(t *testing.T) {
	for _, source := range []string{"prepare", "first start", "update", "next start"} {
		t.Run(source, func(t *testing.T) {
			p, first, next := newLifecycleTestParty()
			failedRound := first
			if source == "next start" {
				failedRound = next
			}
			failure := failedRound.WrapError(errors.New("round failed"), first.params.Parties().IDs()[1])
			var got *Error
			switch source {
			case "prepare":
				got = BaseStart(p, "test", func(Round) *Error { return failure })
			case "first start":
				first.startErr = failure
				got = p.Start()
			default:
				if err := p.Start(); err != nil {
					t.Fatal(err)
				}
				if source == "update" {
					first.updateErr = failure
				} else {
					first.proceed = true
					next.startErr = failure
				}
				_, got = p.Update(lifecycleTestMessage{})
			}
			if got != failure || p.abortedWith() != failure {
				t.Fatalf("failure was not returned and retained: %v", got)
			}
			if p.round() != failedRound || len(got.Culprits()) != 1 {
				t.Fatal("original failure lost its round or culprit")
			}
			stores := p.stores.Load()
			firstCalls, nextCalls := first.calls.updates.Load(), next.calls.updates.Load()
			for i := 0; i < 2; i++ {
				ok, err := p.Update(lifecycleTestMessage{})
				if ok || err == nil || !strings.Contains(err.Error(), "cannot process further messages") {
					t.Fatalf("update after failure was not refused: ok=%v err=%v", ok, err)
				}
				if len(err.Culprits()) != 0 {
					t.Fatal("later delivery repeated culprit attribution")
				}
			}
			if p.stores.Load() != stores || first.calls.updates.Load() != firstCalls || next.calls.updates.Load() != nextCalls {
				t.Fatal("update after failure stored a message or called a round")
			}
			if p.abortedWith() != failure || p.round() != failedRound {
				t.Fatal("update after failure replaced the original failure or round")
			}
			if err := p.Start(); err == nil || len(err.Culprits()) != 0 {
				t.Fatalf("restart must be rejected without culprit attribution: %v", err)
			}
		})
	}
}

func TestBasePartyMessageRejectionsAreRecoverable(t *testing.T) {
	for _, source := range []string{"validation", "storage", "ignored message"} {
		t.Run(source, func(t *testing.T) {
			p, first, _ := newLifecycleTestParty()
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			rejection := first.WrapError(errors.New("message rejected"))
			wantErr := rejection
			switch source {
			case "validation":
				p.validationErr = rejection
			case "storage":
				p.storageErr = rejection
			case "ignored message":
				p.storeOK = false
				wantErr = nil
			}
			if ok, err := p.Update(lifecycleTestMessage{}); ok || err != wantErr {
				t.Fatalf("unexpected rejection: ok=%v err=%v", ok, err)
			}
			if p.abortedWith() != nil || first.calls.updates.Load() != 0 {
				t.Fatal("message rejection aborted or updated the round")
			}
			p.validationErr, p.storageErr, p.storeOK = nil, nil, true
			if ok, err := p.Update(lifecycleTestMessage{}); !ok || err != nil {
				t.Fatalf("valid update did not recover: ok=%v err=%v", ok, err)
			}
			if first.calls.updates.Load() != 1 {
				t.Fatal("valid update did not reach the round")
			}
		})
	}
}

func TestBasePartyNormalProgression(t *testing.T) {
	p, first, next := newLifecycleTestParty()
	if ok, err := p.Update(lifecycleTestMessage{}); !ok || err != nil {
		t.Fatalf("message before start was not stored: ok=%v err=%v", ok, err)
	}
	if p.Running() || p.stores.Load() != 1 || first.calls.updates.Load() != 0 {
		t.Fatal("message before start changed the lifecycle")
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	first.proceed = true
	if ok, err := p.Update(lifecycleTestMessage{}); !ok || err != nil {
		t.Fatalf("round did not advance: ok=%v err=%v", ok, err)
	}
	if p.round() != next || first.calls.updates.Load() != 1 || next.calls.starts.Load() != 1 || next.calls.updates.Load() != 1 {
		t.Fatal("round progression did not start and update the next round")
	}
	next.proceed = true
	if ok, err := p.Update(lifecycleTestMessage{}); !ok || err != nil {
		t.Fatalf("party did not finish: ok=%v err=%v", ok, err)
	}
	if p.Running() || len(p.WaitingFor()) != 0 || p.abortedWith() != nil {
		t.Fatal("successful completion left an active round or abort")
	}
}

// TestBasePartyConcurrentUpdatesRetainExactlyOneFatalError proves that under
// concurrent BaseUpdate deliveries, exactly one caller observes the fatal
// round error while every other caller receives the uniform, culprit-free
// refusal, and that the retained latch keeps the first fatal error.
func TestBasePartyConcurrentUpdatesRetainExactlyOneFatalError(t *testing.T) {
	p, first, next := newLifecycleTestParty()
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	failure := first.WrapError(errors.New("round failed"), first.params.Parties().IDs()[1])
	first.updateErr = failure

	const callers = 50
	results := make(chan *Error, callers)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-release
			_, err := p.Update(lifecycleTestMessage{})
			results <- err
		}()
	}
	close(release)
	wg.Wait()
	close(results)

	var fatal, refused, other int
	for err := range results {
		if err == failure {
			fatal++
			continue
		}
		if err != nil && strings.Contains(err.Error(), "cannot process further messages") && len(err.Culprits()) == 0 {
			refused++
			continue
		}
		other++
	}
	if fatal != 1 || refused != callers-1 || other != 0 {
		t.Fatalf("expected one fatal error and %d refusals, got %d fatal / %d refused / %d other", callers-1, fatal, refused, other)
	}
	if got := first.calls.updates.Load(); got != 1 {
		t.Fatalf("round.Update ran %d times; exactly one caller may reach it", got)
	}
	if next.calls.updates.Load() != 0 {
		t.Fatal("the next round processed a concurrent update")
	}
	if p.abortedWith() != failure {
		t.Fatalf("the first fatal error was not retained: %v", p.abortedWith())
	}
}

// TestBasePartyConcurrentStartRunsExactlyOnce proves that round.Start runs
// exactly once when BaseStart calls race each other alongside BaseUpdate
// deliveries: one caller starts the round and the rest are refused with the
// unexpected-state error.
func TestBasePartyConcurrentStartRunsExactlyOnce(t *testing.T) {
	p, first, _ := newLifecycleTestParty()

	const workers = 20
	starts := make(chan *Error, workers)
	updates := make(chan *Error, workers)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-release
			starts <- p.Start()
		}()
		go func() {
			defer wg.Done()
			<-release
			_, err := p.Update(lifecycleTestMessage{})
			updates <- err
		}()
	}
	close(release)
	wg.Wait()
	close(starts)
	close(updates)

	var succeeded, unexpected, other int
	for err := range starts {
		if err == nil {
			succeeded++
			continue
		}
		if strings.Contains(err.Error(), "unexpected state") {
			unexpected++
			continue
		}
		other++
	}
	for err := range updates {
		if err != nil {
			t.Fatalf("concurrent update failed: %v", err)
		}
	}
	if succeeded != 1 || unexpected != workers-1 || other != 0 {
		t.Fatalf("expected one successful start and %d refusals, got %d / %d / %d other", workers-1, succeeded, unexpected, other)
	}
	if got := first.calls.starts.Load(); got != 1 {
		t.Fatalf("round.Start ran %d times; exactly one caller may start it", got)
	}
	if p.abortedWith() != nil {
		t.Fatalf("concurrent starts latched an error: %v", p.abortedWith())
	}
}

type lifecycleTestParty struct {
	*BaseParty
	first         Round
	params        *Parameters
	validationErr *Error
	storageErr    *Error
	storeOK       bool
	stores        atomic.Int32
}

func newLifecycleTestParty() (*lifecycleTestParty, *lifecycleTestRound, *lifecycleTestRound) {
	ids := GenerateTestPartyIDs(2)
	params := NewParameters(S256(), NewPeerContext(ids), ids[0], len(ids), 1)
	next := &lifecycleTestRound{params: params, number: 2}
	first := &lifecycleTestRound{params: params, number: 1, next: next}
	p := &lifecycleTestParty{BaseParty: new(BaseParty), first: first, params: params, storeOK: true}
	return p, first, next
}

func (p *lifecycleTestParty) FirstRound() Round { return p.first }
func (p *lifecycleTestParty) PartyID() *PartyID { return p.params.PartyID() }
func (p *lifecycleTestParty) Start() *Error     { return BaseStart(p, "test") }
func (p *lifecycleTestParty) Update(msg ParsedMessage) (bool, *Error) {
	return BaseUpdate(p, msg, "test")
}
func (p *lifecycleTestParty) UpdateFromBytes([]byte, *PartyID, bool) (bool, *Error) {
	panic("unused in lifecycle tests")
}
func (p *lifecycleTestParty) ValidateMessage(ParsedMessage) (bool, *Error) {
	return p.validationErr == nil, p.validationErr
}
func (p *lifecycleTestParty) StoreMessage(ParsedMessage) (bool, *Error) {
	p.stores.Add(1)
	return p.storeOK && p.storageErr == nil, p.storageErr
}

type lifecycleTestRound struct {
	params              *Parameters
	number              int
	next                Round
	startErr, updateErr *Error
	proceed             bool
	calls               struct {
		starts, updates, advances atomic.Int64
	}
}

func (r *lifecycleTestRound) Params() *Parameters          { return r.params }
func (r *lifecycleTestRound) RoundNumber() int             { return r.number }
func (r *lifecycleTestRound) CanAccept(ParsedMessage) bool { return true }
func (r *lifecycleTestRound) CanProceed() bool             { return r.proceed }
func (r *lifecycleTestRound) WaitingFor() []*PartyID       { return r.params.Parties().IDs() }
func (r *lifecycleTestRound) WrapError(err error, culprits ...*PartyID) *Error {
	return NewError(err, "test", r.number, r.params.PartyID(), culprits...)
}
func (r *lifecycleTestRound) Start() *Error {
	r.calls.starts.Add(1)
	return r.startErr
}
func (r *lifecycleTestRound) Update() (bool, *Error) {
	r.calls.updates.Add(1)
	return r.updateErr == nil, r.updateErr
}
func (r *lifecycleTestRound) NextRound() Round {
	r.calls.advances.Add(1)
	return r.next
}

type lifecycleTestMessage struct{ ParsedMessage }

func (lifecycleTestMessage) String() string { return "lifecycle test message" }
