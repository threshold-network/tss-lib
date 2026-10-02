package main

import "testing"

// These qualification tests pin the scenario-result acceptance predicates
// (qualifyRejectionScenario / qualifySuccessfulScenario /
// qualifyHomogeneousControl in main.go) against their required invariants:
// a successful exchange must carry round-8 emission evidence from BOTH
// actors, and each of the two captured historical proofs must be observed
// rejecting at the tight N+q^6 bound while accepting under compat. A result
// whose proof passes at both bound settings, or whose round-8 evidence comes
// from only one actor, must be rejected.

func validSuccessResult() *scenarioResult {
	return &scenarioResult{
		// Round-8 emission observed on both sides; the emitted messages were
		// captured and dropped, never forwarded.
		AliceReachedRound8: true,
		BobReachedRound8:   true,
		AliceProgressed:    true,
		// Tight-bound evidence: the observed witness (Bob T1, BobWC T1 both
		// recovered from captured wire bytes) is above N+q^6, so each
		// proof discriminates between the two bound settings.
		AboveTightBound: true,
		BobProofOff:     false,
		BobProofOn:      true,
		BobWCProofOff:   false,
		BobWCProofOn:    true,
	}
}

func validRejectionResult() *scenarioResult {
	return &scenarioResult{
		// A genuine default-config rejection: round-3 closed failure, both
		// production verifier goroutines attributing the historical peer,
		// no round-3 outbound, a high live-drawn witness, and both proofs
		// discriminating between the tight and widened historical bounds.
		DefaultRejected:           true,
		RejectionRound:            3,
		RejectionPeerCulpritCount: 2,
		AboveTightBound:           true,
		BobProofOff:               false,
		BobProofOn:                true,
		BobWCProofOff:             false,
		BobWCProofOn:              true,
	}
}

func TestQualifySuccessfulScenarioRejectsSingleActorRound8(t *testing.T) {
	valid := validSuccessResult()
	if ok, err := qualifySuccessfulScenario(valid); !ok || err != "" {
		t.Fatalf("valid success result rejected: %s", err)
	}

	oneActor := validSuccessResult()
	oneActor.BobReachedRound8 = false // round-8 evidence from only one actor
	if ok, err := qualifySuccessfulScenario(oneActor); ok || err == "" {
		t.Fatalf("single-actor round-8 result was accepted (err=%q)", err)
	}

	none := validSuccessResult()
	none.AliceReachedRound8 = false
	none.BobReachedRound8 = false
	if ok, err := qualifySuccessfulScenario(none); ok || err == "" {
		t.Fatalf("no-round-8 result was accepted (err=%q)", err)
	}
}

func TestQualifySuccessfulScenarioRequiresBothProofDiscriminations(t *testing.T) {
	cases := map[string]*scenarioResult{
		"valid": validSuccessResult(),
		"bob-passes-both-bounds": func() *scenarioResult {
			r := validSuccessResult()
			r.BobProofOff = true // tight-bound rejection missing: not a discrimination
			return r
		}(),
		"bobwc-passes-tight-bound": func() *scenarioResult {
			r := validSuccessResult()
			r.BobWCProofOff = true
			return r
		}(),
		"bob-not-accepted-with-compat": func() *scenarioResult {
			r := validSuccessResult()
			r.BobProofOn = false
			return r
		}(),
		"bobwc-not-accepted-with-compat": func() *scenarioResult {
			r := validSuccessResult()
			r.BobWCProofOn = false
			return r
		}(),
		"low-witness": func() *scenarioResult {
			r := validSuccessResult()
			r.AboveTightBound = false // tight-bound failure cannot be attributed to the witness range
			return r
		}(),
		"did-not-progress": func() *scenarioResult {
			r := validSuccessResult()
			r.AliceProgressed = false
			return r
		}(),
	}
	for name, r := range cases {
		want := name == "valid"
		got, err := qualifySuccessfulScenario(r)
		if want && !got {
			t.Fatalf("%s: should qualify: %s", name, err)
		}
		if !want && (got || err == "") {
			t.Fatalf("%s: should be rejected, but qualified (err=%q)", name, err)
		}
	}
}

func TestQualifyRejectionScenario(t *testing.T) {
	reject := validRejectionResult()
	if ok, err := qualifyRejectionScenario(reject); !ok || err != "" {
		t.Fatalf("genuine rejection not qualified: %s", err)
	}

	for name, mutate := range map[string]func(*scenarioResult){
		"rejection-at-wrong-round": func(r *scenarioResult) { r.RejectionRound = 4 },
		"single-culprit":           func(r *scenarioResult) { r.RejectionPeerCulpritCount = 1 },
		"no-default-rejection":     func(r *scenarioResult) { r.DefaultRejected = false },
		"emitted-round3":           func(r *scenarioResult) { r.AliceEmittedRound3 = true },
		"low-witness":              func(r *scenarioResult) { r.AboveTightBound = false },
		"bob-passes-tight":         func(r *scenarioResult) { r.BobProofOff = true },
		"bobwc-no-compat-accept":   func(r *scenarioResult) { r.BobWCProofOn = false },
	} {
		bad := validRejectionResult()
		mutate(bad)
		if ok, err := qualifyRejectionScenario(bad); ok || err == "" {
			t.Fatalf("%s: violated result was qualified (err=%q)", name, err)
		}
	}
}

func TestQualifyHomogeneousControlRequiresBothActors(t *testing.T) {
	r := validSuccessResult()
	if ok, err := qualifyHomogeneousControl(r); !ok || err != "" {
		t.Fatalf("valid control not qualified: %s", err)
	}
	one := &scenarioResult{AliceReachedRound8: true}
	if ok, err := qualifyHomogeneousControl(one); ok || err == "" {
		t.Fatalf("single-actor control was qualified: %q", err)
	}
	none := &scenarioResult{}
	if ok, err := qualifyHomogeneousControl(none); ok || err == "" {
		t.Fatalf("no-round-8 control was qualified: %q", err)
	}
}
