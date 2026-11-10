package tss

import (
	"crypto/elliptic"
	"testing"
)

type customCurve struct{ elliptic.Curve }

func TestCurveRegistryPreservesImplementationIdentity(t *testing.T) {
	originalRegistry, originalEC := registry, ec
	defer func() { registry, ec = originalRegistry, originalEC }()
	registry = map[CurveName]elliptic.Curve{Secp256k1: S256()}

	if name, ok := GetCurveName(S256()); !ok || name != Secp256k1 {
		t.Fatalf("default curve registered as %q, %v", name, ok)
	}
	custom := &customCurve{S256()}
	if name, ok := GetCurveName(custom); ok {
		t.Fatalf("unregistered implementation recognized as %q", name)
	}
	RegisterCurve("custom", custom)
	if name, ok := GetCurveName(custom); !ok || name != "custom" {
		t.Fatalf("custom curve registered as %q, %v", name, ok)
	}
	if SameCurve(custom, S256()) {
		t.Fatal("different registered implementations treated as the same curve")
	}
	if got, ok := GetCurveByName("custom"); !ok || got != custom {
		t.Fatal("custom curve implementation was not preserved")
	}
	SetCurve(custom)
	if EC() != custom {
		t.Fatal("SetCurve did not preserve the supplied implementation")
	}
}
