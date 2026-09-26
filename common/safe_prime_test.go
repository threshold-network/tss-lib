// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"bytes"
	"context"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_getSafePrime(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	assert.True(t, sPrime.ProbablyPrime(50))
}

func Test_getSafePrime_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	assert.False(t, sPrime.ProbablyPrime(50))
}

func Test_Validate(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.True(t, sgp.Validate())
}

func Test_Validate_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.False(t, sgp.Validate())
}

func TestGetRandomGermainPrimeConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	sgps, err := GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
}

func TestRunGenPrimeRoutineResultDelivery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		capacity  int
		cancelled bool
	}{
		{name: "active"},
		{name: "cancelled without receiver", cancelled: true},
		{name: "cancelled with full buffer", capacity: 1, cancelled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			primeCh := make(chan *GermainSafePrime, tc.capacity)
			errCh := make(chan error, 1)
			if tc.capacity > 0 {
				primeCh <- &GermainSafePrime{}
			}

			// This candidate produces q=29 and p=59. Hold the read until
			// the worker is past its initial cancellation check.
			reader := &gatedSafePrimeReader{
				Reader:  bytes.NewReader([]byte{29}),
				started: make(chan struct{}),
				release: make(chan struct{}),
			}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(reader.release) }) }
			var workers sync.WaitGroup
			workers.Add(1)
			runGenPrimeRoutine(ctx, primeCh, errCh, &workers, reader, 6)
			done := make(chan struct{})
			go func() {
				workers.Wait()
				close(done)
			}()
			t.Cleanup(func() {
				cancel()
				release()
				// Drain any pending delivery so even a failed cancellation
				// assertion leaves the worker joined.
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				for {
					select {
					case <-done:
						return
					case <-primeCh:
					case <-errCh:
					case <-timer.C:
						t.Error("safe-prime worker did not finish during cleanup")
						return
					}
				}
			})

			select {
			case <-reader.started:
			case <-time.After(5 * time.Second):
				t.Fatal("safe-prime worker did not start reading")
			}
			if tc.cancelled {
				cancel()
			}
			release()
			if !tc.cancelled {
				select {
				case prime := <-primeCh:
					assert.True(t, prime.Validate())
					assert.Equal(t, int64(29), prime.Prime().Int64())
					assert.Equal(t, int64(59), prime.SafePrime().Int64())
				case <-time.After(5 * time.Second):
					t.Fatal("safe-prime worker did not deliver a result")
				}
				cancel()
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("safe-prime worker did not finish after cancellation")
			}
		})
	}
}

type gatedSafePrimeReader struct {
	*bytes.Reader
	started, release chan struct{}
	once             sync.Once
}

func (r *gatedSafePrimeReader) Read(p []byte) (int, error) {
	r.once.Do(func() {
		close(r.started)
		<-r.release
	})
	return r.Reader.Read(p)
}
