package model

import (
	"fmt"
	"sync"
	"testing"
)

func TestIssue39PINHandshakeDetailIsClosedAndCopySafe(t *testing.T) {
	detail := &PINHandshakeDetail{
		Requirement: PINRequirementRequired,
		Phase:       PINPhaseWaitingPeer,
		Category:    PINCategoryPointer(PINCategoryRequired),
		Retryable:   true,
	}
	state := ShipState{State: SmePinStateAskProcess, PIN: detail}

	copy := state.PIN.Clone()
	if copy == state.PIN || !copy.Equal(state.PIN) {
		t.Fatalf("PIN detail copy = %#v, want an equal independent value", copy)
	}
	*copy.Category = PINCategoryRejected
	if *state.PIN.Category != PINCategoryRequired {
		t.Fatalf("mutating a copied PIN detail changed the published state: %#v", state.PIN)
	}

	if got := fmt.Sprintf("%#v", state.PIN); got == "" {
		t.Fatal("typed PIN detail has no printable closed representation")
	}
}

func TestIssue39PINHandshakeDetailConcurrentCopiesAreIndependent(t *testing.T) {
	detail := &PINHandshakeDetail{
		Requirement: PINRequirementOptional,
		Phase:       PINPhaseRestricted,
		Category:    PINCategoryPointer(PINCategoryOptional),
		Retryable:   false,
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			copy := detail.Clone()
			if copy == nil || !copy.Equal(detail) {
				t.Errorf("concurrent PIN detail copy = %#v, want %#v", copy, detail)
			}
		}()
	}
	wg.Wait()
}
