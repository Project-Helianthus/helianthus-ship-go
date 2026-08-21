package api

import (
	"errors"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

func TestIssue39ConnectionStateDetailCarriesIndependentTypedPINOutcome(t *testing.T) {
	legacyErr := errors.New("legacy error stays separate")
	detail := NewConnectionStateDetail(ConnectionStatePin, legacyErr)
	detail.SetPINHandshakeDetail(&model.PINHandshakeDetail{
		Requirement: model.PINRequirementRequired,
		Phase:       model.PINPhaseSubmitted,
		Category:    model.PINCategoryRequired,
		Retryable:   true,
	})

	if detail.State() != ConnectionStatePin || !errors.Is(detail.Error(), legacyErr) {
		t.Fatal("typed PIN detail changed legacy state/error compatibility")
	}
	copy := detail.PINHandshakeDetail()
	copy.Category = model.PINCategoryRejected
	if got := detail.PINHandshakeDetail().Category; got != model.PINCategoryRequired {
		t.Fatalf("mutated returned detail leaked into published state: %v", got)
	}
}

func TestIssue39ConnectionStateDetailConcurrentPINReads(t *testing.T) {
	detail := NewConnectionStateDetail(ConnectionStatePin, nil)
	detail.SetPINHandshakeDetail(&model.PINHandshakeDetail{
		Requirement: model.PINRequirementOptional,
		Phase:       model.PINPhaseRestricted,
		Category:    model.PINCategoryOptional,
	})
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := detail.PINHandshakeDetail(); got == nil || got.Phase != model.PINPhaseRestricted {
				t.Errorf("PIN detail = %#v, want optional restricted", got)
			}
		}()
	}
	wg.Wait()
}
