package hub

import (
	"crypto/tls"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

func TestIssue39HubCopiesTypedPINOutcomeIntoCurrentPairingDetail(t *testing.T) {
	hub := NewHub(&attemptTestHubReader{}, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.HandleShipHandshakeStateUpdate("remote-ski", model.ShipState{
		State: model.SmePinStateAskProcess,
		PIN: &model.PINHandshakeDetail{
			Requirement: model.PINRequirementRequired,
			Phase:       model.PINPhaseWaitingPeer,
			Category:    model.PINCategoryBusy,
			Retryable:   true,
		},
	})

	detail := hub.ServiceForSKI("remote-ski").ConnectionStateDetail()
	if detail.State() != api.ConnectionStatePin {
		t.Fatalf("legacy pairing state = %v, want PIN", detail.State())
	}
	if got := detail.PINHandshakeDetail(); got == nil || got.Requirement != model.PINRequirementRequired ||
		got.Phase != model.PINPhaseWaitingPeer || got.Category != model.PINCategoryBusy || !got.Retryable {
		t.Fatalf("stored typed PIN outcome = %#v, want required busy retryable", got)
	}

	copy := snapshotPairingDetail(detail)
	copy.PINHandshakeDetail().Category = model.PINCategoryRejected
	if got := detail.PINHandshakeDetail().Category; got != model.PINCategoryBusy {
		t.Fatalf("queued pairing snapshot mutated current detail: %v", got)
	}
}

func TestIssue39PairingDetailEqualityIncludesTypedPINOutcome(t *testing.T) {
	left := api.NewConnectionStateDetail(api.ConnectionStatePin, nil)
	left.SetPINHandshakeDetail(&model.PINHandshakeDetail{
		Requirement: model.PINRequirementRequired,
		Phase:       model.PINPhaseWaitingPeer,
		Category:    model.PINCategoryBusy,
		Retryable:   true,
	})
	right := snapshotPairingDetail(left)
	if !pairingDetailsEqual(left, right) {
		t.Fatal("equal copied typed PIN details compared unequal")
	}
	right.SetPINHandshakeDetail(&model.PINHandshakeDetail{
		Requirement: model.PINRequirementRequired,
		Phase:       model.PINPhaseFailed,
		Category:    model.PINCategoryUnavailable,
		Retryable:   true,
	})
	if pairingDetailsEqual(left, right) {
		t.Fatal("distinct typed PIN details compared equal and would suppress an update")
	}
}
