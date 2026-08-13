package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

func TestIssue31HubExposesTwoPhasePairingCandidateControl(t *testing.T) {
	var _ api.PairingCandidateController = (*Hub)(nil)
}

func TestIssue31SelectionFreezesObservationWithoutDialOrTrust(t *testing.T) {
	gate := newScriptedAttemptGate(gatePrepareError)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launch = run }
	reportPairingCandidate(
		hub,
		pairingCandidateTestRef,
		pairingCandidateTestSKI,
		"vr940.local",
		"192.168.100.21",
		"192.168.100.22",
	)

	reservation, err := hub.SelectPairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select pairing candidate: %v", err)
	}
	if reservation == (api.PairingCandidateReservation{}) {
		t.Fatal("selection returned an empty reservation")
	}
	if launch != nil {
		t.Fatal("selection scheduled an outbound connection")
	}
	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("selection reached outgoing gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}
	if hub.ServiceForSKI(pairingCandidateTestSKI).Trusted() {
		t.Fatal("selection granted trust")
	}
	formatted := fmt.Sprintf("%v %#v %q", reservation, reservation, reservation)
	if strings.Contains(formatted, "[32]") || !strings.Contains(formatted, "{redacted}") {
		t.Fatalf("reservation formatter disclosed or omitted redaction: %q", formatted)
	}
	if _, err := json.Marshal(reservation); !errors.Is(err, api.ErrPairingCandidateReservationSerialization) {
		t.Fatalf("reservation JSON error = %v, want %v", err, api.ErrPairingCandidateReservationSerialization)
	}

	// Replacement discovery cannot change the endpoint frozen by selection.
	reportPairingCandidate(hub, "shipc_replacement", pairingCandidateTestSKI, "attacker.local", "192.168.100.99")
	if err := hub.ConnectPairingCandidate(reservation); err != nil {
		t.Fatalf("connect selected candidate: %v", err)
	}
	if launch == nil {
		t.Fatal("explicit connect did not schedule the outbound attempt")
	}
	launch()
	request := waitForPairingCandidateRequest(t, gate)
	if request.RemoteSKI != pairingCandidateTestSKI || request.Endpoint.Host != "192.168.100.21" || request.Endpoint.Port != 12480 || request.Path != "/ship/" {
		t.Fatalf("selected frozen outgoing request = %#v", request)
	}
}

func TestIssue31SelectionBindsExistingInboundWinnerRule(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, nil)
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	reservation, err := hub.SelectPairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select pairing candidate: %v", err)
	}
	inbound := hub.reserveInboundPairingConnection(pairingCandidateTestSKI)
	if inbound == nil || inbound.candidate == nil || !inbound.candidate.reservation.Matches(reservation) {
		t.Fatal("selection did not bind the existing exact-SKI inbound winner rule")
	}
}

func TestIssue31SelectionDoesNotRequireOutboundGateButConnectDoes(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, nil)
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	reservation, err := hub.SelectPairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select without outbound gate: %v", err)
	}
	if err := hub.ConnectPairingCandidate(reservation); !errors.Is(err, api.ErrOutgoingAttemptGateRequired) {
		t.Fatalf("connect without outbound gate error = %v, want %v", err, api.ErrOutgoingAttemptGateRequired)
	}
	if hub.ServiceForSKI(pairingCandidateTestSKI).Trusted() {
		t.Fatal("failed connect granted trust")
	}
}

func TestIssue31StaleReservationCannotConnectReplacement(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launches []func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launches = append(launches, run) }
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	stale, err := hub.SelectPairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select first candidate: %v", err)
	}
	hub.CancelPairingWithSKI(pairingCandidateTestSKI)

	const replacementRef = "shipc_fresh-generation"
	reportPairingCandidate(hub, replacementRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.22")
	current, err := hub.SelectPairingCandidate(replacementRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select replacement candidate: %v", err)
	}
	if err := hub.ConnectPairingCandidate(stale); !errors.Is(err, api.ErrPairingCandidateReservationStale) {
		t.Fatalf("stale reservation error = %v, want %v", err, api.ErrPairingCandidateReservationStale)
	}
	if len(launches) != 0 {
		t.Fatalf("stale reservation scheduled %d launches", len(launches))
	}
	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("stale reservation reached gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}

	if err := hub.ConnectPairingCandidate(current); err != nil {
		t.Fatalf("connect current reservation: %v", err)
	}
	if len(launches) != 1 {
		t.Fatalf("current reservation launches = %d, want 1", len(launches))
	}
	if err := hub.ConnectPairingCandidate(current); !errors.Is(err, api.ErrPairingCandidateAlreadyConnecting) {
		t.Fatalf("duplicate connect error = %v, want %v", err, api.ErrPairingCandidateAlreadyConnecting)
	}
	if len(launches) != 1 {
		t.Fatalf("duplicate connect scheduled %d launches, want 1", len(launches))
	}
}

func TestIssue31ZeroReservationFailsClosed(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	if err := hub.ConnectPairingCandidate(api.PairingCandidateReservation{}); !errors.Is(err, api.ErrPairingCandidateReservationStale) {
		t.Fatalf("zero reservation error = %v, want %v", err, api.ErrPairingCandidateReservationStale)
	}
	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("zero reservation reached gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}
}
