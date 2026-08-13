package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
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

func TestIssue31ObservationReplacementRetiresSelectOnlyReservation(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launches []func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launches = append(launches, run) }
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	reservation, err := hub.SelectPairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select pairing candidate: %v", err)
	}
	inbound := hub.reserveInboundPairingConnection(pairingCandidateTestSKI)
	if inbound == nil || inbound.candidate == nil {
		t.Fatal("selection did not become inbound eligible")
	}

	reportPairingCandidate(hub, "shipc_replacement", pairingCandidateTestSKI, "vr940.local", "192.168.100.99")
	if err := hub.ConnectPairingCandidate(reservation); !errors.Is(err, api.ErrPairingCandidateReservationStale) {
		t.Fatalf("replaced observation reservation error = %v, want %v", err, api.ErrPairingCandidateReservationStale)
	}
	if len(launches) != 0 {
		t.Fatalf("replaced observation scheduled %d launches", len(launches))
	}
	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("replaced observation reached gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(connection, inbound); registered || replaced != nil {
		t.Fatalf("stale inbound reservation registered: registered=%t replaced=%#v", registered, replaced)
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
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(connection, inbound); !registered || replaced != nil {
		t.Fatalf("current inbound reservation registration = (%#v, %t), want (nil, true)", replaced, registered)
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

func TestIssue31QueuedNewerMdnsSnapshotBlocksSelectionOfVisiblePriorRevision(t *testing.T) {
	hub, _, reader := newPairingCandidateHub(t, newScriptedAttemptGate(gatePermit))
	firstCallback := make(chan struct{})
	releaseFirst := make(chan struct{})
	var blockOnce sync.Once
	reader.setVisibleUpdate(func(entries []api.RemoteService) {
		if len(entries) == 0 {
			return
		}
		blockOnce.Do(func() {
			close(firstCallback)
			<-releaseFirst
		})
	})

	firstDone := make(chan struct{})
	go func() {
		reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
		close(firstDone)
	}()
	waitForPairingCandidateSignal(t, firstCallback, "first mDNS callback")
	reservation, err := hub.SelectPairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	if err != nil {
		t.Fatalf("select visible prior observation: %v", err)
	}
	inbound := hub.reserveInboundPairingConnection(pairingCandidateTestSKI)
	if inbound == nil || inbound.candidate == nil {
		t.Fatal("visible prior observation did not create candidate-bound inbound reservation")
	}

	const newerRef = "shipc_newer-revision"
	newerAddresses := []net.IP{net.ParseIP("192.168.100.99")}
	hub.ReportMdnsEntriesWithCandidates(
		map[string]*api.MdnsEntry{newerRef: {
			Name: "VR940", Ski: pairingCandidateTestSKI, Identifier: "vr940-ship-id",
			Path: "/ship/", Host: "vr940.local", Port: 12480, Addresses: newerAddresses,
		}},
		true,
		[]api.PairingCandidateObservation{{
			CandidateRef: newerRef, Name: "VR940", SKI: pairingCandidateTestSKI,
			Identifier: "vr940-ship-id", Path: "/ship/", Port: 12480, Addresses: newerAddresses,
		}},
		18,
	)

	if err := hub.ConnectPairingCandidate(reservation); !errors.Is(err, api.ErrPairingCandidateReservationStale) {
		t.Fatalf("connect while newer snapshot queued error = %v, want %v", err, api.ErrPairingCandidateReservationStale)
	}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(connection, inbound); registered || replaced != nil {
		t.Fatalf("candidate-bound inbound registered while newer snapshot queued: registered=%t replaced=%#v", registered, replaced)
	}

	close(releaseFirst)
	waitForPairingCandidateSignal(t, firstDone, "mDNS queue drain")
	if _, err := hub.SelectPairingCandidate(newerRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("select settled newer observation: %v", err)
	}
}

func TestIssue31QueuedMdnsSnapshotDoesNotRejectUnrelatedInbound(t *testing.T) {
	hub, _, reader := newPairingCandidateHub(t, newScriptedAttemptGate(gatePermit))
	const unrelatedSKI = "8fce1db764bd31d3014f48fe927c40a044982ec1"
	hub.RegisterRemoteSKI(unrelatedSKI)
	inbound := hub.reserveInboundPairingConnection(unrelatedSKI)
	if inbound == nil || inbound.candidate != nil {
		t.Fatalf("unrelated inbound reservation = %#v, want non-candidate reservation", inbound)
	}

	firstCallback := make(chan struct{})
	releaseFirst := make(chan struct{})
	var blockOnce sync.Once
	reader.setVisibleUpdate(func(entries []api.RemoteService) {
		if len(entries) == 0 {
			return
		}
		blockOnce.Do(func() {
			close(firstCallback)
			<-releaseFirst
		})
	})
	firstDone := make(chan struct{})
	go func() {
		reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
		close(firstDone)
	}()
	waitForPairingCandidateSignal(t, firstCallback, "first mDNS callback")

	const newerRef = "shipc_unrelated-newer"
	newerAddresses := []net.IP{net.ParseIP("192.168.100.99")}
	hub.ReportMdnsEntriesWithCandidates(
		map[string]*api.MdnsEntry{newerRef: {
			Name: "VR940", Ski: pairingCandidateTestSKI, Identifier: "vr940-ship-id",
			Path: "/ship/", Host: "vr940.local", Port: 12480, Addresses: newerAddresses,
		}},
		true,
		[]api.PairingCandidateObservation{{
			CandidateRef: newerRef, Name: "VR940", SKI: pairingCandidateTestSKI,
			Identifier: "vr940-ship-id", Path: "/ship/", Port: 12480, Addresses: newerAddresses,
		}},
		19,
	)

	connection := &attemptCallbackConnection{ski: unrelatedSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(connection, inbound); !registered || replaced != nil {
		t.Fatalf("unrelated inbound registration = (%#v, %t), want (nil, true)", replaced, registered)
	}

	close(releaseFirst)
	waitForPairingCandidateSignal(t, firstDone, "mDNS queue drain")
}
