package hub

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

const (
	pairingCandidateTestRef = "shipc_test-generation-17"
	pairingCandidateTestSKI = "b1b7197b064084e4cfef2365105d8d36ff185e5b"
)

type pairingCandidateReader struct {
	attemptAwareGateTestHubReader
	mu      sync.Mutex
	visible []api.RemoteService
}

func (reader *pairingCandidateReader) VisibleRemoteServicesUpdated(entries []api.RemoteService) {
	reader.mu.Lock()
	reader.visible = append([]api.RemoteService(nil), entries...)
	reader.mu.Unlock()
}

func (reader *pairingCandidateReader) snapshot() []api.RemoteService {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]api.RemoteService(nil), reader.visible...)
}

func newPairingCandidateHub(t *testing.T, gate api.OutgoingAttemptGate) (*Hub, *scriptedAttemptGate, *pairingCandidateReader) {
	t.Helper()
	reader := &pairingCandidateReader{}
	mdns := &attemptTestMdns{}
	hub := NewHub(reader, mdns, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	var scripted *scriptedAttemptGate
	if gate != nil {
		if candidate, ok := gate.(*scriptedAttemptGate); ok {
			scripted = candidate
		}
		if err := hub.SetOutgoingAttemptGate(gate); err != nil {
			t.Fatalf("install outgoing attempt gate: %v", err)
		}
	}
	hub.hasStarted = true
	return hub, scripted, reader
}

func reportPairingCandidate(hub *Hub, ref, ski, host string, addresses ...string) {
	parsed := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		parsed = append(parsed, net.ParseIP(address))
	}
	hub.ReportMdnsEntries(map[string]*api.MdnsEntry{
		ref: {
			CandidateRef:        ref,
			ObservationRevision: 17,
			Name:                "VR940",
			Ski:                 ski,
			Identifier:          "vr940-ship-id",
			Path:                "/ship/",
			Host:                host,
			Port:                12480,
			Addresses:           parsed,
		},
	}, true)
}

func waitForPairingCandidateRequest(t *testing.T, gate *scriptedAttemptGate) api.OutgoingAttemptRequest {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		requests, _, _, _ := gate.snapshot()
		if len(requests) != 0 {
			if len(requests) != 1 {
				t.Fatalf("outgoing requests = %d, want exactly 1", len(requests))
			}
			return requests[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("timed out waiting for pairing candidate request")
	return api.OutgoingAttemptRequest{}
}

func TestHubExposesGenerationBoundPairingCandidateQueue(t *testing.T) {
	var _ api.PairingCandidateQueuer = (*Hub)(nil)
}

func TestPairingCandidateVisibilityCarriesOpaqueReference(t *testing.T) {
	hub, _, reader := newPairingCandidateHub(t, nil)
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	visible := reader.snapshot()
	if len(visible) != 1 || visible[0].CandidateRef != pairingCandidateTestRef || visible[0].Ski != pairingCandidateTestSKI {
		t.Fatalf("visible candidates = %#v", visible)
	}
}

func TestPairingCandidateRequiresCurrentReferenceExactSKIAndAttemptGate(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, newScriptedAttemptGate(gatePrepareError))
	if err := hub.QueuePairingCandidate("missing", pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingCandidateUnavailable) {
		t.Fatalf("unknown candidate error = %v, want %v", err, api.ErrPairingCandidateUnavailable)
	}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, "0000000000000000000000000000000000000000"); !errors.Is(err, api.ErrPairingCandidateSKIMismatch) {
		t.Fatalf("candidate SKI mismatch error = %v, want %v", err, api.ErrPairingCandidateSKIMismatch)
	}

	hub, _, _ = newPairingCandidateHub(t, nil)
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); !errors.Is(err, api.ErrOutgoingAttemptGateRequired) {
		t.Fatalf("ungated candidate error = %v, want %v", err, api.ErrOutgoingAttemptGateRequired)
	}
}

func TestPairingCandidateRejectsNonCanonicalExpectedSKI(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, newScriptedAttemptGate(gatePrepareError))
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	for _, invalid := range []string{
		" " + pairingCandidateTestSKI,
		pairingCandidateTestSKI + " ",
		"B1B7197B064084E4CFEF2365105D8D36FF185E5B",
	} {
		if err := hub.QueuePairingCandidate(pairingCandidateTestRef, invalid); !errors.Is(err, api.ErrInvalidRemoteSKI) {
			t.Errorf("QueuePairingCandidate(%q) error = %v, want %v", invalid, err, api.ErrInvalidRemoteSKI)
		}
	}
}

func TestPairingCandidateEmptyNewerSnapshotRetiresAndOlderReportCannotResurrect(t *testing.T) {
	hub, _, reader := newPairingCandidateHub(t, newScriptedAttemptGate(gatePrepareError))
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	hub.ReportMdnsEntriesRevision(map[string]*api.MdnsEntry{}, true, 18)
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingCandidateUnavailable) {
		t.Fatalf("retired candidate error = %v, want %v", err, api.ErrPairingCandidateUnavailable)
	}

	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.99")
	if visible := reader.snapshot(); len(visible) != 0 {
		t.Fatalf("older report resurrected visible candidate: %#v", visible)
	}
}

func TestPairingCandidateFreezesOneObservedEndpointWithoutRegistrationCoupling(t *testing.T) {
	gate := newScriptedAttemptGate(gatePrepareError)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	reportPairingCandidate(
		hub,
		pairingCandidateTestRef,
		pairingCandidateTestSKI,
		"vr940.local",
		"192.168.100.21",
		"192.168.100.22",
	)

	// Local register=true controls inbound visibility and is intentionally not
	// an authority prerequisite for this outbound selection.
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate while local registration is closed: %v", err)
	}
	reportPairingCandidate(hub, "shipc_replacement", pairingCandidateTestSKI, "attacker.local", "192.168.100.99")

	request := waitForPairingCandidateRequest(t, gate)
	if request.RemoteSKI != pairingCandidateTestSKI || request.Endpoint.Host != "192.168.100.21" || request.Endpoint.Port != 12480 || request.Path != "/ship/" {
		t.Fatalf("frozen outgoing request = %#v", request)
	}
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingCandidateConsumed) {
		t.Fatalf("reused candidate error = %v, want %v", err, api.ErrPairingCandidateConsumed)
	}
}

func TestPairingCandidateCanceledBeforeAsyncLaunchNeverPreparesAttempt(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.launchPairingCandidate = func(run func()) { launch = run }
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	if launch == nil {
		t.Fatal("candidate launch was not scheduled")
	}
	hub.CancelPairingWithSKI(pairingCandidateTestSKI)
	launch()

	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("canceled candidate reached gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}
}

func TestPairingCandidateCanceledAfterActiveCheckRejectsCapturedAuthorityBeforePrepare(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.launchPairingCandidate = func(run func()) { launch = run }
	gateEntered := make(chan struct{})
	gateRelease := make(chan struct{})
	hub.beforePairingCandidateGate = func() {
		close(gateEntered)
		<-gateRelease
	}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	launchDone := make(chan struct{})
	go func() {
		launch()
		close(launchDone)
	}()
	<-gateEntered
	hub.CancelPairingWithSKI(pairingCandidateTestSKI)
	close(gateRelease)
	<-launchDone

	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("stale candidate authority reached gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}
}

func TestPairingCandidateGateRemovalAfterActiveCheckFailsBeforePrepare(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.launchPairingCandidate = func(run func()) { launch = run }
	gateEntered := make(chan struct{})
	gateRelease := make(chan struct{})
	hub.beforePairingCandidateGate = func() {
		close(gateEntered)
		<-gateRelease
	}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	launchDone := make(chan struct{})
	go func() {
		launch()
		close(launchDone)
	}()
	<-gateEntered
	if err := hub.SetOutgoingAttemptGate(nil); err != nil {
		t.Fatalf("remove outgoing attempt gate: %v", err)
	}
	close(gateRelease)
	<-launchDone

	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf("candidate without current gate reached old gate: requests=%d authorized=%d permits=%d", len(requests), len(authorized), len(permits))
	}
}

func TestPairingRegistrationCloseDoesNotRetireOutboundCandidate(t *testing.T) {
	gate := newScriptedAttemptGate(gatePrepareError)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.launchPairingCandidate = func(run func()) { launch = run }
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	if err := hub.SetPairingRegistration(false); err != nil {
		t.Fatalf("close inbound pairing registration: %v", err)
	}
	launch()

	requests, _, _, _ := gate.snapshot()
	if len(requests) != 1 {
		t.Fatalf("outbound candidate requests after inbound registration close = %d, want 1", len(requests))
	}
}
