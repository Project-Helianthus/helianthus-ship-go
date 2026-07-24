package hub

import (
	"context"
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
	mu            sync.Mutex
	visible       []api.RemoteService
	candidates    []api.PairingCandidateRef
	pairingUpdate func()
	visibleUpdate func([]api.RemoteService)
}

func (reader *pairingCandidateReader) VisibleRemoteServicesUpdated(entries []api.RemoteService) {
	reader.mu.Lock()
	reader.visible = append([]api.RemoteService(nil), entries...)
	update := reader.visibleUpdate
	reader.mu.Unlock()
	if update != nil {
		update(entries)
	}
}

func (reader *pairingCandidateReader) snapshot() []api.RemoteService {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]api.RemoteService(nil), reader.visible...)
}

func (reader *pairingCandidateReader) VisiblePairingCandidatesUpdated(
	entries []api.PairingCandidateRef,
) {
	reader.mu.Lock()
	reader.candidates = append([]api.PairingCandidateRef(nil), entries...)
	reader.mu.Unlock()
}

func (reader *pairingCandidateReader) candidateSnapshot() []api.PairingCandidateRef {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]api.PairingCandidateRef(nil), reader.candidates...)
}

func (reader *pairingCandidateReader) ServicePairingDetailUpdate(
	string,
	*api.ConnectionStateDetail,
) {
	reader.mu.Lock()
	update := reader.pairingUpdate
	reader.mu.Unlock()
	if update != nil {
		update()
	}
}

func (reader *pairingCandidateReader) setPairingUpdate(update func()) {
	reader.mu.Lock()
	reader.pairingUpdate = update
	reader.mu.Unlock()
}

func (reader *pairingCandidateReader) setVisibleUpdate(update func([]api.RemoteService)) {
	reader.mu.Lock()
	reader.visibleUpdate = update
	reader.mu.Unlock()
}

func newPairingCandidateHub(t *testing.T, gate api.OutgoingAttemptGate) (*Hub, *scriptedAttemptGate, *pairingCandidateReader) {
	t.Helper()
	reader := &pairingCandidateReader{}
	mdns := &attemptTestMdns{}
	hub := NewHub(reader, mdns, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.testHooks = &hubTestHooks{}
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
	entries := map[string]*api.MdnsEntry{
		ref: {
			Name:       "VR940",
			Ski:        ski,
			Identifier: "vr940-ship-id",
			Path:       "/ship/",
			Host:       host,
			Port:       12480,
			Addresses:  parsed,
		},
	}
	hub.ReportMdnsEntriesWithCandidates(entries, true, []api.PairingCandidateObservation{{
		CandidateRef: ref,
		Name:         "VR940",
		SKI:          ski,
		Identifier:   "vr940-ship-id",
		Path:         "/ship/",
		Port:         12480,
		Addresses:    parsed,
	}}, 17)
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

	visible := reader.candidateSnapshot()
	if len(visible) != 1 || visible[0].CandidateRef != pairingCandidateTestRef || visible[0].SKI != pairingCandidateTestSKI {
		t.Fatalf("visible candidate refs = %#v", visible)
	}
	stable := reader.snapshot()
	if len(stable) != 1 || stable[0].Ski != pairingCandidateTestSKI {
		t.Fatalf("stable visible services = %#v", stable)
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

	hub.ReportMdnsEntriesWithCandidates(map[string]*api.MdnsEntry{}, true, nil, 18)
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingCandidateUnavailable) {
		t.Fatalf("retired candidate error = %v, want %v", err, api.ErrPairingCandidateUnavailable)
	}

	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.99")
	if visible := reader.snapshot(); len(visible) != 0 {
		t.Fatalf("older report resurrected visible candidate: %#v", visible)
	}
}

func TestPairingCandidateSnapshotSideEffectsFollowRevisionAdmissionOrder(t *testing.T) {
	hub, _, reader := newPairingCandidateHub(t, newScriptedAttemptGate(gatePrepareError))
	firstVisible := make(chan struct{})
	releaseFirst := make(chan struct{})
	var firstOnce sync.Once
	reader.setVisibleUpdate(func(entries []api.RemoteService) {
		if len(entries) == 0 {
			return
		}
		firstOnce.Do(func() {
			close(firstVisible)
			<-releaseFirst
		})
	})

	firstDone := make(chan struct{})
	go func() {
		reportPairingCandidate(
			hub,
			pairingCandidateTestRef,
			pairingCandidateTestSKI,
			"vr940.local",
			"192.168.100.21",
		)
		close(firstDone)
	}()
	waitForPairingCandidateSignal(t, firstVisible, "first visible-service callback")

	hub.ReportMdnsEntriesWithCandidates(map[string]*api.MdnsEntry{}, true, nil, 18)
	close(releaseFirst)
	waitForPairingCandidateSignal(t, firstDone, "serialized mDNS snapshot drain")

	if visible := reader.snapshot(); len(visible) != 0 {
		t.Fatalf("final stable visibility = %#v, want empty revision 18 snapshot", visible)
	}
	if candidates := reader.candidateSnapshot(); len(candidates) != 0 {
		t.Fatalf("final candidate visibility = %#v, want empty revision 18 snapshot", candidates)
	}
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingCandidateUnavailable) {
		t.Fatalf("retired candidate error = %v, want %v", err, api.ErrPairingCandidateUnavailable)
	}
}

func TestPairingCandidateConsumedTombstonePrunedWhenObservationExpires(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, newScriptedAttemptGate(gatePrepareError))
	hub.testHooks.launchPairingCandidate = func(func()) {}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("consume pairing candidate: %v", err)
	}
	hub.ReportMdnsEntriesWithCandidates(map[string]*api.MdnsEntry{}, true, nil, 18)

	hub.muxReg.Lock()
	remaining := len(hub.consumedPairingCandidates)
	hub.muxReg.Unlock()
	if remaining != 0 {
		t.Fatalf("consumed candidate tombstones after observation expiry = %d, want 0", remaining)
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
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingCandidateUnavailable) {
		t.Fatalf("expired consumed candidate error = %v, want %v", err, api.ErrPairingCandidateUnavailable)
	}
}

func TestPairingCandidateCanceledBeforeAsyncLaunchNeverPreparesAttempt(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launch = run }
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
	hub.testHooks.launchPairingCandidate = func(run func()) { launch = run }
	gateEntered := make(chan struct{})
	gateRelease := make(chan struct{})
	hub.testHooks.beforePairingCandidateGate = func() {
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
	hub.testHooks.launchPairingCandidate = func(run func()) { launch = run }
	gateEntered := make(chan struct{})
	gateRelease := make(chan struct{})
	hub.testHooks.beforePairingCandidateGate = func() {
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

func TestPairingCandidateAdmissionLinearizesWithGateRemoval(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launch = run }
	admissionEntered := make(chan struct{})
	admissionRelease := make(chan struct{})
	hub.testHooks.beforePairingCandidateAdmission = func() {
		close(admissionEntered)
		<-admissionRelease
	}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	queueResult := make(chan error, 1)
	go func() {
		queueResult <- hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI)
	}()
	<-admissionEntered

	removeDone := make(chan error, 1)
	go func() {
		removeDone <- hub.SetOutgoingAttemptGate(nil)
	}()
	select {
	case err := <-removeDone:
		t.Fatalf("gate removal crossed candidate admission: %v", err)
	default:
	}

	close(admissionRelease)
	if err := <-queueResult; err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	if err := <-removeDone; err != nil {
		t.Fatalf("remove outgoing attempt gate: %v", err)
	}
	if launch == nil {
		t.Fatal("candidate launch was not scheduled")
	}
	launch()

	requests, authorized, permits, _ := gate.snapshot()
	if len(requests) != 0 || len(authorized) != 0 || len(permits) != 0 {
		t.Fatalf(
			"gate removal after atomic admission reached old gate: requests=%d authorized=%d permits=%d",
			len(requests),
			len(authorized),
			len(permits),
		)
	}
}

func TestPairingRegistrationCloseDoesNotRetireOutboundCandidate(t *testing.T) {
	gate := newScriptedAttemptGate(gatePrepareError)
	hub, gate, _ := newPairingCandidateHub(t, gate)
	var launch func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launch = run }
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

func TestPairingCandidateTerminalCloseAllowsFreshCandidate(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, _, _ := newPairingCandidateHub(t, gate)
	var launches []func()
	hub.testHooks.launchPairingCandidate = func(run func()) { launches = append(launches, run) }
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue first pairing candidate: %v", err)
	}

	metadata := api.OutgoingAttemptMetadata{AttemptID: "terminal", Scope: "pairing", ControlEpoch: 1}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	registration := installPairingCandidateAttempt(t, hub, pairingCandidateTestSKI, connection, metadata)
	hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
	if registration.context.Err() == nil {
		t.Fatal("terminal close did not cancel exact outbound registration")
	}

	reportPairingCandidate(hub, "shipc_fresh-generation", pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate("shipc_fresh-generation", pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue fresh candidate after terminal close: %v", err)
	}
	if len(launches) != 2 {
		t.Fatalf("scheduled candidate launches = %d, want 2", len(launches))
	}
}

func TestPairingCandidateGateInvalidationSynchronouslyAllowsFreshCandidate(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, _, _ := newPairingCandidateHub(t, gate)
	hub.testHooks.launchPairingCandidate = func(func()) {}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue first pairing candidate: %v", err)
	}
	metadata := api.OutgoingAttemptMetadata{AttemptID: "invalidated", Scope: "pairing", ControlEpoch: 1}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	registration := installPairingCandidateAttempt(t, hub, pairingCandidateTestSKI, connection, metadata)
	hub.registerConnection(connection)
	if err := hub.SetOutgoingAttemptGate(nil); err != nil {
		t.Fatalf("remove outgoing attempt gate: %v", err)
	}
	if registration.context.Err() == nil {
		t.Fatal("gate invalidation did not cancel the active registration")
	}
	if got := hub.connectionForSKI(pairingCandidateTestSKI); got != nil {
		t.Fatalf("gate invalidation left closing connection visible to retry: %#v", got)
	}
	hub.muxReg.Lock()
	activeAfterRemoval := hub.activePairingCandidates[pairingCandidateTestSKI]
	hub.muxReg.Unlock()
	if activeAfterRemoval != nil {
		t.Fatal("gate invalidation stranded the active pairing candidate")
	}

	replacementGate := newScriptedAttemptGate(gatePermit)
	if err := hub.SetOutgoingAttemptGate(replacementGate); err != nil {
		t.Fatalf("install replacement outgoing attempt gate: %v", err)
	}
	hub.dialer = &fakePeerDialer{err: errAttemptTestDial}
	hub.testHooks.launchPairingCandidate = func(run func()) { run() }
	reportPairingCandidate(hub, "shipc_after-gate-replacement", pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate("shipc_after-gate-replacement", pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue fresh candidate after gate replacement: %v", err)
	}
	requests, _, _, _ := replacementGate.snapshot()
	if len(requests) != 1 {
		t.Fatalf("fresh candidate reached replacement gate %d times, want 1", len(requests))
	}
}

func TestPairingCandidateTerminalCloseRemovesConnectionBeforeRetryCallback(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, reader := newPairingCandidateHub(t, gate)
	hub.testHooks.launchPairingCandidate = func(func()) {}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue first pairing candidate: %v", err)
	}

	const freshRef = "shipc_retry-from-terminal-callback"
	hub.muxReg.Lock()
	hub.visiblePairingCandidates[freshRef] = pairingCandidateObservation{
		ski:       pairingCandidateTestSKI,
		revision:  18,
		path:      "/ship/",
		port:      12480,
		addresses: []net.IP{net.ParseIP("192.168.100.21")},
	}
	hub.muxReg.Unlock()

	metadata := api.OutgoingAttemptMetadata{AttemptID: "closing", Scope: "pairing", ControlEpoch: 1}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	installPairingCandidateAttempt(t, hub, pairingCandidateTestSKI, connection, metadata)
	hub.registerConnection(connection)
	hub.dialer = &fakePeerDialer{err: errAttemptTestDial}
	hub.testHooks.launchPairingCandidate = func(run func()) { run() }
	var retryMu sync.Mutex
	retryStarted := false
	var retryErr error
	reader.setPairingUpdate(func() {
		retryMu.Lock()
		if retryStarted {
			retryMu.Unlock()
			return
		}
		retryStarted = true
		retryMu.Unlock()
		retryErr = hub.QueuePairingCandidate(freshRef, pairingCandidateTestSKI)
	})

	hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
	if retryErr != nil {
		t.Fatalf("retry from terminal callback: %v", retryErr)
	}
	requests, _, _, _ := gate.snapshot()
	if len(requests) != 1 {
		t.Fatalf("retry reached outgoing gate %d times, want 1 after old connection removal", len(requests))
	}
}

func TestPairingCandidateCloseAndGateReplacementAreJointlyLinearized(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, _, _ := newPairingCandidateHub(t, gate)
	hub.testHooks.launchPairingCandidate = func(func()) {}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue first pairing candidate: %v", err)
	}

	metadata := api.OutgoingAttemptMetadata{AttemptID: "closing-during-gate-replacement", Scope: "pairing", ControlEpoch: 1}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	installPairingCandidateAttempt(t, hub, pairingCandidateTestSKI, connection, metadata)
	hub.registerConnection(connection)

	releaseEntered := make(chan struct{})
	releaseContinue := make(chan struct{})
	hub.testHooks.beforeOutboundAttemptRelease = func() {
		close(releaseEntered)
		<-releaseContinue
	}
	closeDone := make(chan struct{})
	go func() {
		hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
		close(closeDone)
	}()
	waitForPairingCandidateSignal(t, releaseEntered, "close after exact connection removal")
	if got := hub.connectionForSKI(pairingCandidateTestSKI); got != nil {
		t.Fatalf("old connection remained visible before attempt release: %#v", got)
	}

	replacementGate := newScriptedAttemptGate(gatePermit)
	gateStarted := make(chan struct{})
	gateDone := make(chan error, 1)
	go func() {
		close(gateStarted)
		gateDone <- hub.SetOutgoingAttemptGate(replacementGate)
	}()
	waitForPairingCandidateSignal(t, gateStarted, "replacement gate start")
	select {
	case err := <-gateDone:
		t.Fatalf("gate replacement crossed the close lifecycle transaction: %v", err)
	default:
	}

	close(releaseContinue)
	waitForPairingCandidateSignal(t, closeDone, "close lifecycle completion")
	if err := <-gateDone; err != nil {
		t.Fatalf("install replacement outgoing attempt gate: %v", err)
	}

	hub.dialer = &fakePeerDialer{err: errAttemptTestDial}
	hub.testHooks.launchPairingCandidate = func(run func()) { run() }
	const freshRef = "shipc_after-linearized-close"
	reportPairingCandidate(hub, freshRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate(freshRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue candidate after linearized close and gate replacement: %v", err)
	}
	requests, _, _, _ := replacementGate.snapshot()
	if len(requests) != 1 {
		t.Fatalf("fresh candidate reached replacement gate %d times, want 1", len(requests))
	}
}

func TestPairingCandidateTerminalRetirementCannotOverwriteConcurrentTrust(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, _, _ := newPairingCandidateHub(t, gate)
	hub.testHooks.launchPairingCandidate = func(func()) {}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")
	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue first pairing candidate: %v", err)
	}

	metadata := api.OutgoingAttemptMetadata{AttemptID: "trust-race", Scope: "pairing", ControlEpoch: 1}
	connection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	installPairingCandidateAttempt(t, hub, pairingCandidateTestSKI, connection, metadata)
	hub.registerConnection(connection)
	registerLookup := make(chan struct{})
	registerRelease := make(chan struct{})
	registerAttemptingLock := make(chan struct{})
	hub.testHooks.afterRegisterRemoteServiceLookup = func() {
		close(registerLookup)
		<-registerRelease
		close(registerAttemptingLock)
	}
	retireEntered := make(chan struct{})
	retireRelease := make(chan struct{})
	var retireOnce sync.Once
	hub.testHooks.beforePairingCandidateRetire = func() {
		retireOnce.Do(func() { close(retireEntered) })
		<-retireRelease
	}

	registerDone := make(chan struct{})
	go func() {
		hub.RegisterRemoteSKI(pairingCandidateTestSKI)
		close(registerDone)
	}()
	waitForPairingCandidateSignal(t, registerLookup, "durable trust service lookup")

	closeDone := make(chan struct{})
	go func() {
		hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
		close(closeDone)
	}()
	waitForPairingCandidateSignal(t, retireEntered, "terminal retirement critical section")
	close(registerRelease)
	waitForPairingCandidateSignal(t, registerAttemptingLock, "durable trust lock attempt")
	close(retireRelease)
	waitForPairingCandidateSignal(t, closeDone, "terminal retirement completion")
	waitForPairingCandidateSignal(t, registerDone, "durable trust completion")

	if !hub.ServiceForSKI(pairingCandidateTestSKI).Trusted() {
		t.Fatal("terminal retirement overwrote concurrent durable trust")
	}
}

func TestPairingCandidateRetirementDoesNotDeleteNewerRetryState(t *testing.T) {
	tests := []struct {
		name            string
		prepareNewState func(*Hub, *api.ServiceDetails)
	}{
		{
			name: "durable trust",
			prepareNewState: func(_ *Hub, service *api.ServiceDetails) {
				service.SetTrusted(true)
			},
		},
		{
			name: "new authority",
			prepareNewState: func(hub *Hub, _ *api.ServiceDetails) {
				hub.muxAttemptGate.Lock()
				hub.rotateOutboundAuthorityLocked(pairingCandidateTestSKI)
				hub.muxAttemptGate.Unlock()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(gatePermit)
			hub, _, _ := newPairingCandidateHub(t, gate)
			service := hub.ServiceForSKI(pairingCandidateTestSKI)
			hub.muxAttemptGate.Lock()
			retiredAuthority := hub.rotateOutboundAuthorityLocked(pairingCandidateTestSKI)
			hub.muxAttemptGate.Unlock()
			retirement := pairingCandidateRetirement{
				ski:       pairingCandidateTestSKI,
				service:   service,
				authority: retiredAuthority,
			}
			test.prepareNewState(hub, service)
			hub.muxConAttempt.Lock()
			hub.connectionAttemptCounter[pairingCandidateTestSKI] = 2
			hub.muxConAttempt.Unlock()

			hub.finishPairingCandidateRetirements([]pairingCandidateRetirement{retirement})

			counter, exists := hub.getCurrentConnectionAttemptCounter(pairingCandidateTestSKI)
			if !exists || counter != 2 {
				t.Fatalf("new retry state = (%d, %t), want (2, true)", counter, exists)
			}
		})
	}
}

func TestPairingCandidateStaleCloseDoesNotRetireNewerAuthority(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, _, _ := newPairingCandidateHub(t, gate)
	hub.testHooks.launchPairingCandidate = func(func()) {}
	reportPairingCandidate(hub, pairingCandidateTestRef, pairingCandidateTestSKI, "vr940.local", "192.168.100.21")

	if err := hub.QueuePairingCandidate(pairingCandidateTestRef, pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue first pairing candidate: %v", err)
	}
	oldMetadata := api.OutgoingAttemptMetadata{AttemptID: "old", Scope: "pairing", ControlEpoch: 1}
	oldConnection := &attemptCallbackConnection{ski: pairingCandidateTestSKI}
	installPairingCandidateAttempt(t, hub, pairingCandidateTestSKI, oldConnection, oldMetadata)

	hub.muxReg.Lock()
	service := hub.activePairingCandidates[pairingCandidateTestSKI].service
	hub.muxAttemptGate.Lock()
	newAuthority := hub.rotateOutboundAuthorityLocked(pairingCandidateTestSKI)
	hub.muxAttemptGate.Unlock()
	newCandidate := &activePairingCandidate{service: service, authority: newAuthority}
	hub.activePairingCandidates[pairingCandidateTestSKI] = newCandidate
	hub.muxReg.Unlock()

	hub.HandleConnectionClosedWithAttempt(oldConnection, false, oldMetadata)
	hub.muxReg.Lock()
	active := hub.activePairingCandidates[pairingCandidateTestSKI]
	hub.muxReg.Unlock()
	if active != newCandidate {
		t.Fatal("stale close retired the newer pairing candidate")
	}
}

func installPairingCandidateAttempt(
	t *testing.T,
	hub *Hub,
	ski string,
	connection api.ShipConnectionInterface,
	metadata api.OutgoingAttemptMetadata,
) *outboundAttemptRegistration {
	t.Helper()
	hub.muxReg.Lock()
	active := hub.activePairingCandidates[ski]
	hub.muxReg.Unlock()
	if active == nil {
		t.Fatal("pairing candidate is not active")
		return nil
	}
	// #nosec G118 -- cancellation ownership is transferred to the registration.
	attemptContext, cancel := context.WithCancel(context.Background())
	registration := &outboundAttemptRegistration{
		authority:  active.authority,
		metadata:   metadata,
		context:    attemptContext,
		cancel:     cancel,
		connection: connection,
	}
	hub.muxAttemptGate.Lock()
	registrations := hub.outboundAttempts[ski]
	if registrations == nil {
		registrations = make(map[*outboundAttemptRegistration]struct{})
		hub.outboundAttempts[ski] = registrations
	}
	registrations[registration] = struct{}{}
	hub.muxAttemptGate.Unlock()
	return registration
}

func waitForPairingCandidateSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}
