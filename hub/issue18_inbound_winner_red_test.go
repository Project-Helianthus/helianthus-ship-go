package hub

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
)

type issue18PairingReader struct {
	pairingCandidateReader

	stateMu      sync.Mutex
	states       []api.ConnectionState
	receivedOnce sync.Once
	received     chan struct{}
	noneOnce     sync.Once
	none         chan struct{}
}

func (reader *issue18PairingReader) ServicePairingDetailUpdate(
	_ string,
	detail *api.ConnectionStateDetail,
) {
	state := detail.State()
	reader.stateMu.Lock()
	reader.states = append(reader.states, state)
	reader.stateMu.Unlock()
	if state == api.ConnectionStateReceivedPairingRequest {
		reader.receivedOnce.Do(func() { close(reader.received) })
	}
	if state == api.ConnectionStateNone {
		reader.noneOnce.Do(func() { close(reader.none) })
	}
}

func (reader *issue18PairingReader) pairingStates() []api.ConnectionState {
	reader.stateMu.Lock()
	defer reader.stateMu.Unlock()
	return append([]api.ConnectionState(nil), reader.states...)
}

func TestIssue18AuthenticatedInboundWinnerPreservesSelectedCandidate(t *testing.T) {
	serverCertificate, err := cert.CreateCertificate("unit", "org", "DE", "server")
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := cert.CreateCertificate("unit", "org", "DE", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	remoteSKI, err := cert.SkiFromCertificate(clientLeaf)
	if err != nil {
		t.Fatal(err)
	}

	reader := &issue18PairingReader{
		received: make(chan struct{}),
		none:     make(chan struct{}),
	}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		serverCertificate,
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	hub.testHooks = &hubTestHooks{}
	if err := hub.SetOutgoingAttemptGate(newScriptedAttemptGate(gatePermit)); err != nil {
		t.Fatalf("install outgoing attempt gate: %v", err)
	}
	hub.hasStarted = true

	outboundAtConnectionCheck := make(chan struct{})
	releaseOutbound := make(chan struct{})
	hub.testHooks.beforePairingCandidateGate = func() {
		close(outboundAtConnectionCheck)
		<-releaseOutbound
	}
	outboundDone := make(chan struct{})
	hub.testHooks.launchPairingCandidate = func(run func()) {
		go func() {
			defer close(outboundDone)
			run()
		}()
	}

	const candidateRef = "shipc_issue18-inbound-winner"
	reportPairingCandidate(
		hub,
		candidateRef,
		remoteSKI,
		"vr940.local",
		"192.168.100.21",
	)
	if err := hub.QueuePairingCandidate(candidateRef, remoteSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	waitForPairingCandidateSignal(t, outboundAtConnectionCheck, "outbound candidate connection check")
	if states := reader.pairingStates(); len(states) != 1 || states[0] != api.ConnectionStateQueued {
		t.Fatalf("pre-inbound pairing states = %v, want [Queued]", states)
	}

	server := newIssue16TLSServer(t, hub, serverCertificate)
	connection, response, err := issue16Dial(server.URL, clientCertificate)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatalf("authenticated inbound websocket dial: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })

	waitForPairingCandidateSignal(t, reader.received, "authenticated inbound pairing request")

	close(releaseOutbound)
	waitForPairingCandidateSignal(t, outboundDone, "losing outbound candidate completion")

	hub.muxReg.Lock()
	active := hub.activePairingCandidates[remoteSKI]
	hub.muxReg.Unlock()
	if active == nil {
		t.Error("authenticated inbound winner retired the active pairing candidate")
	}

	states := reader.pairingStates()
	for _, state := range states {
		if state == api.ConnectionStateNone {
			t.Errorf("losing outbound attempt appended terminal None state: %v", states)
			break
		}
	}

	if err := connection.Close(); err != nil {
		t.Fatalf("close authenticated inbound winner: %v", err)
	}
	waitForPairingCandidateSignal(t, reader.none, "failed inbound winner retirement")
	hub.muxReg.Lock()
	active = hub.activePairingCandidates[remoteSKI]
	hub.muxReg.Unlock()
	if active != nil {
		t.Fatal("failed inbound winner left the pairing candidate active")
	}
}

func TestIssue18FailedInboundReservationStillRetiresSelectedCandidate(t *testing.T) {
	reader := &issue18PairingReader{
		received: make(chan struct{}),
		none:     make(chan struct{}),
	}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	hub.testHooks = &hubTestHooks{}
	if err := hub.SetOutgoingAttemptGate(newScriptedAttemptGate(gatePermit)); err != nil {
		t.Fatalf("install outgoing attempt gate: %v", err)
	}
	hub.hasStarted = true

	outboundAtConnectionCheck := make(chan struct{})
	releaseOutbound := make(chan struct{})
	hub.testHooks.beforePairingCandidateGate = func() {
		close(outboundAtConnectionCheck)
		<-releaseOutbound
	}
	outboundDone := make(chan struct{})
	hub.testHooks.launchPairingCandidate = func(run func()) {
		go func() {
			defer close(outboundDone)
			run()
		}()
	}

	const remoteSKI = "b1b7197b064084e4cfef2365105d8d36ff185e5b"
	const candidateRef = "shipc_issue18-failed-inbound"
	reportPairingCandidate(
		hub,
		candidateRef,
		remoteSKI,
		"vr940.local",
		"192.168.100.21",
	)
	if err := hub.QueuePairingCandidate(candidateRef, remoteSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	waitForPairingCandidateSignal(t, outboundAtConnectionCheck, "outbound candidate connection check")

	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("reserve failed inbound pairing connection")
	}

	close(releaseOutbound)
	waitForPairingCandidateSignal(t, outboundDone, "outbound handoff to pending inbound reservation")

	hub.muxReg.Lock()
	active := hub.activePairingCandidates[remoteSKI]
	hub.muxReg.Unlock()
	if active == nil {
		t.Fatal("pending inbound reservation did not preserve the pairing candidate")
	}
	if states := reader.pairingStates(); len(states) != 1 || states[0] != api.ConnectionStateQueued {
		t.Fatalf("pending inbound pairing states = %v, want [Queued]", states)
	}

	hub.abandonInboundPairingReservation(remoteSKI, reservation)
	waitForPairingCandidateSignal(t, reader.none, "abandoned inbound reservation retirement")
	hub.muxReg.Lock()
	active = hub.activePairingCandidates[remoteSKI]
	hub.muxReg.Unlock()
	if active != nil {
		t.Fatal("abandoned inbound reservation left the pairing candidate active")
	}
	states := reader.pairingStates()
	if len(states) != 2 ||
		states[0] != api.ConnectionStateQueued ||
		states[1] != api.ConnectionStateNone {
		t.Fatalf("abandoned inbound pairing states = %v, want [Queued None]", states)
	}
}
