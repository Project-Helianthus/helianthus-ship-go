package hub

import (
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

const outboundPairingTestSKI = "b1b7197b064084e4cfef2365105d8d36ff185e5b"

var outboundPairingTestEndpoint = api.RemoteEndpoint{
	Host: "192.168.100.21",
	Port: 12480,
	Path: "/ship/",
}

func TestOutboundPairingGateDenialPreventsDial(t *testing.T) {
	gate := newScriptedAttemptGate(gateAuthorizeDeny)
	gate.authorizeEntered = make(chan struct{})
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, _, _ := newAttemptTestHub(t, gate, dialer)

	if err := hub.QueueRemoteSKI(outboundPairingTestSKI); err != nil {
		t.Fatalf("queue remote: %v", err)
	}
	if err := hub.ReportRemoteEndpoint(outboundPairingTestSKI, outboundPairingTestEndpoint); err != nil {
		t.Fatalf("report endpoint: %v", err)
	}
	waitForSignal(t, gate.authorizeEntered)

	requests, _, _, _ := gate.snapshot()
	if len(requests) != 1 {
		t.Fatalf("gate requests = %d, want 1", len(requests))
	}
	assertOutboundPairingRequest(t, requests[0])
	calls, peerEffects := dialer.snapshot()
	if len(calls) != 0 || peerEffects != 0 {
		t.Fatalf("denied endpoint dial/peer effects = %d/%d, want 0/0", len(calls), peerEffects)
	}
	if hub.ServiceForSKI(outboundPairingTestSKI).Trusted() {
		t.Fatal("denied endpoint granted trust")
	}
}

func TestOutboundPairingPermitCarriesExactEndpointWithoutTrustPromotion(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	dialer := &fakePeerDialer{err: errAttemptTestDial, started: make(chan struct{})}
	hub, _, _ := newAttemptTestHub(t, gate, dialer)

	if err := hub.QueueRemoteSKI(outboundPairingTestSKI); err != nil {
		t.Fatalf("queue remote: %v", err)
	}
	if err := hub.ReportRemoteEndpoint(outboundPairingTestSKI, outboundPairingTestEndpoint); err != nil {
		t.Fatalf("report endpoint: %v", err)
	}
	waitForSignal(t, dialer.started)

	requests, _, _, _ := gate.snapshot()
	if len(requests) == 0 {
		t.Fatal("permitted endpoint did not reach the gate")
	}
	assertOutboundPairingRequest(t, requests[0])
	calls, _ := dialer.snapshot()
	if len(calls) == 0 || calls[0].url != "wss://192.168.100.21:12480/ship/" {
		t.Fatalf("first dial = %#v, want exact VR940 endpoint", calls)
	}
	if hub.ServiceForSKI(outboundPairingTestSKI).Trusted() {
		t.Fatal("outgoing attempt granted trust before confirmation")
	}

	hub.HandleShipHandshakeStateUpdateWithAttempt(
		outboundPairingTestSKI,
		model.ShipState{State: model.SmeHelloStateOk},
		api.OutgoingAttemptMetadata{AttemptID: "attempt-1", Scope: "remote-scope", ControlEpoch: 17},
	)
	if hub.ServiceForSKI(outboundPairingTestSKI).Trusted() {
		t.Fatal("attempt-aware hello completion bypassed explicit trust promotion")
	}
}

func TestOutboundPairingCancellationBeforeLaunchPreventsDial(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	gate.authorizeEntered = make(chan struct{})
	gate.authorizeRelease = make(chan struct{})
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, _, _ := newAttemptTestHub(t, gate, dialer)

	if err := hub.QueueRemoteSKI(outboundPairingTestSKI); err != nil {
		t.Fatalf("queue remote: %v", err)
	}
	if err := hub.ReportRemoteEndpoint(outboundPairingTestSKI, outboundPairingTestEndpoint); err != nil {
		t.Fatalf("report endpoint: %v", err)
	}
	waitForSignal(t, gate.authorizeEntered)
	hub.CancelPairingWithSKI(outboundPairingTestSKI)
	gate.cancelLatest(t)
	close(gate.authorizeRelease)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, authorized, _, _ := gate.snapshot()
		if len(authorized) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	calls, peerEffects := dialer.snapshot()
	if len(calls) != 0 || peerEffects != 0 {
		t.Fatalf("canceled endpoint dial/peer effects = %d/%d, want 0/0", len(calls), peerEffects)
	}
	remote := hub.ServiceForSKI(outboundPairingTestSKI)
	if remote.Trusted() || remote.ConnectionStateDetail().State() == api.ConnectionStateQueued {
		t.Fatal("cancellation retained trust or queued admission")
	}
}

func assertOutboundPairingRequest(t *testing.T, request api.OutgoingAttemptRequest) {
	t.Helper()
	if request.RemoteSKI != outboundPairingTestSKI ||
		request.Endpoint.Host != outboundPairingTestEndpoint.Host ||
		request.Endpoint.Port != outboundPairingTestEndpoint.Port ||
		request.Path != outboundPairingTestEndpoint.Path {
		t.Fatalf("outbound request = %#v, want exact configured peer and endpoint", request)
	}
}
