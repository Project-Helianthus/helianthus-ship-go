package hub

import (
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

const outboundPairingTestSKI = "0123456789abcdef0123456789abcdef01234567"

var outboundPairingTestEndpoint = api.RemoteEndpoint{
	Host: "192.0.2.21",
	Port: 54321,
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
	if len(calls) == 0 || calls[0].url != "wss://192.0.2.21:54321/ship/" {
		t.Fatalf("first dial = %#v, want exact synthetic endpoint", calls)
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
	tests := []struct {
		name       string
		invalidate func(*Hub)
	}{
		{
			name: "cancel pairing",
			invalidate: func(hub *Hub) {
				hub.CancelPairingWithSKI(outboundPairingTestSKI)
			},
		},
		{
			name: "unregister remote",
			invalidate: func(hub *Hub) {
				hub.UnregisterRemoteSKI(outboundPairingTestSKI)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(gatePermit)
			gate.authorizeEntered = make(chan struct{})
			gate.authorizeRelease = make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-gate.authorizeRelease:
				default:
					close(gate.authorizeRelease)
				}
			})
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, _, remote := newAttemptTestHub(t, gate, dialer)
			queueOutboundPairingWithoutBackgroundDial(t, hub)

			result := make(chan error, 1)
			go func() {
				result <- hub.connectFoundService(remote, outboundPairingTestEndpoint.Host, "54321", outboundPairingTestEndpoint.Path)
			}()

			waitForSignal(t, gate.authorizeEntered)
			test.invalidate(hub)
			close(gate.authorizeRelease)
			assertTypedAttemptDenial(t, waitForError(t, result))

			calls, peerEffects := dialer.snapshot()
			if len(calls) != 0 || peerEffects != 0 {
				t.Fatalf("invalidated endpoint dial/peer effects = %d/%d, want 0/0", len(calls), peerEffects)
			}
			if remote.Trusted() || remote.ConnectionStateDetail().State() == api.ConnectionStateQueued {
				t.Fatal("invalidation retained trust or queued admission")
			}
		})
	}
}

func TestOutboundPairingGateLifecycleChangeBeforeAuthorizationPreventsDial(t *testing.T) {
	tests := []struct {
		name        string
		reconfigure func(*testing.T, *Hub)
	}{
		{
			name: "gate removed",
			reconfigure: func(t *testing.T, hub *Hub) {
				t.Helper()
				if err := hub.SetOutgoingAttemptGate(nil); err != nil {
					t.Fatalf("remove outgoing attempt gate: %v", err)
				}
			},
		},
		{
			name: "gate replaced",
			reconfigure: func(t *testing.T, hub *Hub) {
				t.Helper()
				if err := hub.SetOutgoingAttemptGate(newScriptedAttemptGate(gatePermit)); err != nil {
					t.Fatalf("replace outgoing attempt gate: %v", err)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(gatePermit)
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, _, remote := newAttemptTestHub(t, gate, dialer)
			queueOutboundPairingWithoutBackgroundDial(t, hub)

			test.reconfigure(t, hub)
			err := hub.connectFoundService(remote, outboundPairingTestEndpoint.Host, "54321", outboundPairingTestEndpoint.Path)
			assertTypedAttemptDenial(t, err)

			calls, peerEffects := dialer.snapshot()
			if len(calls) != 0 || peerEffects != 0 {
				t.Fatalf("stale admission dial/peer effects = %d/%d, want 0/0", len(calls), peerEffects)
			}
			if remote.Trusted() {
				t.Fatal("stale admission promoted trust")
			}
		})
	}
}

func queueOutboundPairingWithoutBackgroundDial(t *testing.T, hub *Hub) {
	t.Helper()
	if err := hub.QueueRemoteSKI(outboundPairingTestSKI); err != nil {
		t.Fatalf("queue remote: %v", err)
	}
	hub.setConnectionAttemptRunning(outboundPairingTestSKI, true)
	if err := hub.ReportRemoteEndpoint(outboundPairingTestSKI, outboundPairingTestEndpoint); err != nil {
		t.Fatalf("report endpoint: %v", err)
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
