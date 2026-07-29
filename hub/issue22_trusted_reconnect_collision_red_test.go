package hub

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

func TestIssue22TrustedInboundLoserDoesNotEnterSHIPWhileOutboundIsInitiating(t *testing.T) {
	localSKI := strings.Repeat("f", 40)
	remoteSKI := strings.Repeat("0", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)

	hub.muxCon.Lock()
	hub.connectionsInitiating[remoteSKI] = true
	hub.muxCon.Unlock()

	if hub.keepThisConnection(nil, true, remote) {
		t.Fatal("trusted inbound loser entered SHIP while the winning outbound attempt was initiating")
	}
}

func TestIssue22TrustedInboundWinnerSurvivesWhileOutboundIsInitiating(t *testing.T) {
	localSKI := strings.Repeat("0", 40)
	remoteSKI := strings.Repeat("f", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)

	hub.muxCon.Lock()
	hub.connectionsInitiating[remoteSKI] = true
	hub.muxCon.Unlock()

	if !hub.keepThisConnection(nil, true, remote) {
		t.Fatal("trusted inbound winner was rejected because an outbound attempt was initiating")
	}
}

func TestIssue22InboundWinnerRegisteredBeforeLateOutboundCannotBeOverwritten(t *testing.T) {
	localSKI := strings.Repeat("0", 40)
	remoteSKI := strings.Repeat("f", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	inbound := &shutdownCallbackConnection{ski: remoteSKI}
	outbound := &shutdownCallbackConnection{ski: remoteSKI}

	hub.muxCon.Lock()
	hub.connectionsInitiating[remoteSKI] = true
	hub.muxCon.Unlock()
	if !hub.registerInboundConnection(inbound) {
		t.Fatal("remote-higher inbound winner was rejected")
	}
	if result := hub.registerOutgoingConnection(outbound, context.Background(), nil); result != outgoingConnectionRegistrationInboundHandoff {
		t.Fatalf("late outbound registration result = %v, want inbound handoff", result)
	}
	outbound.CloseConnection(false, 0, "inbound handoff")
	hub.HandleConnectionClosed(outbound, false)

	if got := hub.connectionForSKI(remoteSKI); got != inbound {
		t.Fatalf("registered connection after late outbound = %p, want inbound %p", got, inbound)
	}
	if got := outbound.closeCalls.Load(); got != 1 {
		t.Fatalf("late outbound close count = %d, want 1", got)
	}
}

func TestIssue22InboundWinnerAtomicallyReplacesOutboundRegisteredFirst(t *testing.T) {
	localSKI := strings.Repeat("0", 40)
	remoteSKI := strings.Repeat("f", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	inbound := &shutdownCallbackConnection{ski: remoteSKI}
	outbound := &shutdownCallbackConnection{ski: remoteSKI}

	if result := hub.registerOutgoingConnection(outbound, context.Background(), nil); result != outgoingConnectionRegistrationAccepted {
		t.Fatalf("first outbound registration result = %v, want accepted", result)
	}
	if !hub.registerInboundConnection(inbound) {
		t.Fatal("remote-higher inbound winner was rejected after outbound registration")
	}
	hub.HandleConnectionClosed(outbound, false)

	if got := hub.connectionForSKI(remoteSKI); got != inbound {
		t.Fatalf("registered connection after inbound replacement = %p, want inbound %p", got, inbound)
	}
	if got := outbound.closeCalls.Load(); got != 1 {
		t.Fatalf("replaced outbound close count = %d, want 1", got)
	}
}

func TestIssue22OutboundWinnerAtomicallyReplacesInboundRegisteredFirst(t *testing.T) {
	localSKI := strings.Repeat("f", 40)
	remoteSKI := strings.Repeat("0", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	inbound := &shutdownCallbackConnection{ski: remoteSKI}
	outbound := &shutdownCallbackConnection{ski: remoteSKI}

	if !hub.registerInboundConnection(inbound) {
		t.Fatal("first inbound connection was rejected without a collision")
	}
	if result := hub.registerOutgoingConnection(outbound, context.Background(), nil); result != outgoingConnectionRegistrationAccepted {
		t.Fatalf("local-higher outbound registration result = %v, want accepted", result)
	}
	hub.HandleConnectionClosed(inbound, false)

	if got := hub.connectionForSKI(remoteSKI); got != outbound {
		t.Fatalf("registered connection after outbound replacement = %p, want outbound %p", got, outbound)
	}
	if got := inbound.closeCalls.Load(); got != 1 {
		t.Fatalf("replaced inbound close count = %d, want 1", got)
	}
}
