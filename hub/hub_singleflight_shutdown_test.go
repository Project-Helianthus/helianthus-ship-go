package hub

import (
	"errors"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

type notifyingAttemptGate struct {
	*scriptedAttemptGate
	prepared chan struct{}
}

const (
	outgoingAttemptTestSKI  = "0123456789abcdef0123456789abcdef01234567"
	outgoingAttemptTestHost = "192.0.2.21"
	outgoingAttemptTestPort = "54321"
	outgoingAttemptTestPath = "/ship/"
)

func (g *notifyingAttemptGate) Prepare(request api.OutgoingAttemptRequest) (api.OutgoingAttemptHandle, error) {
	handle, err := g.scriptedAttemptGate.Prepare(request)
	g.prepared <- struct{}{}
	return handle, err
}

func TestHubSingleFlightReservationClearsAfterTerminalFailure(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, _, _ := newAttemptTestHub(t, gate, dialer)
	remote := hub.ServiceForSKI(outgoingAttemptTestSKI)
	remote.SetTrusted(true)

	for attempt := 1; attempt <= 2; attempt++ {
		err := hub.connectFoundService(
			remote,
			outgoingAttemptTestHost,
			outgoingAttemptTestPort,
			outgoingAttemptTestPath,
			nil,
		)
		if !errors.Is(err, errAttemptTestDial) {
			t.Fatalf("terminal failure %d = %v, want %v", attempt, err, errAttemptTestDial)
		}
		requests, authorized, _, _ := gate.snapshot()
		want := attempt * 2 // Path retry is part of one reserved connection operation.
		if len(requests) != want || len(authorized) != want {
			t.Fatalf("after terminal failure %d prepare/authorize counts = %d/%d, want %d/%d", attempt, len(requests), len(authorized), want, want)
		}
	}
}

func TestHubShutdownCancelsBlockedGatedDialsWithoutLateRegistration(t *testing.T) {
	dialRelease := make(chan struct{})
	t.Cleanup(func() { close(dialRelease) })
	gate := newScriptedAttemptGate(gatePermit)
	dialer := &fakePeerDialer{
		err:                 errAttemptTestDial,
		started:             make(chan struct{}),
		waitForCancellation: true,
		release:             dialRelease,
	}
	hub, _, _ := newAttemptTestHub(t, gate, dialer)
	remote := hub.ServiceForSKI(outgoingAttemptTestSKI)
	remote.SetTrusted(true)

	result := make(chan error, 1)
	go func() {
		result <- hub.connectFoundService(
			remote,
			outgoingAttemptTestHost,
			outgoingAttemptTestPort,
			outgoingAttemptTestPath,
			nil,
		)
	}()
	waitForSignal(t, dialer.started)

	shutdownDone := make(chan struct{})
	go func() {
		hub.Shutdown()
		close(shutdownDone)
	}()
	waitForShutdownTestSignal(t, shutdownDone, "shutdown with blocked gated dial")
	assertTypedAttemptDenial(t, waitForError(t, result))

	calls, peerEffects := dialer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("shutdown-canceled dial calls = %d, want 1", len(calls))
	}
	if calls[0].context.Err() == nil || peerEffects != 0 {
		t.Fatalf("shutdown-canceled context/peer effects = %v/%d, want canceled/0", calls[0].context.Err(), peerEffects)
	}
	if connection := hub.connectionForSKI(outgoingAttemptTestSKI); connection != nil {
		t.Fatalf("shutdown allowed late registration for %s: %#v", outgoingAttemptTestSKI, connection)
	}

	// Repeated shutdown remains idempotent after outbound cancellation.
	hub.Shutdown()
}
