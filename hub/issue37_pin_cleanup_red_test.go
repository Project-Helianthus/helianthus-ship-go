package hub

import (
	"context"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

type issue37TransientPINProbe struct {
	hub *Hub

	mu           sync.Mutex
	consumeCalls int
	discardCalls int
}

func (probe *issue37TransientPINProbe) WithTransientPIN(
	_ string,
	consume func([]byte) error,
) (bool, error) {
	probe.mu.Lock()
	probe.consumeCalls++
	probe.mu.Unlock()

	pin := []byte{'3', '7', '3', '7'}
	err := consume(pin)
	clear(pin)
	return true, err
}

func (probe *issue37TransientPINProbe) DiscardTransientPIN(_ string) {
	// A Hub cleanup must release its registration lock before calling an
	// untrusted owner. Re-entering the same lock makes a violation observable
	// as a bounded test timeout instead of inspecting mutex internals.
	probe.hub.muxReg.Lock()
	probe.hub.muxReg.Unlock()

	probe.mu.Lock()
	probe.discardCalls++
	probe.mu.Unlock()
}

func (probe *issue37TransientPINProbe) counts() (consume, discard int) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.consumeCalls, probe.discardCalls
}

func issue37InstallTransientPIN(
	hub *Hub,
	ski string,
	authority *outboundAttemptAuthority,
) *issue37TransientPINProbe {
	probe := &issue37TransientPINProbe{hub: hub}
	hub.muxReg.Lock()
	hub.transientPINProviders[ski] = transientPINProviderRegistration{
		authority: authority,
		provider:  probe,
	}
	hub.muxReg.Unlock()
	return probe
}

func issue37InstallTerminalClose(
	t *testing.T,
	hub *Hub,
	ski string,
	authority *outboundAttemptAuthority,
) func() {
	t.Helper()
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "issue37-terminal",
		Scope:        "pairing",
		ControlEpoch: authority.epoch,
	}
	connection := &attemptCallbackConnection{ski: ski}
	// #nosec G118 -- cancellation ownership is transferred to the registration.
	attemptContext, cancel := context.WithCancel(context.Background())
	registration := &outboundAttemptRegistration{
		authority:  authority,
		metadata:   metadata,
		context:    attemptContext,
		cancel:     cancel,
		connection: connection,
	}
	hub.muxAttemptGate.Lock()
	hub.outboundAttempts[ski] = map[*outboundAttemptRegistration]struct{}{
		registration: {},
	}
	hub.muxAttemptGate.Unlock()
	if !hub.registerConnection(connection) {
		t.Fatal("register terminal-close connection")
	}
	return func() {
		hub.claimClosedOutboundAttempt(ski, connection, metadata)
	}
}

func issue37WaitDone(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	waitForPairingCandidateSignal(t, done, operation)
}

func TestIssue37UnconsumedPINCleanupDiscardsInnerOwnerExactlyOnceOutsideLock(t *testing.T) {
	for _, cleanupCase := range []struct {
		name    string
		cleanup func(*testing.T, *Hub, string, *outboundAttemptAuthority) func()
	}{
		{
			name: "no PIN or optional restricted",
			cleanup: func(
				_ *testing.T,
				hub *Hub,
				ski string,
				_ *outboundAttemptAuthority,
			) func() {
				return func() { hub.DiscardTransientPIN(ski) }
			},
		},
		{
			name:    "terminal close",
			cleanup: issue37InstallTerminalClose,
		},
	} {
		t.Run(cleanupCase.name, func(t *testing.T) {
			hub, _, _ := newPairingCandidateHub(t, nil)
			authority := &outboundAttemptAuthority{epoch: 37}
			probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, authority)
			cleanup := cleanupCase.cleanup(t, hub, pairingCandidateTestSKI, authority)

			done := make(chan struct{})
			go func() {
				cleanup()
				close(done)
			}()
			issue37WaitDone(t, done, cleanupCase.name+" cleanup")

			consumeCalls, discardCalls := probe.counts()
			if consumeCalls != 0 || discardCalls != 1 {
				t.Fatalf(
					"inner PIN outcomes = consume:%d discard:%d, want 0/1",
					consumeCalls,
					discardCalls,
				)
			}
		})
	}
}

func TestIssue37ConsumedPINIsNotDiscardedAgain(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, nil)
	authority := &outboundAttemptAuthority{epoch: 37}
	probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, authority)

	provided, err := hub.withTransientPINForAuthority(
		pairingCandidateTestSKI,
		authority,
		func([]byte) error { return nil },
	)
	if err != nil || !provided {
		t.Fatalf("consume registered PIN = provided:%t err:%v, want true/nil", provided, err)
	}
	hub.discardTransientPINForAuthority(pairingCandidateTestSKI, authority)
	hub.DiscardTransientPIN(pairingCandidateTestSKI)

	consumeCalls, discardCalls := probe.counts()
	if consumeCalls != 1 || discardCalls != 0 {
		t.Fatalf(
			"consumed PIN outcomes after repeated cleanup = consume:%d discard:%d, want 1/0",
			consumeCalls,
			discardCalls,
		)
	}
}

func TestIssue37ConcurrentConsumeDiscardAndCloseHasOneTerminalOwner(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, nil)
	authority := &outboundAttemptAuthority{epoch: 37}
	probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, authority)
	closeAttempt := issue37InstallTerminalClose(t, hub, pairingCandidateTestSKI, authority)

	cleanupStart := make(chan struct{})
	consumeStart := make(chan struct{})
	var operations sync.WaitGroup
	var cleanups sync.WaitGroup
	operations.Add(3)
	cleanups.Add(2)
	go func() {
		defer operations.Done()
		defer cleanups.Done()
		<-cleanupStart
		hub.discardTransientPINForAuthority(pairingCandidateTestSKI, authority)
	}()
	go func() {
		defer operations.Done()
		defer cleanups.Done()
		<-cleanupStart
		closeAttempt()
	}()
	go func() {
		defer operations.Done()
		<-consumeStart
		_, _ = hub.withTransientPINForAuthority(
			pairingCandidateTestSKI,
			authority,
			func([]byte) error { return nil },
		)
	}()

	close(cleanupStart)
	cleanupsDone := make(chan struct{})
	go func() {
		cleanups.Wait()
		close(cleanupsDone)
	}()
	// Consume is intentionally released after the competing discard/close
	// cleanup has claimed ownership. This pins the no-consume interleaving while
	// all three operations remain live and race-safe under -race.
	issue37WaitDone(t, cleanupsDone, "competing discard/close")
	close(consumeStart)
	allDone := make(chan struct{})
	go func() {
		operations.Wait()
		close(allDone)
	}()
	issue37WaitDone(t, allDone, "concurrent consume/discard/close")

	consumeCalls, discardCalls := probe.counts()
	if consumeCalls+discardCalls != 1 {
		t.Fatalf(
			"concurrent PIN terminal outcomes = consume:%d discard:%d, want exactly one",
			consumeCalls,
			discardCalls,
		)
	}
}

func TestIssue37WrongAuthorityCannotDiscardAnotherPINRegistration(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, nil)
	owner := &outboundAttemptAuthority{epoch: 37}
	wrong := &outboundAttemptAuthority{epoch: 38}
	probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, owner)

	hub.discardTransientPINForAuthority(pairingCandidateTestSKI, wrong)
	consumeCalls, discardCalls := probe.counts()
	if consumeCalls != 0 || discardCalls != 0 {
		t.Fatalf(
			"wrong authority reached inner PIN owner: consume:%d discard:%d",
			consumeCalls,
			discardCalls,
		)
	}
	hub.muxReg.Lock()
	registration, exists := hub.transientPINProviders[pairingCandidateTestSKI]
	hub.muxReg.Unlock()
	if !exists || registration.authority != owner {
		t.Fatal("wrong authority removed another PIN registration")
	}

	provided, err := hub.withTransientPINForAuthority(
		pairingCandidateTestSKI,
		owner,
		func([]byte) error { return nil },
	)
	if err != nil || !provided {
		t.Fatalf("owner consume after wrong discard = provided:%t err:%v", provided, err)
	}
}
