package hub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

type issue37TransientPINProbe struct {
	hub *Hub

	mu                     sync.Mutex
	consumeCalls           int
	discardCalls           int
	discardSawRegistration bool
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

func (probe *issue37TransientPINProbe) DiscardTransientPIN(remoteSKI string) {
	// A Hub cleanup must release its registration lock before calling an
	// untrusted owner. Re-entering the same lock makes a violation observable
	// as a bounded test timeout instead of inspecting mutex internals.
	probe.hub.muxReg.Lock()
	_, registrationVisible := probe.hub.transientPINProviders[remoteSKI]
	probe.hub.muxReg.Unlock()

	probe.mu.Lock()
	probe.discardCalls++
	probe.discardSawRegistration = probe.discardSawRegistration || registrationVisible
	probe.mu.Unlock()
}

func (probe *issue37TransientPINProbe) counts() (consume, discard int) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.consumeCalls, probe.discardCalls
}

func (probe *issue37TransientPINProbe) sawRegistrationDuringDiscard() bool {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return probe.discardSawRegistration
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

type issue37CleanupCase struct {
	name    string
	cleanup func(*testing.T, *Hub, string, *outboundAttemptAuthority) func()
}

func issue37RemainingCleanupCases() []issue37CleanupCase {
	return []issue37CleanupCase{
		{
			name: "pairing candidate retire",
			cleanup: func(
				_ *testing.T,
				hub *Hub,
				ski string,
				authority *outboundAttemptAuthority,
			) func() {
				service := hub.ServiceForSKI(ski)
				candidate := &activePairingCandidate{service: service, authority: authority}
				hub.muxReg.Lock()
				hub.activePairingCandidates[ski] = candidate
				hub.muxReg.Unlock()
				return func() { hub.retirePairingCandidate(ski, candidate, authority) }
			},
		},
		{
			name: "unregister remote",
			cleanup: func(
				_ *testing.T,
				hub *Hub,
				ski string,
				_ *outboundAttemptAuthority,
			) func() {
				return func() { hub.UnregisterRemoteSKI(ski) }
			},
		},
		{
			name: "cancel pairing",
			cleanup: func(
				_ *testing.T,
				hub *Hub,
				ski string,
				_ *outboundAttemptAuthority,
			) func() {
				return func() { hub.CancelPairingWithSKI(ski) }
			},
		},
		{
			name: "begin shutdown",
			cleanup: func(
				_ *testing.T,
				hub *Hub,
				_ string,
				_ *outboundAttemptAuthority,
			) func() {
				return func() {
					_, cancellations, _ := hub.beginShutdown()
					cancelOutboundAttemptRegistrations(cancellations)
				}
			},
		},
	}
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
			if probe.sawRegistrationDuringDiscard() {
				t.Fatal("inner discarder ran before atomic registration removal")
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
	if probe.sawRegistrationDuringDiscard() {
		t.Fatal("concurrent inner discarder observed a still-registered provider")
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

func TestIssue37EveryRemainingNoConsumeExitDiscardsInnerOwnerExactlyOnce(t *testing.T) {
	for _, cleanupCase := range issue37RemainingCleanupCases() {
		t.Run(cleanupCase.name, func(t *testing.T) {
			hub, _, _ := newPairingCandidateHub(t, nil)
			authority := &outboundAttemptAuthority{epoch: 37}
			probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, authority)
			cleanup := cleanupCase.cleanup(t, hub, pairingCandidateTestSKI, authority)

			done := make(chan struct{})
			go func() {
				cleanup()
				cleanup()
				close(done)
			}()
			issue37WaitDone(t, done, cleanupCase.name+" repeated cleanup")

			consumeCalls, discardCalls := probe.counts()
			if consumeCalls != 0 || discardCalls != 1 {
				t.Fatalf(
					"repeated cleanup PIN outcomes = consume:%d discard:%d, want 0/1",
					consumeCalls,
					discardCalls,
				)
			}
			if probe.sawRegistrationDuringDiscard() {
				t.Fatal("remaining cleanup called inner discarder before registration removal")
			}
		})
	}
}

func TestIssue37RemainingCleanupDoesNotDiscardConsumedRegistration(t *testing.T) {
	for _, cleanupCase := range issue37RemainingCleanupCases() {
		t.Run(cleanupCase.name, func(t *testing.T) {
			hub, _, _ := newPairingCandidateHub(t, nil)
			authority := &outboundAttemptAuthority{epoch: 37}
			probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, authority)
			cleanup := cleanupCase.cleanup(t, hub, pairingCandidateTestSKI, authority)

			provided, err := hub.withTransientPINForAuthority(
				pairingCandidateTestSKI,
				authority,
				func([]byte) error { return nil },
			)
			if err != nil || !provided {
				t.Fatalf("consume before cleanup = provided:%t err:%v", provided, err)
			}
			cleanup()

			consumeCalls, discardCalls := probe.counts()
			if consumeCalls != 1 || discardCalls != 0 {
				t.Fatalf(
					"consumed cleanup PIN outcomes = consume:%d discard:%d, want 1/0",
					consumeCalls,
					discardCalls,
				)
			}
		})
	}
}

func TestIssue37ShutdownAndTerminalCloseAvoidABBADedlockAndCleanExactlyOnce(t *testing.T) {
	hub, _, _ := newPairingCandidateHub(t, nil)
	authority := &outboundAttemptAuthority{epoch: 37}
	probe := issue37InstallTransientPIN(hub, pairingCandidateTestSKI, authority)
	closeAttempt := issue37InstallTerminalClose(t, hub, pairingCandidateTestSKI, authority)

	closeEntered := make(chan struct{})
	releaseClose := make(chan struct{})
	var barrierOnce sync.Once
	hub.testHooks.beforeOutboundAttemptRelease = func() {
		barrierOnce.Do(func() { close(closeEntered) })
		<-releaseClose
	}
	closeDone := make(chan struct{})
	go func() {
		closeAttempt()
		close(closeDone)
	}()
	issue37WaitDone(t, closeEntered, "terminal close lock barrier")

	shutdownDone := make(chan struct{})
	go func() {
		_, cancellations, _ := hub.beginShutdown()
		cancelOutboundAttemptRegistrations(cancellations)
		close(shutdownDone)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		hub.muxCon.Lock()
		shutdownClaimed := hub.hasShutdown
		hub.muxCon.Unlock()
		if shutdownClaimed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shutdown did not reach the ABBA barrier")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseClose)
	issue37WaitDone(t, closeDone, "terminal close after shutdown barrier")
	issue37WaitDone(t, shutdownDone, "shutdown after terminal close barrier")

	consumeCalls, discardCalls := probe.counts()
	if consumeCalls != 0 || discardCalls != 1 {
		t.Fatalf(
			"shutdown/terminal PIN outcomes = consume:%d discard:%d, want 0/1",
			consumeCalls,
			discardCalls,
		)
	}
	if probe.sawRegistrationDuringDiscard() {
		t.Fatal("shutdown/terminal discarder observed a registered provider")
	}
}
