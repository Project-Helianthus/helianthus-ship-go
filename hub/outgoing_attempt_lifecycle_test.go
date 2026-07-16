package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/gorilla/websocket"
)

var errReservationStillActive = errors.New("reservation still active")

type reservationState uint8

const (
	reservationPrepared reservationState = iota + 1
	reservationLaunchAuthorized
)

type durableReservation struct {
	handle   *attemptTestHandle
	request  api.OutgoingAttemptRequest
	metadata api.OutgoingAttemptMetadata
	state    reservationState
}

type durableReservationGateReader struct {
	*attemptAwareHubReader

	mu sync.Mutex

	sequence       int
	denyLaunch     bool
	active         map[string]*durableReservation
	requests       []api.OutgoingAttemptRequest
	terminals      []api.OutgoingAttemptMetadata
	terminalCounts map[string]int
	terminalSignal chan api.OutgoingAttemptMetadata
	panicTerminal  bool
}

func newDurableReservationGateReader() *durableReservationGateReader {
	return &durableReservationGateReader{
		attemptAwareHubReader: &attemptAwareHubReader{},
		active:                make(map[string]*durableReservation),
		terminalCounts:        make(map[string]int),
		terminalSignal:        make(chan api.OutgoingAttemptMetadata, 16),
	}
}

func (r *durableReservationGateReader) Prepare(request api.OutgoingAttemptRequest) (api.OutgoingAttemptHandle, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.active[request.RemoteSKI] != nil {
		return nil, errReservationStillActive
	}
	r.sequence++
	attemptContext, cancel := context.WithCancel(context.Background())
	handle := &attemptTestHandle{
		id:      fmt.Sprintf("durable-attempt-%d", r.sequence),
		scope:   "durable-scope",
		epoch:   91,
		context: attemptContext,
		cancel:  cancel,
	}
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    handle.id,
		Scope:        handle.scope,
		ControlEpoch: handle.epoch,
	}
	r.active[request.RemoteSKI] = &durableReservation{
		handle:   handle,
		request:  request,
		metadata: metadata,
		state:    reservationPrepared,
	}
	r.requests = append(r.requests, request)
	return handle, nil
}

func (r *durableReservationGateReader) AuthorizeLaunch(handle api.OutgoingAttemptHandle) (api.OutgoingAttemptPermit, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for remoteSKI, reservation := range r.active {
		if reservation.handle != handle || reservation.state != reservationPrepared {
			continue
		}
		if r.denyLaunch {
			reservation.handle.cancel()
			delete(r.active, remoteSKI)
			return api.OutgoingAttemptPermit{
				Decision: api.OutgoingAttemptDecisionDeny,
				Reason:   api.OutgoingAttemptReasonPolicyDenied,
			}, nil
		}
		reservation.state = reservationLaunchAuthorized
		return api.OutgoingAttemptPermit{
			Decision: api.OutgoingAttemptDecisionPermit,
			Reason:   api.OutgoingAttemptReasonAuthorized,
			Metadata: reservation.metadata,
			Context:  reservation.handle.context,
		}, nil
	}
	return api.OutgoingAttemptPermit{
		Decision: api.OutgoingAttemptDecisionDeny,
		Reason:   api.OutgoingAttemptReasonStaleHandle,
	}, nil
}

func (r *durableReservationGateReader) AbortPrepared(handle api.OutgoingAttemptHandle) (api.OutgoingAttemptAbortResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for remoteSKI, reservation := range r.active {
		if reservation.handle == handle && reservation.state == reservationPrepared {
			reservation.handle.cancel()
			delete(r.active, remoteSKI)
			return api.OutgoingAttemptAbortConsumed, nil
		}
	}
	return api.OutgoingAttemptAbortStaleNoOp, nil
}

func (r *durableReservationGateReader) OutgoingAttemptConnectionClosed(
	remoteSKI string,
	_ bool,
	metadata api.OutgoingAttemptMetadata,
) {
	if r.panicTerminal {
		panic("private terminal callback panic")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.terminals = append(r.terminals, metadata)
	r.terminalCounts[metadata.AttemptID]++
	reservation := r.active[remoteSKI]
	if reservation != nil && reservation.state == reservationLaunchAuthorized && reservation.metadata == metadata {
		reservation.handle.cancel()
		delete(r.active, remoteSKI)
	}
	r.terminalSignal <- metadata
}

func TestTerminalCallbackPanicSuppressesFallbackAndKeepsReservationForRecovery(t *testing.T) {
	model := newDurableReservationGateReader()
	model.panicTerminal = true
	dialer := &lifecycleDialer{outcomes: []scriptedDialOutcome{dialOutcomeError, dialOutcomeError}}
	hub := NewHub(model, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.dialer = dialer
	if err := hub.SetOutgoingAttemptGate(model); err != nil {
		t.Fatalf("install durable gate: %v", err)
	}

	err := hub.connectFoundService(hub.ServiceForSKI("remote-ski"), "peer.local", "4712", "/ship/")
	assertTypedAttemptDenial(t, err)
	requests, terminals, _, active := model.snapshotLifecycle()
	if len(requests) != 1 || len(terminals) != 0 || active != 1 || dialer.count() != 1 {
		t.Fatalf("prepare/terminal/active/dial = %d/%d/%d/%d, want 1/0/1/1", len(requests), len(terminals), active, dialer.count())
	}
}

func (r *durableReservationGateReader) snapshotLifecycle() (
	[]api.OutgoingAttemptRequest,
	[]api.OutgoingAttemptMetadata,
	map[string]int,
	int,
) {
	r.mu.Lock()
	defer r.mu.Unlock()

	counts := make(map[string]int, len(r.terminalCounts))
	for attemptID, count := range r.terminalCounts {
		counts[attemptID] = count
	}
	return append([]api.OutgoingAttemptRequest(nil), r.requests...),
		append([]api.OutgoingAttemptMetadata(nil), r.terminals...),
		counts,
		len(r.active)
}

type scriptedDialOutcome uint8

const (
	dialOutcomeError scriptedDialOutcome = iota + 1
	dialOutcomePanic
	dialOutcomeNil
)

type lifecycleDialer struct {
	mu       sync.Mutex
	outcomes []scriptedDialOutcome
	calls    int
}

func (d *lifecycleDialer) DialContext(context.Context, string, http.Header) (*websocket.Conn, *http.Response, error) {
	d.mu.Lock()
	index := d.calls
	d.calls++
	outcome := d.outcomes[index]
	d.mu.Unlock()

	switch outcome {
	case dialOutcomeError:
		return nil, nil, errAttemptTestDial
	case dialOutcomePanic:
		panic("private dial panic")
	case dialOutcomeNil:
		return nil, nil, nil
	default:
		panic("unexpected dial outcome")
	}
}

func (d *lifecycleDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func TestAuthorizedPreconstructionFailuresTerminalizeBeforeFallback(t *testing.T) {
	tests := []struct {
		name    string
		outcome scriptedDialOutcome
	}{
		{name: "dial error", outcome: dialOutcomeError},
		{name: "dial panic", outcome: dialOutcomePanic},
		{name: "nil connection", outcome: dialOutcomeNil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := newDurableReservationGateReader()
			dialer := &lifecycleDialer{outcomes: []scriptedDialOutcome{test.outcome, test.outcome}}
			hub := NewHub(model, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
			hub.dialer = dialer
			if err := hub.SetOutgoingAttemptGate(model); err != nil {
				t.Fatalf("install durable gate: %v", err)
			}
			remote := hub.ServiceForSKI("remote-ski")

			err := hub.connectFoundService(remote, "peer.local", "4712", "/ship/")
			if err == nil || isOutgoingAttemptDenied(err) {
				t.Fatalf("authorized failure = %T %v, want ordinary terminal failure", err, err)
			}

			requests, terminals, counts, active := model.snapshotLifecycle()
			if len(requests) != 2 || requests[0].Path != "/ship/" || requests[1].Path != "" {
				t.Fatalf("reservation paths = %#v, want selected then root fallback", requests)
			}
			if dialer.count() != 2 || len(terminals) != 2 || active != 0 {
				t.Fatalf("dial/terminal/active = %d/%d/%d, want 2/2/0", dialer.count(), len(terminals), active)
			}
			if terminals[0].AttemptID == terminals[1].AttemptID {
				t.Fatalf("fallback overwrote or reused attempt metadata: %#v", terminals)
			}
			for _, terminal := range terminals {
				if counts[terminal.AttemptID] != 1 {
					t.Errorf("terminal callback count for %q = %d, want exactly one", terminal.AttemptID, counts[terminal.AttemptID])
				}
			}
		})
	}
}

func TestDeniedUnlaunchedReservationDoesNotInventTerminalResult(t *testing.T) {
	model := newDurableReservationGateReader()
	model.denyLaunch = true
	dialer := &lifecycleDialer{outcomes: []scriptedDialOutcome{dialOutcomeError}}
	hub := NewHub(model, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.dialer = dialer
	if err := hub.SetOutgoingAttemptGate(model); err != nil {
		t.Fatalf("install durable gate: %v", err)
	}

	err := hub.connectFoundService(hub.ServiceForSKI("remote-ski"), "peer.local", "4712", "/ship/")
	assertTypedAttemptDenial(t, err)
	requests, terminals, _, active := model.snapshotLifecycle()
	if len(requests) != 1 || len(terminals) != 0 || active != 0 || dialer.count() != 0 {
		t.Fatalf("prepare/terminal/active/dial = %d/%d/%d/%d, want 1/0/0/0", len(requests), len(terminals), active, dialer.count())
	}
}

func TestAuthorizedFailuresTerminalizeBeforeEndpointFallback(t *testing.T) {
	lifecycle := newDurableReservationGateReader()
	dialer := &lifecycleDialer{outcomes: []scriptedDialOutcome{
		dialOutcomeError,
		dialOutcomeError,
		dialOutcomeError,
		dialOutcomeError,
		dialOutcomeError,
		dialOutcomeError,
	}}
	hub := NewHub(lifecycle, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.dialer = dialer
	if err := hub.SetOutgoingAttemptGate(lifecycle); err != nil {
		t.Fatalf("install durable gate: %v", err)
	}
	remote := hub.ServiceForSKI("remote-ski")
	remote.SetTrusted(true)

	success, err := hub.initateConnectionWithError(remote, attemptTestEntry())
	if success || !errors.Is(err, errAttemptTestDial) {
		t.Fatalf("endpoint fallback result = success:%t error:%v", success, err)
	}
	requests, terminals, counts, active := lifecycle.snapshotLifecycle()
	wantHosts := []string{
		"peer.local", "peer.local",
		"192.0.2.10", "192.0.2.10",
		"2001:db8::10", "2001:db8::10",
	}
	wantPaths := []string{"/ship/", "", "/ship/", "", "/ship/", ""}
	if len(requests) != len(wantHosts) || len(terminals) != len(wantHosts) || dialer.count() != len(wantHosts) || active != 0 {
		t.Fatalf("prepare/terminal/dial/active = %d/%d/%d/%d, want 6/6/6/0", len(requests), len(terminals), dialer.count(), active)
	}
	for index := range wantHosts {
		if requests[index].Endpoint.Host != wantHosts[index] || requests[index].Path != wantPaths[index] {
			t.Errorf("request %d = %#v, want host=%q path=%q", index, requests[index], wantHosts[index], wantPaths[index])
		}
		if terminals[index].AttemptID == "" || counts[terminals[index].AttemptID] != 1 {
			t.Errorf("terminal %d = %#v count=%d, want one exact callback", index, terminals[index], counts[terminals[index].AttemptID])
		}
	}
}
