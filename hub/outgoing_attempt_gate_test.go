package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/gorilla/websocket"
)

var (
	errAttemptTestDial = errors.New("fake peer rejected the dial")
	errPrivateGate     = errors.New("private gate failure detail")
)

type gateMode uint8

const (
	gatePermit gateMode = iota
	gatePrepareError
	gatePreparePanic
	gatePrepareNoHandle
	gatePrepareTypedNil
	gateAuthorizeDeny
	gateAuthorizeError
	gateAuthorizePanic
	gateAuthorizeZeroPermit
	gateAuthorizeNilContext
	gateAuthorizeWrongMetadata
	gateCancelBeforePermit
	gateStaleHandle
	gateReuseHandle
	gateCopyHandle
)

type attemptTestHandle struct {
	id      string
	scope   string
	epoch   uint64
	context context.Context
	cancel  context.CancelFunc
}

func (h *attemptTestHandle) AttemptID() string        { return h.id }
func (h *attemptTestHandle) Scope() string            { return h.scope }
func (h *attemptTestHandle) ControlEpoch() uint64     { return h.epoch }
func (h *attemptTestHandle) Context() context.Context { return h.context }

type scriptedAttemptGate struct {
	mu sync.Mutex

	mode             gateMode
	sequence         int
	shared           *attemptTestHandle
	latest           *attemptTestHandle
	requests         []api.OutgoingAttemptRequest
	authorized       []api.OutgoingAttemptHandle
	permits          []api.OutgoingAttemptPermit
	aborted          []api.OutgoingAttemptHandle
	consumed         map[string]bool
	authorizeEntered chan struct{}
	authorizeRelease chan struct{}
	authorizeOnce    sync.Once
}

func newScriptedAttemptGate(mode gateMode) *scriptedAttemptGate {
	return &scriptedAttemptGate{mode: mode, consumed: make(map[string]bool)}
}

func (g *scriptedAttemptGate) Prepare(request api.OutgoingAttemptRequest) (api.OutgoingAttemptHandle, error) {
	g.mu.Lock()
	g.requests = append(g.requests, request)
	g.sequence++
	sequence := g.sequence

	switch g.mode {
	case gatePrepareError:
		g.mu.Unlock()
		return nil, errPrivateGate
	case gatePreparePanic:
		g.mu.Unlock()
		panic("private prepare panic detail")
	case gatePrepareNoHandle:
		g.mu.Unlock()
		return nil, nil
	case gatePrepareTypedNil:
		g.mu.Unlock()
		var handle *attemptTestHandle
		return handle, nil
	}

	var handle *attemptTestHandle
	if (g.mode == gateReuseHandle || g.mode == gateCopyHandle) && g.shared != nil {
		if g.mode == gateReuseHandle {
			handle = g.shared
		} else {
			copied := *g.shared
			handle = &copied
		}
	} else {
		ctx, cancel := context.WithCancel(context.Background())
		handle = &attemptTestHandle{
			id:      fmt.Sprintf("attempt-%d", sequence),
			scope:   "remote-scope",
			epoch:   17,
			context: ctx,
			cancel:  cancel,
		}
		if g.mode == gateReuseHandle || g.mode == gateCopyHandle {
			g.shared = handle
		}
	}
	if g.mode == gateStaleHandle {
		g.consumed[handle.id] = true
	}
	g.latest = handle
	g.mu.Unlock()
	return handle, nil
}

func (g *scriptedAttemptGate) AuthorizeLaunch(handle api.OutgoingAttemptHandle) (api.OutgoingAttemptPermit, error) {
	g.mu.Lock()
	g.authorized = append(g.authorized, handle)
	entered := g.authorizeEntered
	release := g.authorizeRelease
	g.mu.Unlock()

	if entered != nil {
		g.authorizeOnce.Do(func() { close(entered) })
	}
	if release != nil {
		<-release
	}

	switch g.mode {
	case gateAuthorizeError:
		return api.OutgoingAttemptPermit{}, errPrivateGate
	case gateAuthorizePanic:
		panic("private authorize panic detail")
	case gateAuthorizeZeroPermit:
		return api.OutgoingAttemptPermit{}, nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if handle == nil || g.consumed[handle.AttemptID()] || handle.Context().Err() != nil || g.mode == gateAuthorizeDeny {
		permit := api.OutgoingAttemptPermit{
			Decision: api.OutgoingAttemptDecisionDeny,
			Reason:   api.OutgoingAttemptReasonPolicyDenied,
		}
		if handle != nil && g.consumed[handle.AttemptID()] {
			permit.Reason = api.OutgoingAttemptReasonStaleHandle
		}
		if handle != nil {
			g.consumed[handle.AttemptID()] = true
		}
		g.permits = append(g.permits, permit)
		return permit, nil
	}

	g.consumed[handle.AttemptID()] = true
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    handle.AttemptID(),
		Scope:        handle.Scope(),
		ControlEpoch: handle.ControlEpoch(),
	}
	permitContext := handle.Context()
	if g.mode == gateAuthorizeNilContext {
		permitContext = nil
	}
	if g.mode == gateAuthorizeWrongMetadata {
		metadata.AttemptID = "different-attempt"
	}
	if g.mode == gateCancelBeforePermit {
		g.latest.cancel()
	}
	permit := api.OutgoingAttemptPermit{
		Decision: api.OutgoingAttemptDecisionPermit,
		Reason:   api.OutgoingAttemptReasonAuthorized,
		Metadata: metadata,
		Context:  permitContext,
	}
	g.permits = append(g.permits, permit)
	return permit, nil
}

func (g *scriptedAttemptGate) AbortPrepared(handle api.OutgoingAttemptHandle) (api.OutgoingAttemptAbortResult, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if handle == nil || g.consumed[handle.AttemptID()] {
		return api.OutgoingAttemptAbortStaleNoOp, nil
	}
	g.consumed[handle.AttemptID()] = true
	g.aborted = append(g.aborted, handle)
	return api.OutgoingAttemptAbortConsumed, nil
}

func (g *scriptedAttemptGate) snapshot() ([]api.OutgoingAttemptRequest, []api.OutgoingAttemptHandle, []api.OutgoingAttemptPermit, []api.OutgoingAttemptHandle) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]api.OutgoingAttemptRequest(nil), g.requests...),
		append([]api.OutgoingAttemptHandle(nil), g.authorized...),
		append([]api.OutgoingAttemptPermit(nil), g.permits...),
		append([]api.OutgoingAttemptHandle(nil), g.aborted...)
}

type dialObservation struct {
	context context.Context
	url     string
}

type fakePeerDialer struct {
	mu sync.Mutex

	calls               []dialObservation
	peerEffects         int
	err                 error
	connection          *websocket.Conn
	started             chan struct{}
	startedOnce         sync.Once
	waitForCancellation bool
	release             <-chan struct{}
}

func (d *fakePeerDialer) DialContext(ctx context.Context, url string, _ http.Header) (*websocket.Conn, *http.Response, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dialObservation{context: ctx, url: url})
	d.mu.Unlock()
	if d.started != nil {
		d.startedOnce.Do(func() { close(d.started) })
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if d.waitForCancellation {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-d.release:
			return nil, nil, d.err
		}
	}
	d.mu.Lock()
	d.peerEffects++
	d.mu.Unlock()
	return d.connection, nil, d.err
}

func (d *fakePeerDialer) snapshot() ([]dialObservation, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialObservation(nil), d.calls...), d.peerEffects
}

type attemptTestMdns struct {
	mu       sync.Mutex
	announce int
	request  int
}

func (m *attemptTestMdns) Start(api.MdnsReportInterface) error { return nil }
func (m *attemptTestMdns) Shutdown()                           {}
func (m *attemptTestMdns) UnannounceMdnsEntry()                {}
func (m *attemptTestMdns) SetAutoAccept(bool)                  {}
func (m *attemptTestMdns) AnnounceMdnsEntry() error {
	m.mu.Lock()
	m.announce++
	m.mu.Unlock()
	return nil
}
func (m *attemptTestMdns) RequestMdnsEntries() {
	m.mu.Lock()
	m.request++
	m.mu.Unlock()
}
func (m *attemptTestMdns) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.announce, m.request
}

type attemptTestHubReader struct{}

func (*attemptTestHubReader) RemoteSKIConnected(string)    {}
func (*attemptTestHubReader) RemoteSKIDisconnected(string) {}
func (*attemptTestHubReader) SetupRemoteDevice(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
	return nil
}
func (*attemptTestHubReader) VisibleRemoteServicesUpdated([]api.RemoteService) {}
func (*attemptTestHubReader) ServiceShipIDUpdate(string, string)               {}
func (*attemptTestHubReader) ServicePairingDetailUpdate(string, *api.ConnectionStateDetail) {
}
func (*attemptTestHubReader) AllowWaitingForTrust(string) bool { return false }

type attemptAwareGateTestHubReader struct{ attemptTestHubReader }

func (*attemptAwareGateTestHubReader) OutgoingAttemptConnectionClosed(string, bool, api.OutgoingAttemptMetadata) {
}
func (*attemptAwareGateTestHubReader) OutgoingAttemptHandshakeStateUpdate(string, model.ShipState, api.OutgoingAttemptMetadata) {
}

func TestOutgoingAttemptGateDenialsFailClosed(t *testing.T) {
	tests := []struct {
		name          string
		mode          gateMode
		wantAuthorize int
		wantAbort     int
	}{
		{name: "prepare error", mode: gatePrepareError},
		{name: "prepare panic", mode: gatePreparePanic},
		{name: "missing handle ambiguity", mode: gatePrepareNoHandle},
		{name: "typed nil handle ambiguity", mode: gatePrepareTypedNil},
		{name: "authorize denial", mode: gateAuthorizeDeny, wantAuthorize: 1},
		{name: "authorize error", mode: gateAuthorizeError, wantAuthorize: 1, wantAbort: 1},
		{name: "authorize panic", mode: gateAuthorizePanic, wantAuthorize: 1, wantAbort: 1},
		{name: "zero permit ambiguity", mode: gateAuthorizeZeroPermit, wantAuthorize: 1, wantAbort: 1},
		{name: "nil permit context", mode: gateAuthorizeNilContext, wantAuthorize: 1},
		{name: "mismatched permit metadata", mode: gateAuthorizeWrongMetadata, wantAuthorize: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(test.mode)
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, _, remote := newAttemptTestHub(t, gate, dialer)

			err := hub.connectFoundService(remote, "private-peer.local", "4712", "/private-path")
			assertTypedAttemptDenial(t, err)
			for _, privateValue := range []string{"private-peer.local", "/private-path", errPrivateGate.Error(), "panic detail"} {
				if strings.Contains(err.Error(), privateValue) {
					t.Errorf("denial error leaks private value %q: %v", privateValue, err)
				}
			}

			requests, authorized, _, aborted := gate.snapshot()
			calls, peerEffects := dialer.snapshot()
			if len(requests) != 1 || len(authorized) != test.wantAuthorize || len(aborted) != test.wantAbort {
				t.Errorf("gate counts prepare/authorize/abort = %d/%d/%d, want 1/%d/%d", len(requests), len(authorized), len(aborted), test.wantAuthorize, test.wantAbort)
			}
			if len(calls) != 0 || peerEffects != 0 {
				t.Errorf("denied attempt reached dialer/peer = %d/%d, want zero/zero", len(calls), peerEffects)
			}
		})
	}
}

func TestOutgoingAttemptGateSetterRejectsTypedNil(t *testing.T) {
	hub, _, _ := newAttemptTestHub(t, nil, &fakePeerDialer{err: errAttemptTestDial})
	setter, ok := any(hub).(api.OutgoingAttemptGateSetter)
	if !ok {
		t.Fatal("hub does not expose the optional outgoing attempt gate setter")
	}

	var typedNil *scriptedAttemptGate
	if err := setter.SetOutgoingAttemptGate(typedNil); !errors.Is(err, api.ErrInvalidOutgoingAttemptGate) {
		t.Fatalf("typed-nil installation error = %v, want %v", err, api.ErrInvalidOutgoingAttemptGate)
	}
	if hub.configuredOutgoingAttemptGate() != nil {
		t.Fatal("typed-nil installation changed the configured gate")
	}

	valid := newScriptedAttemptGate(gatePermit)
	if err := setter.SetOutgoingAttemptGate(valid); err != nil {
		t.Fatalf("install valid gate: %v", err)
	}
	if err := setter.SetOutgoingAttemptGate(typedNil); !errors.Is(err, api.ErrInvalidOutgoingAttemptGate) {
		t.Fatalf("typed-nil replacement error = %v, want %v", err, api.ErrInvalidOutgoingAttemptGate)
	}
	if got := hub.configuredOutgoingAttemptGate(); got != valid {
		t.Fatal("typed-nil replacement displaced the valid gate")
	}
	if err := setter.SetOutgoingAttemptGate(nil); err != nil {
		t.Fatalf("remove optional gate: %v", err)
	}
	if hub.configuredOutgoingAttemptGate() != nil {
		t.Fatal("nil removal left a configured gate")
	}
}

func TestOutgoingAttemptGateSetterRejectsReaderWithoutAttemptCallbacks(t *testing.T) {
	hub := NewHub(&attemptTestHubReader{}, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	gate := newScriptedAttemptGate(gatePermit)

	if err := hub.SetOutgoingAttemptGate(gate); !errors.Is(err, api.ErrInvalidOutgoingAttemptGate) {
		t.Fatalf("legacy-only reader installation error = %v, want %v", err, api.ErrInvalidOutgoingAttemptGate)
	}
	if hub.configuredOutgoingAttemptGate() != nil {
		t.Fatal("legacy-only reader installation changed the configured gate")
	}
}

func TestTypedDenialSuppressesAddressRetryAndAutoReannounce(t *testing.T) {
	tests := []struct {
		name string
		mode gateMode
	}{
		{name: "prepare error", mode: gatePrepareError},
		{name: "prepare panic", mode: gatePreparePanic},
		{name: "missing handle", mode: gatePrepareNoHandle},
		{name: "typed nil handle", mode: gatePrepareTypedNil},
		{name: "authorize denial", mode: gateAuthorizeDeny},
		{name: "authorize error", mode: gateAuthorizeError},
		{name: "authorize panic", mode: gateAuthorizePanic},
		{name: "zero permit", mode: gateAuthorizeZeroPermit},
		{name: "nil permit context", mode: gateAuthorizeNilContext},
		{name: "mismatched metadata", mode: gateAuthorizeWrongMetadata},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(test.mode)
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, mdns, remote := newAttemptTestHub(t, gate, dialer)
			entry := attemptTestEntry()
			prepareAttemptTestService(hub, remote, entry)

			hub.prepareConnectionInitation(remote.SKI(), 0, entry)

			requests, _, _, _ := gate.snapshot()
			calls, peerEffects := dialer.snapshot()
			announce, requested := mdns.counts()
			if len(requests) != 1 {
				t.Fatalf("typed denial prepared %d path/address attempts, want one", len(requests))
			}
			if len(calls) != 0 || peerEffects != 0 || announce != 0 || requested != 0 {
				t.Fatalf("typed denial effects dial/peer/announce/request = %d/%d/%d/%d, want all zero", len(calls), peerEffects, announce, requested)
			}
		})
	}
}

func TestAuthorizedAttemptsGateEveryPathAndEndpointFallback(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, mdns, remote := newAttemptTestHub(t, gate, dialer)
	entry := attemptTestEntry()
	prepareAttemptTestService(hub, remote, entry)

	hub.prepareConnectionInitation(remote.SKI(), 0, entry)

	requests, authorized, permits, aborted := gate.snapshot()
	calls, peerEffects := dialer.snapshot()
	announce, requested := mdns.counts()
	want := []struct {
		host string
		path string
		url  string
	}{
		{host: "peer.local", path: "/ship/", url: "wss://peer.local:4712/ship/"},
		{host: "peer.local", path: "", url: "wss://peer.local:4712"},
		{host: "192.0.2.10", path: "/ship/", url: "wss://192.0.2.10:4712/ship/"},
		{host: "192.0.2.10", path: "", url: "wss://192.0.2.10:4712"},
		{host: "2001:db8::10", path: "/ship/", url: "wss://[2001:db8::10]:4712/ship/"},
		{host: "2001:db8::10", path: "", url: "wss://[2001:db8::10]:4712"},
	}
	if len(requests) != len(want) || len(authorized) != len(want) || len(permits) != len(want) || len(calls) != len(want) {
		t.Fatalf("prepare/authorize/permit/dial = %d/%d/%d/%d, want %d each", len(requests), len(authorized), len(permits), len(calls), len(want))
	}
	seenAttempts := make(map[string]bool)
	for index, expected := range want {
		request := requests[index]
		if request.RemoteSKI != remote.SKI() || request.Endpoint.Host != expected.host || request.Endpoint.Port != 4712 || request.Path != expected.path {
			t.Errorf("request %d = %#v, want ski=%q host=%q port=4712 path=%q", index, request, remote.SKI(), expected.host, expected.path)
		}
		if calls[index].url != expected.url {
			t.Errorf("dial %d URL = %q, want %q", index, calls[index].url, expected.url)
		}
		if permits[index].Decision != api.OutgoingAttemptDecisionPermit || permits[index].Context != calls[index].context {
			t.Errorf("dial %d did not receive its exact permit context", index)
		}
		attemptID := permits[index].Metadata.AttemptID
		if attemptID == "" || seenAttempts[attemptID] {
			t.Errorf("attempt %d reused or omitted identity %q", index, attemptID)
		}
		seenAttempts[attemptID] = true
	}
	if len(aborted) != 0 {
		t.Errorf("launched attempts were aborted: %d", len(aborted))
	}
	if peerEffects != len(want) || announce != 1 || requested != 1 {
		t.Errorf("ordinary dial failure effects peer/announce/request = %d/%d/%d, want %d/1/1", peerEffects, announce, requested, len(want))
	}
}

func TestNoGatePreservesUpstreamRetryFallbackAndReannounce(t *testing.T) {
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, mdns, remote := newAttemptTestHub(t, nil, dialer)
	entry := attemptTestEntry()
	prepareAttemptTestService(hub, remote, entry)

	hub.prepareConnectionInitation(remote.SKI(), 0, entry)

	calls, peerEffects := dialer.snapshot()
	announce, requested := mdns.counts()
	wantURLs := []string{
		"wss://peer.local:4712/ship/", "wss://peer.local:4712",
		"wss://192.0.2.10:4712/ship/", "wss://192.0.2.10:4712",
		"wss://[2001:db8::10]:4712/ship/", "wss://[2001:db8::10]:4712",
	}
	if len(calls) != len(wantURLs) {
		t.Fatalf("ungated dial count = %d, want %d", len(calls), len(wantURLs))
	}
	for index, want := range wantURLs {
		if calls[index].url != want {
			t.Errorf("ungated dial %d = %q, want %q", index, calls[index].url, want)
		}
		if calls[index].context == nil {
			t.Errorf("ungated dial %d received nil context", index)
		}
	}
	if peerEffects != len(wantURLs) || announce != 1 || requested != 1 {
		t.Errorf("ungated peer/announce/request = %d/%d/%d, want %d/1/1", peerEffects, announce, requested, len(wantURLs))
	}
}

func TestNoGatePreservesUpstreamRawIPv6URLConstruction(t *testing.T) {
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, _, remote := newAttemptTestHub(t, nil, dialer)

	err := hub.connectFoundService(remote, "2001:db8::77", "4712", "/ship/")
	if !errors.Is(err, errAttemptTestDial) {
		t.Fatalf("ungated IPv6 error = %v, want %v", err, errAttemptTestDial)
	}
	calls, _ := dialer.snapshot()
	want := []string{
		"wss://2001:db8::77:4712/ship/",
		"wss://2001:db8::77:4712",
	}
	if len(calls) != len(want) {
		t.Fatalf("ungated raw IPv6 dial count = %d, want %d", len(calls), len(want))
	}
	for index := range want {
		if calls[index].url != want[index] {
			t.Errorf("ungated raw IPv6 URL %d = %q, want upstream %q", index, calls[index].url, want[index])
		}
	}
}

func TestPreparedHandlesAreSingleUseAcrossFallback(t *testing.T) {
	tests := []struct {
		name         string
		mode         gateMode
		wantPrepare  int
		wantDialCall int
	}{
		{name: "already stale", mode: gateStaleHandle, wantPrepare: 1},
		{name: "same handle reused", mode: gateReuseHandle, wantPrepare: 2, wantDialCall: 1},
		{name: "copied handle reused", mode: gateCopyHandle, wantPrepare: 2, wantDialCall: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(test.mode)
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, _, remote := newAttemptTestHub(t, gate, dialer)

			err := hub.connectFoundService(remote, "peer.local", "4712", "/ship/")
			assertTypedAttemptDenial(t, err)
			requests, authorized, _, aborted := gate.snapshot()
			calls, _ := dialer.snapshot()
			if len(requests) != test.wantPrepare || len(authorized) != test.wantPrepare || len(calls) != test.wantDialCall {
				t.Errorf("prepare/authorize/dial = %d/%d/%d, want %d/%d/%d", len(requests), len(authorized), len(calls), test.wantPrepare, test.wantPrepare, test.wantDialCall)
			}
			if len(aborted) != 0 {
				t.Errorf("stale, copied, or launched handle was aborted: %d", len(aborted))
			}
		})
	}
}

func TestAbortPreparedOnlyCleansUnlaunchedReservation(t *testing.T) {
	t.Run("authorize panic aborts once and never dials", func(t *testing.T) {
		gate := newScriptedAttemptGate(gateAuthorizePanic)
		dialer := &fakePeerDialer{err: errAttemptTestDial}
		hub, _, remote := newAttemptTestHub(t, gate, dialer)

		_, _, _, err := hub.gatedDialContext(remote, "peer.local", "4712", "/ship/")
		assertTypedAttemptDenial(t, err)
		_, _, _, aborted := gate.snapshot()
		calls, peerEffects := dialer.snapshot()
		if len(aborted) != 1 || len(calls) != 0 || peerEffects != 0 {
			t.Fatalf("abort/dial/peer = %d/%d/%d, want 1/0/0", len(aborted), len(calls), peerEffects)
		}
	})

	t.Run("launched dial failure is never aborted", func(t *testing.T) {
		gate := newScriptedAttemptGate(gatePermit)
		dialer := &fakePeerDialer{err: errAttemptTestDial}
		hub, _, remote := newAttemptTestHub(t, gate, dialer)

		_, _, attempt, err := hub.gatedDialContext(remote, "peer.local", "4712", "/ship/")
		if !errors.Is(err, errAttemptTestDial) {
			t.Fatalf("dial error = %v, want %v", err, errAttemptTestDial)
		}
		_, _, permits, aborted := gate.snapshot()
		if len(permits) != 1 || attempt == nil || attempt.metadata != permits[0].Metadata {
			t.Fatalf("helper attempt = %#v, permit metadata = %#v", attempt, permits)
		}
		calls, peerEffects := dialer.snapshot()
		if len(aborted) != 0 || len(calls) != 1 || peerEffects != 1 {
			t.Fatalf("abort/dial/peer = %d/%d/%d, want 0/1/1", len(aborted), len(calls), peerEffects)
		}
	})
}

func TestCanceledPermitContextPreventsPeerEffect(t *testing.T) {
	gate := newScriptedAttemptGate(gateCancelBeforePermit)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, _, remote := newAttemptTestHub(t, gate, dialer)

	err := hub.connectFoundService(remote, "peer.local", "4712", "/ship/")
	assertTypedAttemptDenial(t, err)
	_, _, permits, _ := gate.snapshot()
	calls, peerEffects := dialer.snapshot()
	if len(permits) != 1 || len(calls) != 1 {
		t.Fatalf("permit/dial = %d/%d, want 1/1", len(permits), len(calls))
	}
	if permits[0].Context.Err() == nil || calls[0].context.Err() == nil {
		t.Fatal("DialContext did not receive an already-canceled attempt context")
	}
	if peerEffects != 0 {
		t.Fatalf("already-canceled context reached fake peer %d times, want zero", peerEffects)
	}
}

func TestHubUnregisterRechecksTrustedAttemptImmediatelyBeforeDial(t *testing.T) {
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
	remote.SetTrusted(true)
	result := make(chan error, 1)
	go func() {
		_, _, _, err := hub.gatedDialContext(remote, "peer.local", "4712", "/ship/")
		result <- err
	}()

	waitForSignal(t, gate.authorizeEntered)
	invalidationDone := make(chan struct{})
	go func() {
		hub.UnregisterRemoteSKI(remote.SKI())
		close(invalidationDone)
	}()
	select {
	case <-invalidationDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Hub cancellation API blocked while launch authorization was paused")
	}
	close(gate.authorizeRelease)
	err := waitForError(t, result)
	calls, peerEffects := dialer.snapshot()
	if len(calls) != 0 || peerEffects != 0 {
		t.Fatalf("invalidated trusted attempt reached dialer/peer = %d/%d, want zero/zero", len(calls), peerEffects)
	}
	assertTypedAttemptDenial(t, err)
}

func TestHubUnregisterInterruptsContextBlockedGatedDialWithoutDeadlock(t *testing.T) {
	const remoteSKI = "13579bdf2468ace013579bdf2468ace013579bdf"
	attemptKinds := []struct {
		name  string
		admit func(*testing.T, *Hub, *api.ServiceDetails)
	}{
		{
			name: "queued pairing",
			admit: func(t *testing.T, hub *Hub, _ *api.ServiceDetails) {
				t.Helper()
				if err := hub.QueueRemoteSKI(remoteSKI); err != nil {
					t.Fatalf("queue synthetic remote: %v", err)
				}
			},
		},
		{
			name: "trusted reconnect",
			admit: func(_ *testing.T, _ *Hub, remote *api.ServiceDetails) {
				remote.SetTrusted(true)
			},
		},
	}
	for _, attemptKind := range attemptKinds {
		t.Run(attemptKind.name, func(t *testing.T) {
			release := make(chan struct{})
			t.Cleanup(func() {
				select {
				case <-release:
				default:
					close(release)
				}
			})
			gate := newScriptedAttemptGate(gatePermit)
			dialer := &fakePeerDialer{
				err:                 errAttemptTestDial,
				started:             make(chan struct{}),
				waitForCancellation: true,
				release:             release,
			}
			hub, _, _ := newAttemptTestHub(t, gate, dialer)
			remote := hub.ServiceForSKI(remoteSKI)
			attemptKind.admit(t, hub, remote)
			result := make(chan error, 1)
			go func() {
				_, _, _, err := hub.gatedDialContext(remote, "peer.local", "4712", "/ship/")
				result <- err
			}()

			waitForSignal(t, dialer.started)
			invalidationDone := make(chan struct{})
			go func() {
				hub.UnregisterRemoteSKI(remoteSKI)
				close(invalidationDone)
			}()
			select {
			case <-invalidationDone:
			case <-time.After(2 * time.Second):
				t.Fatal("Hub cancellation API blocked while DialContext was running; admission lock may be held across DialContext")
			}

			var err error
			select {
			case err = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("context-blocked DialContext did not observe Hub-owned cancellation")
			}
			assertTypedAttemptDenial(t, err)
			calls, peerEffects := dialer.snapshot()
			if len(calls) != 1 {
				t.Fatalf("canceled dial calls = %d, want 1", len(calls))
			}
			if calls[0].context.Err() == nil || peerEffects != 0 {
				t.Fatalf("canceled dial context/peer = %v/%d, want canceled/0", calls[0].context.Err(), peerEffects)
			}
		})
	}
}

func TestTrustedReconnectStillDialsWhenNotInvalidated(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	wantConnection := &websocket.Conn{}
	dialer := &fakePeerDialer{connection: wantConnection}
	hub, _, remote := newAttemptTestHub(t, gate, dialer)
	remote.SetTrusted(true)

	connection, _, attempt, err := hub.gatedDialContext(remote, "peer.local", "4712", "/ship/")
	if err != nil {
		t.Fatalf("non-revoked trusted reconnect: %v", err)
	}
	if connection != wantConnection || attempt == nil {
		t.Fatalf("trusted reconnect connection/attempt = %p/%#v, want %p/authorized attempt", connection, attempt, wantConnection)
	}
	calls, peerEffects := dialer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("trusted reconnect dials = %d, want 1", len(calls))
	}
	if calls[0].context.Err() != nil || peerEffects != 1 {
		t.Fatalf("trusted reconnect context/peer = %v/%d, want active/1", calls[0].context.Err(), peerEffects)
	}
}

func newAttemptTestHub(t *testing.T, gate api.OutgoingAttemptGate, dialer *fakePeerDialer) (*Hub, *attemptTestMdns, *api.ServiceDetails) {
	t.Helper()
	mdns := &attemptTestMdns{}
	hub := NewHub(&attemptAwareGateTestHubReader{}, mdns, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.dialer = dialer
	if gate != nil {
		if err := hub.SetOutgoingAttemptGate(gate); err != nil {
			t.Fatalf("install outgoing attempt gate: %v", err)
		}
	}
	remote := hub.ServiceForSKI("remote-ski")
	return hub, mdns, remote
}

func prepareAttemptTestService(hub *Hub, remote *api.ServiceDetails, entry *api.MdnsEntry) {
	remote.SetTrusted(true)
	remote.ConnectionStateDetail().SetState(api.ConnectionStateNone)
	hub.connectionAttemptCounter[remote.SKI()] = 0
	entry.Ski = remote.SKI()
}

func attemptTestEntry() *api.MdnsEntry {
	return &api.MdnsEntry{
		Host:      "peer.local",
		Port:      4712,
		Path:      "/ship/",
		Addresses: []net.IP{net.ParseIP("2001:db8::10"), net.ParseIP("192.0.2.10")},
	}
}

type attemptDenial interface {
	error
	AttemptDenied() bool
}

func assertTypedAttemptDenial(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("attempt unexpectedly succeeded")
	}
	var denial attemptDenial
	if !errors.As(err, &denial) || !denial.AttemptDenied() {
		t.Fatalf("error %T %v is not a typed attempt denial", err, err)
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for synchronization point")
	}
}

func waitForError(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for attempt result")
		return nil
	}
}
