package hub

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/Project-Helianthus/helianthus-ship-go/ship"
	"github.com/gorilla/websocket"
)

type acceptedShipMessage struct {
	messageType int
	payload     []byte
	err         error
}

type localShipPeer struct {
	server    *httptest.Server
	host      string
	port      string
	remoteSKI string
	accepted  chan struct{}
	messages  chan acceptedShipMessage
	release   chan struct{}
	once      sync.Once
}

type reconnectingShipSession struct {
	connection *websocket.Conn
	message    chan acceptedShipMessage
	release    chan struct{}
	once       sync.Once
}

func (s *reconnectingShipSession) close() {
	s.once.Do(func() {
		close(s.release)
		_ = s.connection.Close()
	})
}

type reconnectingLocalShipPeer struct {
	server    *httptest.Server
	host      string
	port      int
	remoteSKI string
	sessions  chan *reconnectingShipSession
	mu        sync.Mutex
	active    map[*reconnectingShipSession]struct{}
	once      sync.Once
}

func newReconnectingLocalShipPeer(t *testing.T) (*reconnectingLocalShipPeer, tls.Certificate) {
	t.Helper()
	serverCertificate, err := cert.CreateCertificate("test-unit", "test-org", "DE", "reconnecting-peer")
	if err != nil {
		t.Fatalf("create reconnecting server certificate: %v", err)
	}
	clientCertificate, err := cert.CreateCertificate("test-unit", "test-org", "DE", "reconnecting-client")
	if err != nil {
		t.Fatalf("create reconnecting client certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse reconnecting server certificate: %v", err)
	}
	remoteSKI, err := cert.SkiFromCertificate(leaf)
	if err != nil {
		t.Fatalf("derive reconnecting server SKI: %v", err)
	}

	peer := &reconnectingLocalShipPeer{
		remoteSKI: remoteSKI,
		sessions:  make(chan *reconnectingShipSession, 4),
		active:    make(map[*reconnectingShipSession]struct{}),
	}
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{api.ShipWebsocketSubProtocol},
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := upgrader.Upgrade(response, request, nil)
		if upgradeErr != nil {
			return
		}
		session := &reconnectingShipSession{
			connection: connection,
			message:    make(chan acceptedShipMessage, 1),
			release:    make(chan struct{}),
		}
		peer.mu.Lock()
		peer.active[session] = struct{}{}
		peer.mu.Unlock()
		defer func() {
			peer.mu.Lock()
			delete(peer.active, session)
			peer.mu.Unlock()
			_ = connection.Close()
		}()

		peer.sessions <- session
		messageType, payload, readErr := connection.ReadMessage()
		session.message <- acceptedShipMessage{messageType: messageType, payload: payload, err: readErr}
		<-session.release
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAnyClientCert,
		CipherSuites: cert.CipherSuites, // #nosec G402 -- SHIP mandates this suite set.
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	peer.server = server
	parsed, err := url.Parse(server.URL)
	if err != nil {
		peer.close()
		t.Fatalf("parse reconnecting peer URL: %v", err)
	}
	peer.host = parsed.Hostname()
	peer.port, err = strconv.Atoi(parsed.Port())
	if err != nil {
		peer.close()
		t.Fatalf("parse reconnecting peer port: %v", err)
	}
	t.Cleanup(peer.close)
	return peer, clientCertificate
}

func (p *reconnectingLocalShipPeer) close() {
	p.once.Do(func() {
		p.mu.Lock()
		active := make([]*reconnectingShipSession, 0, len(p.active))
		for session := range p.active {
			active = append(active, session)
		}
		p.mu.Unlock()
		for _, session := range active {
			session.close()
		}
		p.server.CloseClientConnections()
		p.server.Close()
	})
}

func waitForReconnectingSession(t *testing.T, peer *reconnectingLocalShipPeer) *reconnectingShipSession {
	t.Helper()
	select {
	case session := <-peer.sessions:
		return session
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reconnecting SHIP session")
		return nil
	}
}

func waitForSessionMessage(t *testing.T, session *reconnectingShipSession) acceptedShipMessage {
	t.Helper()
	select {
	case observed := <-session.message:
		return observed
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for reconnecting SHIP message")
		return acceptedShipMessage{}
	}
}

func TestExpectedSKIPinFailsBeforeWebsocketUpgrade(t *testing.T) {
	peer, clientCertificate := newReconnectingLocalShipPeer(t)
	dialer, ok := newOutgoingAttemptDialer(clientCertificate).(expectedSKIOutgoingAttemptDialer)
	if !ok {
		t.Fatal("production dialer does not support an expected-SKI TLS pin")
	}

	connection, response, err := dialer.DialContextExpectedSKI(
		context.Background(),
		"wss"+peer.server.URL[len("https"):]+"/ship/",
		nil,
		"0000000000000000000000000000000000000000",
	)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil {
		t.Fatal("mismatched certificate SKI reached websocket upgrade")
	}
	select {
	case session := <-peer.sessions:
		session.close()
		t.Fatal("mismatched certificate SKI invoked the websocket handler")
	case <-time.After(200 * time.Millisecond):
	}

	connection, response, err = dialer.DialContextExpectedSKI(
		context.Background(),
		"wss"+peer.server.URL[len("https"):]+"/ship/",
		nil,
		peer.remoteSKI,
	)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		t.Fatalf("matching certificate SKI: %v", err)
	}
	session := waitForReconnectingSession(t, peer)
	_ = connection.Close()
	session.close()
}

func waitForHubConnection(t *testing.T, hub *Hub, ski string, connected bool) api.ShipConnectionInterface {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection := hub.connectionForSKI(ski)
		if (connection != nil) == connected {
			return connection
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("connection state for %s did not become connected=%t", ski, connected)
	return nil
}

func waitForMdnsCounts(mdns *attemptTestMdns, announce, request int) bool {
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		gotAnnounce, gotRequest := mdns.counts()
		if gotAnnounce >= announce && gotRequest >= request {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestDiscoveredServiceReportsAreSingleFlightAndReconnectAfterTerminalDisconnect(t *testing.T) {
	peer, clientCertificate := newReconnectingLocalShipPeer(t)
	authorizeRelease := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-authorizeRelease:
		default:
			close(authorizeRelease)
		}
	})
	gate := &notifyingAttemptGate{
		scriptedAttemptGate: newScriptedAttemptGate(gatePermit),
		prepared:            make(chan struct{}, 8),
	}
	gate.authorizeEntered = make(chan struct{})
	gate.authorizeRelease = authorizeRelease
	mdns := &attemptTestMdns{}
	hub := NewHub(&attemptAwareGateTestHubReader{}, mdns, 0, clientCertificate, api.NewServiceDetails("local-ski"))
	if err := hub.SetOutgoingAttemptGate(gate); err != nil {
		t.Fatalf("install outgoing attempt gate: %v", err)
	}
	hub.muxStarted.Lock()
	hub.hasStarted = true
	hub.muxStarted.Unlock()

	hub.RegisterRemoteSKI(peer.remoteSKI)
	if !hub.ServiceForSKI(peer.remoteSKI).Trusted() {
		t.Fatal("RegisterRemoteSKI did not authorize the discovered service")
	}
	requests, _, _, _ := gate.snapshot()
	if len(requests) != 0 {
		t.Fatalf("authorization initiated %d attempts without a discovered entry", len(requests))
	}

	entry := &api.MdnsEntry{
		Ski:  peer.remoteSKI,
		Host: peer.host,
		Port: peer.port,
		Path: "/ship/",
	}
	report := map[string]*api.MdnsEntry{peer.remoteSKI: entry}
	hub.ReportMdnsEntries(report, true)
	waitForSignal(t, gate.prepared)
	waitForSignal(t, gate.authorizeEntered)
	for range 3 {
		hub.ReportMdnsEntries(report, true)
	}
	select {
	case <-gate.prepared:
		requests, _, _, _ = gate.snapshot()
		t.Fatalf("duplicate discovery reports prepared %d concurrent attempts, want 1", len(requests))
	case <-time.After(250 * time.Millisecond):
	}

	close(authorizeRelease)
	first := waitForReconnectingSession(t, peer)
	observed := waitForSessionMessage(t, first)
	if observed.err != nil || observed.messageType != websocket.BinaryMessage || !bytes.Equal(observed.payload, model.ShipInit) {
		t.Fatalf("first discovered connection message = type:%d payload:%x err:%v", observed.messageType, observed.payload, observed.err)
	}
	waitForHubConnection(t, hub, peer.remoteSKI, true)

	first.close()
	waitForHubConnection(t, hub, peer.remoteSKI, false)
	if !waitForMdnsCounts(mdns, 1, 2) {
		announce, request := mdns.counts()
		t.Errorf("terminal disconnect mDNS announce/request counts = %d/%d, want at least 1/2", announce, request)
	}

	hub.ReportMdnsEntries(map[string]*api.MdnsEntry{}, true)
	hub.ReportMdnsEntries(report, true)
	waitForSignal(t, gate.prepared)
	second := waitForReconnectingSession(t, peer)
	observed = waitForSessionMessage(t, second)
	if observed.err != nil || observed.messageType != websocket.BinaryMessage || !bytes.Equal(observed.payload, model.ShipInit) {
		t.Fatalf("reconnected discovered service message = type:%d payload:%x err:%v", observed.messageType, observed.payload, observed.err)
	}
	waitForHubConnection(t, hub, peer.remoteSKI, true)
	requests, _, _, _ = gate.snapshot()
	if len(requests) != 2 {
		t.Fatalf("disappear/reannounce prepared %d attempts total, want exactly 2", len(requests))
	}
	second.close()
}

func newLocalShipPeer(t *testing.T) (*localShipPeer, tls.Certificate) {
	t.Helper()
	serverCertificate, err := cert.CreateCertificate("test-unit", "test-org", "DE", "test-peer")
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	clientCertificate, err := cert.CreateCertificate("test-unit", "test-org", "DE", "test-client")
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(serverCertificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse server certificate: %v", err)
	}
	remoteSKI, err := cert.SkiFromCertificate(leaf)
	if err != nil {
		t.Fatalf("derive server SKI: %v", err)
	}

	peer := &localShipPeer{
		remoteSKI: remoteSKI,
		accepted:  make(chan struct{}, 1),
		messages:  make(chan acceptedShipMessage, 1),
		release:   make(chan struct{}),
	}
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(*http.Request) bool { return true },
		Subprotocols: []string{api.ShipWebsocketSubProtocol},
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := upgrader.Upgrade(response, request, nil)
		if upgradeErr != nil {
			peer.messages <- acceptedShipMessage{err: upgradeErr}
			return
		}
		defer connection.Close()
		peer.accepted <- struct{}{}
		messageType, payload, readErr := connection.ReadMessage()
		peer.messages <- acceptedShipMessage{messageType: messageType, payload: payload, err: readErr}
		<-peer.release
	})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAnyClientCert,
		CipherSuites: cert.CipherSuites, // #nosec G402 -- SHIP mandates this suite set.
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	peer.server = server
	parsed, err := url.Parse(server.URL)
	if err != nil {
		peer.close()
		t.Fatalf("parse local peer URL: %v", err)
	}
	peer.host = parsed.Hostname()
	peer.port = parsed.Port()
	t.Cleanup(peer.close)
	return peer, clientCertificate
}

func (p *localShipPeer) close() {
	p.once.Do(func() {
		p.server.CloseClientConnections()
		close(p.release)
		p.server.Close()
	})
}

func waitForAcceptedShipMessage(t *testing.T, peer *localShipPeer) acceptedShipMessage {
	t.Helper()
	select {
	case observed := <-peer.messages:
		return observed
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for local SHIP message")
		return acceptedShipMessage{}
	}
}

func waitForAttemptTerminal(t *testing.T, model *durableReservationGateReader) api.OutgoingAttemptMetadata {
	t.Helper()
	select {
	case metadata := <-model.terminalSignal:
		return metadata
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for attempt terminal callback")
		return api.OutgoingAttemptMetadata{}
	}
}

func TestRealTLSPeerDrivesAcceptRegistrationAndTerminalCallback(t *testing.T) {
	peer, clientCertificate := newLocalShipPeer(t)
	lifecycle := newDurableReservationGateReader()
	hub := NewHub(lifecycle, &attemptTestMdns{}, 0, clientCertificate, api.NewServiceDetails("local-ski"))
	if err := hub.SetOutgoingAttemptGate(lifecycle); err != nil {
		t.Fatalf("install durable gate: %v", err)
	}
	remote := hub.ServiceForSKI(peer.remoteSKI)

	if err := hub.connectFoundService(remote, peer.host, peer.port, "/ship/", nil); err != nil {
		t.Fatal("connect to local TLS peer failed")
	}
	select {
	case <-peer.accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("local TLS/WebSocket peer did not observe accept")
	}
	observed := waitForAcceptedShipMessage(t, peer)
	if observed.err != nil {
		t.Fatalf("read real SHIP message: %v", observed.err)
	}
	if observed.messageType != websocket.BinaryMessage || !bytes.Equal(observed.payload, model.ShipInit) {
		t.Fatalf("accepted message = type:%d payload:%x, want binary SHIP init", observed.messageType, observed.payload)
	}
	registered := hub.connectionForSKI(peer.remoteSKI)
	if registered == nil {
		t.Fatal("outgoing SHIP connection was not registered before peer release")
	}

	peer.close()
	terminal := waitForAttemptTerminal(t, lifecycle)
	requests, terminals, counts, active := lifecycle.snapshotLifecycle()
	if len(requests) != 1 || len(terminals) != 1 || terminal != terminals[0] || counts[terminal.AttemptID] != 1 || active != 0 {
		t.Fatalf("real attempt prepare/terminal/count/active = %d/%d/%d/%d", len(requests), len(terminals), counts[terminal.AttemptID], active)
	}
	if hub.connectionForSKI(peer.remoteSKI) != nil {
		t.Fatal("terminal callback left the exact real connection registered")
	}
	registered.CloseConnection(false, 0, "repeat close")
	_, terminals, counts, _ = lifecycle.snapshotLifecycle()
	if len(terminals) != 1 || counts[terminal.AttemptID] != 1 {
		t.Fatalf("repeat close emitted duplicate terminal callback: terminals=%d count=%d", len(terminals), counts[terminal.AttemptID])
	}
}

func TestAuthorizedCertificateValidationFailureTerminalizesOnce(t *testing.T) {
	peer, clientCertificate := newLocalShipPeer(t)
	lifecycle := newDurableReservationGateReader()
	hub := NewHub(lifecycle, &attemptTestMdns{}, 0, clientCertificate, api.NewServiceDetails("local-ski"))
	if err := hub.SetOutgoingAttemptGate(lifecycle); err != nil {
		t.Fatalf("install durable gate: %v", err)
	}

	err := hub.connectFoundService(hub.ServiceForSKI("different-ski"), peer.host, peer.port, "/ship/", nil)
	if err == nil {
		t.Fatal("certificate mismatch unexpectedly connected")
	}
	terminal := waitForAttemptTerminal(t, lifecycle)
	_, terminals, counts, active := lifecycle.snapshotLifecycle()
	if len(terminals) != 1 || counts[terminal.AttemptID] != 1 || active != 0 {
		t.Fatalf("validation terminal/count/active = %d/%d/%d, want 1/1/0", len(terminals), counts[terminal.AttemptID], active)
	}
}

func TestAuthorizedDuplicateRejectionTerminalizesOnce(t *testing.T) {
	peer, clientCertificate := newLocalShipPeer(t)
	lifecycle := newDurableReservationGateReader()
	hub := NewHub(lifecycle, &attemptTestMdns{}, 0, clientCertificate, api.NewServiceDetails("0000"))
	if err := hub.SetOutgoingAttemptGate(lifecycle); err != nil {
		t.Fatalf("install durable gate: %v", err)
	}
	existing := &attemptCallbackConnection{ski: peer.remoteSKI}
	hub.dialer = &registerAfterDialer{
		outgoingAttemptDialer: hub.dialer,
		afterDial: func() {
			hub.registerConnection(existing)
		},
	}

	err := hub.connectFoundService(hub.ServiceForSKI(peer.remoteSKI), peer.host, peer.port, "/ship/", nil)
	if err == nil {
		t.Fatal("duplicate outgoing connection unexpectedly replaced active connection")
	}
	terminal := waitForAttemptTerminal(t, lifecycle)
	_, terminals, counts, active := lifecycle.snapshotLifecycle()
	if len(terminals) != 1 || counts[terminal.AttemptID] != 1 || active != 0 {
		t.Fatalf("duplicate terminal/count/active = %d/%d/%d, want 1/1/0", len(terminals), counts[terminal.AttemptID], active)
	}
	if got := hub.connectionForSKI(peer.remoteSKI); got != existing {
		t.Fatalf("duplicate rejection changed registered connection: got %#v, want %#v", got, existing)
	}
}

type registerAfterDialer struct {
	outgoingAttemptDialer
	afterDial func()
	once      sync.Once
}

func (d *registerAfterDialer) DialContext(
	attemptContext context.Context,
	address string,
	header http.Header,
) (*websocket.Conn, *http.Response, error) {
	connection, response, err := d.outgoingAttemptDialer.DialContext(attemptContext, address, header)
	if err == nil && connection != nil {
		d.once.Do(d.afterDial)
	}
	return connection, response, err
}

type registrationTestWriter struct {
	mu     sync.Mutex
	reader api.WebsocketDataReaderInterface
	closed int
}

func (w *registrationTestWriter) InitDataProcessing(reader api.WebsocketDataReaderInterface) {
	w.mu.Lock()
	w.reader = reader
	w.mu.Unlock()
}
func (*registrationTestWriter) WriteMessageToWebsocketConnection([]byte) error { return nil }
func (w *registrationTestWriter) CloseDataConnection(int, string) {
	w.mu.Lock()
	w.closed++
	w.mu.Unlock()
}
func (w *registrationTestWriter) IsDataConnectionClosed() (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed == 0 {
		return false, nil
	}
	return true, errors.New("closed")
}

func (w *registrationTestWriter) snapshot() (api.WebsocketDataReaderInterface, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.reader, w.closed
}

func TestAttemptCancellationBeforeAndAfterRegistrationCannotRemainRegistered(t *testing.T) {
	tests := []struct {
		name         string
		cancelBefore bool
	}{
		{name: "before registration", cancelBefore: true},
		{name: "after registration", cancelBefore: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			lifecycle := newDurableReservationGateReader()
			hub := NewHub(lifecycle, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
			attemptContext, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			metadata := api.OutgoingAttemptMetadata{AttemptID: "registration-attempt", Scope: "scope", ControlEpoch: 5}
			connection, err := ship.NewOutgoingConnectionHandler(
				hub,
				&registrationTestWriter{},
				ship.ShipRoleClient,
				"local-ship-id",
				"remote-ski",
				"remote-ship-id",
				ship.OutgoingAttemptConnectionConfiguration{Metadata: metadata, Context: attemptContext},
			)
			if err != nil {
				t.Fatalf("create outgoing connection: %v", err)
			}
			if test.cancelBefore {
				cancel()
			}
			result := hub.registerOutgoingConnection(connection, attemptContext, nil)
			want := outgoingConnectionRegistrationAccepted
			if test.cancelBefore {
				want = outgoingConnectionRegistrationRejected
			}
			if result != want {
				t.Fatalf("registration result = %v, want %v", result, want)
			}
			connection.Run()
			if !test.cancelBefore {
				cancel()
			}
			terminal := waitForAttemptTerminal(t, lifecycle)
			if terminal != metadata {
				t.Fatalf("terminal metadata = %#v, want %#v", terminal, metadata)
			}
			if hub.connectionForSKI("remote-ski") != nil {
				t.Fatal("canceled outgoing attempt remained registered")
			}
		})
	}
}

func TestCanceledAttemptCannotDisconnectNewerConnection(t *testing.T) {
	lifecycle := newDurableReservationGateReader()
	hub := NewHub(lifecycle, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	attemptContext, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	metadata := api.OutgoingAttemptMetadata{AttemptID: "old-attempt", Scope: "scope", ControlEpoch: 7}
	oldConnection, err := ship.NewOutgoingConnectionHandler(
		hub,
		&registrationTestWriter{},
		ship.ShipRoleClient,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
		ship.OutgoingAttemptConnectionConfiguration{Metadata: metadata, Context: attemptContext},
	)
	if err != nil {
		t.Fatalf("create old outgoing connection: %v", err)
	}
	if result := hub.registerOutgoingConnection(
		oldConnection,
		attemptContext,
		nil,
	); result != outgoingConnectionRegistrationAccepted {
		t.Fatalf("old connection registration result = %v, want accepted", result)
	}
	oldConnection.Run()

	newer := &attemptCallbackConnection{ski: "remote-ski"}
	hub.registerConnection(newer)
	cancel()
	if terminal := waitForAttemptTerminal(t, lifecycle); terminal != metadata {
		t.Fatalf("terminal metadata = %#v, want %#v", terminal, metadata)
	}
	if got := hub.connectionForSKI("remote-ski"); got != newer {
		t.Fatalf("old cancellation changed newer connection: got %#v, want %#v", got, newer)
	}
}
