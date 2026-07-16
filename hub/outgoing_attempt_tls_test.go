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

	if err := hub.connectFoundService(remote, peer.host, peer.port, "/ship/"); err != nil {
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

	err := hub.connectFoundService(hub.ServiceForSKI("different-ski"), peer.host, peer.port, "/ship/")
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

	err := hub.connectFoundService(hub.ServiceForSKI(peer.remoteSKI), peer.host, peer.port, "/ship/")
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
			registered := hub.registerOutgoingConnection(connection, attemptContext)
			if registered == test.cancelBefore {
				t.Fatalf("registered = %t with cancelBefore=%t", registered, test.cancelBefore)
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
	if !hub.registerOutgoingConnection(oldConnection, attemptContext) {
		t.Fatal("old connection was not registered")
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
