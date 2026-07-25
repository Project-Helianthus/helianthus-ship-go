package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/gorilla/websocket"
)

type issue16PairingReader struct {
	attemptTestHubReader
	mu           sync.Mutex
	states       []api.ConnectionState
	shipIDs      int
	connected    int
	disconnected int
}

type issue16AttemptReader struct {
	issue16PairingReader
	muAttempt  sync.Mutex
	terminals  []api.OutgoingAttemptMetadata
	handshakes []api.OutgoingAttemptMetadata
}

func (reader *issue16AttemptReader) OutgoingAttemptConnectionClosed(
	_ string,
	_ bool,
	metadata api.OutgoingAttemptMetadata,
) {
	reader.muAttempt.Lock()
	reader.terminals = append(reader.terminals, metadata)
	reader.muAttempt.Unlock()
}

func (reader *issue16AttemptReader) OutgoingAttemptHandshakeStateUpdate(
	_ string,
	_ model.ShipState,
	metadata api.OutgoingAttemptMetadata,
) {
	reader.muAttempt.Lock()
	reader.handshakes = append(reader.handshakes, metadata)
	reader.muAttempt.Unlock()
}

func (reader *issue16AttemptReader) terminalCount() int {
	reader.muAttempt.Lock()
	defer reader.muAttempt.Unlock()
	return len(reader.terminals)
}

func (reader *issue16AttemptReader) handshakeCount() int {
	reader.muAttempt.Lock()
	defer reader.muAttempt.Unlock()
	return len(reader.handshakes)
}

func (reader *issue16PairingReader) ServicePairingDetailUpdate(
	_ string,
	detail *api.ConnectionStateDetail,
) {
	reader.mu.Lock()
	reader.states = append(reader.states, detail.State())
	reader.mu.Unlock()
}

func (reader *issue16PairingReader) RemoteSKIConnected(string) {
	reader.mu.Lock()
	reader.connected++
	reader.mu.Unlock()
}

func (reader *issue16PairingReader) RemoteSKIDisconnected(string) {
	reader.mu.Lock()
	reader.disconnected++
	reader.mu.Unlock()
}

func (reader *issue16PairingReader) ServiceShipIDUpdate(string, string) {
	reader.mu.Lock()
	reader.shipIDs++
	reader.mu.Unlock()
}

func (reader *issue16PairingReader) pairingStates() []api.ConnectionState {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]api.ConnectionState(nil), reader.states...)
}

func (reader *issue16PairingReader) evidenceCounts() (int, int, int) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.connected, reader.disconnected, reader.shipIDs
}

func TestIssue16LosingInboundConnectionCannotPublishPairingRequest(t *testing.T) {
	serverCertificate, err := cert.CreateCertificate("unit", "org", "DE", "server")
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := cert.CreateCertificate("unit", "org", "DE", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	remoteSKI, err := cert.SkiFromCertificate(clientLeaf)
	if err != nil {
		t.Fatal(err)
	}

	reader := &issue16PairingReader{}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		serverCertificate,
		api.NewServiceDetails(strings.Repeat("f", 40)),
	)
	hub.ServiceForSKI(remoteSKI).ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	hub.registerConnection(&attemptCallbackConnection{ski: remoteSKI})

	server := httptest.NewUnstartedServer(hub)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAnyClientCert,
		CipherSuites: cert.CipherSuites, // #nosec G402 -- SHIP mandates this suite set.
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})

	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{clientCertificate},
			InsecureSkipVerify: true,              // #nosec G402 -- local test certificate.
			CipherSuites:       cert.CipherSuites, // #nosec G402 -- SHIP mandates this suite set.
			MinVersion:         tls.VersionTLS12,
		},
		Subprotocols: []string{api.ShipWebsocketSubProtocol},
	}
	connection, response, err := dialer.Dial(
		"wss"+strings.TrimPrefix(server.URL, "https"),
		nil,
	)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	_ = connection.Close()
	time.Sleep(100 * time.Millisecond)

	if states := reader.pairingStates(); len(states) != 0 {
		t.Fatalf("losing inbound connection published pairing states %v, want none", states)
	}
	if connected, disconnected, shipIDs := reader.evidenceCounts(); connected != 0 || disconnected != 0 || shipIDs != 0 {
		t.Fatalf("losing inbound evidence counts = connected:%d disconnected:%d ship_ids:%d, want zero", connected, disconnected, shipIDs)
	}
}

func TestIssue16HigherRemoteSKIAtomicallyReplacesQueuedConnectionBeforePairingRequest(t *testing.T) {
	serverCertificate, err := cert.CreateCertificate("unit", "org", "DE", "server")
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := cert.CreateCertificate("unit", "org", "DE", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	remoteSKI, err := cert.SkiFromCertificate(clientLeaf)
	if err != nil {
		t.Fatal(err)
	}

	reader := &issue16PairingReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, serverCertificate, api.NewServiceDetails(strings.Repeat("0", 40)))
	hub.ServiceForSKI(remoteSKI).ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	existing := &attemptCallbackConnection{ski: remoteSKI}
	hub.registerConnection(existing)
	server := newIssue16TLSServer(t, hub, serverCertificate)

	connection, response, err := issue16Dial(server.URL, clientCertificate)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer connection.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(reader.pairingStates()) != 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	states := reader.pairingStates()
	if len(states) != 1 || states[0] != api.ConnectionStateReceivedPairingRequest {
		t.Fatalf("winning inbound pairing states = %v, want [ReceivedPairingRequest]", states)
	}
	if registered := hub.connectionForSKI(remoteSKI); registered == nil || registered == existing {
		t.Fatalf("registered winning connection = %#v, want replacement", registered)
	}
	if connected, disconnected, shipIDs := reader.evidenceCounts(); connected != 0 || disconnected != 0 || shipIDs != 0 {
		t.Fatalf("pre-SHIP evidence counts = connected:%d disconnected:%d ship_ids:%d, want zero", connected, disconnected, shipIDs)
	}
}

func TestIssue16LosingConnectionCloseCannotPublishDisconnectEvidence(t *testing.T) {
	reader := &issue16PairingReader{}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	current := &attemptCallbackConnection{ski: strings.Repeat("a", 40)}
	loser := &attemptCallbackConnection{ski: current.ski}
	hub.registerConnection(current)

	hub.HandleConnectionClosed(loser, false)

	if registered := hub.connectionForSKI(current.ski); registered != current {
		t.Fatalf("loser close changed registered connection to %#v, want %#v", registered, current)
	}
	if _, disconnected, _ := reader.evidenceCounts(); disconnected != 0 {
		t.Fatalf("loser close published %d disconnect callbacks, want zero", disconnected)
	}
}

func TestIssue16ReplacedAttemptTaggedConnectionOnlyReleasesPrivateReservation(t *testing.T) {
	tests := []struct {
		name  string
		scope string
	}{
		{name: "internal", scope: internalOutgoingAttemptScope},
		{name: "gated", scope: "candidate-scope"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &issue16AttemptReader{}
			hub := NewHub(
				reader,
				&attemptTestMdns{},
				0,
				tls.Certificate{},
				api.NewServiceDetails(strings.Repeat("0", 40)),
			)
			remoteSKI := strings.Repeat("a", 40)
			loser := &attemptCallbackConnection{ski: remoteSKI}
			hub.registerConnection(loser)
			reservation := hub.reserveInboundPairingConnection(remoteSKI)
			if reservation == nil {
				t.Fatal("inbound replacement reservation was denied")
			}
			current := &attemptCallbackConnection{ski: remoteSKI}
			replaced, registered := hub.registerReservedInboundPairingConnection(current, reservation)
			if !registered || replaced != loser {
				t.Fatalf("replacement registration = %#v, %t; want exact loser and true", replaced, registered)
			}

			attemptContext, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			metadata := api.OutgoingAttemptMetadata{
				AttemptID:    "replaced-" + test.name,
				Scope:        test.scope,
				ControlEpoch: 16,
			}
			authority := &outboundAttemptAuthority{epoch: 16}
			registration := &outboundAttemptRegistration{
				authority:  authority,
				metadata:   metadata,
				context:    attemptContext,
				cancel:     cancel,
				connection: loser,
			}
			hub.outboundAttempts[remoteSKI] = map[*outboundAttemptRegistration]struct{}{
				registration: {},
			}
			service := hub.ServiceForSKI(remoteSKI)
			service.SetTrusted(true)
			hub.outboundAuthorities[remoteSKI] = authority

			hub.HandleShipHandshakeStateUpdateWithAttempt(
				remoteSKI,
				model.ShipState{State: model.SmeStateComplete},
				metadata,
			)
			if reader.handshakeCount() != 0 {
				t.Fatalf("superseded attempt published %d pre-terminal handshake callbacks, want zero", reader.handshakeCount())
			}
			if state := service.ConnectionStateDetail().State(); state == api.ConnectionStateCompleted {
				t.Fatal("superseded internal attempt changed pairing state before terminal")
			}

			hub.HandleConnectionClosedWithAttempt(loser, false, metadata)

			if registered := hub.connectionForSKI(remoteSKI); registered != current {
				t.Fatalf("loser terminal changed registered connection to %#v, want %#v", registered, current)
			}
			select {
			case <-attemptContext.Done():
			default:
				t.Fatal("losing private attempt reservation was not released")
			}
			if registrations := hub.outboundAttempts[remoteSKI]; len(registrations) != 0 {
				t.Fatalf("losing private attempt registrations = %d, want zero", len(registrations))
			}
			if reader.terminalCount() != 0 {
				t.Fatalf("losing attempt published %d terminal callbacks, want zero", reader.terminalCount())
			}
			if _, disconnected, _ := reader.evidenceCounts(); disconnected != 0 {
				t.Fatalf("losing attempt published %d disconnect callbacks, want zero", disconnected)
			}

			hub.HandleShipHandshakeStateUpdateWithAttempt(
				remoteSKI,
				model.ShipState{State: model.SmeStateComplete},
				metadata,
			)
			if reader.handshakeCount() != 0 {
				t.Fatalf("superseded attempt published %d post-terminal handshake callbacks, want zero", reader.handshakeCount())
			}
			if state := service.ConnectionStateDetail().State(); state == api.ConnectionStateCompleted {
				t.Fatal("superseded internal attempt changed pairing state after terminal")
			}
		})
	}
}

func TestIssue16ConcurrentInboundConnectionsPublishOnePairingWinner(t *testing.T) {
	serverCertificate, err := cert.CreateCertificate("unit", "org", "DE", "server")
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := cert.CreateCertificate("unit", "org", "DE", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	remoteSKI, err := cert.SkiFromCertificate(clientLeaf)
	if err != nil {
		t.Fatal(err)
	}

	reader := &issue16PairingReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, serverCertificate, api.NewServiceDetails(strings.Repeat("f", 40)))
	hub.ServiceForSKI(remoteSKI).ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	server := newIssue16TLSServer(t, hub, serverCertificate)

	const attempts = 2
	var group sync.WaitGroup
	group.Add(attempts)
	for range attempts {
		go func() {
			defer group.Done()
			connection, response, dialErr := issue16Dial(server.URL, clientCertificate)
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			if dialErr == nil && connection != nil {
				_ = connection.Close()
			}
		}()
	}
	group.Wait()
	time.Sleep(100 * time.Millisecond)

	received := 0
	for _, state := range reader.pairingStates() {
		if state == api.ConnectionStateReceivedPairingRequest {
			received++
		}
	}
	if received != 1 {
		t.Fatalf("concurrent inbound pairing callbacks = %d, want 1; states=%v", received, reader.pairingStates())
	}
}

func TestIssue16PendingOutboundReservationBlocksInboundPairingEvidence(t *testing.T) {
	serverCertificate, err := cert.CreateCertificate("unit", "org", "DE", "server")
	if err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := cert.CreateCertificate("unit", "org", "DE", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientLeaf, err := x509.ParseCertificate(clientCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	remoteSKI, err := cert.SkiFromCertificate(clientLeaf)
	if err != nil {
		t.Fatal(err)
	}

	reader := &issue16PairingReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, serverCertificate, api.NewServiceDetails(strings.Repeat("f", 40)))
	hub.ServiceForSKI(remoteSKI).ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	hub.muxCon.Lock()
	hub.connectionsInitiating[remoteSKI] = true
	hub.muxCon.Unlock()
	t.Cleanup(func() {
		hub.muxCon.Lock()
		delete(hub.connectionsInitiating, remoteSKI)
		hub.muxCon.Unlock()
	})
	server := newIssue16TLSServer(t, hub, serverCertificate)

	connection, response, _ := issue16Dial(server.URL, clientCertificate)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if connection != nil {
		_ = connection.Close()
	}
	time.Sleep(100 * time.Millisecond)

	if states := reader.pairingStates(); len(states) != 0 {
		t.Fatalf("outbound-losing inbound published pairing states %v, want none", states)
	}
}

func TestIssue16ForgedSubjectKeyIDCannotPublishPairingEvidence(t *testing.T) {
	serverCertificate, err := cert.CreateCertificate("unit", "org", "DE", "server")
	if err != nil {
		t.Fatal(err)
	}
	reader := &issue16PairingReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, serverCertificate, api.NewServiceDetails(strings.Repeat("f", 40)))
	server := newIssue16TLSServer(t, hub, serverCertificate)

	connection, response, _ := issue16Dial(server.URL, issue16ForgedCertificate(t))
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if connection != nil {
		_ = connection.Close()
	}
	time.Sleep(100 * time.Millisecond)

	if states := reader.pairingStates(); len(states) != 0 {
		t.Fatalf("forged certificate published pairing states %v, want none", states)
	}
}

func newIssue16TLSServer(t *testing.T, hub *Hub, certificate tls.Certificate) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(hub)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAnyClientCert,
		CipherSuites: cert.CipherSuites, // #nosec G402 -- SHIP mandates this suite set.
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})
	return server
}

func issue16Dial(serverURL string, certificate tls.Certificate) (*websocket.Conn, *http.Response, error) {
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,              // #nosec G402 -- local test certificate.
			CipherSuites:       cert.CipherSuites, // #nosec G402 -- SHIP mandates this suite set.
			MinVersion:         tls.VersionTLS12,
		},
		Subprotocols: []string{api.ShipWebsocketSubProtocol},
	}
	return dialer.Dial("wss"+strings.TrimPrefix(serverURL, "https"), nil)
}

func issue16ForgedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(16),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          bytes.Repeat([]byte{0x5a}, 20),
	}
	certificate, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate:                  [][]byte{certificate},
		PrivateKey:                   privateKey,
		SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
	}
}
