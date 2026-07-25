package hub

import (
	"bytes"
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
