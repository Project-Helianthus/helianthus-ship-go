package hub

import (
	"crypto/tls"
	"crypto/x509"
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
	mu     sync.Mutex
	states []api.ConnectionState
}

func (reader *issue16PairingReader) ServicePairingDetailUpdate(
	_ string,
	detail *api.ConnectionStateDetail,
) {
	reader.mu.Lock()
	reader.states = append(reader.states, detail.State())
	reader.mu.Unlock()
}

func (reader *issue16PairingReader) pairingStates() []api.ConnectionState {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]api.ConnectionState(nil), reader.states...)
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
}
