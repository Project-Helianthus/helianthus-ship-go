package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	setups       int

	connectedEntered chan struct{}
	connectedRelease chan struct{}
}

type issue16AttemptReader struct {
	issue16PairingReader
	muAttempt  sync.Mutex
	terminals  []api.OutgoingAttemptMetadata
	handshakes []api.OutgoingAttemptMetadata
}

type issue16SpineReader struct {
	mu       sync.Mutex
	payloads [][]byte
}

func (reader *issue16SpineReader) HandleShipPayloadMessage(message []byte) {
	reader.mu.Lock()
	reader.payloads = append(reader.payloads, append([]byte(nil), message...))
	reader.mu.Unlock()
}

func (reader *issue16SpineReader) payloadCount() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return len(reader.payloads)
}

type issue16SpineAttemptReader struct {
	issue16AttemptReader
	spine *issue16SpineReader
}

func (reader *issue16SpineAttemptReader) SetupRemoteDevice(
	string,
	api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	reader.mu.Lock()
	reader.setups++
	reader.mu.Unlock()
	return reader.spine
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
	entered := reader.connectedEntered
	release := reader.connectedRelease
	reader.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
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

func (reader *issue16PairingReader) SetupRemoteDevice(
	string,
	api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	reader.mu.Lock()
	reader.setups++
	reader.mu.Unlock()
	return nil
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

func (reader *issue16PairingReader) setupCount() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.setups
}

func (reader *issue16PairingReader) setConnectedBarrier(entered, release chan struct{}) {
	reader.mu.Lock()
	reader.connectedEntered = entered
	reader.connectedRelease = release
	reader.mu.Unlock()
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
			provider := &outgoingAttemptInfoProvider{hub: hub, registration: registration}

			provider.HandleShipHandshakeStateUpdateWithAttempt(
				remoteSKI,
				model.ShipState{State: model.SmeStateComplete},
				metadata,
			)
			provider.ReportServiceShipID(remoteSKI, "loser-ship-id")
			_ = provider.SetupRemoteDevice(remoteSKI, nil)
			if reader.handshakeCount() != 0 {
				t.Fatalf("superseded attempt published %d pre-terminal handshake callbacks, want zero", reader.handshakeCount())
			}
			if state := service.ConnectionStateDetail().State(); state == api.ConnectionStateCompleted {
				t.Fatal("superseded internal attempt changed pairing state before terminal")
			}
			if connected, _, shipIDs := reader.evidenceCounts(); connected != 0 || shipIDs != 0 || reader.setupCount() != 0 {
				t.Fatalf("superseded pre-terminal evidence = connected:%d ship_ids:%d setups:%d, want zero", connected, shipIDs, reader.setupCount())
			}

			provider.HandleConnectionClosedWithAttempt(loser, false, metadata)

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

			provider.HandleShipHandshakeStateUpdateWithAttempt(
				remoteSKI,
				model.ShipState{State: model.SmeStateComplete},
				metadata,
			)
			provider.ReportServiceShipID(remoteSKI, "late-loser-ship-id")
			_ = provider.SetupRemoteDevice(remoteSKI, nil)
			if reader.handshakeCount() != 0 {
				t.Fatalf("superseded attempt published %d post-terminal handshake callbacks, want zero", reader.handshakeCount())
			}
			if state := service.ConnectionStateDetail().State(); state == api.ConnectionStateCompleted {
				t.Fatal("superseded internal attempt changed pairing state after terminal")
			}
			if connected, _, shipIDs := reader.evidenceCounts(); connected != 0 || shipIDs != 0 || reader.setupCount() != 0 {
				t.Fatalf("superseded post-terminal evidence = connected:%d ship_ids:%d setups:%d, want zero", connected, shipIDs, reader.setupCount())
			}
		})
	}
}

func TestIssue16ReusedMetadataOnLaterExactConnectionIsNotTombstoned(t *testing.T) {
	reader := &issue16AttemptReader{}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	remoteSKI := strings.Repeat("a", 40)
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "reused-by-external-gate",
		Scope:        "candidate-scope",
		ControlEpoch: 16,
	}
	authority := &outboundAttemptAuthority{epoch: 16}

	oldContext, oldCancel := context.WithCancel(context.Background())
	oldConnection := &attemptCallbackConnection{ski: remoteSKI}
	oldRegistration := &outboundAttemptRegistration{
		authority:  authority,
		metadata:   metadata,
		context:    oldContext,
		cancel:     oldCancel,
		connection: oldConnection,
	}
	hub.outboundAttempts[remoteSKI] = map[*outboundAttemptRegistration]struct{}{oldRegistration: {}}
	hub.registerConnection(oldConnection)
	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("inbound replacement reservation was denied")
	}
	inboundWinner := &attemptCallbackConnection{ski: remoteSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(inboundWinner, reservation); !registered || replaced != oldConnection {
		t.Fatalf("inbound replacement = %#v, %t; want exact old connection and true", replaced, registered)
	}
	oldProvider := &outgoingAttemptInfoProvider{hub: hub, registration: oldRegistration}
	oldProvider.HandleConnectionClosedWithAttempt(oldConnection, false, metadata)

	if !hub.removeExactConnection(inboundWinner) {
		t.Fatal("remove inbound winner before later reconnect")
	}
	newContext, newCancel := context.WithCancel(context.Background())
	t.Cleanup(newCancel)
	newConnection := &attemptCallbackConnection{ski: remoteSKI}
	newRegistration := &outboundAttemptRegistration{
		authority:  authority,
		metadata:   metadata,
		context:    newContext,
		cancel:     newCancel,
		connection: newConnection,
	}
	hub.outboundAttempts[remoteSKI] = map[*outboundAttemptRegistration]struct{}{newRegistration: {}}
	hub.registerConnection(newConnection)
	newProvider := &outgoingAttemptInfoProvider{hub: hub, registration: newRegistration}

	newProvider.HandleShipHandshakeStateUpdateWithAttempt(
		remoteSKI,
		model.ShipState{State: model.SmeStateComplete},
		metadata,
	)
	newProvider.ReportServiceShipID(remoteSKI, "new-ship-id")
	_ = newProvider.SetupRemoteDevice(remoteSKI, nil)

	if reader.handshakeCount() != 1 {
		t.Fatalf("later exact connection handshake callbacks = %d, want 1", reader.handshakeCount())
	}
	if connected, _, shipIDs := reader.evidenceCounts(); connected != 1 || shipIDs != 1 || reader.setupCount() != 1 {
		t.Fatalf("later exact connection evidence = connected:%d ship_ids:%d setups:%d, want 1/1/1", connected, shipIDs, reader.setupCount())
	}
}

func TestIssue16InboundReplacementWaitsForAdmittedOutboundEvidenceCallback(t *testing.T) {
	reader := &issue16AttemptReader{}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	remoteSKI := strings.Repeat("a", 40)
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "callback-lease",
		Scope:        "candidate-scope",
		ControlEpoch: 16,
	}
	authority := &outboundAttemptAuthority{epoch: 16}
	attemptContext, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	outbound := &attemptCallbackConnection{ski: remoteSKI}
	registration := &outboundAttemptRegistration{
		authority:  authority,
		metadata:   metadata,
		context:    attemptContext,
		cancel:     cancel,
		connection: outbound,
	}
	hub.outboundAttempts[remoteSKI] = map[*outboundAttemptRegistration]struct{}{registration: {}}
	hub.registerConnection(outbound)
	provider := &outgoingAttemptInfoProvider{hub: hub, registration: registration}

	entered := make(chan struct{})
	release := make(chan struct{})
	reader.setConnectedBarrier(entered, release)
	evidenceDone := make(chan struct{})
	go func() {
		provider.ReportServiceShipID(remoteSKI, "outbound-ship-id")
		close(evidenceDone)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("outbound evidence callback did not enter")
	}

	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("inbound replacement reservation was denied")
	}
	inbound := &attemptCallbackConnection{ski: remoteSKI}
	replacementDone := make(chan struct{})
	var replaced api.ShipConnectionInterface
	var registered bool
	go func() {
		replaced, registered = hub.registerReservedInboundPairingConnection(inbound, reservation)
		close(replacementDone)
	}()
	select {
	case <-replacementDone:
		t.Fatal("inbound replacement overtook an admitted outbound evidence callback")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	select {
	case <-evidenceDone:
	case <-time.After(time.Second):
		t.Fatal("outbound evidence callback did not finish")
	}
	select {
	case <-replacementDone:
	case <-time.After(time.Second):
		t.Fatal("inbound replacement did not resume after callback completion")
	}
	if !registered || replaced != outbound {
		t.Fatalf("inbound replacement = %#v, %t; want exact outbound and true", replaced, registered)
	}
	if connected, _, shipIDs := reader.evidenceCounts(); connected != 1 || shipIDs != 1 {
		t.Fatalf("ordered outbound evidence = connected:%d ship_ids:%d, want 1/1", connected, shipIDs)
	}

	provider.ReportServiceShipID(remoteSKI, "late-outbound-ship-id")
	if connected, _, shipIDs := reader.evidenceCounts(); connected != 1 || shipIDs != 1 {
		t.Fatalf("post-replacement loser evidence = connected:%d ship_ids:%d, want unchanged 1/1", connected, shipIDs)
	}
}

func TestIssue16RejectedReplacementDoesNotDisableLiveOutboundCallbacks(t *testing.T) {
	reader := &issue16AttemptReader{}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	remoteSKI := strings.Repeat("a", 40)
	for index := 0; index < maximumSupersededConnectionsPerSKI; index++ {
		connection := &attemptCallbackConnection{ski: remoteSKI}
		hub.supersededConnections[connection] = struct{}{}
	}

	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "saturated-replacement",
		Scope:        "candidate-scope",
		ControlEpoch: 16,
	}
	authority := &outboundAttemptAuthority{epoch: 16}
	attemptContext, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	outbound := &attemptCallbackConnection{ski: remoteSKI}
	registration := &outboundAttemptRegistration{
		authority:  authority,
		metadata:   metadata,
		context:    attemptContext,
		cancel:     cancel,
		connection: outbound,
	}
	hub.outboundAttempts[remoteSKI] = map[*outboundAttemptRegistration]struct{}{registration: {}}
	hub.registerConnection(outbound)
	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("inbound replacement reservation was denied before bounded registration")
	}
	inbound := &attemptCallbackConnection{ski: remoteSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(inbound, reservation); registered || replaced != nil {
		t.Fatalf("saturated replacement = %#v, %t; want nil and false", replaced, registered)
	}

	provider := &outgoingAttemptInfoProvider{hub: hub, registration: registration}
	provider.ReportServiceShipID(remoteSKI, "still-live")
	if connected, _, shipIDs := reader.evidenceCounts(); connected != 1 || shipIDs != 1 {
		t.Fatalf("live outbound evidence after rejected replacement = connected:%d ship_ids:%d, want 1/1", connected, shipIDs)
	}
}

func TestIssue16SupersededOutboundReaderDropsSpinePayloads(t *testing.T) {
	spineReader := &issue16SpineReader{}
	reader := &issue16SpineAttemptReader{spine: spineReader}
	hub := NewHub(
		reader,
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	remoteSKI := strings.Repeat("a", 40)
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "spine-reader-fence",
		Scope:        "candidate-scope",
		ControlEpoch: 16,
	}
	attemptContext, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	outbound := &attemptCallbackConnection{ski: remoteSKI}
	registration := &outboundAttemptRegistration{
		authority:  &outboundAttemptAuthority{epoch: 16},
		metadata:   metadata,
		context:    attemptContext,
		cancel:     cancel,
		connection: outbound,
	}
	hub.outboundAttempts[remoteSKI] = map[*outboundAttemptRegistration]struct{}{registration: {}}
	hub.registerConnection(outbound)
	provider := &outgoingAttemptInfoProvider{hub: hub, registration: registration}

	dataReader := provider.SetupRemoteDevice(remoteSKI, nil)
	if dataReader == nil {
		t.Fatal("live outbound setup returned no SPINE reader")
	}
	dataReader.HandleShipPayloadMessage([]byte("before-replacement"))
	if got := spineReader.payloadCount(); got != 1 {
		t.Fatalf("live outbound SPINE payloads = %d, want 1", got)
	}

	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("inbound replacement reservation was denied")
	}
	inbound := &attemptCallbackConnection{ski: remoteSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(inbound, reservation); !registered || replaced != outbound {
		t.Fatalf("inbound replacement = %#v, %t; want exact outbound and true", replaced, registered)
	}

	dataReader.HandleShipPayloadMessage([]byte("after-replacement"))
	if got := spineReader.payloadCount(); got != 1 {
		t.Fatalf("superseded outbound delivered %d SPINE payloads, want unchanged 1", got)
	}
}

func TestIssue16RemoteHigherInboundWinsWhileOutboundIsInitiating(t *testing.T) {
	localSKI := strings.Repeat("0", 40)
	remoteSKI := strings.Repeat("a", 40)
	hub := NewHub(
		&issue16AttemptReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	hub.connectionsInitiating[remoteSKI] = true

	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("SHIP-defined remote-higher inbound winner was rejected by an outbound dial in flight")
	}
	outbound := &attemptCallbackConnection{ski: remoteSKI}
	if hub.registerOutgoingConnection(outbound, context.Background()) {
		t.Fatal("outbound loser registered over the reserved remote-higher inbound winner")
	}
	inbound := &attemptCallbackConnection{ski: remoteSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(inbound, reservation); !registered || replaced != nil {
		t.Fatalf("remote-higher inbound winner = %#v, %t; want nil and true", replaced, registered)
	}
}

func TestIssue16InboundReservationSurvivesWinnerRegistrationUntilClose(t *testing.T) {
	remoteSKI := strings.Repeat("a", 40)
	hub := NewHub(
		&issue16AttemptReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("inbound reservation was denied")
	}
	winner := &attemptCallbackConnection{ski: remoteSKI}
	if _, registered := hub.registerReservedInboundPairingConnection(winner, reservation); !registered {
		t.Fatal("inbound winner was not registered")
	}
	if second := hub.reserveInboundPairingConnection(remoteSKI); second != nil {
		t.Fatal("second inbound reserved before the exact winner terminated")
	}

	hub.HandleConnectionClosed(winner, false)
	if next := hub.reserveInboundPairingConnection(remoteSKI); next == nil {
		t.Fatal("winner terminal close did not release the inbound reservation")
	}
}

func TestIssue16SupersededConnectionsAreReclaimedAndCapacityIsPerSKI(t *testing.T) {
	hub := NewHub(
		&issue16AttemptReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	for index := 0; index < maximumSupersededConnectionsPerSKI; index++ {
		connection := &attemptCallbackConnection{ski: fmt.Sprintf("%040x", index+1)}
		hub.supersededConnections[connection] = struct{}{}
	}

	remoteSKI := strings.Repeat("a", 40)
	outbound := &attemptCallbackConnection{ski: remoteSKI}
	hub.registerConnection(outbound)
	reservation := hub.reserveInboundPairingConnection(remoteSKI)
	if reservation == nil {
		t.Fatal("inbound reservation was denied by unrelated superseded connections")
	}
	inbound := &attemptCallbackConnection{ski: remoteSKI}
	if replaced, registered := hub.registerReservedInboundPairingConnection(inbound, reservation); !registered || replaced != outbound {
		t.Fatalf("per-SKI replacement = %#v, %t; want exact outbound and true", replaced, registered)
	}
	if _, superseded := hub.claimClosedConnection(outbound); !superseded {
		t.Fatal("superseded outbound was not claimed")
	}
	if _, superseded := hub.claimClosedConnection(outbound); superseded {
		t.Fatal("superseded outbound tombstone was not reclaimed after its terminal claim")
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
