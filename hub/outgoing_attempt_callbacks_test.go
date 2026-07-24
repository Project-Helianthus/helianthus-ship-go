package hub

import (
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

type attemptAwareHubReader struct {
	mu sync.Mutex

	closedMetadata    []api.OutgoingAttemptMetadata
	handshakeMetadata []api.OutgoingAttemptMetadata
	setupWriter       api.ShipConnectionDataWriterInterface
	pairingStates     []api.ConnectionState
}

func (*attemptAwareHubReader) RemoteSKIConnected(string)    {}
func (*attemptAwareHubReader) RemoteSKIDisconnected(string) {}
func (r *attemptAwareHubReader) SetupRemoteDevice(
	_ string,
	writer api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	r.mu.Lock()
	r.setupWriter = writer
	r.mu.Unlock()
	return nil
}
func (*attemptAwareHubReader) VisibleRemoteServicesUpdated([]api.RemoteService) {}
func (*attemptAwareHubReader) ServiceShipIDUpdate(string, string)               {}
func (r *attemptAwareHubReader) ServicePairingDetailUpdate(
	_ string,
	detail *api.ConnectionStateDetail,
) {
	r.mu.Lock()
	r.pairingStates = append(r.pairingStates, detail.State())
	r.mu.Unlock()
}
func (*attemptAwareHubReader) AllowWaitingForTrust(string) bool { return false }
func (r *attemptAwareHubReader) OutgoingAttemptConnectionClosed(_ string, _ bool, metadata api.OutgoingAttemptMetadata) {
	r.mu.Lock()
	r.closedMetadata = append(r.closedMetadata, metadata)
	r.mu.Unlock()
}
func (r *attemptAwareHubReader) OutgoingAttemptHandshakeStateUpdate(_ string, _ model.ShipState, metadata api.OutgoingAttemptMetadata) {
	r.mu.Lock()
	r.handshakeMetadata = append(r.handshakeMetadata, metadata)
	r.mu.Unlock()
}
func (r *attemptAwareHubReader) snapshot() ([]api.OutgoingAttemptMetadata, []api.OutgoingAttemptMetadata) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]api.OutgoingAttemptMetadata(nil), r.closedMetadata...),
		append([]api.OutgoingAttemptMetadata(nil), r.handshakeMetadata...)
}

type attemptMetadataWriter struct {
	metadata api.OutgoingAttemptMetadata
}

func (*attemptMetadataWriter) WriteShipMessageWithPayload([]byte) {}
func (w *attemptMetadataWriter) OutgoingAttemptMetadata() (api.OutgoingAttemptMetadata, bool) {
	return w.metadata, true
}

func TestInternalAttemptMetadataIsHiddenFromPublicSetupCallback(t *testing.T) {
	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	writer := &attemptMetadataWriter{
		metadata: api.OutgoingAttemptMetadata{
			AttemptID:    "ship-internal-1",
			Scope:        internalOutgoingAttemptScope,
			ControlEpoch: 17,
		},
	}

	hub.SetupRemoteDevice("remote-ski", writer)
	reader.mu.Lock()
	publicWriter := reader.setupWriter
	reader.mu.Unlock()
	if publicWriter == nil {
		t.Fatal("public setup callback did not receive a writer")
	}
	if _, leaked := publicWriter.(api.OutgoingAttemptConnectionInterface); leaked {
		t.Fatal("internal outgoing attempt metadata leaked through public setup writer")
	}
	publicWriter.WriteShipMessageWithPayload([]byte("probe"))
}

func TestDelayedInternalPairingUpdateCannotFollowUnregister(t *testing.T) {
	const remoteSKI = "13579bdf2468ace013579bdf2468ace013579bdf"
	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)
	authority, eligible := hub.outboundReconnectAuthority(remote)
	if !eligible || authority == nil {
		t.Fatal("trusted service did not receive reconnect authority")
	}
	_, metadata, registered := hub.registerInternalOutboundAttemptForLaunch(remoteSKI, authority)
	if !registered {
		t.Fatal("register internal reconnect attempt")
	}

	hub.HandleShipHandshakeStateUpdateWithAttempt(
		remoteSKI,
		model.ShipState{State: model.SmeStateComplete},
		metadata,
	)
	hub.UnregisterRemoteSKI(remoteSKI)
	time.Sleep(650 * time.Millisecond)

	reader.mu.Lock()
	states := append([]api.ConnectionState(nil), reader.pairingStates...)
	reader.mu.Unlock()
	if len(states) == 0 || states[len(states)-1] != api.ConnectionStateNone {
		t.Fatalf("pairing states after unregister = %v, want terminal none", states)
	}
	for _, state := range states {
		if state == api.ConnectionStateCompleted {
			t.Fatalf("stale delayed pairing state published after unregister: %v", states)
		}
	}
}

var _ api.HubReaderInterface = (*attemptAwareHubReader)(nil)
var _ api.OutgoingAttemptHubReaderInterface = (*attemptAwareHubReader)(nil)
var _ api.OutgoingAttemptShipConnectionInfoProviderInterface = (*Hub)(nil)

type attemptCallbackConnection struct {
	ski string
}

func (*attemptCallbackConnection) DataHandler() api.WebsocketDataWriterInterface { return nil }
func (*attemptCallbackConnection) CloseConnection(bool, int, string)             {}
func (c *attemptCallbackConnection) RemoteSKI() string                           { return c.ski }
func (*attemptCallbackConnection) ApprovePendingHandshake()                      {}
func (*attemptCallbackConnection) AbortPendingHandshake()                        {}
func (*attemptCallbackConnection) ShipHandshakeState() (model.ShipMessageExchangeState, error) {
	return model.CmiStateInitStart, nil
}

func TestHubForwardsOutgoingAttemptTerminalAndHandshakeMetadata(t *testing.T) {
	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "attempt-52",
		Scope:        "remote-scope",
		ControlEpoch: 29,
	}
	connection := &attemptCallbackConnection{ski: "remote-ski"}
	state := model.ShipState{State: model.SmeStateError}

	hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
	hub.HandleShipHandshakeStateUpdateWithAttempt(connection.ski, state, metadata)

	closed, handshake := reader.snapshot()
	if len(closed) != 1 || closed[0] != metadata {
		t.Fatalf("terminal attempt metadata = %#v, want [%#v]", closed, metadata)
	}
	if len(handshake) != 1 || handshake[0] != metadata {
		t.Fatalf("handshake attempt metadata = %#v, want [%#v]", handshake, metadata)
	}
}

func TestAttemptAwareHandshakeDoesNotFallThroughToLegacyTrust(t *testing.T) {
	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	metadata := api.OutgoingAttemptMetadata{AttemptID: "stale-attempt", Scope: "remote-scope", ControlEpoch: 31}

	hub.HandleShipHandshakeStateUpdateWithAttempt(
		"remote-ski",
		model.ShipState{State: model.SmeHelloStateOk},
		metadata,
	)

	if hub.ServiceForSKI("remote-ski").Trusted() {
		t.Fatal("attempt-aware callback fell through to legacy SetTrusted(true)")
	}
	_, handshake := reader.snapshot()
	if len(handshake) != 1 || handshake[0] != metadata {
		t.Fatalf("attempt-aware handshake callbacks = %#v, want exact stale metadata once", handshake)
	}
}

func TestAttemptAwareCloseRemovesOnlyExactRegisteredConnection(t *testing.T) {
	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	oldConnection := &attemptCallbackConnection{ski: "remote-ski"}
	newConnection := &attemptCallbackConnection{ski: "remote-ski"}
	oldMetadata := api.OutgoingAttemptMetadata{AttemptID: "old", Scope: "remote-scope", ControlEpoch: 1}
	newMetadata := api.OutgoingAttemptMetadata{AttemptID: "new", Scope: "remote-scope", ControlEpoch: 1}

	hub.registerConnection(newConnection)
	hub.HandleConnectionClosedWithAttempt(oldConnection, false, oldMetadata)
	if got := hub.connectionForSKI("remote-ski"); got != newConnection {
		t.Fatalf("stale close changed active connection: got %#v, want %#v", got, newConnection)
	}

	hub.HandleConnectionClosedWithAttempt(newConnection, false, newMetadata)
	if got := hub.connectionForSKI("remote-ski"); got != nil {
		t.Fatalf("exact close left registered connection %#v", got)
	}
	closed, _ := reader.snapshot()
	if len(closed) != 2 || closed[0] != oldMetadata || closed[1] != newMetadata {
		t.Fatalf("close metadata = %#v, want stale then active", closed)
	}
}

func TestAttemptCallbacksFallBackToLegacyWhenReaderIsNotAware(t *testing.T) {
	hub := NewHub(&attemptTestHubReader{}, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	metadata := api.OutgoingAttemptMetadata{AttemptID: "attempt", Scope: "remote-scope", ControlEpoch: 3}

	hub.HandleShipHandshakeStateUpdateWithAttempt(
		"remote-ski",
		model.ShipState{State: model.SmeHelloStateOk},
		metadata,
	)

	if !hub.ServiceForSKI("remote-ski").Trusted() {
		t.Fatal("reader without optional interface did not receive legacy trust behavior")
	}
}
