package hub

import (
	"crypto/tls"
	"sync"
	"testing"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/model"
)

type attemptAwareHubReader struct {
	mu sync.Mutex

	closedMetadata    []api.OutgoingAttemptMetadata
	handshakeMetadata []api.OutgoingAttemptMetadata
}

func (*attemptAwareHubReader) RemoteSKIConnected(string)    {}
func (*attemptAwareHubReader) RemoteSKIDisconnected(string) {}
func (*attemptAwareHubReader) SetupRemoteDevice(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
	return nil
}
func (*attemptAwareHubReader) VisibleRemoteServicesUpdated([]api.RemoteService) {}
func (*attemptAwareHubReader) ServiceShipIDUpdate(string, string)               {}
func (*attemptAwareHubReader) ServicePairingDetailUpdate(string, *api.ConnectionStateDetail) {
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
