package ship

import (
	"errors"
	"sync"
	"testing"

	"github.com/enbility/ship-go/api"
	"github.com/enbility/ship-go/model"
)

type attemptCallbackRecord struct {
	kind     string
	ski      string
	metadata api.OutgoingAttemptMetadata
}

type attemptCallbackProvider struct {
	mu sync.Mutex

	baseClosed    int
	baseHandshake int
	attemptEvents []attemptCallbackRecord
}

func (*attemptCallbackProvider) IsRemoteServiceForSKIPaired(string) bool { return false }
func (*attemptCallbackProvider) IsAutoAcceptEnabled() bool               { return false }
func (*attemptCallbackProvider) ReportServiceShipID(string, string)      {}
func (*attemptCallbackProvider) AllowWaitingForTrust(string) bool        { return false }
func (*attemptCallbackProvider) SetupRemoteDevice(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
	return nil
}
func (p *attemptCallbackProvider) HandleConnectionClosed(api.ShipConnectionInterface, bool) {
	p.mu.Lock()
	p.baseClosed++
	p.mu.Unlock()
}
func (p *attemptCallbackProvider) HandleShipHandshakeStateUpdate(string, model.ShipState) {
	p.mu.Lock()
	p.baseHandshake++
	p.mu.Unlock()
}
func (p *attemptCallbackProvider) HandleConnectionClosedWithAttempt(connection api.ShipConnectionInterface, _ bool, metadata api.OutgoingAttemptMetadata) {
	p.mu.Lock()
	p.attemptEvents = append(p.attemptEvents, attemptCallbackRecord{
		kind:     "closed",
		ski:      connection.RemoteSKI(),
		metadata: metadata,
	})
	p.mu.Unlock()
}
func (p *attemptCallbackProvider) HandleShipHandshakeStateUpdateWithAttempt(ski string, _ model.ShipState, metadata api.OutgoingAttemptMetadata) {
	p.mu.Lock()
	p.attemptEvents = append(p.attemptEvents, attemptCallbackRecord{
		kind:     "handshake",
		ski:      ski,
		metadata: metadata,
	})
	p.mu.Unlock()
}
func (p *attemptCallbackProvider) snapshot() (int, int, []attemptCallbackRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.baseClosed, p.baseHandshake, append([]attemptCallbackRecord(nil), p.attemptEvents...)
}

var _ api.ShipConnectionInfoProviderInterface = (*attemptCallbackProvider)(nil)
var _ api.OutgoingAttemptShipConnectionInfoProviderInterface = (*attemptCallbackProvider)(nil)

type attemptCallbackWriter struct {
	reader api.WebsocketDataReaderInterface
}

func (w *attemptCallbackWriter) InitDataProcessing(reader api.WebsocketDataReaderInterface) {
	w.reader = reader
}
func (*attemptCallbackWriter) WriteMessageToWebsocketConnection([]byte) error { return nil }
func (*attemptCallbackWriter) CloseDataConnection(int, string)                {}
func (*attemptCallbackWriter) IsDataConnectionClosed() (bool, error)          { return false, nil }

func TestOutgoingConnectionCarriesAttemptMetadataIntoOptionalCallbacks(t *testing.T) {
	provider := &attemptCallbackProvider{}
	writer := &attemptCallbackWriter{}
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "attempt-41",
		Scope:        "peer-scope",
		ControlEpoch: 23,
	}
	connection := NewConnectionHandler(
		provider,
		writer,
		ShipRoleClient,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
		metadata,
	)

	attemptConnection, ok := any(connection).(api.OutgoingAttemptConnectionInterface)
	if !ok {
		t.Fatal("outgoing ShipConnection does not expose the optional attempt metadata interface")
	}
	gotMetadata, ok := attemptConnection.OutgoingAttemptMetadata()
	if !ok || gotMetadata != metadata {
		t.Fatalf("connection attempt metadata = %#v, %t; want %#v, true", gotMetadata, ok, metadata)
	}

	connection.ReportConnectionError(errors.New("synthetic terminal failure"))
	baseClosed, baseHandshake, events := provider.snapshot()
	if baseClosed != 1 || baseHandshake != 1 {
		t.Fatalf("legacy callback counts = closed:%d handshake:%d, want 1/1", baseClosed, baseHandshake)
	}
	if len(events) != 2 {
		t.Fatalf("attempt callback count = %d, want terminal and handshake callbacks", len(events))
	}
	for _, event := range events {
		if event.ski != "remote-ski" || event.metadata != metadata {
			t.Errorf("%s callback = ski:%q metadata:%#v, want exact outgoing attempt", event.kind, event.ski, event.metadata)
		}
	}
}

func TestIncomingConnectionKeepsLegacyCallbacksOnly(t *testing.T) {
	provider := &attemptCallbackProvider{}
	connection := NewConnectionHandler(
		provider,
		&attemptCallbackWriter{},
		ShipRoleServer,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
	)

	attemptConnection, ok := any(connection).(api.OutgoingAttemptConnectionInterface)
	if !ok {
		t.Fatal("ShipConnection should expose one additive metadata query interface")
	}
	metadata, hasAttempt := attemptConnection.OutgoingAttemptMetadata()
	if hasAttempt || metadata != (api.OutgoingAttemptMetadata{}) {
		t.Fatalf("incoming connection acquired outgoing metadata: %#v, %t", metadata, hasAttempt)
	}

	connection.ReportConnectionError(errors.New("synthetic incoming failure"))
	baseClosed, baseHandshake, events := provider.snapshot()
	if baseClosed != 1 || baseHandshake != 1 {
		t.Fatalf("incoming legacy callback counts = closed:%d handshake:%d, want 1/1", baseClosed, baseHandshake)
	}
	if len(events) != 0 {
		t.Fatalf("incoming connection emitted %d outgoing attempt callbacks", len(events))
	}
}

func TestAttemptIdentityMakesStaleCallbacksDiscardable(t *testing.T) {
	provider := &attemptCallbackProvider{}
	oldMetadata := api.OutgoingAttemptMetadata{AttemptID: "attempt-old", Scope: "peer-scope", ControlEpoch: 4}
	activeMetadata := api.OutgoingAttemptMetadata{AttemptID: "attempt-active", Scope: "peer-scope", ControlEpoch: 4}
	oldConnection := NewConnectionHandler(
		provider, &attemptCallbackWriter{}, ShipRoleClient,
		"local-ship-id", "remote-ski", "remote-ship-id", oldMetadata,
	)
	activeConnection := NewConnectionHandler(
		provider, &attemptCallbackWriter{}, ShipRoleClient,
		"local-ship-id", "remote-ski", "remote-ship-id", activeMetadata,
	)

	oldConnection.ReportConnectionError(errors.New("delayed old callback"))
	activeConnection.ReportConnectionError(errors.New("active callback"))
	_, _, events := provider.snapshot()
	if len(events) != 4 {
		t.Fatalf("attempt callback count = %d, want two callbacks per attempt", len(events))
	}
	var stale, active int
	for _, event := range events {
		switch event.metadata.AttemptID {
		case oldMetadata.AttemptID:
			stale++
		case activeMetadata.AttemptID:
			active++
		default:
			t.Errorf("callback carried unknown attempt identity %q", event.metadata.AttemptID)
		}
	}
	if stale != 2 || active != 2 {
		t.Fatalf("stale/active callback identities = %d/%d, want 2/2", stale, active)
	}
}
