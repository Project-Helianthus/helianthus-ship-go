package hub

import (
	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

type outgoingAttemptInfoProvider struct {
	hub          *Hub
	registration *outboundAttemptRegistration
}

func (provider *outgoingAttemptInfoProvider) IsRemoteServiceForSKIPaired(ski string) bool {
	return provider.hub.IsRemoteServiceForSKIPaired(ski)
}

func (provider *outgoingAttemptInfoProvider) IsAutoAcceptEnabled() bool {
	return provider.hub.IsAutoAcceptEnabled()
}

func (provider *outgoingAttemptInfoProvider) HandleConnectionClosed(
	connection api.ShipConnectionInterface,
	handshakeCompleted bool,
) {
	provider.hub.HandleConnectionClosed(connection, handshakeCompleted)
}

func (provider *outgoingAttemptInfoProvider) ReportServiceShipID(ski, shipID string) {
	if !provider.registration.beginCallback() {
		return
	}
	defer provider.registration.endCallback()
	if !provider.hub.outboundAttemptRegistrationOwnsCallbacks(provider.registration) {
		return
	}
	provider.hub.ReportServiceShipID(ski, shipID)
}

func (provider *outgoingAttemptInfoProvider) AllowWaitingForTrust(ski string) bool {
	if !provider.registration.beginCallback() {
		return false
	}
	defer provider.registration.endCallback()
	if !provider.hub.outboundAttemptRegistrationOwnsCallbacks(provider.registration) {
		return false
	}
	return provider.hub.AllowWaitingForTrust(ski)
}

func (provider *outgoingAttemptInfoProvider) HandleShipHandshakeStateUpdate(
	ski string,
	state model.ShipState,
) {
	provider.hub.HandleShipHandshakeStateUpdate(ski, state)
}

func (provider *outgoingAttemptInfoProvider) SetupRemoteDevice(
	ski string,
	writer api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	if !provider.registration.beginCallback() {
		return nil
	}
	defer provider.registration.endCallback()
	if !provider.hub.outboundAttemptRegistrationOwnsCallbacks(provider.registration) {
		return nil
	}
	return provider.hub.SetupRemoteDevice(ski, writer)
}

func (provider *outgoingAttemptInfoProvider) HandleConnectionClosedWithAttempt(
	connection api.ShipConnectionInterface,
	handshakeCompleted bool,
	metadata api.OutgoingAttemptMetadata,
) {
	provider.hub.HandleConnectionClosedWithAttempt(connection, handshakeCompleted, metadata)
}

func (provider *outgoingAttemptInfoProvider) HandleShipHandshakeStateUpdateWithAttempt(
	ski string,
	state model.ShipState,
	metadata api.OutgoingAttemptMetadata,
) {
	if !provider.registration.beginCallback() {
		return
	}
	defer provider.registration.endCallback()
	if !provider.hub.outboundAttemptRegistrationOwnsCallbacks(provider.registration) {
		return
	}
	provider.hub.HandleShipHandshakeStateUpdateWithAttempt(ski, state, metadata)
}

func (h *Hub) outboundAttemptRegistrationOwnsCallbacks(
	registration *outboundAttemptRegistration,
) bool {
	if registration == nil {
		return false
	}
	h.muxAttemptGate.RLock()
	connection := registration.connection
	if connection == nil {
		h.muxAttemptGate.RUnlock()
		return false
	}
	remoteSKI := connection.RemoteSKI()
	_, active := h.outboundAttempts[remoteSKI][registration]
	active = active && registration.context.Err() == nil
	h.muxAttemptGate.RUnlock()
	if !active {
		return false
	}

	h.muxCon.Lock()
	defer h.muxCon.Unlock()
	if _, superseded := h.supersededConnections[connection]; superseded {
		return false
	}
	return h.connections[remoteSKI] == connection
}

var _ api.ShipConnectionInfoProviderInterface = (*outgoingAttemptInfoProvider)(nil)
var _ api.OutgoingAttemptShipConnectionInfoProviderInterface = (*outgoingAttemptInfoProvider)(nil)
