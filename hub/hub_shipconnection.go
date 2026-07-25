package hub

import (
	"errors"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
)

var _ api.ShipConnectionInfoProviderInterface = (*Hub)(nil)
var _ api.OutgoingAttemptShipConnectionInfoProviderInterface = (*Hub)(nil)

// check if the SKI is paired
func (h *Hub) IsRemoteServiceForSKIPaired(ski string) bool {
	service := h.ServiceForSKI(ski)

	return service.Trusted()
}

// report closing of a connection and if handshake did complete
func (h *Hub) HandleConnectionClosed(connection api.ShipConnectionInterface, handshakeCompleted bool) {
	remoteSki := connection.RemoteSKI()

	if h.claimSupersededConnection(connection) {
		return
	}
	// only remove this connection if it is the registered one for the ski!
	// as we can have double connections but only one can be registered
	if !h.removeExactConnection(connection) {
		return
	}
	// connection close was after a completed handshake, so we can reset the attetmpt counter
	if handshakeCompleted {
		h.removeConnectionAttemptCounter(remoteSki)
	}

	h.hubReader.RemoteSKIDisconnected(remoteSki)

	// Do not automatically reconnect if handshake failed and not already paired
	remoteService := h.ServiceForSKI(remoteSki)
	if !handshakeCompleted && !remoteService.Trusted() {
		return
	}

	h.checkAutoReannounce()
}

func (h *Hub) HandleConnectionClosedWithAttempt(
	connection api.ShipConnectionInterface,
	handshakeCompleted bool,
	metadata api.OutgoingAttemptMetadata,
) {
	remoteSKI := connection.RemoteSKI()
	retirement, superseded := h.claimClosedOutboundAttempt(remoteSKI, connection, metadata)
	if superseded {
		return
	}
	if retirement != nil {
		h.finishPairingCandidateRetirements([]pairingCandidateRetirement{*retirement})
	}
	if metadata.Scope == internalOutgoingAttemptScope {
		if handshakeCompleted {
			h.removeConnectionAttemptCounter(remoteSKI)
		}
		h.hubReader.RemoteSKIDisconnected(remoteSKI)
		if handshakeCompleted || h.IsRemoteServiceForSKIPaired(remoteSKI) {
			h.checkAutoReannounce()
		}
		return
	}
	if reader, ok := h.hubReader.(api.OutgoingAttemptHubReaderInterface); ok {
		reader.OutgoingAttemptConnectionClosed(remoteSKI, handshakeCompleted, metadata)
		if handshakeCompleted || h.IsRemoteServiceForSKIPaired(remoteSKI) {
			h.checkAutoReannounce()
		}
		return
	}
	h.HandleConnectionClosed(connection, handshakeCompleted)
}

func (h *Hub) claimClosedOutboundAttempt(
	remoteSKI string,
	connection api.ShipConnectionInterface,
	metadata api.OutgoingAttemptMetadata,
) (*pairingCandidateRetirement, bool) {
	h.muxReg.Lock()
	h.muxAttemptGate.Lock()
	superseded := h.claimSupersededConnection(connection)
	h.removeExactConnection(connection)
	if h.testHooks != nil && h.testHooks.beforeOutboundAttemptRelease != nil {
		h.testHooks.beforeOutboundAttemptRelease()
	}
	removed, releasedAuthority := h.releaseOutboundAttemptForConnectionLocked(remoteSKI, connection, metadata)
	var retirement *pairingCandidateRetirement
	if !superseded && releasedAuthority != nil {
		retirement = h.retireActivePairingCandidateLocked(remoteSKI, nil, releasedAuthority)
	}
	h.muxAttemptGate.Unlock()
	h.muxReg.Unlock()

	cancelOutboundAttemptRegistrations(removed)
	return retirement, superseded
}

func (h *Hub) claimSupersededConnection(connection api.ShipConnectionInterface) bool {
	h.muxCon.Lock()
	defer h.muxCon.Unlock()
	_, superseded := h.supersededConnections[connection]
	return superseded
}

func (h *Hub) removeExactConnection(connection api.ShipConnectionInterface) bool {
	remoteSKI := connection.RemoteSKI()

	h.muxCon.Lock()
	existing := h.connections[remoteSKI]
	if existing != connection {
		h.muxCon.Unlock()
		return false
	}
	delete(h.connections, remoteSKI)
	h.muxCon.Unlock()
	return true
}

// report the ship ID provided during the handshake
func (h *Hub) ReportServiceShipID(ski string, shipdID string) {
	h.hubReader.RemoteSKIConnected(ski)

	h.hubReader.ServiceShipIDUpdate(ski, shipdID)
}

// check if the user is still able to trust the connection
func (h *Hub) AllowWaitingForTrust(ski string) bool {
	if service := h.ServiceForSKI(ski); service != nil {
		if service.Trusted() {
			return true
		}
	}

	return h.hubReader.AllowWaitingForTrust(ski)
}

// report the updated SHIP handshake state and optional error message for a SKI
func (h *Hub) HandleShipHandshakeStateUpdate(ski string, state model.ShipState) {
	// overwrite service Paired value
	if state.State == model.SmeHelloStateOk {
		service := h.ServiceForSKI(ski)
		h.muxReg.Lock()
		service.SetTrusted(true)
		delete(h.activePairingCandidates, ski)
		h.muxReg.Unlock()
	}

	pairingState := h.mapShipMessageExchangeState(state.State, ski)
	if state.Error != nil && !errors.Is(state.Error, api.ErrConnectionNotFound) {
		pairingState = api.ConnectionStateError
	}

	pairingDetail := api.NewConnectionStateDetail(pairingState, state.Error)

	service := h.ServiceForSKI(ski)

	existingDetails := service.ConnectionStateDetail()
	existingState := existingDetails.State()
	if existingState != pairingState || !errors.Is(existingDetails.Error(), state.Error) {
		service.SetConnectionStateDetail(pairingDetail)

		// always send a delayed update, as the processing of the new state has to be done
		// and the SHIP message has to be received by the other service before
		// acting upon the new state is safe
		go h.publishCurrentPairingDetailAfterDelay(ski, pairingDetail, api.OutgoingAttemptMetadata{}, false)
	}
}

func (h *Hub) HandleShipHandshakeStateUpdateWithAttempt(
	ski string,
	state model.ShipState,
	metadata api.OutgoingAttemptMetadata,
) {
	if metadata.Scope == internalOutgoingAttemptScope {
		h.handleInternalShipHandshakeStateUpdate(ski, state, metadata)
		return
	}
	if reader, ok := h.hubReader.(api.OutgoingAttemptHubReaderInterface); ok {
		reader.OutgoingAttemptHandshakeStateUpdate(ski, state, metadata)
		return
	}
	h.HandleShipHandshakeStateUpdate(ski, state)
}

func (h *Hub) handleInternalShipHandshakeStateUpdate(
	ski string,
	state model.ShipState,
	metadata api.OutgoingAttemptMetadata,
) {
	ski = util.NormalizeSKI(ski)
	pairingState := h.mapShipMessageExchangeState(state.State, ski)
	if state.Error != nil && !errors.Is(state.Error, api.ErrConnectionNotFound) {
		pairingState = api.ConnectionStateError
	}
	pairingDetail := api.NewConnectionStateDetail(pairingState, state.Error)

	h.muxReg.Lock()
	h.muxAttemptGate.RLock()
	if !h.internalOutboundAttemptActiveLocked(ski, metadata) {
		h.muxAttemptGate.RUnlock()
		h.muxReg.Unlock()
		return
	}
	service := h.remoteServices[ski]
	existingDetails := service.ConnectionStateDetail()
	changed := existingDetails.State() != pairingState || !errors.Is(existingDetails.Error(), state.Error)
	if changed {
		service.SetConnectionStateDetail(pairingDetail)
	}
	h.muxAttemptGate.RUnlock()
	h.muxReg.Unlock()

	if changed {
		go h.publishCurrentPairingDetailAfterDelay(ski, pairingDetail, metadata, true)
	}
}

func (h *Hub) publishCurrentPairingDetailAfterDelay(
	ski string,
	detail *api.ConnectionStateDetail,
	metadata api.OutgoingAttemptMetadata,
	requireInternalAttempt bool,
) {
	<-time.After(time.Millisecond * 500)

	h.muxReg.Lock()
	if requireInternalAttempt {
		h.muxAttemptGate.RLock()
		if !h.internalOutboundAttemptActiveLocked(ski, metadata) {
			h.muxAttemptGate.RUnlock()
			h.muxReg.Unlock()
			return
		}
	}
	service := h.remoteServices[ski]
	current := service != nil && pairingDetailsEqual(service.ConnectionStateDetail(), detail)
	if !current {
		if requireInternalAttempt {
			h.muxAttemptGate.RUnlock()
		}
		h.muxReg.Unlock()
		return
	}
	shouldDrain := h.enqueuePairingDetailLocked(ski, detail)
	if requireInternalAttempt {
		h.muxAttemptGate.RUnlock()
	}
	h.muxReg.Unlock()
	if shouldDrain {
		h.drainPairingNotifications()
	}
}

func pairingDetailsEqual(left, right *api.ConnectionStateDetail) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.State() == right.State() && errors.Is(left.Error(), right.Error())
}

func snapshotPairingDetail(detail *api.ConnectionStateDetail) *api.ConnectionStateDetail {
	if detail == nil {
		return nil
	}
	return api.NewConnectionStateDetail(detail.State(), detail.Error())
}

func (h *Hub) publishPairingDetail(ski string, detail *api.ConnectionStateDetail) {
	if h.hubReader == nil {
		return
	}
	h.pairingNotificationMux.Lock()
	shouldDrain := h.enqueuePairingDetailLockedWithoutMutex(ski, snapshotPairingDetail(detail))
	h.pairingNotificationMux.Unlock()
	if shouldDrain {
		h.drainPairingNotifications()
	}
}

// enqueuePairingDetailLocked is called while the state locks establishing the
// notification order are held.
func (h *Hub) enqueuePairingDetailLocked(ski string, detail *api.ConnectionStateDetail) bool {
	h.pairingNotificationMux.Lock()
	defer h.pairingNotificationMux.Unlock()
	return h.enqueuePairingDetailLockedWithoutMutex(ski, snapshotPairingDetail(detail))
}

func (h *Hub) enqueuePairingDetailLockedWithoutMutex(
	ski string,
	detail *api.ConnectionStateDetail,
) bool {
	h.pairingNotificationQueue = append(h.pairingNotificationQueue, func() {
		h.hubReader.ServicePairingDetailUpdate(ski, detail)
	})
	if h.pairingNotificationDraining {
		return false
	}
	h.pairingNotificationDraining = true
	return true
}

func (h *Hub) drainPairingNotifications() {
	for {
		h.pairingNotificationMux.Lock()
		if len(h.pairingNotificationQueue) == 0 {
			h.pairingNotificationDraining = false
			h.pairingNotificationMux.Unlock()
			return
		}
		task := h.pairingNotificationQueue[0]
		h.pairingNotificationQueue[0] = nil
		h.pairingNotificationQueue = h.pairingNotificationQueue[1:]
		h.pairingNotificationMux.Unlock()
		task()
	}
}

type publicShipDataWriter struct {
	writer api.ShipConnectionDataWriterInterface
}

func (w publicShipDataWriter) WriteShipMessageWithPayload(message []byte) {
	w.writer.WriteShipMessageWithPayload(message)
}

// report an approved handshake by a remote device
func (h *Hub) SetupRemoteDevice(ski string, writeI api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
	if attempt, ok := writeI.(api.OutgoingAttemptConnectionInterface); ok {
		if metadata, hasMetadata := attempt.OutgoingAttemptMetadata(); hasMetadata &&
			metadata.Scope == internalOutgoingAttemptScope {
			writeI = publicShipDataWriter{writer: writeI}
		}
	}
	return h.hubReader.SetupRemoteDevice(ski, writeI)
}
