package hub

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
)

// Provide the current pairing state for a SKI
//
// returns:
//
//	ErrNotPaired if the SKI is not in the (to be) paired list
//	ErrNoConnectionFound if no connection for the SKI was found
func (h *Hub) PairingDetailForSki(ski string) *api.ConnectionStateDetail {
	service := h.ServiceForSKI(ski)

	if conn := h.connectionForSKI(ski); conn != nil {
		shipState, shipError := conn.ShipHandshakeState()
		state := h.mapShipMessageExchangeState(shipState, ski)
		return api.NewConnectionStateDetail(state, shipError)
	}

	return service.ConnectionStateDetail()
}

// maps ShipMessageExchangeState to PairingState
func (h *Hub) mapShipMessageExchangeState(state model.ShipMessageExchangeState, _ string) api.ConnectionState {
	var connState api.ConnectionState

	// map the SHIP states to a public ConnectionState
	switch state {
	case model.CmiStateInitStart:
		connState = api.ConnectionStateQueued
	case model.CmiStateClientSend, model.CmiStateClientWait, model.CmiStateClientEvaluate,
		model.CmiStateServerWait, model.CmiStateServerEvaluate:
		connState = api.ConnectionStateInitiated
	case model.SmeHelloStateReadyInit, model.SmeHelloStateReadyListen, model.SmeHelloStateReadyTimeout,
		model.SmeHelloStatePendingInit, model.SmeHelloStatePendingTimeout:
		connState = api.ConnectionStateInProgress
	case model.SmeHelloStatePendingListen:
		connState = api.ConnectionStateReceivedPairingRequest
	case model.SmeHelloStateOk:
		connState = api.ConnectionStateTrusted
	case model.SmeHelloStateAbort, model.SmeHelloStateAbortDone:
		connState = api.ConnectionStateNone
	case model.SmeHelloStateRemoteAbortDone, model.SmeHelloStateRejected:
		connState = api.ConnectionStateRemoteDeniedTrust
	case model.SmePinStateCheckInit, model.SmePinStateCheckListen, model.SmePinStateCheckError,
		model.SmePinStateCheckBusyInit, model.SmePinStateCheckBusyWait, model.SmePinStateCheckOk,
		model.SmePinStateAskInit, model.SmePinStateAskProcess, model.SmePinStateAskRestricted,
		model.SmePinStateAskOk:
		connState = api.ConnectionStatePin
	case model.SmeAccessMethodsRequest, model.SmeStateApproved:
		connState = api.ConnectionStateInProgress
	case model.SmeStateComplete:
		connState = api.ConnectionStateCompleted
	case model.SmeStateError:
		connState = api.ConnectionStateError
	default:
		connState = api.ConnectionStateInProgress
	}

	return connState
}

func (h *Hub) SetAutoAccept(autoaccept bool) {
	h.muxReg.Lock()
	defer h.muxReg.Unlock()

	h.autoaccept = autoaccept

	h.mdns.SetAutoAccept(autoaccept)
}

// SetPairingRegistration changes only the SHIP mDNS registration signal.
// Manual approval flows use it to advertise availability without enabling
// automatic handshake acceptance.
func (h *Hub) SetPairingRegistration(available bool) error {
	h.muxReg.Lock()
	setter, ok := h.mdns.(api.PairingRegistrationSetter)
	if !ok {
		h.muxReg.Unlock()
		return errors.New("mDNS does not support pairing registration")
	}
	if err := setter.SetPairingRegistration(available); err != nil {
		h.muxReg.Unlock()
		return err
	}
	h.pairingRegistration = available
	if available {
		h.muxReg.Unlock()
		return nil
	}

	candidates := make(map[string]*api.ServiceDetails, len(h.pairingCandidates))
	for ski := range h.pairingCandidates {
		if service := h.remoteServices[ski]; service != nil {
			candidates[ski] = service
		}
		delete(h.pairingCandidates, ski)
	}
	h.muxReg.Unlock()

	for ski, service := range candidates {
		h.retirePairingCandidate(ski, service)
	}
	return nil
}

// QueuePairingCandidate admits one OOB-validated SKI for locally initiated
// pairing. The concrete endpoint is resolved only from the mDNS manager's
// current observations, and trust remains false until RegisterRemoteSKI.
func (h *Hub) QueuePairingCandidate(ski string) error {
	normalized, err := validPairingCandidateSKI(ski)
	if err != nil {
		return err
	}
	if h.configuredOutgoingAttemptGate() == nil {
		return api.ErrOutgoingAttemptGateRequired
	}

	h.muxReg.Lock()
	if !h.pairingRegistration {
		h.muxReg.Unlock()
		return api.ErrPairingRegistrationClosed
	}
	service := h.remoteServices[normalized]
	if service == nil {
		service = api.NewServiceDetails(normalized)
		h.remoteServices[normalized] = service
	}
	if service.Trusted() {
		h.muxReg.Unlock()
		return api.ErrRemoteAlreadyTrusted
	}
	h.pairingCandidates[normalized] = struct{}{}
	service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	h.muxReg.Unlock()

	if h.hubReader != nil {
		h.hubReader.ServicePairingDetailUpdate(normalized, service.ConnectionStateDetail())
	}
	if h.checkHasStarted() && h.mdns != nil {
		h.mdns.RequestMdnsEntries()
	}
	return nil
}

func validPairingCandidateSKI(ski string) (string, error) {
	normalized := util.NormalizeSKI(strings.TrimSpace(ski))
	if len(normalized) != 40 {
		return "", api.ErrInvalidRemoteSKI
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != 20 {
		return "", api.ErrInvalidRemoteSKI
	}
	return normalized, nil
}

func (h *Hub) retirePairingCandidate(ski string, service *api.ServiceDetails) {
	h.revokeOutboundAttempts(ski, service)
	h.removeConnectionAttemptCounter(ski)
	if existing := h.connectionForSKI(ski); existing != nil {
		existing.AbortPendingHandshake()
	}
	if h.hubReader != nil {
		h.hubReader.ServicePairingDetailUpdate(ski, service.ConnectionStateDetail())
	}
}

// check if auto accept is true
func (h *Hub) IsAutoAcceptEnabled() bool {
	h.muxReg.Lock()
	defer h.muxReg.Unlock()

	return h.autoaccept
}

func (h *Hub) checkHasStarted() bool {
	h.muxStarted.Lock()
	defer h.muxStarted.Unlock()
	return h.hasStarted
}

// Sets the SKI as being paired or not
// Should be used for services which completed the pairing process and
// which were stored as having the process completed
func (h *Hub) RegisterRemoteSKI(ski string) {
	ski = util.NormalizeSKI(ski)
	service := h.ServiceForSKI(ski)
	service.SetTrusted(true)
	h.muxReg.Lock()
	delete(h.pairingCandidates, ski)
	h.muxReg.Unlock()

	// if the hub has not started, simply add it
	if !h.checkHasStarted() {
		h.checkAutoReannounce()
		return
	}

	// if the hub has started, trigger a search and connection attempt
	conn := h.connectionForSKI(ski)

	// remotely initiated?
	if conn != nil {
		conn.ApprovePendingHandshake()

		return
	}

	// locally initiated
	service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)

	h.hubReader.ServicePairingDetailUpdate(ski, service.ConnectionStateDetail())

	h.mdns.RequestMdnsEntries()
}

// Remove pairing for the SKI
func (h *Hub) UnregisterRemoteSKI(ski string) {
	ski = util.NormalizeSKI(ski)
	service := h.ServiceForSKI(ski)
	h.muxReg.Lock()
	delete(h.pairingCandidates, ski)
	h.muxReg.Unlock()
	h.revokeOutboundAttempts(ski, service)

	h.removeConnectionAttemptCounter(ski)

	h.hubReader.ServicePairingDetailUpdate(ski, service.ConnectionStateDetail())

	if existingC := h.connectionForSKI(ski); existingC != nil {
		existingC.CloseConnection(true, 4500, "User close")
	}
}

// Disconnect a connection to an SKI, used by a service implementation
// e.g. if heartbeats go wrong
func (h *Hub) DisconnectSKI(ski string, reason string) {
	con := h.connectionForSKI(ski)
	if con == nil {
		return
	}

	con.CloseConnection(true, 0, reason)
}

// Cancels the pairing process for a SKI
func (h *Hub) CancelPairingWithSKI(ski string) {
	ski = util.NormalizeSKI(ski)
	service := h.ServiceForSKI(ski)
	h.muxReg.Lock()
	delete(h.pairingCandidates, ski)
	h.muxReg.Unlock()
	h.revokeOutboundAttempts(ski, service)
	h.removeConnectionAttemptCounter(ski)

	if existingC := h.connectionForSKI(ski); existingC != nil {
		existingC.AbortPendingHandshake()
	}

	h.hubReader.ServicePairingDetailUpdate(ski, service.ConnectionStateDetail())
}
