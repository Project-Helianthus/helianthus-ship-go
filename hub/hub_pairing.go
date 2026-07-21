package hub

import (
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"

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
	h.muxReg.Unlock()
	return nil
}

// QueuePairingCandidate consumes one exact mDNS observation after the operator
// validates its claimed SKI out of band. The endpoint is frozen from discovery,
// never accepted as input, and trust remains false until RegisterRemoteSKI.
func (h *Hub) QueuePairingCandidate(candidateRef, expectedSKI string) error {
	validatedSKI, err := validPairingCandidateSKI(expectedSKI)
	if err != nil {
		return err
	}

	h.muxReg.Lock()
	if _, consumed := h.consumedPairingCandidates[candidateRef]; consumed {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateConsumed
	}
	entry, exists := h.visiblePairingCandidates[candidateRef]
	if !exists {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateUnavailable
	}
	if entry.ski != validatedSKI {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateSKIMismatch
	}
	host, ok := pairingCandidateAddress(entry.addresses)
	if !ok || entry.port <= 0 || entry.port > 65535 || entry.path == "" {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateUnavailable
	}
	service := h.remoteServices[validatedSKI]
	if service == nil {
		service = api.NewServiceDetails(validatedSKI)
		h.remoteServices[validatedSKI] = service
	}
	if service.Trusted() {
		h.muxReg.Unlock()
		return api.ErrRemoteAlreadyTrusted
	}
	if h.activePairingCandidates[validatedSKI] != nil {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateActive
	}
	h.muxReg.Unlock()

	if h.configuredOutgoingAttemptGate() == nil {
		return api.ErrOutgoingAttemptGateRequired
	}

	h.muxReg.Lock()
	// Revalidate after the gate lookup so a newer discovery report cannot swap
	// the capability while selection is being admitted.
	current, exists := h.visiblePairingCandidates[candidateRef]
	if !exists || current.ski != validatedSKI || current.revision != entry.revision {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateUnavailable
	}
	if _, consumed := h.consumedPairingCandidates[candidateRef]; consumed {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateConsumed
	}
	if service.Trusted() {
		h.muxReg.Unlock()
		return api.ErrRemoteAlreadyTrusted
	}
	if h.activePairingCandidates[validatedSKI] != nil {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateActive
	}
	h.consumedPairingCandidates[candidateRef] = struct{}{}
	h.muxAttemptGate.Lock()
	candidateAuthority := h.currentOutboundAuthorityLocked(validatedSKI)
	h.muxAttemptGate.Unlock()
	activeCandidate := &activePairingCandidate{
		service:   service,
		authority: candidateAuthority,
	}
	h.activePairingCandidates[validatedSKI] = activeCandidate
	service.SetShipID("")
	service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	h.muxReg.Unlock()

	if h.hubReader != nil {
		h.hubReader.ServicePairingDetailUpdate(validatedSKI, service.ConnectionStateDetail())
	}

	port := strconv.Itoa(entry.port)
	path := entry.path
	h.launchPairingCandidate(func() {
		h.muxReg.Lock()
		active := h.activePairingCandidates[validatedSKI] == activeCandidate
		h.muxReg.Unlock()
		if !active {
			return
		}
		if err := h.connectFoundPairingCandidate(service, host, port, path, validatedSKI, candidateAuthority); err != nil {
			h.retirePairingCandidate(validatedSKI, activeCandidate, nil)
		}
	})
	return nil
}

func validPairingCandidateSKI(ski string) (string, error) {
	if len(ski) != 40 {
		return "", api.ErrInvalidRemoteSKI
	}
	decoded, err := hex.DecodeString(ski)
	if err != nil || len(decoded) != 20 || ski != hex.EncodeToString(decoded) {
		return "", api.ErrInvalidRemoteSKI
	}
	return ski, nil
}

func pairingCandidateAddress(addresses []net.IP) (string, bool) {
	values := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address == nil || address.IsUnspecified() || address.IsMulticast() {
			continue
		}
		values = append(values, address.String())
	}
	if len(values) == 0 {
		return "", false
	}
	sort.Slice(values, func(left, right int) bool {
		leftIP := net.ParseIP(values[left])
		rightIP := net.ParseIP(values[right])
		if (leftIP.To4() != nil) != (rightIP.To4() != nil) {
			return leftIP.To4() != nil
		}
		return values[left] < values[right]
	})
	return values[0], true
}

func (h *Hub) retirePairingCandidate(
	ski string,
	expectedCandidate *activePairingCandidate,
	expectedAuthority *outboundAttemptAuthority,
) {
	h.muxReg.Lock()
	h.muxAttemptGate.Lock()
	retirement := h.retireActivePairingCandidateLocked(ski, expectedCandidate, expectedAuthority)
	var cancellations []*outboundAttemptRegistration
	if retirement != nil {
		cancellations = h.removeOutboundAttemptRegistrationsLocked(ski)
	}
	h.muxAttemptGate.Unlock()
	h.removeOutboundAttemptConnections(cancellations)
	h.muxReg.Unlock()

	cancelOutboundAttemptRegistrations(cancellations)
	if retirement != nil {
		h.finishPairingCandidateRetirements([]pairingCandidateRetirement{*retirement})
	}
}

// retireActivePairingCandidateLocked requires muxReg and muxAttemptGate. Trust
// approval uses muxReg too, making durable approval and retirement linearizable.
func (h *Hub) retireActivePairingCandidateLocked(
	ski string,
	expectedCandidate *activePairingCandidate,
	expectedAuthority *outboundAttemptAuthority,
) *pairingCandidateRetirement {
	active := h.activePairingCandidates[ski]
	if active == nil ||
		(expectedCandidate != nil && active != expectedCandidate) ||
		(expectedAuthority != nil && active.authority != expectedAuthority) ||
		active.service.Trusted() {
		return nil
	}

	h.beforePairingCandidateRetire()
	h.rotateOutboundAuthorityLocked(ski)
	active.service.ConnectionStateDetail().SetState(api.ConnectionStateNone)
	delete(h.activePairingCandidates, ski)
	return &pairingCandidateRetirement{ski: ski, service: active.service}
}

func (h *Hub) finishPairingCandidateRetirements(retirements []pairingCandidateRetirement) {
	for _, retirement := range retirements {
		h.removeConnectionAttemptCounter(retirement.ski)
		if h.hubReader != nil {
			h.hubReader.ServicePairingDetailUpdate(
				retirement.ski,
				retirement.service.ConnectionStateDetail(),
			)
		}
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
	h.muxReg.Lock()
	service.SetTrusted(true)
	delete(h.activePairingCandidates, ski)
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
	h.revokeOutboundAttempts(ski, service)
	h.removeConnectionAttemptCounter(ski)

	if existingC := h.connectionForSKI(ski); existingC != nil {
		existingC.AbortPendingHandshake()
	}

	h.hubReader.ServicePairingDetailUpdate(ski, service.ConnectionStateDetail())
}
