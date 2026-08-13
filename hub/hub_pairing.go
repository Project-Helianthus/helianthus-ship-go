package hub

import (
	"crypto/rand"
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
	h.muxReg.Unlock()
	return nil
}

type pairingCandidateLaunch struct {
	ski       string
	service   *api.ServiceDetails
	candidate *activePairingCandidate
}

// SelectPairingCandidate consumes and freezes one exact mDNS observation after
// the operator validates its claimed SKI. It grants neither trust nor an
// outbound attempt; the returned process-local reservation is the only later
// connect authority.
func (h *Hub) SelectPairingCandidate(candidateRef, expectedSKI string) (api.PairingCandidateReservation, error) {
	reservation, _, err := h.admitPairingCandidate(candidateRef, expectedSKI, false)
	return reservation, err
}

// QueuePairingCandidate preserves the original combined select-and-connect
// behavior for existing dependency consumers.
func (h *Hub) QueuePairingCandidate(candidateRef, expectedSKI string) error {
	_, launch, err := h.admitPairingCandidate(candidateRef, expectedSKI, true)
	if err != nil {
		return err
	}
	h.launchPairingCandidate(launch)
	return nil
}

func (h *Hub) admitPairingCandidate(
	candidateRef string,
	expectedSKI string,
	connect bool,
) (api.PairingCandidateReservation, *pairingCandidateLaunch, error) {
	validatedSKI, err := validPairingCandidateSKI(expectedSKI)
	if err != nil {
		return api.PairingCandidateReservation{}, nil, err
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return api.PairingCandidateReservation{}, nil, api.ErrPairingCandidateReservationUnavailable
	}
	reservation := api.NewPairingCandidateReservation(token)

	h.muxReg.Lock()
	if _, consumed := h.consumedPairingCandidates[candidateRef]; consumed {
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrPairingCandidateConsumed
	}
	entry, exists := h.visiblePairingCandidates[candidateRef]
	if !exists {
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrPairingCandidateUnavailable
	}
	if entry.ski != validatedSKI {
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrPairingCandidateSKIMismatch
	}
	host, ok := pairingCandidateAddress(entry.addresses)
	if !ok || entry.port <= 0 || entry.port > 65535 || entry.path == "" {
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrPairingCandidateUnavailable
	}
	service := h.remoteServices[validatedSKI]
	if service == nil {
		service = api.NewServiceDetails(validatedSKI)
		h.remoteServices[validatedSKI] = service
	}
	if service.Trusted() {
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrRemoteAlreadyTrusted
	}
	if h.activePairingCandidates[validatedSKI] != nil {
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrPairingCandidateActive
	}
	if h.testHooks != nil && h.testHooks.beforePairingCandidateAdmission != nil {
		h.testHooks.beforePairingCandidateAdmission()
	}
	h.muxAttemptGate.Lock()
	if connect && (h.outgoingAttemptGate == nil || isNilOutgoingAttemptValue(h.outgoingAttemptGate)) {
		h.muxAttemptGate.Unlock()
		h.muxReg.Unlock()
		return api.PairingCandidateReservation{}, nil, api.ErrOutgoingAttemptGateRequired
	}
	h.consumedPairingCandidates[candidateRef] = struct{}{}
	candidateAuthority := h.rotateOutboundAuthorityLocked(validatedSKI)
	activeCandidate := &activePairingCandidate{
		service:       service,
		authority:     candidateAuthority,
		reservation:   reservation,
		host:          host,
		port:          strconv.Itoa(entry.port),
		path:          entry.path,
		connectIssued: connect,
	}
	h.activePairingCandidates[validatedSKI] = activeCandidate
	service.SetShipID("")
	if connect {
		service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	}
	h.muxAttemptGate.Unlock()
	h.muxReg.Unlock()

	if !connect {
		return reservation, nil, nil
	}
	return reservation, &pairingCandidateLaunch{
		ski: validatedSKI, service: service, candidate: activeCandidate,
	}, nil
}

// ConnectPairingCandidate launches one outbound attempt for the exact current
// selection. It never accepts an endpoint or identity from the caller.
func (h *Hub) ConnectPairingCandidate(reservation api.PairingCandidateReservation) error {
	if !reservation.Valid() {
		return api.ErrPairingCandidateReservationStale
	}
	h.muxReg.Lock()
	var ski string
	var activeCandidate *activePairingCandidate
	for candidateSKI, candidate := range h.activePairingCandidates {
		if candidate != nil && candidate.reservation.Matches(reservation) {
			ski = candidateSKI
			activeCandidate = candidate
			break
		}
	}
	if activeCandidate == nil || activeCandidate.service == nil || activeCandidate.service.Trusted() {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateReservationStale
	}
	if activeCandidate.connectIssued {
		h.muxReg.Unlock()
		return api.ErrPairingCandidateAlreadyConnecting
	}
	h.muxAttemptGate.Lock()
	if h.outgoingAttemptGate == nil || isNilOutgoingAttemptValue(h.outgoingAttemptGate) {
		h.muxAttemptGate.Unlock()
		h.muxReg.Unlock()
		return api.ErrOutgoingAttemptGateRequired
	}
	activeCandidate.connectIssued = true
	activeCandidate.service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	launch := &pairingCandidateLaunch{
		ski: ski, service: activeCandidate.service, candidate: activeCandidate,
	}
	h.muxAttemptGate.Unlock()
	h.muxReg.Unlock()

	h.launchPairingCandidate(launch)
	return nil
}

func (h *Hub) launchPairingCandidate(candidateLaunch *pairingCandidateLaunch) {
	if candidateLaunch == nil || candidateLaunch.candidate == nil || candidateLaunch.service == nil {
		return
	}
	ski := candidateLaunch.ski
	activeCandidate := candidateLaunch.candidate
	service := candidateLaunch.service
	h.publishPairingDetail(ski, service.ConnectionStateDetail())

	launch := func(run func()) { go run() }
	if h.testHooks != nil && h.testHooks.launchPairingCandidate != nil {
		launch = h.testHooks.launchPairingCandidate
	}
	launch(func() {
		h.muxReg.Lock()
		active := h.activePairingCandidates[ski] == activeCandidate && activeCandidate.connectIssued
		h.muxReg.Unlock()
		if !active {
			return
		}
		if err := h.connectFoundPairingCandidate(
			service,
			activeCandidate.host,
			activeCandidate.port,
			activeCandidate.path,
			ski,
			activeCandidate.authority,
		); err != nil && !isInboundPairingDirectionHandoff(err) {
			h.retirePairingCandidate(ski, activeCandidate, nil)
		}
	})
}

func isInboundPairingDirectionHandoff(err error) bool {
	var handoff inboundPairingDirectionHandoffError
	return errors.As(err, &handoff)
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

	if h.testHooks != nil && h.testHooks.beforePairingCandidateRetire != nil {
		h.testHooks.beforePairingCandidateRetire()
	}
	retirementAuthority := h.rotateOutboundAuthorityLocked(ski)
	active.service.ConnectionStateDetail().SetState(api.ConnectionStateNone)
	delete(h.activePairingCandidates, ski)
	return &pairingCandidateRetirement{
		ski:       ski,
		service:   active.service,
		authority: retirementAuthority,
	}
}

func (h *Hub) finishPairingCandidateRetirements(retirements []pairingCandidateRetirement) {
	for _, retirement := range retirements {
		h.muxReg.Lock()
		h.muxAttemptGate.RLock()
		removeRetryState := h.outboundAuthorities[retirement.ski] == retirement.authority &&
			!retirement.service.Trusted()
		if removeRetryState {
			h.removeConnectionAttemptCounter(retirement.ski)
		}
		h.muxAttemptGate.RUnlock()
		h.muxReg.Unlock()
		h.publishPairingDetail(retirement.ski, retirement.service.ConnectionStateDetail())
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
	if h.testHooks != nil && h.testHooks.afterRegisterRemoteServiceLookup != nil {
		h.testHooks.afterRegisterRemoteServiceLookup()
	}
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

	h.publishPairingDetail(ski, service.ConnectionStateDetail())

	h.mdns.RequestMdnsEntries()
}

// Remove pairing for the SKI
func (h *Hub) UnregisterRemoteSKI(ski string) {
	ski = util.NormalizeSKI(ski)
	service := h.ServiceForSKI(ski)
	h.revokeOutboundAttempts(ski, service)

	h.removeConnectionAttemptCounter(ski)

	h.publishPairingDetail(ski, service.ConnectionStateDetail())

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

	h.publishPairingDetail(ski, service.ConnectionStateDetail())
}
