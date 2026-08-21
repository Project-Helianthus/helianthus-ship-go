package model

type ShipState struct {
	State ShipMessageExchangeState
	Error error
	// PIN contains a closed, secret-free summary of an authentic PIN handshake
	// observation. It deliberately contains neither supplied PIN bytes nor peer
	// identity, endpoint, or transport error text.
	PIN *PINHandshakeDetail
}

type PINRequirement string

const (
	PINRequirementUnknown  PINRequirement = "unknown"
	PINRequirementNone     PINRequirement = "none"
	PINRequirementRequired PINRequirement = "required"
	PINRequirementOptional PINRequirement = "optional"
)

type PINPhase string

const (
	PINPhaseNotRequired PINPhase = "not_required"
	PINPhaseWaitingPeer PINPhase = "waiting_peer"
	PINPhaseSubmitted   PINPhase = "submitted"
	PINPhaseAccepted    PINPhase = "accepted"
	PINPhaseRestricted  PINPhase = "restricted"
	PINPhaseFailed      PINPhase = "failed"
)

type PINCategory string

const (
	PINCategoryRequired    PINCategory = "required"
	PINCategoryOptional    PINCategory = "optional"
	PINCategoryBusy        PINCategory = "busy"
	PINCategoryRejected    PINCategory = "rejected"
	PINCategoryUnavailable PINCategory = "unavailable"
	PINCategoryProtocol    PINCategory = "protocol"
)

// PINHandshakeDetail is intentionally a closed value: callers can act on the
// outcome but cannot recover credentials, peer identity, transport locations,
// or arbitrary error text from it. Category is nil when no categorical reason
// applies (for example PIN not required or accepted).
type PINHandshakeDetail struct {
	Requirement PINRequirement
	Phase       PINPhase
	Category    *PINCategory
	Retryable   bool
}

func PINCategoryPointer(value PINCategory) *PINCategory {
	return &value
}

func (detail *PINHandshakeDetail) Clone() *PINHandshakeDetail {
	if detail == nil {
		return nil
	}
	copy := *detail
	if detail.Category != nil {
		category := *detail.Category
		copy.Category = &category
	}
	return &copy
}

func (detail *PINHandshakeDetail) Equal(other *PINHandshakeDetail) bool {
	if detail == nil || other == nil {
		return detail == other
	}
	if detail.Requirement != other.Requirement || detail.Phase != other.Phase || detail.Retryable != other.Retryable {
		return false
	}
	if detail.Category == nil || other.Category == nil {
		return detail.Category == nil && other.Category == nil
	}
	return *detail.Category == *other.Category
}

type ShipMessageExchangeState uint

// set the values manually instead of using iota, so log data can be associated easier
const (
	// Connection Mode Initialisation (CMI) SHIP 13.4.3
	CmiStateInitStart      ShipMessageExchangeState = 0
	CmiStateClientSend     ShipMessageExchangeState = 1
	CmiStateClientWait     ShipMessageExchangeState = 2
	CmiStateClientEvaluate ShipMessageExchangeState = 3
	CmiStateServerWait     ShipMessageExchangeState = 4
	CmiStateServerEvaluate ShipMessageExchangeState = 5
	// Connection Data Preparation SHIP 13.4.4
	SmeHelloState                ShipMessageExchangeState = 6
	SmeHelloStateReadyInit       ShipMessageExchangeState = 7
	SmeHelloStateReadyListen     ShipMessageExchangeState = 8
	SmeHelloStateReadyTimeout    ShipMessageExchangeState = 9
	SmeHelloStatePendingInit     ShipMessageExchangeState = 10
	SmeHelloStatePendingListen   ShipMessageExchangeState = 11
	SmeHelloStatePendingTimeout  ShipMessageExchangeState = 12
	SmeHelloStateOk              ShipMessageExchangeState = 13
	SmeHelloStateAbort           ShipMessageExchangeState = 14 // Sent abort to remote
	SmeHelloStateAbortDone       ShipMessageExchangeState = 15 // Sending abort to remote is done
	SmeHelloStateRemoteAbortDone ShipMessageExchangeState = 16 // Received abort from remote
	SmeHelloStateRejected        ShipMessageExchangeState = 17 // Connection closed after remote pending: "4452: Node rejected by application"

	// Connection State Protocol Handhsake SHIP 13.4.4.2
	SmeProtHStateServerInit           ShipMessageExchangeState = 18
	SmeProtHStateClientInit           ShipMessageExchangeState = 19
	SmeProtHStateServerListenProposal ShipMessageExchangeState = 20
	SmeProtHStateServerListenConfirm  ShipMessageExchangeState = 21
	SmeProtHStateClientListenChoice   ShipMessageExchangeState = 22
	SmeProtHStateTimeout              ShipMessageExchangeState = 23
	SmeProtHStateClientOk             ShipMessageExchangeState = 24
	SmeProtHStateServerOk             ShipMessageExchangeState = 25
	// Connection PIN State 13.4.5
	SmePinStateCheckInit     ShipMessageExchangeState = 26
	SmePinStateCheckListen   ShipMessageExchangeState = 27
	SmePinStateCheckError    ShipMessageExchangeState = 28
	SmePinStateCheckBusyInit ShipMessageExchangeState = 29
	SmePinStateCheckBusyWait ShipMessageExchangeState = 30
	SmePinStateCheckOk       ShipMessageExchangeState = 31
	SmePinStateAskInit       ShipMessageExchangeState = 32
	SmePinStateAskProcess    ShipMessageExchangeState = 33
	SmePinStateAskRestricted ShipMessageExchangeState = 34
	SmePinStateAskOk         ShipMessageExchangeState = 35
	// ConnectionAccess Methods Identification 13.4.6
	SmeAccessMethodsRequest ShipMessageExchangeState = 36

	// Handshake approved on both ends
	SmeStateApproved ShipMessageExchangeState = 37

	// Handshake process is successfully completed
	SmeStateComplete ShipMessageExchangeState = 38

	// Handshake ended with an error
	SmeStateError ShipMessageExchangeState = 39
)

var ShipInit []byte = []byte{MsgTypeInit, 0x00}
