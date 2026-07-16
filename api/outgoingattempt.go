package api

import (
	"context"
	"errors"

	"github.com/enbility/ship-go/model"
)

// OutgoingAttemptEndpoint identifies one concrete network endpoint.
type OutgoingAttemptEndpoint struct {
	Host string
	Port uint16
}

// OutgoingAttemptRequest binds one outgoing attempt to its peer, endpoint, and path.
type OutgoingAttemptRequest struct {
	RemoteSKI string
	Endpoint  OutgoingAttemptEndpoint
	Path      string
}

// OutgoingAttemptMetadata is the immutable identity propagated with an authorized attempt.
type OutgoingAttemptMetadata struct {
	AttemptID    string
	Scope        string
	ControlEpoch uint64
}

type OutgoingAttemptDecision uint8

const (
	OutgoingAttemptDecisionPermit OutgoingAttemptDecision = iota + 1
	OutgoingAttemptDecisionDeny
)

type OutgoingAttemptReason uint8

const (
	OutgoingAttemptReasonAuthorized OutgoingAttemptReason = iota + 1
	OutgoingAttemptReasonPolicyDenied
	OutgoingAttemptReasonStaleHandle
)

type OutgoingAttemptAbortResult uint8

const (
	OutgoingAttemptAbortConsumed OutgoingAttemptAbortResult = iota + 1
	OutgoingAttemptAbortStaleNoOp
)

// OutgoingAttemptHandle is an opaque, single-use lease returned by Prepare.
type OutgoingAttemptHandle interface {
	AttemptID() string
	Scope() string
	ControlEpoch() uint64
	Context() context.Context
}

// OutgoingAttemptPermit is the complete result of launch authorization.
type OutgoingAttemptPermit struct {
	Decision OutgoingAttemptDecision
	Reason   OutgoingAttemptReason
	Metadata OutgoingAttemptMetadata
	Context  context.Context
}

// OutgoingAttemptGate optionally authorizes each concrete outgoing dial.
type OutgoingAttemptGate interface {
	Prepare(OutgoingAttemptRequest) (OutgoingAttemptHandle, error)
	AuthorizeLaunch(OutgoingAttemptHandle) (OutgoingAttemptPermit, error)
	AbortPrepared(OutgoingAttemptHandle) (OutgoingAttemptAbortResult, error)
}

var ErrInvalidOutgoingAttemptGate = errors.New("invalid outgoing attempt gate")

// OutgoingAttemptGateSetter is the optional configuration surface exposed by a hub.
type OutgoingAttemptGateSetter interface {
	SetOutgoingAttemptGate(OutgoingAttemptGate) error
}

// OutgoingAttemptConnectionInterface exposes metadata only for outgoing attempts.
type OutgoingAttemptConnectionInterface interface {
	OutgoingAttemptMetadata() (OutgoingAttemptMetadata, bool)
}

// OutgoingAttemptShipConnectionInfoProviderInterface receives attempt-aware callbacks.
type OutgoingAttemptShipConnectionInfoProviderInterface interface {
	HandleConnectionClosedWithAttempt(ShipConnectionInterface, bool, OutgoingAttemptMetadata)
	HandleShipHandshakeStateUpdateWithAttempt(string, model.ShipState, OutgoingAttemptMetadata)
}

// OutgoingAttemptHubReaderInterface receives attempt-aware hub callbacks.
type OutgoingAttemptHubReaderInterface interface {
	OutgoingAttemptConnectionClosed(string, bool, OutgoingAttemptMetadata)
	OutgoingAttemptHandshakeStateUpdate(string, model.ShipState, OutgoingAttemptMetadata)
}
