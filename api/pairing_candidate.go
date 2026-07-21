package api

import "errors"

var (
	ErrInvalidRemoteSKI            = errors.New("remote SKI must contain exactly 40 lowercase hexadecimal characters")
	ErrPairingCandidateUnavailable = errors.New("pairing candidate is unavailable")
	ErrPairingCandidateSKIMismatch = errors.New("pairing candidate SKI does not match expected SKI")
	ErrPairingCandidateConsumed    = errors.New("pairing candidate was already consumed")
	ErrPairingCandidateActive      = errors.New("pairing candidate is already active for remote SKI")
	ErrOutgoingAttemptGateRequired = errors.New("outgoing attempt gate is required")
	ErrRemoteAlreadyTrusted        = errors.New("remote is already trusted")
)

// PairingCandidateQueuer consumes one process-local discovery observation and
// binds it to an independently supplied expected SKI. It accepts no endpoint
// input and grants no durable trust.
type PairingCandidateQueuer interface {
	QueuePairingCandidate(candidateRef, expectedSKI string) error
}
