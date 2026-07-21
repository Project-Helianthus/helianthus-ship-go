package api

import "errors"

var (
	ErrInvalidRemoteSKI            = errors.New("remote SKI must contain 40 hexadecimal characters")
	ErrPairingRegistrationClosed   = errors.New("pairing registration is closed")
	ErrOutgoingAttemptGateRequired = errors.New("outgoing attempt gate is required")
	ErrRemoteAlreadyTrusted        = errors.New("remote is already trusted")
)

// PairingCandidateQueuer admits one operator-validated SKI for a SHIP
// connection through a live mDNS observation. It neither accepts an endpoint
// nor grants durable trust.
type PairingCandidateQueuer interface {
	QueuePairingCandidate(string) error
}
