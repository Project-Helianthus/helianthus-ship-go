package api

import (
	"errors"
	"net"
)

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

// PairingCandidateObservation is an experimental dependency-fork contract
// between mDNS and Hub. Endpoint fields never leave the SHIP pairing owner.
type PairingCandidateObservation struct {
	CandidateRef string
	Name         string
	SKI          string
	Identifier   string
	Brand        string
	Type         string
	Model        string
	Path         string
	Port         int
	Addresses    []net.IP
}

// PairingCandidateMdnsReportInterface atomically reports stable discovery and
// its process-local candidate capabilities without changing MdnsEntry.
type PairingCandidateMdnsReportInterface interface {
	ReportMdnsEntriesWithCandidates(
		entries map[string]*MdnsEntry,
		newEntries bool,
		candidates []PairingCandidateObservation,
		observationRevision uint64,
	)
}

// PairingCandidateRef is the redacted experimental inspection form. It carries
// no endpoint, path, trust state, or persistent identity.
type PairingCandidateRef struct {
	CandidateRef string
	Name         string
	SKI          string
	Identifier   string
	Brand        string
	Type         string
	Model        string
}

// PairingCandidateHubReaderInterface is an optional experimental callback for
// dependency consumers that own the local candidate admin surface.
type PairingCandidateHubReaderInterface interface {
	VisiblePairingCandidatesUpdated([]PairingCandidateRef)
}
