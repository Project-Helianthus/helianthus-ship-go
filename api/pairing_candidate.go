package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
)

var (
	ErrInvalidRemoteSKI                         = errors.New("remote SKI must contain exactly 40 lowercase hexadecimal characters")
	ErrPairingCandidateUnavailable              = errors.New("pairing candidate is unavailable")
	ErrPairingCandidateSKIMismatch              = errors.New("pairing candidate SKI does not match expected SKI")
	ErrPairingCandidateConsumed                 = errors.New("pairing candidate was already consumed")
	ErrPairingCandidateActive                   = errors.New("pairing candidate is already active for remote SKI")
	ErrPairingCandidateReservationStale         = errors.New("pairing candidate reservation is stale")
	ErrPairingCandidateAlreadyConnecting        = errors.New("pairing candidate reservation is already connecting")
	ErrPairingCandidateReservationUnavailable   = errors.New("pairing candidate reservation is unavailable")
	ErrPairingCandidateReservationSerialization = errors.New("pairing candidate reservation cannot be serialized")
	ErrOutgoingAttemptGateRequired              = errors.New("outgoing attempt gate is required")
	ErrRemoteAlreadyTrusted                     = errors.New("remote is already trusted")
)

const pairingCandidateReservationTokenBytes = 32

// PairingCandidateReservation is a process-local, non-serializable capability
// for one exact selected discovery observation. Its contents are intentionally
// opaque; only the Hub that issued it can admit a connection.
type PairingCandidateReservation struct {
	token [pairingCandidateReservationTokenBytes]byte
}

// NewPairingCandidateReservation constructs a reservation from library-owned
// entropy. Callers cannot gain authority by constructing a value because the
// Hub compares it with the currently active reservation.
func NewPairingCandidateReservation(token [pairingCandidateReservationTokenBytes]byte) PairingCandidateReservation {
	return PairingCandidateReservation{token: token}
}

// Valid reports whether the reservation carries a non-zero capability token.
func (reservation PairingCandidateReservation) Valid() bool {
	var zero [pairingCandidateReservationTokenBytes]byte
	return subtle.ConstantTimeCompare(reservation.token[:], zero[:]) == 0
}

// Matches compares two opaque reservations without disclosing their tokens.
func (reservation PairingCandidateReservation) Matches(other PairingCandidateReservation) bool {
	return reservation.Valid() && other.Valid() &&
		subtle.ConstantTimeCompare(reservation.token[:], other.token[:]) == 1
}

func (PairingCandidateReservation) String() string {
	return "ship.pairing_candidate_reservation{redacted}"
}

func (reservation PairingCandidateReservation) GoString() string { return reservation.String() }

func (reservation PairingCandidateReservation) Format(state fmt.State, verb rune) {
	if verb == 'q' {
		_, _ = fmt.Fprintf(state, "%q", reservation.String())
		return
	}
	_, _ = fmt.Fprint(state, reservation.String())
}

func (PairingCandidateReservation) MarshalJSON() ([]byte, error) {
	return nil, ErrPairingCandidateReservationSerialization
}

// PairingCandidateController separates selection from the explicit outbound
// connection action. Selection grants neither trust nor a dial.
type PairingCandidateController interface {
	SelectPairingCandidate(candidateRef, expectedSKI string) (PairingCandidateReservation, error)
	ConnectPairingCandidate(PairingCandidateReservation) error
}

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
