package api

import "errors"

var (
	// ErrPINUnavailable is the categorical result when a peer requires a PIN
	// but the one-shot provider has no value for this connection.
	ErrPINUnavailable = errors.New("SHIP PIN unavailable")
	// ErrPINRejected is the categorical result of a remote wrong-PIN reply.
	ErrPINRejected = errors.New("SHIP PIN rejected")
	// ErrPINInvalid reports a locally supplied value outside the SHIP PIN
	// grammar without including that value.
	ErrPINInvalid = errors.New("SHIP PIN invalid")
	// ErrPINProtocol reports an invalid remote PIN-state message shape.
	ErrPINProtocol = errors.New("SHIP PIN protocol error")
	// ErrPINProviderInvalid reports a nil or typed-nil per-connect provider.
	ErrPINProviderInvalid = errors.New("SHIP PIN provider invalid")
)

// TransientPINProvider lends a PIN to exactly one synchronous consumer call.
// The provider retains ownership of the input slice and should clear it after
// consume returns. Implementations must not place the PIN in errors.
type TransientPINProvider interface {
	WithTransientPIN(remoteSKI string, consume func([]byte) error) (provided bool, err error)
}

// TransientPINProviderFunc adapts a function to TransientPINProvider.
type TransientPINProviderFunc func(string, func([]byte) error) (bool, error)

func (provider TransientPINProviderFunc) WithTransientPIN(
	remoteSKI string,
	consume func([]byte) error,
) (bool, error) {
	return provider(remoteSKI, consume)
}

// PairingCandidatePINController supplies a one-shot provider only for the
// selected candidate connection. The existing no-PIN controller stays stable.
type PairingCandidatePINController interface {
	ConnectPairingCandidateWithPIN(PairingCandidateReservation, TransientPINProvider) error
}

// SensitiveWebsocketDataWriterInterface is the synchronous write path for
// control frames containing secrets. Implementations must neither queue nor
// retain message and must not log its payload.
type SensitiveWebsocketDataWriterInterface interface {
	WriteSensitiveMessageToWebsocketConnection(message []byte) error
}

// TransientPINDiscarder releases a provider that was not consumed because the
// peer did not request a PIN or the handshake terminated first.
type TransientPINDiscarder interface {
	DiscardTransientPIN(remoteSKI string)
}
