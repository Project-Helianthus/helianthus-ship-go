package api

import "errors"

var (
	ErrTrustedRemoteRetryUnavailable = errors.New("trusted remote retry is unavailable")
	ErrTrustedRemoteRetryNotTrusted  = errors.New("remote is not trusted")
	ErrTrustedRemoteRetryConnected   = errors.New("remote is already connected")
	ErrTrustedRemoteRetryBusy        = errors.New("trusted remote retry is busy")
	ErrTrustedRemoteObservationStale = errors.New("trusted remote observation is stale")
)

// TrustedRemoteRetryController starts one target-specific reconnect path for
// an already trusted, disconnected remote using only SHIP-owned discovery
// state. Callers provide identity, never an endpoint or trust material.
type TrustedRemoteRetryController interface {
	RetryTrustedRemote(expectedSKI string) error
}
