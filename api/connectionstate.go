package api

import (
	"errors"
	"sync"

	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

// connection state for global usage, e.g. UI
type ConnectionState uint

const (
	ConnectionStateNone                   ConnectionState = iota // The initial state, when no pairing exists
	ConnectionStateQueued                                        // The connection request has been started and is pending connection initialization
	ConnectionStateInitiated                                     // This service initiated the connection process
	ConnectionStateReceivedPairingRequest                        // A remote service initiated the connection process
	ConnectionStateInProgress                                    // The connection handshake is in progress
	ConnectionStateTrusted                                       // The connection is trusted on both ends
	ConnectionStatePin                                           // PIN processing, not supported right now!
	ConnectionStateCompleted                                     // The connection handshake is completed from both ends
	ConnectionStateRemoteDeniedTrust                             // The remote service denied trust
	ConnectionStateError                                         // The connection handshake resulted in an error
)

// the connection state of a service and error if applicable
type ConnectionStateDetail struct {
	state              ConnectionState
	error              error
	pinHandshakeDetail *model.PINHandshakeDetail

	mux sync.Mutex
}

func NewConnectionStateDetail(state ConnectionState, err error) *ConnectionStateDetail {
	return &ConnectionStateDetail{
		state: state,
		error: err,
	}
}

func (c *ConnectionStateDetail) State() ConnectionState {
	c.mux.Lock()
	defer c.mux.Unlock()

	return c.state
}

func (c *ConnectionStateDetail) SetState(state ConnectionState) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.state = state
}

func (c *ConnectionStateDetail) Error() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	return c.error
}

func (c *ConnectionStateDetail) SetError(err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.error = err
}

// PINHandshakeDetail returns an independent, secret-free typed PIN outcome.
// The legacy State and Error accessors remain unchanged for existing callers.
func (c *ConnectionStateDetail) PINHandshakeDetail() *model.PINHandshakeDetail {
	c.mux.Lock()
	defer c.mux.Unlock()

	return c.pinHandshakeDetail.Clone()
}

// SetPINHandshakeDetail stores an independent copy so a callback caller cannot
// mutate the current connection state after publication.
func (c *ConnectionStateDetail) SetPINHandshakeDetail(detail *model.PINHandshakeDetail) {
	c.mux.Lock()
	defer c.mux.Unlock()

	c.pinHandshakeDetail = detail.Clone()
}

// ErrServiceNotPaired if the given SKI is not paired yet
var ErrServiceNotPaired = errors.New("the provided SKI is not paired")

// ErrConnectionNotFound that there was no active connection for a given SKI found
var ErrConnectionNotFound = errors.New("no connection for provided SKI found")
