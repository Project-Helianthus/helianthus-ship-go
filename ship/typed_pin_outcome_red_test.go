package ship

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

type issue39PINStateProvider struct {
	*issue35PINProvider
	mu     sync.Mutex
	states []model.ShipState
}

func (*issue39PINStateProvider) IsRemoteServiceForSKIPaired(string) bool { return true }
func (*issue39PINStateProvider) IsAutoAcceptEnabled() bool               { return false }
func (*issue39PINStateProvider) HandleConnectionClosed(api.ShipConnectionInterface, bool) {
}
func (*issue39PINStateProvider) ReportServiceShipID(string, string) {}
func (*issue39PINStateProvider) AllowWaitingForTrust(string) bool   { return true }
func (p *issue39PINStateProvider) HandleShipHandshakeStateUpdate(_ string, state model.ShipState) {
	p.mu.Lock()
	p.states = append(p.states, state)
	p.mu.Unlock()
}
func (*issue39PINStateProvider) SetupRemoteDevice(
	string,
	api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	return issue35PINSpineReader{}
}

func (p *issue39PINStateProvider) latest() model.ShipState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.states[len(p.states)-1]
}

func newIssue39PINConnection(pin []byte, available bool) (*ShipConnection, *issue39PINStateProvider) {
	provider := &issue39PINStateProvider{issue35PINProvider: &issue35PINProvider{
		available: available,
		pin:       append([]byte(nil), pin...),
	}}
	writer := &issue35PINWriter{expectedPIN: append([]byte(nil), pin...)}
	connection := NewConnectionHandler(
		provider,
		writer,
		ShipRoleClient,
		"local-ship-id",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"remote-ship-id",
	)
	connection.setState(model.SmePinStateCheckListen, nil)
	return connection, provider
}

func TestIssue39AuthenticPINHandshakeStatesPublishClosedTypedOutcomes(t *testing.T) {
	tests := []struct {
		name        string
		pinState    model.PinStateType
		permission  model.PinInputPermissionType
		available   bool
		phase       model.PINPhase
		category    model.PINCategory
		requirement model.PINRequirement
		retryable   bool
	}{
		{"required", model.PinStateTypeRequired, model.PinInputPermissionTypeOk, false, model.PINPhaseFailed, model.PINCategoryUnavailable, model.PINRequirementRequired, true},
		{"optional", model.PinStateTypeOptional, model.PinInputPermissionTypeOk, false, model.PINPhaseRestricted, model.PINCategoryOptional, model.PINRequirementOptional, false},
		{"busy", model.PinStateTypeRequired, model.PinInputPermissionTypeBusy, true, model.PINPhaseWaitingPeer, model.PINCategoryBusy, model.PINRequirementRequired, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, provider := newIssue39PINConnection([]byte(issue35TestPIN), test.available)
			connection.processRemotePINState(model.ConnectionPinStateType{
				PinState:        test.pinState,
				InputPermission: pinPermission(test.permission),
			})
			state := provider.latest()
			if state.PIN == nil || state.PIN.Requirement != test.requirement ||
				state.PIN.Phase != test.phase || state.PIN.Category != test.category ||
				state.PIN.Retryable != test.retryable {
				t.Fatalf("typed PIN outcome = %#v, want requirement=%v phase=%v category=%v retryable=%v",
					state.PIN, test.requirement, test.phase, test.category, test.retryable)
			}
			if got := fmt.Sprintf("%#v", state.PIN); strings.Contains(got, issue35TestPIN) || strings.Contains(got, "remote-ship-id") {
				t.Fatalf("typed PIN outcome leaked a secret or identity: %q", got)
			}
		})
	}
}

func TestIssue39AuthenticWrongPINAndProtocolFailuresStayCategorical(t *testing.T) {
	connection, provider := newIssue39PINConnection([]byte(issue35TestPIN), true)
	connection.processRemotePINState(model.ConnectionPinStateType{
		PinState:        model.PinStateTypeRequired,
		InputPermission: pinPermission(model.PinInputPermissionTypeOk),
	})
	connection.endHandshakeWithError(api.ErrPINRejected)
	if got := provider.latest().PIN; got == nil || got.Phase != model.PINPhaseFailed ||
		got.Category != model.PINCategoryRejected || got.Retryable {
		t.Fatalf("wrong PIN outcome = %#v, want terminal rejected and non-retryable", got)
	}

	connection, provider = newIssue39PINConnection([]byte(issue35TestPIN), true)
	connection.endHandshakeWithError(api.ErrPINProtocol)
	if got := provider.latest().PIN; got == nil || got.Phase != model.PINPhaseFailed ||
		got.Category != model.PINCategoryProtocol || got.Retryable {
		t.Fatalf("protocol outcome = %#v, want terminal protocol and non-retryable", got)
	}
}
