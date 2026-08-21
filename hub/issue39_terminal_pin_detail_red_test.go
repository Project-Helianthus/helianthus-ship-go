package hub

import (
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

type issue39TerminalPairingReader struct {
	mu      sync.Mutex
	updates []*api.ConnectionStateDetail
	notify  chan struct{}
}

const issue39TerminalRemoteSKI = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newIssue39TerminalPairingReader() *issue39TerminalPairingReader {
	return &issue39TerminalPairingReader{notify: make(chan struct{}, 16)}
}

func (*issue39TerminalPairingReader) RemoteSKIConnected(string)    {}
func (*issue39TerminalPairingReader) RemoteSKIDisconnected(string) {}
func (*issue39TerminalPairingReader) SetupRemoteDevice(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
	return nil
}
func (*issue39TerminalPairingReader) VisibleRemoteServicesUpdated([]api.RemoteService) {}
func (*issue39TerminalPairingReader) ServiceShipIDUpdate(string, string)               {}
func (*issue39TerminalPairingReader) AllowWaitingForTrust(string) bool                 { return false }
func (reader *issue39TerminalPairingReader) ServicePairingDetailUpdate(_ string, detail *api.ConnectionStateDetail) {
	reader.mu.Lock()
	reader.updates = append(reader.updates, snapshotPairingDetail(detail))
	reader.mu.Unlock()
	reader.notify <- struct{}{}
}

func (reader *issue39TerminalPairingReader) last() *api.ConnectionStateDetail {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(reader.updates) == 0 {
		return nil
	}
	return snapshotPairingDetail(reader.updates[len(reader.updates)-1])
}

func (reader *issue39TerminalPairingReader) waitForTerminal(t *testing.T) *api.ConnectionStateDetail {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-reader.notify:
			if detail := reader.last(); detail != nil &&
				(detail.State() == api.ConnectionStateCompleted || detail.State() == api.ConnectionStateError) {
				return detail
			}
		case <-deadline:
			t.Fatal("timed out waiting for delayed terminal pairing detail")
		}
	}
}

func issue39TerminalHub(reader api.HubReaderInterface) *Hub {
	return NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
}

func issue39PINDetail(
	requirement model.PINRequirement,
	phase model.PINPhase,
	category *model.PINCategory,
	retryable bool,
) *model.PINHandshakeDetail {
	return &model.PINHandshakeDetail{
		Requirement: requirement,
		Phase:       phase,
		Category:    category,
		Retryable:   retryable,
	}
}

func assertIssue39TerminalPINDetail(
	t *testing.T,
	detail *api.ConnectionStateDetail,
	want *model.PINHandshakeDetail,
) {
	t.Helper()
	got := detail.PINHandshakeDetail()
	if !got.Equal(want) {
		t.Fatalf("terminal PIN detail = %#v, want %#v", got, want)
	}
	if got == want {
		t.Fatal("terminal callback retained a mutable caller-owned PIN detail")
	}
}

func TestIssue39TerminalCompletionRetainsTypedPINOutcomeThroughDelayedPublication(t *testing.T) {
	tests := []struct {
		name    string
		initial *model.PINHandshakeDetail
	}{
		{
			name: "successful PIN",
			initial: issue39PINDetail(
				model.PINRequirementRequired, model.PINPhaseAccepted, nil, false),
		},
		{
			name: "PIN free",
			initial: issue39PINDetail(
				model.PINRequirementNone, model.PINPhaseNotRequired, nil, false),
		},
		{
			name: "optional restricted",
			initial: issue39PINDetail(
				model.PINRequirementOptional, model.PINPhaseRestricted,
				model.PINCategoryPointer(model.PINCategoryOptional), false),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newIssue39TerminalPairingReader()
			hub := issue39TerminalHub(reader)
			hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{
				State: model.SmePinStateCheckOk,
				PIN:   test.initial.Clone(),
			})
			hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{State: model.SmeStateComplete})

			terminal := reader.waitForTerminal(t)
			if terminal.State() != api.ConnectionStateCompleted {
				t.Fatalf("terminal state = %v, want completed", terminal.State())
			}
			assertIssue39TerminalPINDetail(t, terminal, test.initial)
		})
	}
}

func TestIssue39DuplicateConnectionErrorRetainsTypedPINFailure(t *testing.T) {
	tests := []struct {
		name    string
		error   error
		initial *model.PINHandshakeDetail
	}{
		{
			name:  "rejected",
			error: api.ErrPINRejected,
			initial: issue39PINDetail(model.PINRequirementRequired, model.PINPhaseFailed,
				model.PINCategoryPointer(model.PINCategoryRejected), false),
		},
		{
			name:  "unavailable",
			error: api.ErrPINUnavailable,
			initial: issue39PINDetail(model.PINRequirementRequired, model.PINPhaseFailed,
				model.PINCategoryPointer(model.PINCategoryUnavailable), true),
		},
		{
			name:  "protocol",
			error: api.ErrPINProtocol,
			initial: issue39PINDetail(model.PINRequirementUnknown, model.PINPhaseFailed,
				model.PINCategoryPointer(model.PINCategoryProtocol), false),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := newIssue39TerminalPairingReader()
			hub := issue39TerminalHub(reader)
			hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{
				State: model.SmeStateError,
				Error: test.error,
				PIN:   test.initial.Clone(),
			})
			// A connection error can be reported again after SHIP has already
			// published its typed terminal state. It must not erase that state.
			hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{
				State: model.SmeStateError,
				Error: test.error,
			})

			terminal := reader.waitForTerminal(t)
			if terminal.State() != api.ConnectionStateError || !errors.Is(terminal.Error(), test.error) {
				t.Fatalf("terminal error detail = %v/%v, want error/%v", terminal.State(), terminal.Error(), test.error)
			}
			assertIssue39TerminalPINDetail(t, terminal, test.initial)
		})
	}
}

func TestIssue39NewHandshakeClearsPriorTerminalPINDetail(t *testing.T) {
	reader := newIssue39TerminalPairingReader()
	hub := issue39TerminalHub(reader)
	hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{
		State: model.SmeStateComplete,
		PIN: issue39PINDetail(
			model.PINRequirementRequired, model.PINPhaseAccepted, nil, false),
	})
	hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{State: model.CmiStateInitStart})
	hub.HandleShipHandshakeStateUpdate(issue39TerminalRemoteSKI, model.ShipState{
		State: model.SmeStateError,
		Error: api.ErrPINProtocol,
	})

	terminal := reader.waitForTerminal(t)
	if got := terminal.PINHandshakeDetail(); got != nil {
		t.Fatalf("new attempt terminal retained stale PIN detail: %#v", got)
	}
}
