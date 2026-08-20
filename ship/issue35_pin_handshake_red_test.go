package ship

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

const issue35TestPIN = "12aBc34D"

type issue35PINProvider struct {
	available bool
	pin       []byte

	mux   sync.Mutex
	calls int
}

var _ api.TransientPINProvider = (*issue35PINProvider)(nil)

func (provider *issue35PINProvider) WithTransientPIN(
	_ string,
	consume func([]byte) error,
) (bool, error) {
	provider.mux.Lock()
	provider.calls++
	provider.mux.Unlock()
	if !provider.available {
		return false, nil
	}
	value := append([]byte(nil), provider.pin...)
	defer clear(value)
	return true, consume(value)
}

func (provider *issue35PINProvider) callCount() int {
	provider.mux.Lock()
	defer provider.mux.Unlock()
	return provider.calls
}

type issue35PINWriter struct {
	mux sync.Mutex

	expectedPIN    []byte
	sensitiveCalls int
	sensitiveMatch bool
	retainedSecret []byte
	normalMessages [][]byte
	closeReasons   []string
	sensitiveErr   error
	onSensitive    func()
}

var _ api.WebsocketDataWriterInterface = (*issue35PINWriter)(nil)
var _ api.SensitiveWebsocketDataWriterInterface = (*issue35PINWriter)(nil)

func (*issue35PINWriter) InitDataProcessing(api.WebsocketDataReaderInterface) {}

func (writer *issue35PINWriter) WriteMessageToWebsocketConnection(message []byte) error {
	writer.mux.Lock()
	defer writer.mux.Unlock()
	writer.normalMessages = append(writer.normalMessages, append([]byte(nil), message...))
	return nil
}

func (writer *issue35PINWriter) WriteSensitiveMessageToWebsocketConnection(message []byte) error {
	writer.mux.Lock()
	writer.sensitiveCalls++
	writer.sensitiveMatch = bytes.Contains(message, writer.expectedPIN)
	// Deliberately retain the caller-owned slice. The production sender must
	// zero its transient wire buffer after this synchronous method returns.
	writer.retainedSecret = message
	err := writer.sensitiveErr
	onSensitive := writer.onSensitive
	writer.mux.Unlock()
	if onSensitive != nil {
		onSensitive()
	}
	return err
}

func (writer *issue35PINWriter) CloseDataConnection(_ int, reason string) {
	writer.mux.Lock()
	defer writer.mux.Unlock()
	writer.closeReasons = append(writer.closeReasons, reason)
}

func (*issue35PINWriter) IsDataConnectionClosed() (bool, error) { return false, nil }

func (writer *issue35PINWriter) snapshot() (int, bool, []byte, [][]byte, []string) {
	writer.mux.Lock()
	defer writer.mux.Unlock()
	normal := make([][]byte, len(writer.normalMessages))
	for index := range writer.normalMessages {
		normal[index] = append([]byte(nil), writer.normalMessages[index]...)
	}
	return writer.sensitiveCalls,
		writer.sensitiveMatch,
		append([]byte(nil), writer.retainedSecret...),
		normal,
		append([]string(nil), writer.closeReasons...)
}

type issue35PINInfoProvider struct {
	*issue35PINProvider
}

func (*issue35PINInfoProvider) IsRemoteServiceForSKIPaired(string) bool { return true }
func (*issue35PINInfoProvider) IsAutoAcceptEnabled() bool               { return false }
func (*issue35PINInfoProvider) HandleConnectionClosed(api.ShipConnectionInterface, bool) {
}
func (*issue35PINInfoProvider) ReportServiceShipID(string, string) {}
func (*issue35PINInfoProvider) AllowWaitingForTrust(string) bool   { return true }
func (*issue35PINInfoProvider) HandleShipHandshakeStateUpdate(string, model.ShipState) {
}
func (*issue35PINInfoProvider) SetupRemoteDevice(
	string,
	api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	return issue35PINSpineReader{}
}

type issue35PINSpineReader struct{}

func (issue35PINSpineReader) HandleShipPayloadMessage([]byte) {}

func TestIssue35RequiredCorrectPINCompletesFakePeerHandshake(t *testing.T) {
	connection, provider, writer := newIssue35PINConnection([]byte(issue35TestPIN), true)
	defer connection.stopHandshakeTimerAndWait()

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeOk))
	if state := connection.getState(); state != model.SmePinStateAskProcess {
		t.Fatalf("state after required PIN challenge = %v, want %v", state, model.SmePinStateAskProcess)
	}
	assertIssue35SensitiveWrite(t, provider, writer)

	issue35FakePeerPINState(t, connection, model.PinStateTypePinOk, nil)
	issue35FakePeerAccessComplete(t, connection)
	if state := connection.getState(); state != model.SmeStateComplete {
		t.Fatalf("state after correct required PIN = %v, want complete", state)
	}
}

func TestIssue35BusyPINPermissionWaitsWithoutConsumingSecret(t *testing.T) {
	connection, provider, writer := newIssue35PINConnection([]byte(issue35TestPIN), true)
	defer connection.stopHandshakeTimerAndWait()

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeBusy))
	if state := connection.getState(); state != model.SmePinStateAskProcess {
		t.Fatalf("state while PIN input is busy = %v, want %v", state, model.SmePinStateAskProcess)
	}
	if provider.callCount() != 0 {
		t.Fatalf("provider calls while peer is busy = %d, want 0", provider.callCount())
	}
	if calls, _, _, _, _ := writer.snapshot(); calls != 0 {
		t.Fatalf("sensitive writes while peer is busy = %d, want 0", calls)
	}
	busyDuration := issue35HandshakeTimerDuration(t, connection)
	if busyDuration < 60*time.Second || busyDuration > 90*time.Second {
		t.Fatalf("pre-input busy timer = %s, want SHIP-compliant 60–90s", busyDuration)
	}

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeOk))
	if responseDuration := issue35HandshakeTimerDuration(t, connection); responseDuration != pinResponseTimeout {
		t.Fatalf("post-send PIN response timer = %s, want %s", responseDuration, pinResponseTimeout)
	}
	assertIssue35SensitiveWrite(t, provider, writer)
	issue35FakePeerPINState(t, connection, model.PinStateTypePinOk, nil)
	issue35FakePeerAccessComplete(t, connection)
	if state := connection.getState(); state != model.SmeStateComplete {
		t.Fatalf("state after busy-to-ok PIN flow = %v, want complete", state)
	}
}

func TestIssue35FastWrongPINAfterWireVisibilityIsRejectedCategorically(t *testing.T) {
	connection, _, writer := newIssue35PINConnection([]byte(issue35TestPIN), true)
	defer connection.stopHandshakeTimerAndWait()
	wrongPIN, err := connection.shipMessage(model.MsgTypeControl, model.ConnectionPinError{
		ConnectionPinError: model.ConnectionPinErrorType{
			Error: model.ConnectionPinErrorErrorTypeWrongPIN,
		},
	})
	if err != nil {
		t.Fatalf("create wrong-PIN message: %v", err)
	}
	done := make(chan struct{})
	writer.onSensitive = func() {
		go func() {
			connection.handleShipMessage(false, wrongPIN)
			close(done)
		}()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if state, _ := connection.ShipHandshakeState(); state == model.SmeStateError {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("fast wrong-PIN response was not observed while sensitive write was visible")
	}

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeOk))
	state, stateErr := connection.ShipHandshakeState()
	if state != model.SmeStateError || !errors.Is(stateErr, api.ErrPINRejected) {
		t.Fatalf("fast wrong-PIN state/error = %v/%v, want error/%v",
			state, stateErr, api.ErrPINRejected)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fast wrong-PIN handler did not finish")
	}
}

func TestIssue35SensitiveWriteFailureRollsBackPINInFlight(t *testing.T) {
	connection, _, writer := newIssue35PINConnection([]byte(issue35TestPIN), true)
	defer connection.stopHandshakeTimerAndWait()
	writer.sensitiveErr = errors.New("synthetic write failure")

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeOk))
	if connection.wasPINInputSent() {
		t.Fatal("failed sensitive write left PIN marked in flight")
	}
	state, stateErr := connection.ShipHandshakeState()
	if state != model.SmeStateError || !errors.Is(stateErr, api.ErrPINUnavailable) {
		t.Fatalf("failed sensitive write state/error = %v/%v, want error/%v",
			state, stateErr, api.ErrPINUnavailable)
	}
}

func TestIssue35OptionalPINSupportsSuppliedAndAbsentOutcomes(t *testing.T) {
	tests := []struct {
		name          string
		available     bool
		wantSensitive int
	}{
		{name: "supplied", available: true, wantSensitive: 1},
		{name: "absent uses restricted path", available: false, wantSensitive: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, provider, writer := newIssue35PINConnection([]byte(issue35TestPIN), test.available)
			defer connection.stopHandshakeTimerAndWait()

			issue35FakePeerPINState(t, connection, model.PinStateTypeOptional, pinPermission(model.PinInputPermissionTypeOk))
			if test.available {
				issue35FakePeerPINState(t, connection, model.PinStateTypePinOk, nil)
			}
			issue35FakePeerAccessComplete(t, connection)
			if state := connection.getState(); state != model.SmeStateComplete {
				t.Fatalf("optional PIN state = %v, want complete", state)
			}
			sensitiveCalls, _, _, _, _ := writer.snapshot()
			if sensitiveCalls != test.wantSensitive {
				t.Fatalf("sensitive writes = %d, want %d", sensitiveCalls, test.wantSensitive)
			}
			if provider.callCount() != 1 {
				t.Fatalf("provider calls = %d, want exactly 1", provider.callCount())
			}
		})
	}
}

func TestIssue35RequiredMissingPINClosesCategorically(t *testing.T) {
	connection, provider, writer := newIssue35PINConnection(nil, false)
	defer connection.stopHandshakeTimerAndWait()

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeOk))
	state, stateErr := connection.ShipHandshakeState()
	if state != model.SmeStateError || !errors.Is(stateErr, api.ErrPINUnavailable) {
		t.Fatalf("required missing PIN state/error = %v/%v, want error/%v",
			state, stateErr, api.ErrPINUnavailable)
	}
	if provider.callCount() != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.callCount())
	}
	assertIssue35NoSecretDisclosure(t, writer, issue35TestPIN)
}

func TestIssue35WrongPINClosesCategoricallyWithoutDisclosure(t *testing.T) {
	connection, provider, writer := newIssue35PINConnection([]byte(issue35TestPIN), true)
	defer connection.stopHandshakeTimerAndWait()

	issue35FakePeerPINState(t, connection, model.PinStateTypeRequired, pinPermission(model.PinInputPermissionTypeOk))
	assertIssue35SensitiveWrite(t, provider, writer)
	issue35FakePeerControl(t, connection, model.ConnectionPinError{
		ConnectionPinError: model.ConnectionPinErrorType{
			Error: model.ConnectionPinErrorErrorTypeWrongPIN,
		},
	})

	state, stateErr := connection.ShipHandshakeState()
	if state != model.SmeStateError || !errors.Is(stateErr, api.ErrPINRejected) {
		t.Fatalf("wrong PIN state/error = %v/%v, want error/%v", state, stateErr, api.ErrPINRejected)
	}
	assertIssue35NoSecretDisclosure(t, writer, issue35TestPIN)
}

func TestIssue35RequiredPINProtocolShapeFailsClosed(t *testing.T) {
	tests := []struct {
		name       string
		state      model.PinStateType
		permission *model.PinInputPermissionType
	}{
		{name: "required missing permission", state: model.PinStateTypeRequired},
		{name: "optional missing permission", state: model.PinStateTypeOptional},
		{name: "none carries permission", state: model.PinStateTypeNone, permission: pinPermission(model.PinInputPermissionTypeOk)},
		{name: "pin ok carries permission", state: model.PinStateTypePinOk, permission: pinPermission(model.PinInputPermissionTypeBusy)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection, _, writer := newIssue35PINConnection([]byte(issue35TestPIN), true)
			defer connection.stopHandshakeTimerAndWait()
			issue35FakePeerPINState(t, connection, test.state, test.permission)
			state, stateErr := connection.ShipHandshakeState()
			if state != model.SmeStateError || !errors.Is(stateErr, api.ErrPINProtocol) {
				t.Fatalf("invalid PIN shape state/error = %v/%v, want error/%v",
					state, stateErr, api.ErrPINProtocol)
			}
			assertIssue35NoSecretDisclosure(t, writer, issue35TestPIN)
		})
	}
}

func newIssue35PINConnection(pin []byte, available bool) (*ShipConnection, *issue35PINProvider, *issue35PINWriter) {
	provider := &issue35PINProvider{available: available, pin: append([]byte(nil), pin...)}
	info := &issue35PINInfoProvider{issue35PINProvider: provider}
	writer := &issue35PINWriter{expectedPIN: append([]byte(nil), pin...)}
	connection := NewConnectionHandler(
		info,
		writer,
		ShipRoleClient,
		"local-ship-id",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"remote-ship-id",
	)
	connection.setState(model.SmePinStateCheckListen, nil)
	return connection, provider, writer
}

func issue35FakePeerPINState(
	t *testing.T,
	connection *ShipConnection,
	state model.PinStateType,
	permission *model.PinInputPermissionType,
) {
	t.Helper()
	issue35FakePeerControl(t, connection, model.ConnectionPinState{
		ConnectionPinState: model.ConnectionPinStateType{
			PinState:        state,
			InputPermission: permission,
		},
	})
}

func issue35FakePeerAccessComplete(t *testing.T, connection *ShipConnection) {
	t.Helper()
	remoteID := "remote-ship-id"
	issue35FakePeerControl(t, connection, model.AccessMethods{
		AccessMethods: model.AccessMethodsType{Id: &remoteID},
	})
}

func issue35FakePeerControl(t *testing.T, connection *ShipConnection, value any) {
	t.Helper()
	message, err := connection.shipMessage(model.MsgTypeControl, value)
	if err != nil {
		t.Fatalf("create fake-peer control message: %v", err)
	}
	connection.handleShipMessage(false, message)
}

func pinPermission(value model.PinInputPermissionType) *model.PinInputPermissionType {
	return &value
}

func issue35HandshakeTimerDuration(t *testing.T, connection *ShipConnection) time.Duration {
	t.Helper()
	connection.handshakeTimerMux.Lock()
	defer connection.handshakeTimerMux.Unlock()
	value := reflect.ValueOf(connection).Elem().FieldByName("handshakeTimerDuration")
	if !value.IsValid() {
		t.Fatal("ShipConnection does not expose the active handshake timer duration for deterministic protocol tests")
	}
	return time.Duration(value.Int())
}

func assertIssue35SensitiveWrite(
	t *testing.T,
	provider *issue35PINProvider,
	writer *issue35PINWriter,
) {
	t.Helper()
	sensitiveCalls, matched, retained, normal, _ := writer.snapshot()
	if provider.callCount() != 1 || sensitiveCalls != 1 || !matched {
		t.Fatalf("provider/sensitive/match = %d/%d/%t, want 1/1/true",
			provider.callCount(), sensitiveCalls, matched)
	}
	if bytes.Contains(bytes.Join(normal, nil), []byte(issue35TestPIN)) {
		t.Fatal("PIN traversed the ordinary queued websocket writer")
	}
	if len(retained) == 0 {
		t.Fatal("fake sensitive writer did not retain the sender buffer")
	}
	for index, value := range retained {
		if value != 0 {
			t.Fatalf("transient PIN wire buffer byte %d was not cleared", index)
		}
	}
}

func assertIssue35NoSecretDisclosure(t *testing.T, writer *issue35PINWriter, secret string) {
	t.Helper()
	_, _, _, normal, closeReasons := writer.snapshot()
	for _, message := range normal {
		if bytes.Contains(message, []byte(secret)) {
			t.Fatal("ordinary websocket message disclosed PIN")
		}
	}
	for _, reason := range closeReasons {
		if strings.Contains(reason, secret) {
			t.Fatal("close reason disclosed PIN")
		}
	}
}
