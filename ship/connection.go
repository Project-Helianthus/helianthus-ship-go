package ship

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
)

// A ShipConnection handles the data connection and coordinates SHIP and SPINE messages i/o
type ShipConnection struct {
	// The ship connection mode of this connection
	role shipRole

	// The remote SKI
	remoteSKI string

	// the remote SHIP Id
	remoteShipID string

	// The local SHIP ID
	localShipID string

	// data provider
	infoProvider api.ShipConnectionInfoProviderInterface

	outgoingAttemptMetadata   api.OutgoingAttemptMetadata
	outgoingAttemptContext    context.Context
	hasOutgoingAttempt        bool
	requirePairingApproval    bool
	pairingApprovalRequested  bool
	pairingApprovalReleased   bool
	pairingCommitStarted      bool
	pairingCommitCallbackDone bool
	pairingClosing            bool
	pairingTerminal           bool
	spineSetupStarted         bool
	pairingApprovalMux        sync.Mutex
	testHooks                 *shipConnectionTestHooks

	// Where to pass incoming SPINE messages to
	dataReader api.ShipConnectionDataReaderInterface

	// the (web socket) handler for sending messages
	dataWriter api.WebsocketDataWriterInterface

	// The current SHIP state
	smeState model.ShipMessageExchangeState

	// the current error value if SHIP state is in error
	smeError error

	// handles timeouts for the various states
	//
	// WaitForReady SHIP 13.4.4.1.3: The communication partner must send its "READY" state (or request for prolongation") before the timer expires.
	//
	// SendProlongationRequest SHIP 13.4.4.1.3: Local timer to request for prolongation at the communication partner in time (i.e. before the communication partner's Wait-For-Ready-Timer expires).
	//
	// ProlongationRequestReply SHIP 13.4.4.1.3: Detection of response timeout on prolongation request.
	handshakeTimerRunning  bool
	handshakeTimerType     timeoutTimerType
	handshakeTimerStopChan chan struct{}
	handshakeTimerDoneChan chan struct{}
	handshakeTimerMux      sync.Mutex
	handshakeTimerIdle     *sync.Cond
	handshakeTimerActive   int

	lastReceivedWaitingValue time.Duration // required for Prolong-Request-Reply-Timer

	shutdownOnce sync.Once

	dataHandlerInitOnce        sync.Once
	outgoingAttemptTerminal    sync.Once
	attemptCancellationMux     sync.Mutex
	stopAttemptCancellation    func() bool
	initializeDataHandlerOnRun bool

	// buffer for SPINE messages that came in before the handshake was completed
	spineBuffer      [][]byte
	spineBufferBytes int

	mux                   sync.Mutex
	bufferMux             sync.Mutex
	spineDispatchMux      sync.Mutex
	spineDispatching      bool
	spineDispatchQueue    []func()
	pairingEffectMux      sync.Mutex
	pairingEffectQueue    []pairingEffectTask
	pairingEffectDraining bool
}

type shipConnectionTestHooks struct {
	beforePairingTerminalLock func()
	beforePairingCommit       func()
	beforeHandshakeErrorState func()
}

type pairingEffectTask struct {
	run  func()
	done chan struct{}
}

var _ api.ShipConnectionInterface = (*ShipConnection)(nil)
var _ api.OutgoingAttemptConnectionInterface = (*ShipConnection)(nil)

var ErrInvalidOutgoingAttemptConnectionConfiguration = errors.New("invalid outgoing attempt connection configuration")

const (
	maxBufferedSpineMessages = 16
	maxBufferedSpineBytes    = 16 * 1024
)

// OutgoingAttemptConnectionConfiguration binds an outgoing connection to its launch.
type OutgoingAttemptConnectionConfiguration struct {
	Metadata               api.OutgoingAttemptMetadata
	Context                context.Context
	RequirePairingApproval bool
}

func NewConnectionHandler(
	dataProvider api.ShipConnectionInfoProviderInterface,
	dataHandler api.WebsocketDataWriterInterface,
	role shipRole,
	localShipID,
	remoteSki,
	remoteShipId string) *ShipConnection {
	// The Hub must register inbound ownership before read-pump callbacks can close it.
	connection := newConnectionHandler(dataProvider, dataHandler, role, localShipID, remoteSki, remoteShipId, false)
	connection.initializeDataHandlerOnRun = true
	return connection
}

// NewOutgoingConnectionHandler creates a connection carrying one exact authorized attempt.
func NewOutgoingConnectionHandler(
	dataProvider api.ShipConnectionInfoProviderInterface,
	dataHandler api.WebsocketDataWriterInterface,
	role shipRole,
	localShipID,
	remoteSki,
	remoteShipId string,
	configuration OutgoingAttemptConnectionConfiguration) (*ShipConnection, error) {
	if configuration.Metadata.AttemptID == "" ||
		configuration.Metadata.Scope == "" ||
		isNilOutgoingAttemptContext(configuration.Context) {
		return nil, ErrInvalidOutgoingAttemptConnectionConfiguration
	}

	connection := newConnectionHandler(
		dataProvider,
		dataHandler,
		role,
		localShipID,
		remoteSki,
		remoteShipId,
		false,
	)
	connection.outgoingAttemptMetadata = configuration.Metadata
	connection.outgoingAttemptContext = configuration.Context
	connection.hasOutgoingAttempt = true
	connection.requirePairingApproval = configuration.RequirePairingApproval
	connection.initializeDataHandlerOnRun = true
	connection.setAttemptCancellationStop(context.AfterFunc(configuration.Context, func() {
		connection.initializeDataProcessing()
		connection.CloseConnection(false, 0, "outgoing attempt canceled")
	}))
	return connection, nil
}

func newConnectionHandler(
	dataProvider api.ShipConnectionInfoProviderInterface,
	dataHandler api.WebsocketDataWriterInterface,
	role shipRole,
	localShipID,
	remoteSki,
	remoteShipId string,
	initializeDataHandler bool) *ShipConnection {
	ship := &ShipConnection{
		infoProvider: dataProvider,
		dataWriter:   dataHandler,
		role:         role,
		localShipID:  localShipID,
		remoteSKI:    remoteSki,
		remoteShipID: remoteShipId,
		smeState:     model.CmiStateInitStart,
		smeError:     nil,
	}
	ship.handshakeTimerIdle = sync.NewCond(&ship.handshakeTimerMux)

	if initializeDataHandler {
		ship.initializeDataProcessing()
	}

	return ship
}

func isNilOutgoingAttemptContext(attemptContext context.Context) bool {
	if attemptContext == nil {
		return true
	}
	value := reflect.ValueOf(attemptContext)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (c *ShipConnection) initializeDataProcessing() {
	c.dataHandlerInitOnce.Do(func() {
		if c.dataWriter != nil {
			c.dataWriter.InitDataProcessing(c)
		}
	})
}

func (c *ShipConnection) setAttemptCancellationStop(stop func() bool) {
	c.attemptCancellationMux.Lock()
	c.stopAttemptCancellation = stop
	c.attemptCancellationMux.Unlock()
}

func (c *ShipConnection) stopOutgoingAttemptCancellation() {
	c.attemptCancellationMux.Lock()
	stop := c.stopAttemptCancellation
	c.stopAttemptCancellation = nil
	c.attemptCancellationMux.Unlock()
	if stop != nil {
		stop()
	}
}

func (c *ShipConnection) RemoteSKI() string {
	return c.remoteSKI
}

func (c *ShipConnection) DataHandler() api.WebsocketDataWriterInterface {
	return c.dataWriter
}

func (c *ShipConnection) OutgoingAttemptMetadata() (api.OutgoingAttemptMetadata, bool) {
	return c.outgoingAttemptMetadata, c.hasOutgoingAttempt
}

func (c *ShipConnection) reportConnectionClosed(handshakeCompleted bool) {
	if c.hasOutgoingAttempt {
		if provider, ok := c.infoProvider.(api.OutgoingAttemptShipConnectionInfoProviderInterface); ok {
			c.outgoingAttemptTerminal.Do(func() {
				c.stopOutgoingAttemptCancellation()
				provider.HandleConnectionClosedWithAttempt(c, handshakeCompleted, c.outgoingAttemptMetadata)
			})
			return
		}
	}
	c.infoProvider.HandleConnectionClosed(c, handshakeCompleted)
}

func (c *ShipConnection) reportShipHandshakeStateUpdate(state model.ShipState) {
	if c.hasOutgoingAttempt {
		if provider, ok := c.infoProvider.(api.OutgoingAttemptShipConnectionInfoProviderInterface); ok {
			provider.HandleShipHandshakeStateUpdateWithAttempt(c.remoteSKI, state, c.outgoingAttemptMetadata)
			return
		}
	}
	c.infoProvider.HandleShipHandshakeStateUpdate(c.remoteSKI, state)
}

// start SHIP communication
func (c *ShipConnection) Run() {
	if c.initializeDataHandlerOnRun {
		if !c.pairingEffectAllowed() {
			return
		}
		c.initializeDataProcessing()
		if c.hasOutgoingAttempt && c.outgoingAttemptContext.Err() != nil {
			c.CloseConnection(false, 0, "outgoing attempt canceled")
			return
		}
	}
	c.handleShipMessage(false, nil)
}

// provides the current ship state and error value if the state is in error
func (c *ShipConnection) ShipHandshakeState() (model.ShipMessageExchangeState, error) {
	return c.getState(), c.smeError
}

// invoked when pairing for a pending request is approved
func (c *ShipConnection) ApprovePendingHandshake() {
	if required, ready := c.requestPairingApproval(); required {
		if ready {
			c.approveHandshake()
		}
		return
	}

	state := c.getState()
	if state == model.SmeStateApproved {
		c.approveHandshake()
		return
	}
	if state != model.SmeHelloStatePendingListen {
		// TODO: what to do if the state is different?

		return
	}

	// TODO: move this into hs_hello.go and add tests

	// HELLO_OK
	c.stopHandshakeTimer()
	c.setAndHandleState(model.SmeHelloStateReadyInit)

	// TODO: check if we need to do some validations before moving on to the next state
	c.setAndHandleState(model.SmeHelloStateOk)
}

// invoked when pairing for a pending request is denied
func (c *ShipConnection) AbortPendingHandshake() {
	state := c.getState()
	if state == model.SmeStateApproved {
		c.CloseConnection(false, 4452, "pairing approval aborted")
		return
	}
	if state != model.SmeHelloStatePendingListen && state != model.SmeHelloStateReadyListen {
		// TODO: what to do if the state is differnet?

		return
	}

	// TODO: Move this into hs_hello.go and add tests

	c.stopHandshakeTimer()
	c.setAndHandleState(model.SmeHelloStateAbort)
}

func (c *ShipConnection) pairingApprovalPending() bool {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	return c.requirePairingApproval && !c.pairingApprovalReleased
}

func (c *ShipConnection) requestPairingApproval() (required bool, ready bool) {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	if c.pairingCommitStarted && !c.pairingCommitCallbackDone &&
		!c.pairingClosing && !c.pairingTerminal {
		c.pairingApprovalRequested = true
		return true, false
	}
	if !c.requirePairingApproval {
		return false, false
	}
	if c.pairingClosing || c.pairingTerminal || c.pairingApprovalReleased {
		return true, false
	}
	c.pairingApprovalRequested = true
	return true, c.pairingCommitStarted && c.pairingCommitCallbackDone
}

func (c *ShipConnection) beginPairingCommit() bool {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	if c.pairingClosing || c.pairingTerminal {
		return false
	}
	c.pairingCommitStarted = true
	c.pairingCommitCallbackDone = false
	return true
}

func (c *ShipConnection) completePairingCommitCallback() bool {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	if c.pairingClosing || c.pairingTerminal {
		return false
	}
	c.pairingCommitCallbackDone = true
	return c.pairingApprovalRequested
}

func (c *ShipConnection) pairingEffectAllowed() bool {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	return !c.pairingClosing && !c.pairingTerminal
}

// runPairingEffect serializes external pairing callbacks with terminal close.
// Blocking effects must not be started reentrantly from another pairing effect;
// reentrant CloseConnection is intentionally queued without waiting.
func (c *ShipConnection) runPairingEffect(run func(), wait bool) {
	task, shouldDrain := c.enqueuePairingEffect(run)
	if shouldDrain {
		c.drainPairingEffects()
	}
	if wait {
		<-task.done
	}
}

func (c *ShipConnection) enqueuePairingEffect(run func()) (pairingEffectTask, bool) {
	task := pairingEffectTask{run: run, done: make(chan struct{})}
	c.pairingEffectMux.Lock()
	c.pairingEffectQueue = append(c.pairingEffectQueue, task)
	if c.pairingEffectDraining {
		c.pairingEffectMux.Unlock()
		return task, false
	}
	c.pairingEffectDraining = true
	c.pairingEffectMux.Unlock()
	return task, true
}

func (c *ShipConnection) drainPairingEffects() {
	for {
		c.pairingEffectMux.Lock()
		if len(c.pairingEffectQueue) == 0 {
			c.pairingEffectDraining = false
			c.pairingEffectMux.Unlock()
			return
		}
		task := c.pairingEffectQueue[0]
		c.pairingEffectQueue[0] = pairingEffectTask{}
		c.pairingEffectQueue = c.pairingEffectQueue[1:]
		c.pairingEffectMux.Unlock()

		task.run()
		close(task.done)
	}
}

func (c *ShipConnection) reportServiceShipID() bool {
	reported := false
	c.runPairingEffect(func() {
		if !c.pairingEffectAllowed() {
			return
		}
		c.infoProvider.ReportServiceShipID(c.remoteSKI, c.remoteShipID)
		reported = true
	}, true)
	return reported
}

func (c *ShipConnection) publishPairingApproved() bool {
	published := false
	c.runPairingEffect(func() {
		if !c.pairingEffectAllowed() {
			return
		}
		c.setState(model.SmeStateApproved, nil)
		published = true
	}, true)
	return published
}

// close this ship connection
func (c *ShipConnection) CloseConnection(safe bool, code int, reason string) {
	closeClaimed := false
	c.shutdownOnce.Do(func() {
		closeClaimed = true
	})
	if !closeClaimed {
		return
	}
	c.pairingApprovalMux.Lock()
	c.pairingClosing = true
	c.pairingApprovalMux.Unlock()
	c.runPairingEffect(func() {
		c.closeConnection(safe, code, reason)
	}, false)
}

func (c *ShipConnection) closeConnection(safe bool, code int, reason string) {
	if c.testHooks != nil && c.testHooks.beforePairingTerminalLock != nil {
		c.testHooks.beforePairingTerminalLock()
	}
	c.pairingApprovalMux.Lock()
	c.pairingClosing = true
	c.pairingTerminal = true
	c.pairingApprovalMux.Unlock()
	c.discardBufferedSpineMessages()
	c.discardPendingSpineDispatches()
	c.stopOutgoingAttemptCancellation()
	c.stopHandshakeTimer()

	// handshake is completed if approved or aborted
	state := c.getState()
	handshakeEnd := state == model.SmeStateComplete ||
		state == model.SmeHelloStateAbortDone ||
		state == model.SmeHelloStateRemoteAbortDone ||
		state == model.SmeHelloStateRejected

	// this may not be used for Connection Data Exchange is entered!
	if safe && state == model.SmeStateComplete {
		// SHIP 13.4.7: Connection Termination Announce
		closeMessage := model.ConnectionClose{
			ConnectionClose: model.ConnectionCloseType{
				Phase:   model.ConnectionClosePhaseTypeAnnounce,
				MaxTime: util.Ptr(uint(500)),
				Reason:  util.Ptr(model.ConnectionCloseReasonType(reason)),
			},
		}

		_ = c.sendShipModel(model.MsgTypeEnd, closeMessage)

		go func() {
			// wait a bit to let it send
			<-time.After(500 * time.Millisecond)

			//
			c.dataWriter.CloseDataConnection(4001, "close")
			c.reportConnectionClosed(handshakeEnd)
		}()
		return
	}

	closeCode := 4001
	if code != 0 {
		closeCode = code
	}
	c.dataWriter.CloseDataConnection(closeCode, reason)

	c.reportConnectionClosed(handshakeEnd)
}

var _ api.ShipConnectionDataWriterInterface = (*ShipConnection)(nil)

// SpineDataConnection interface implementation
func (c *ShipConnection) WriteShipMessageWithPayload(message []byte) {
	if err := c.sendSpineData(message); err != nil {
		logging.Log().Debug(c.RemoteSKI(), "Error sending spine message: ", err)
		return
	}
}

var _ api.WebsocketDataReaderInterface = (*ShipConnection)(nil)

func (c *ShipConnection) shipModelFromMessage(message []byte) (*model.ShipData, error) {
	_, jsonData := c.parseMessage(message, true)

	// Get the datagram from the message
	data := model.ShipData{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		logging.Log().Debug(c.RemoteSKI(), "error unmarshalling message: ", err)
		return nil, err
	}

	if data.Data.Payload == nil {
		errorMsg := "received no valid payload"
		logging.Log().Debug(c.RemoteSKI(), errorMsg)
		return nil, errors.New(errorMsg)
	}

	return &data, nil
}

func (c *ShipConnection) discardBufferedSpineMessages() {
	c.bufferMux.Lock()
	c.spineBuffer = nil
	c.spineBufferBytes = 0
	c.bufferMux.Unlock()
}

func (c *ShipConnection) discardPendingSpineDispatches() {
	c.spineDispatchMux.Lock()
	c.spineDispatchQueue = nil
	c.spineDispatchMux.Unlock()
}

// route the incoming message to either SHIP or SPINE message handlers
func (c *ShipConnection) HandleIncomingWebsocketMessage(message []byte) {
	// Check if this is a SHIP SME or SPINE message
	if !c.hasSpineDatagram(message) {
		c.handleShipMessage(false, message)
		return
	}

	data, err := c.shipModelFromMessage(message)
	if err != nil {
		return
	}

	payload := []byte(data.Data.Payload)
	c.spineDispatchMux.Lock()
	reader, closeCode, closeReason := c.routeOrBufferSpinePayload(payload)
	if closeCode != 0 {
		c.spineDispatchMux.Unlock()
		c.CloseConnection(false, closeCode, closeReason)
		return
	}
	if reader == nil {
		c.spineDispatchMux.Unlock()
		return
	}
	payload = append([]byte(nil), payload...)
	shouldDrain := c.enqueueSpineDispatchLocked(func() {
		if !c.spineDispatchTerminated() {
			reader.HandleShipPayloadMessage(payload)
		}
	})
	c.spineDispatchMux.Unlock()
	if shouldDrain {
		c.drainSpineDispatchQueue()
	}
}

// enqueueSpineDispatchLocked appends work in admission order. The first caller
// owns synchronous draining; reentrant and concurrent arrivals only enqueue.
func (c *ShipConnection) enqueueSpineDispatchLocked(tasks ...func()) bool {
	c.spineDispatchQueue = append(c.spineDispatchQueue, tasks...)
	if c.spineDispatching {
		return false
	}
	c.spineDispatching = true
	return true
}

func (c *ShipConnection) drainSpineDispatchQueue() {
	for {
		c.spineDispatchMux.Lock()
		if len(c.spineDispatchQueue) == 0 {
			c.spineDispatching = false
			c.spineDispatchMux.Unlock()
			return
		}
		task := c.spineDispatchQueue[0]
		c.spineDispatchQueue[0] = nil
		c.spineDispatchQueue = c.spineDispatchQueue[1:]
		c.spineDispatchMux.Unlock()
		task()
	}
}

func (c *ShipConnection) routeOrBufferSpinePayload(
	payload []byte,
) (api.ShipConnectionDataReaderInterface, int, string) {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	c.bufferMux.Lock()
	defer c.bufferMux.Unlock()

	if c.pairingClosing || c.pairingTerminal {
		return nil, 0, ""
	}
	if c.dataReader != nil {
		return c.dataReader, 0, ""
	}
	if c.requirePairingApproval && !c.pairingApprovalReleased {
		c.pairingTerminal = true
		return nil, 4452, "SPINE data before pairing approval"
	}
	if len(c.spineBuffer) >= maxBufferedSpineMessages ||
		len(payload) > maxBufferedSpineBytes-c.spineBufferBytes {
		c.pairingTerminal = true
		return nil, 4452, "SPINE setup buffer limit exceeded"
	}
	c.spineBuffer = append(c.spineBuffer, append([]byte(nil), payload...))
	c.spineBufferBytes += len(payload)
	return nil, 0, ""
}

func (c *ShipConnection) spineDispatchTerminated() bool {
	c.pairingApprovalMux.Lock()
	defer c.pairingApprovalMux.Unlock()
	return c.pairingClosing || c.pairingTerminal
}

// checks wether the provided messages is a SHIP message
func (c *ShipConnection) hasSpineDatagram(message []byte) bool {
	return bytes.Contains(message, []byte("datagram"))
}

// the websocket data connection was closed from remote
func (c *ShipConnection) ReportConnectionError(err error) {
	if !c.pairingEffectAllowed() {
		return
	}
	// if the handshake is aborted, a closed connection is no error
	currentState := c.getState()

	// rejections are also received by sending `{"connectionHello":[{"phase":"pending"},{"waiting":60000}]}`
	// and then closing the websocket connection with `4452: Node rejected by application.`
	if currentState == model.SmeHelloStateReadyListen {
		c.setState(model.SmeHelloStateRejected, nil)
		c.CloseConnection(false, 0, "")
		return
	}

	if currentState == model.SmeHelloStateRemoteAbortDone {
		// remote service should close the connection
		c.CloseConnection(false, 0, "")
		return
	}

	if currentState == model.SmeHelloStateAbort ||
		currentState == model.SmeHelloStateAbortDone {
		c.CloseConnection(false, 4452, "Node rejected by application")
		return
	}

	c.setState(model.SmeStateError, err)

	c.CloseConnection(false, 0, "")

	state := model.ShipState{
		State: model.SmeStateError,
		Error: err,
	}
	c.reportShipHandshakeStateUpdate(state)
}

const payloadPlaceholder = `{"place":"holder"}`

func (c *ShipConnection) transformSpineDataIntoShipJson(data []byte) ([]byte, error) {
	spineMsg, err := JsonIntoEEBUSJson(data)
	if err != nil {
		return nil, err
	}

	payload := json.RawMessage([]byte(spineMsg))

	// Workaround for the fact that SHIP payload is a json.RawMessage
	// which would also be transformed into an array element but it shouldn't
	// hence patching the payload into the message later after the SHIP
	// and SPINE model are transformed independently

	// Create the message
	shipMessage := model.ShipData{
		Data: model.DataType{
			Header: model.HeaderType{
				ProtocolId: model.ShipProtocolId,
			},
			Payload: json.RawMessage([]byte(payloadPlaceholder)),
		},
	}

	msg, err := json.Marshal(shipMessage)
	if err != nil {
		return nil, err
	}

	eebusMsg, err := JsonIntoEEBUSJson(msg)
	if err != nil {
		return nil, err
	}

	eebusMsg = strings.ReplaceAll(eebusMsg, `[`+payloadPlaceholder+`]`, string(payload))

	return []byte(eebusMsg), nil
}

func (c *ShipConnection) sendSpineData(data []byte) error {
	eebusMsg, err := c.transformSpineDataIntoShipJson(data)
	if err != nil {
		return err
	}

	if isClosed, err := c.dataWriter.IsDataConnectionClosed(); isClosed {
		c.CloseConnection(false, 0, "")
		return err
	}

	// Wrap the message into a binary message with the ship header
	shipMsg := []byte{model.MsgTypeData}
	shipMsg = append(shipMsg, eebusMsg...)

	err = c.dataWriter.WriteMessageToWebsocketConnection(shipMsg)
	if err != nil {
		logging.Log().Debug("error sending message: ", err)
		return err
	}

	return nil
}

// send a json message for a provided model to the websocket connection
func (c *ShipConnection) sendShipModel(typ byte, model interface{}) error {
	shipMsg, err := c.shipMessage(typ, model)
	if err != nil {
		return err
	}

	err = c.dataWriter.WriteMessageToWebsocketConnection(shipMsg)
	if err != nil {
		return err
	}

	return nil
}

// Process a SHIP Json message
func (c *ShipConnection) processShipJsonMessage(message []byte, target any) error {
	_, data := c.parseMessage(message, true)

	return json.Unmarshal(data, &target)
}

// transform a SHIP model into EEBUS specific JSON
func (c *ShipConnection) shipMessage(typ byte, model interface{}) ([]byte, error) {
	if isClosed, err := c.dataWriter.IsDataConnectionClosed(); isClosed {
		c.CloseConnection(false, 0, "")
		return nil, err
	}

	if model == nil {
		return nil, errors.New("invalid data")
	}

	msg, err := json.Marshal(model)
	if err != nil {
		return nil, err
	}

	eebusMsg, err := JsonIntoEEBUSJson(msg)
	if err != nil {
		return nil, err
	}

	// Wrap the message into a binary message with the ship header
	shipMsg := []byte{typ}
	shipMsg = append(shipMsg, eebusMsg...)

	return shipMsg, nil
}

// return the SHIP message type, the SHIP message and an error
//
// enable jsonFormat if the return message is expected to be encoded in the eebus json format
func (c *ShipConnection) parseMessage(msg []byte, jsonFormat bool) (byte, []byte) {
	if len(msg) == 0 {
		return 0, nil
	}

	// Extract the SHIP header byte
	shipHeaderByte := msg[0]
	// remove the SHIP header byte from the message
	msg = msg[1:]

	if jsonFormat {
		return shipHeaderByte, JsonFromEEBUSJson(msg)
	}

	return shipHeaderByte, msg
}
