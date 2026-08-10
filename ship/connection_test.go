package ship

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/mocks"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

func TestConnectionSuite(t *testing.T) {
	suite.Run(t, new(ConnectionSuite))
}

func (s *ConnectionSuite) AfterTest(_, _ string) {
	if s.sut != nil {
		s.sut.stopHandshakeTimerAndWait()
	}
}

func (s *ConnectionSuite) TestStopHandshakeTimerAndWaitJoinsAdmittedTimeout() {
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		closed: func(api.ShipConnectionInterface, bool) {
			close(callbackEntered)
			<-releaseCallback
		},
	}
	s.sut.setState(model.CmiStateClientWait, nil)
	s.sut.setHandshakeTimer(timeoutTimerTypeWaitForReady, time.Millisecond)

	waitForConnectionSignal(s.T(), callbackEntered, "admitted timeout callback")
	waitComplete := make(chan struct{})
	go func() {
		s.sut.stopHandshakeTimerAndWait()
		close(waitComplete)
	}()

	select {
	case <-waitComplete:
		s.T().Fatal("timer teardown returned before admitted callback completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseCallback)
	waitForConnectionSignal(s.T(), waitComplete, "timer teardown barrier")
}

func (s *ConnectionSuite) TestStopHandshakeTimerAndWaitCancelsTimerSpawnedByCallback() {
	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		allow: func(string) bool {
			close(callbackEntered)
			<-releaseCallback
			return true
		},
	}
	s.sut.setState(model.SmeHelloStatePendingListen, nil)
	s.sut.setHandshakeTimer(timeoutTimerTypeWaitForReady, time.Millisecond)

	waitForConnectionSignal(s.T(), callbackEntered, "timer replacement callback")
	waitComplete := make(chan struct{})
	go func() {
		s.sut.stopHandshakeTimerAndWait()
		close(waitComplete)
	}()
	close(releaseCallback)
	waitForConnectionSignal(s.T(), waitComplete, "replacement timer teardown")
}

type ConnectionSuite struct {
	suite.Suite

	sut *ShipConnection

	infoProvider *mocks.ShipConnectionInfoProviderInterface
	wsDataWriter *mocks.WebsocketDataWriterInterface

	shipConnectionReader *mocks.ShipConnectionDataReaderInterface

	sentMessage []byte

	mux sync.Mutex
}

type callbackSpineReader struct {
	handle func([]byte)
}

type concurrentConnectionInfoProvider struct {
	setup  func(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface
	report func(string, string)
	closed func(api.ShipConnectionInterface, bool)
	state  func(string, model.ShipState)
	allow  func(string) bool
}

func (*concurrentConnectionInfoProvider) IsRemoteServiceForSKIPaired(string) bool { return false }
func (*concurrentConnectionInfoProvider) IsAutoAcceptEnabled() bool               { return false }
func (p *concurrentConnectionInfoProvider) HandleConnectionClosed(connection api.ShipConnectionInterface, complete bool) {
	if p.closed != nil {
		p.closed(connection, complete)
	}
}
func (p *concurrentConnectionInfoProvider) ReportServiceShipID(ski, shipID string) {
	if p.report != nil {
		p.report(ski, shipID)
	}
}
func (p *concurrentConnectionInfoProvider) AllowWaitingForTrust(id string) bool {
	if p.allow == nil {
		return false
	}
	return p.allow(id)
}
func (p *concurrentConnectionInfoProvider) HandleShipHandshakeStateUpdate(ski string, state model.ShipState) {
	if p.state != nil {
		p.state(ski, state)
	}
}
func (p *concurrentConnectionInfoProvider) SetupRemoteDevice(
	ski string,
	writer api.ShipConnectionDataWriterInterface,
) api.ShipConnectionDataReaderInterface {
	if p.setup == nil {
		return nil
	}
	return p.setup(ski, writer)
}

func (r *callbackSpineReader) HandleShipPayloadMessage(message []byte) {
	r.handle(message)
}

func (s *ConnectionSuite) BeforeTest(suiteName, testName string) {
	s.mux.Lock()
	s.sentMessage = nil
	s.mux.Unlock()

	s.infoProvider = mocks.NewShipConnectionInfoProviderInterface(s.T())
	s.infoProvider.EXPECT().HandleShipHandshakeStateUpdate(mock.Anything, mock.Anything).Return().Maybe()
	s.infoProvider.EXPECT().HandleConnectionClosed(mock.Anything, mock.Anything).Return().Maybe()
	s.infoProvider.EXPECT().IsRemoteServiceForSKIPaired(mock.Anything).Return(false).Maybe()
	s.infoProvider.EXPECT().AllowWaitingForTrust(mock.Anything).Return(false).Maybe()

	s.wsDataWriter = mocks.NewWebsocketDataWriterInterface(s.T())
	s.wsDataWriter.EXPECT().InitDataProcessing(mock.Anything).Return().Maybe()
	s.wsDataWriter.EXPECT().WriteMessageToWebsocketConnection(mock.Anything).
		RunAndReturn(func(message []byte) error {
			s.mux.Lock()
			defer s.mux.Unlock()

			s.sentMessage = message

			return nil
		}).
		Maybe()
	s.wsDataWriter.EXPECT().IsDataConnectionClosed().Return(false, nil).Maybe()
	s.wsDataWriter.EXPECT().CloseDataConnection(mock.Anything, mock.Anything).Return().Maybe()

	s.shipConnectionReader = mocks.NewShipConnectionDataReaderInterface(s.T())
	s.shipConnectionReader.EXPECT().HandleShipPayloadMessage(mock.Anything).Return().Maybe()

	s.sut = NewConnectionHandler(s.infoProvider, s.wsDataWriter, ShipRoleServer, "LocalShipID", "RemoveDevice", "RemoteShipID")
}

func (s *ConnectionSuite) Test_RemoteSKI() {
	remoteSki := s.sut.RemoteSKI()
	assert.NotEqual(s.T(), "", remoteSki)
}

func (s *ConnectionSuite) Test_DataHandler() {
	handler := s.sut.DataHandler()
	assert.NotNil(s.T(), handler)
}

func (s *ConnectionSuite) TestRun() {
	s.sut.Run()
	state, err := s.sut.ShipHandshakeState()
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), model.CmiStateServerWait, state)
}

func (s *ConnectionSuite) Test_HandleShipCloseMessage() {
	s.sut.handleShipMessage(false, []byte{})
	state, err := s.sut.ShipHandshakeState()
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), model.CmiStateServerWait, state)

	closeMsg := model.ConnectionClose{
		ConnectionClose: model.ConnectionCloseType{
			Phase: model.ConnectionClosePhaseTypeAnnounce,
		},
	}

	msg, err := s.sut.shipMessage(model.MsgTypeControl, closeMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleShipMessage(false, msg)

	closeMsg = model.ConnectionClose{
		ConnectionClose: model.ConnectionCloseType{
			Phase: model.ConnectionClosePhaseTypeConfirm,
		},
	}

	msg, err = s.sut.shipMessage(model.MsgTypeControl, closeMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleShipMessage(false, msg)
}

func (s *ConnectionSuite) TestProtocolCloseIsTerminalBeforePendingTimeoutCanPublish() {
	for _, phase := range []model.ConnectionClosePhaseType{
		model.ConnectionClosePhaseTypeAnnounce,
		model.ConnectionClosePhaseTypeConfirm,
	} {
		s.Run(string(phase), func() {
			var stateMux sync.Mutex
			var states []model.ShipMessageExchangeState
			closed := make(chan struct{}, 1)
			provider := &concurrentConnectionInfoProvider{
				closed: func(api.ShipConnectionInterface, bool) {
					closed <- struct{}{}
				},
				state: func(_ string, state model.ShipState) {
					stateMux.Lock()
					states = append(states, state.State)
					stateMux.Unlock()
				},
			}
			s.sut = NewConnectionHandler(
				provider,
				s.wsDataWriter,
				ShipRoleServer,
				"LocalShipID",
				"RemoveDevice",
				"RemoteShipID",
			)
			s.sut.setState(model.SmeAccessMethodsRequest, nil)
			s.sut.setHandshakeTimer(timeoutTimerTypeWaitForReady, time.Hour)

			closeMsg := model.ConnectionClose{
				ConnectionClose: model.ConnectionCloseType{
					Phase: phase,
				},
			}
			msg, err := s.sut.shipMessage(model.MsgTypeControl, closeMsg)
			assert.NoError(s.T(), err)
			s.sut.handleShipMessage(false, msg)

			select {
			case <-closed:
			case <-time.After(time.Second):
				s.T().Fatal("protocol close did not report terminal connection")
			}
			assert.True(s.T(), s.sut.pairingTerminal)
			assert.False(s.T(), s.sut.getHandshakeTimerRunning())
			stateMux.Lock()
			beforeTimeout := append([]model.ShipMessageExchangeState(nil), states...)
			stateMux.Unlock()

			s.sut.handleState(true, nil)
			stateMux.Lock()
			afterTimeout := append([]model.ShipMessageExchangeState(nil), states...)
			stateMux.Unlock()
			assert.Equal(s.T(), beforeTimeout, afterTimeout)
		})
	}
}

func (s *ConnectionSuite) TestAdmittedTimeoutCannotPublishAfterTerminalClose() {
	var stateMux sync.Mutex
	var states []model.ShipMessageExchangeState
	closed := make(chan struct{}, 1)
	provider := &concurrentConnectionInfoProvider{
		closed: func(api.ShipConnectionInterface, bool) {
			closed <- struct{}{}
		},
		state: func(_ string, state model.ShipState) {
			stateMux.Lock()
			states = append(states, state.State)
			stateMux.Unlock()
		},
	}
	s.sut = NewConnectionHandler(
		provider,
		s.wsDataWriter,
		ShipRoleServer,
		"LocalShipID",
		"RemoveDevice",
		"RemoteShipID",
	)
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	timeoutAdmitted := make(chan struct{})
	timeoutRelease := make(chan struct{})
	s.sut.testHooks = &shipConnectionTestHooks{
		beforeHandshakeErrorState: func() {
			close(timeoutAdmitted)
			<-timeoutRelease
		},
	}
	timeoutDone := make(chan struct{})
	go func() {
		s.sut.handleState(true, nil)
		close(timeoutDone)
	}()
	waitForConnectionSignal(s.T(), timeoutAdmitted, "admitted timeout")

	s.sut.CloseConnection(false, 4001, "terminal during timeout")
	waitForConnectionSignal(s.T(), closed, "terminal close")
	assert.True(s.T(), s.sut.pairingTerminal)
	stateMux.Lock()
	beforeRelease := append([]model.ShipMessageExchangeState(nil), states...)
	stateMux.Unlock()

	close(timeoutRelease)
	waitForConnectionSignal(s.T(), timeoutDone, "rejected timeout publication")
	stateMux.Lock()
	afterRelease := append([]model.ShipMessageExchangeState(nil), states...)
	stateMux.Unlock()
	assert.Equal(s.T(), beforeRelease, afterRelease)
	assert.Equal(s.T(), model.SmeAccessMethodsRequest, s.sut.getState())
}

func (s *ConnectionSuite) TestShipHandshakeState() {
	state, err := s.sut.ShipHandshakeState()
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), model.CmiStateInitStart, state)
}

func (s *ConnectionSuite) Test_HandleErrorState() {
	s.sut.setState(model.SmeStateError, errors.New("error"))

	state, err := s.sut.ShipHandshakeState()
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), model.SmeStateError, state)

	s.sut.handleState(false, []byte{})
}

func (s *ConnectionSuite) TestApprovePendingHandshake() {
	s.sut.smeState = model.CmiStateInitStart
	s.sut.ApprovePendingHandshake()
	assert.Equal(s.T(), model.CmiStateInitStart, s.sut.smeState)

	s.sut.smeState = model.SmeHelloStatePendingListen
	s.sut.ApprovePendingHandshake()
	assert.Equal(s.T(), model.SmeProtHStateServerListenProposal, s.sut.smeState)
}

func (s *ConnectionSuite) TestAbortPendingHandshake() {
	s.sut.smeState = model.CmiStateInitStart
	s.sut.AbortPendingHandshake()
	assert.Equal(s.T(), model.CmiStateInitStart, s.sut.smeState)

	s.sut.smeState = model.SmeHelloStatePendingListen
	s.sut.AbortPendingHandshake()
	assert.Equal(s.T(), model.SmeHelloStateAbortDone, s.sut.smeState)
}

func (s *ConnectionSuite) TestCloseConnection_StateComplete() {
	s.sut.smeState = model.SmeStateComplete
	s.sut.CloseConnection(true, 450, "User Close")
	state, err := s.sut.ShipHandshakeState()
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), model.SmeStateComplete, state)
}

func (s *ConnectionSuite) TestCloseConnection_StateComplete_2() {
	s.sut.smeState = model.SmeStateError
	s.sut.CloseConnection(false, 0, "User Close")
	state, err := s.sut.ShipHandshakeState()
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), model.SmeStateError, state)
}

func (s *ConnectionSuite) TestCloseConnection_StateComplete_3() {
	s.sut.smeState = model.SmeStateError
	s.sut.CloseConnection(false, 450, "User Close")
	state, err := s.sut.ShipHandshakeState()
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), model.SmeStateError, state)
}

func (s *ConnectionSuite) TestShipModelFromMessage() {
	msg := []byte{}
	data, err := s.sut.shipModelFromMessage(msg)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), data)

	modelData := model.ShipData{}
	jsonData, err := json.Marshal(modelData)
	assert.Nil(s.T(), err)

	msg = []byte{0}
	msg = append(msg, jsonData...)
	data, err = s.sut.shipModelFromMessage(msg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), data)
}

func (s *ConnectionSuite) TestHandleIncomingShipMessage() {
	modelData := model.ShipData{}
	jsonData, err := json.Marshal(modelData)
	assert.Nil(s.T(), err)

	msg := []byte{0}
	msg = append(msg, jsonData...)

	s.sut.HandleIncomingWebsocketMessage(msg)

	spineData := `{"datagram":{}}`
	jsonData = []byte(spineData)

	modelData = model.ShipData{
		Data: model.DataType{
			Payload: jsonData,
		},
	}
	jsonData, err = json.Marshal(modelData)
	assert.Nil(s.T(), err)

	msg = []byte{0}
	msg = append(msg, jsonData...)

	s.sut.HandleIncomingWebsocketMessage(msg)
	assert.Len(s.T(), s.sut.spineBuffer, 1)
	assert.Equal(s.T(), len(spineData), s.sut.spineBufferBytes)

	s.infoProvider.EXPECT().SetupRemoteDevice("RemoveDevice", s.sut).Return(s.shipConnectionReader).Once()
	s.sut.approveHandshake()
	assert.Empty(s.T(), s.sut.spineBuffer)
	assert.Zero(s.T(), s.sut.spineBufferBytes)

	s.sut.HandleIncomingWebsocketMessage(msg)
}

func (s *ConnectionSuite) TestPreApprovalSpineDataClosesWithoutBuffering() {
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.setState(model.SmeStateApproved, nil)

	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), []byte(`{"datagram":{}}`)))

	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Empty(s.T(), s.sut.spineBuffer)
	assert.Zero(s.T(), s.sut.spineBufferBytes)
}

func (s *ConnectionSuite) TestPreApprovalSpineRejectionWinsAgainstConcurrentApproval() {
	s.sut.infoProvider = &concurrentConnectionInfoProvider{}
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.setState(model.SmeStateApproved, nil)

	closeEntered := make(chan struct{})
	closeRelease := make(chan struct{})
	s.sut.testHooks = &shipConnectionTestHooks{
		beforePairingTerminalLock: func() {
			close(closeEntered)
			<-closeRelease
		},
	}
	arrivalDone := make(chan struct{})
	go func() {
		s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), []byte(`{"datagram":{}}`)))
		close(arrivalDone)
	}()
	waitForConnectionSignal(s.T(), closeEntered, "pre-approval SPINE rejection")

	approvalDone := make(chan struct{})
	go func() {
		s.sut.ApprovePendingHandshake()
		close(approvalDone)
	}()
	select {
	case <-approvalDone:
	case <-time.After(time.Second):
		s.T().Fatal("rejected approval did not return")
	}

	close(closeRelease)
	waitForConnectionSignal(s.T(), arrivalDone, "pre-approval SPINE close")
	assert.True(s.T(), s.sut.pairingTerminal)
	assert.False(s.T(), s.sut.pairingApprovalReleased)
	assert.Nil(s.T(), s.sut.dataReader)
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())
}

func (s *ConnectionSuite) TestTerminalConnectionDropsSpineWithInstalledReader() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	s.sut.dataReader = reader
	s.sut.CloseConnection(false, 4001, "terminal")

	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), []byte(`{"datagram":{}}`)))

	assert.True(s.T(), s.sut.pairingTerminal)
}

func (s *ConnectionSuite) TestWaitingLiveArrivalIsDroppedAfterReentrantClose() {
	s.sut.infoProvider = &concurrentConnectionInfoProvider{}
	first := []byte(`{"datagram":{"sequence":1}}`)
	second := []byte(`{"datagram":{"sequence":2}}`)
	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	var receivedMu sync.Mutex
	var received [][]byte
	reader := &callbackSpineReader{handle: func(payload []byte) {
		receivedMu.Lock()
		received = append(received, append([]byte(nil), payload...))
		count := len(received)
		receivedMu.Unlock()
		if count == 1 {
			close(firstEntered)
			<-firstRelease
			s.sut.CloseConnection(false, 4001, "reentrant close")
		}
	}}
	s.sut.dataReader = reader

	firstDone := make(chan struct{})
	go func() {
		s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), first))
		close(firstDone)
	}()
	waitForConnectionSignal(s.T(), firstEntered, "first live SPINE delivery")

	secondStarted := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		close(secondStarted)
		s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), second))
		close(secondDone)
	}()
	waitForConnectionSignal(s.T(), secondStarted, "second live SPINE arrival")
	select {
	case <-secondDone:
	case <-time.After(time.Second):
		s.T().Fatal("reentrant-safe delivery queue did not admit the second payload")
	}

	close(firstRelease)
	waitForConnectionSignal(s.T(), firstDone, "first live SPINE completion")
	waitForConnectionSignal(s.T(), secondDone, "terminal live SPINE drop")
	receivedMu.Lock()
	defer receivedMu.Unlock()
	assert.Equal(s.T(), [][]byte{first}, received)
	assert.True(s.T(), s.sut.pairingTerminal)
}

func (s *ConnectionSuite) TestApprovalDrainAllowsReentrantCloseAndStopsReplay() {
	first := []byte(`{"datagram":{"sequence":1}}`)
	second := []byte(`{"datagram":{"sequence":2}}`)
	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), first))
	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), second))

	var receivedMu sync.Mutex
	var received [][]byte
	reader := &callbackSpineReader{handle: func(payload []byte) {
		receivedMu.Lock()
		received = append(received, append([]byte(nil), payload...))
		count := len(received)
		receivedMu.Unlock()
		if count == 1 {
			s.sut.CloseConnection(false, 4001, "reentrant close")
		}
	}}
	s.infoProvider.EXPECT().SetupRemoteDevice("RemoveDevice", s.sut).Return(reader).Once()

	done := make(chan struct{})
	go func() {
		s.sut.approveHandshake()
		close(done)
	}()
	waitForConnectionSignal(s.T(), done, "reentrant approval drain")

	receivedMu.Lock()
	defer receivedMu.Unlock()
	assert.Equal(s.T(), [][]byte{first}, received)
	assert.True(s.T(), s.sut.pairingTerminal)
}

func (s *ConnectionSuite) TestApprovalDrainOrdersConcurrentArrivalAfterBufferedPayloads() {
	first := []byte(`{"datagram":{"sequence":1}}`)
	second := []byte(`{"datagram":{"sequence":2}}`)
	third := []byte(`{"datagram":{"sequence":3}}`)
	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), first))
	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), second))

	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	var firstOnce sync.Once
	var receivedMu sync.Mutex
	var received [][]byte
	reader := &callbackSpineReader{handle: func(payload []byte) {
		receivedMu.Lock()
		received = append(received, append([]byte(nil), payload...))
		count := len(received)
		receivedMu.Unlock()
		if count == 1 {
			firstOnce.Do(func() { close(firstEntered) })
			<-firstRelease
		}
	}}
	s.infoProvider.EXPECT().SetupRemoteDevice("RemoveDevice", s.sut).Return(reader).Once()

	approvalDone := make(chan struct{})
	go func() {
		s.sut.approveHandshake()
		close(approvalDone)
	}()
	waitForConnectionSignal(s.T(), firstEntered, "first buffered SPINE delivery")

	arrivalDone := make(chan struct{})
	go func() {
		s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), third))
		close(arrivalDone)
	}()
	select {
	case <-arrivalDone:
	case <-time.After(time.Second):
		s.T().Fatal("concurrent SPINE arrival was not admitted to the delivery queue")
	}
	receivedMu.Lock()
	assert.Equal(s.T(), [][]byte{first}, received)
	receivedMu.Unlock()

	close(firstRelease)
	waitForConnectionSignal(s.T(), approvalDone, "approval drain completion")
	waitForConnectionSignal(s.T(), arrivalDone, "concurrent SPINE delivery completion")

	receivedMu.Lock()
	defer receivedMu.Unlock()
	assert.Equal(s.T(), [][]byte{first, second, third}, received)
}

func (s *ConnectionSuite) TestLivePayloadCallbackCanReenterIncomingDeliveryInOrder() {
	first := []byte(`{"datagram":{"sequence":1}}`)
	second := []byte(`{"datagram":{"sequence":2}}`)
	var received [][]byte
	reader := &callbackSpineReader{handle: func(payload []byte) {
		received = append(received, append([]byte(nil), payload...))
		if len(received) == 1 {
			s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), second))
		}
	}}
	s.sut.dataReader = reader

	done := make(chan struct{})
	go func() {
		s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), first))
		close(done)
	}()
	waitForConnectionSignal(s.T(), done, "reentrant live SPINE delivery")
	assert.Equal(s.T(), [][]byte{first, second}, received)
}

func (s *ConnectionSuite) TestReaderInstallationIsOneShotForOrdinaryConnection() {
	setupEntered := make(chan struct{})
	setupRelease := make(chan struct{})
	var setupMu sync.Mutex
	setupCount := 0
	reader := &callbackSpineReader{handle: func([]byte) {}}
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		setup: func(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
			setupMu.Lock()
			setupCount++
			setupMu.Unlock()
			close(setupEntered)
			<-setupRelease
			return reader
		},
	}

	firstDone := make(chan struct{})
	go func() {
		s.sut.approveHandshake()
		close(firstDone)
	}()
	waitForConnectionSignal(s.T(), setupEntered, "first SPINE reader setup")

	secondDone := make(chan struct{})
	go func() {
		s.sut.approveHandshake()
		close(secondDone)
	}()
	waitForConnectionSignal(s.T(), secondDone, "duplicate SPINE reader setup rejection")

	close(setupRelease)
	waitForConnectionSignal(s.T(), firstDone, "first SPINE reader setup completion")
	setupMu.Lock()
	defer setupMu.Unlock()
	assert.Equal(s.T(), 1, setupCount)
	assert.Same(s.T(), reader, s.sut.dataReader)
}

func (s *ConnectionSuite) TestNilSpineReaderClosesFailClosedWithoutDraining() {
	payload := []byte(`{"datagram":{"sequence":1}}`)
	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), payload))
	s.infoProvider.EXPECT().SetupRemoteDevice("RemoveDevice", s.sut).Return(nil).Once()

	assert.NotPanics(s.T(), func() {
		s.sut.approveHandshake()
	})
	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Nil(s.T(), s.sut.dataReader)
}

func (s *ConnectionSuite) TestSpineSetupBufferCountLimitClosesFailClosed() {
	message := spineWebsocketMessage(s.T(), []byte(`{"datagram":{}}`))
	for range maxBufferedSpineMessages {
		s.sut.HandleIncomingWebsocketMessage(message)
	}

	assert.Len(s.T(), s.sut.spineBuffer, maxBufferedSpineMessages)
	assert.False(s.T(), s.sut.pairingTerminal)

	s.sut.HandleIncomingWebsocketMessage(message)

	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Empty(s.T(), s.sut.spineBuffer)
	assert.Zero(s.T(), s.sut.spineBufferBytes)
}

func (s *ConnectionSuite) TestSpineSetupBufferByteLimitAcceptsBoundaryThenCloses() {
	const envelope = `{"datagram":""}`
	payload := []byte(`{"datagram":"` +
		strings.Repeat("x", maxBufferedSpineBytes-len(envelope)) +
		`"}`)
	assert.Len(s.T(), payload, maxBufferedSpineBytes)

	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), payload))
	assert.Equal(s.T(), maxBufferedSpineBytes, s.sut.spineBufferBytes)
	assert.False(s.T(), s.sut.pairingTerminal)

	s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), []byte(`{"datagram":{}}`)))

	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Empty(s.T(), s.sut.spineBuffer)
	assert.Zero(s.T(), s.sut.spineBufferBytes)
}

func spineWebsocketMessage(t *testing.T, payload []byte) []byte {
	t.Helper()
	modelData := model.ShipData{
		Data: model.DataType{
			Payload: payload,
		},
	}
	jsonData, err := json.Marshal(modelData)
	if err != nil {
		t.Fatalf("marshal SPINE websocket message: %v", err)
	}
	return append([]byte{0}, jsonData...)
}

func waitForConnectionSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func (s *ConnectionSuite) TestReportConnectionError() {
	tests := []struct {
		name  string
		state model.ShipMessageExchangeState
		want  model.ShipMessageExchangeState
	}{
		{name: "ordinary error", state: model.CmiStateInitStart, want: model.SmeStateError},
		{name: "ready rejection", state: model.SmeHelloStateReadyListen, want: model.SmeHelloStateRejected},
		{name: "remote abort", state: model.SmeHelloStateRemoteAbortDone, want: model.SmeHelloStateRemoteAbortDone},
		{name: "local abort", state: model.SmeHelloStateAbort, want: model.SmeHelloStateAbort},
	}
	for _, test := range tests {
		s.Run(test.name, func() {
			s.sut = NewConnectionHandler(
				s.infoProvider,
				s.wsDataWriter,
				ShipRoleServer,
				"LocalShipID",
				"RemoveDevice",
				"RemoteShipID",
			)
			s.sut.smeState = test.state
			s.sut.ReportConnectionError(nil)
			assert.Equal(s.T(), test.want, s.sut.smeState)
		})
	}
}

func (s *ConnectionSuite) TestSendShipModel() {
	err := s.sut.sendShipModel(model.MsgTypeInit, nil)
	assert.NotNil(s.T(), err)

	closeMessage := model.ConnectionClose{
		ConnectionClose: model.ConnectionCloseType{
			Phase: model.ConnectionClosePhaseTypeAnnounce,
		},
	}

	err = s.sut.sendShipModel(model.MsgTypeControl, closeMessage)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), s.sentMessage)
}

func (s *ConnectionSuite) TestCloseConnectionCallbackCanCloseReentrantly() {
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		closed: func(api.ShipConnectionInterface, bool) {
			s.sut.CloseConnection(false, 4001, "reentrant close")
		},
	}

	done := make(chan struct{})
	go func() {
		s.sut.CloseConnection(false, 4001, "initial close")
		close(done)
	}()
	waitForConnectionSignal(s.T(), done, "reentrant connection-close callback")
	assert.True(s.T(), s.sut.pairingTerminal)
}

func (s *ConnectionSuite) TestProcessShipJsonMessage() {
	closeMessage := model.ConnectionClose{
		ConnectionClose: model.ConnectionCloseType{
			Phase: model.ConnectionClosePhaseTypeAnnounce,
		},
	}
	msg, err := json.Marshal(closeMessage)
	assert.Nil(s.T(), err)

	newMsg := []byte{model.MsgTypeControl}
	newMsg = append(newMsg, msg...)

	var data any
	err = s.sut.processShipJsonMessage(newMsg, &data)
	assert.Nil(s.T(), err)
}

func (s *ConnectionSuite) TestSendSpineMessage() {
	data := `{"datagram":{"header":{},"payload":{"cmd":[]}}}`

	err := s.sut.sendSpineData([]byte(data))
	assert.Nil(s.T(), err)
}

func (s *ConnectionSuite) Test_HandshakeTimer() {
	s.sut.setState(model.CmiStateInitStart, nil)
	assert.Equal(s.T(), model.CmiStateInitStart, s.sut.getState())

	s.sut.setHandshakeTimer(timeoutTimerTypeWaitForReady, time.Duration(time.Millisecond*500))
	assert.Equal(s.T(), true, s.sut.getHandshakeTimerRunning())

	time.Sleep(time.Second * 1)
	assert.Equal(s.T(), model.CmiStateServerWait, s.sut.getState())
	assert.Equal(s.T(), timeoutTimerTypeWaitForReady, s.sut.getHandshakeTimerType())
	assert.Equal(s.T(), true, s.sut.getHandshakeTimerRunning())
}
