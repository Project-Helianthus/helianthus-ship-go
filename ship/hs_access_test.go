package ship

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/mocks"
	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

func TestAccessSuite(t *testing.T) {
	suite.Run(t, new(AccessSuite))
}

type AccessSuite struct {
	suite.Suite

	mockWSWrite  *mocks.WebsocketDataWriterInterface
	mockShipInfo *mocks.ShipConnectionInfoProviderInterface

	sut *ShipConnection

	sentMessage     []byte
	wsReturnFailure error

	currentTestName string

	mux sync.Mutex
}

func (s *AccessSuite) lastMessage() []byte {
	s.mux.Lock()
	defer s.mux.Unlock()

	return s.sentMessage
}

func (s *AccessSuite) BeforeTest(suiteName, testName string) {
	s.mux.Lock()
	s.sentMessage = nil
	s.wsReturnFailure = nil
	s.currentTestName = testName
	s.mux.Unlock()

	s.mockWSWrite = mocks.NewWebsocketDataWriterInterface(s.T())
	s.mockWSWrite.EXPECT().InitDataProcessing(mock.Anything).Return().Maybe()
	s.mockWSWrite.EXPECT().IsDataConnectionClosed().Return(false, nil).Maybe()
	s.mockWSWrite.EXPECT().CloseDataConnection(mock.Anything, mock.Anything).Return().Maybe()
	s.mockWSWrite.
		EXPECT().
		WriteMessageToWebsocketConnection(mock.Anything).
		RunAndReturn(func(msg []byte) error {
			s.mux.Lock()
			defer s.mux.Unlock()

			if s.currentTestName != testName {
				return nil
			}

			s.sentMessage = msg

			return s.wsReturnFailure
		}).Maybe()

	s.mockShipInfo = mocks.NewShipConnectionInfoProviderInterface(s.T())
	s.mockShipInfo.EXPECT().HandleShipHandshakeStateUpdate(mock.Anything, mock.Anything).Return().Maybe()
	s.mockShipInfo.EXPECT().IsRemoteServiceForSKIPaired(mock.Anything).Return(true).Maybe()
	s.mockShipInfo.EXPECT().HandleConnectionClosed(mock.Anything, mock.Anything).Return().Maybe()

	s.sut = NewConnectionHandler(s.mockShipInfo, s.mockWSWrite, ShipRoleClient, "LocalShipID", "RemoveDevice", "RemoteShipID")
}

func (s *AccessSuite) AfterTest(suiteName, testName string) {
	s.sut.stopHandshakeTimer()
}

func (s *AccessSuite) Test_Init() {
	s.sut.setState(model.SmePinStateCheckOk, nil)
	s.sut.handleState(false, nil)

	assert.Equal(s.T(), true, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeAccessMethodsRequest, s.sut.getState())
	assert.NotNil(s.T(), s.lastMessage())
}

func (s *AccessSuite) Test_Request() {
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethodsRequest{
		AccessMethodsRequest: model.AccessMethodsRequestType{},
	}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleState(false, msg)

	assert.Equal(s.T(), false, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeAccessMethodsRequest, s.sut.getState())
	assert.NotNil(s.T(), s.lastMessage())
}

func (s *AccessSuite) Test_Request_Invalid() {
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.MessageProtocolHandshake{}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleState(false, msg)

	assert.Equal(s.T(), false, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeStateError, s.sut.getState())
}

func (s *AccessSuite) Test_Methods_Ok() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	s.mockShipInfo.EXPECT().SetupRemoteDevice(mock.Anything, mock.Anything).Return(reader)
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{
		AccessMethods: model.AccessMethodsType{
			Id: util.Ptr("RemoteShipID"),
		},
	}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleState(false, msg)

	assert.Equal(s.T(), false, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
}

func (s *AccessSuite) Test_Methods_NoID() {
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{
		AccessMethods: model.AccessMethodsType{},
	}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleState(false, msg)

	assert.Equal(s.T(), false, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeStateError, s.sut.getState())
	assert.Nil(s.T(), s.lastMessage())
}

func (s *AccessSuite) Test_Methods_WrongShipID() {
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{
		AccessMethods: model.AccessMethodsType{
			Id: util.Ptr("WrongRemoteShipID"),
		},
	}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleState(false, msg)

	assert.Equal(s.T(), false, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeStateError, s.sut.getState())
	assert.Nil(s.T(), s.lastMessage())
}

func (s *AccessSuite) Test_Methods_NoShipID() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	s.mockShipInfo.EXPECT().ReportServiceShipID(mock.Anything, mock.Anything)
	s.mockShipInfo.EXPECT().SetupRemoteDevice(mock.Anything, mock.Anything).Return(reader)
	s.sut.remoteShipID = ""

	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{
		AccessMethods: model.AccessMethodsType{
			Id: util.Ptr(""),
		},
	}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), msg)

	s.sut.handleState(false, msg)

	assert.Equal(s.T(), false, s.sut.handshakeTimerRunning)
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
}

func (s *AccessSuite) Test_Methods_NoShipIDSynchronousApprovalWaitsForCallbackReturn() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	reportingShipID := false
	setupDuringReport := false
	s.mockShipInfo.EXPECT().ReportServiceShipID("RemoveDevice", "ObservedRemoteShipID").
		Run(func(string, string) {
			reportingShipID = true
			s.sut.ApprovePendingHandshake()
			reportingShipID = false
		}).
		Once()
	s.mockShipInfo.EXPECT().SetupRemoteDevice("RemoveDevice", s.sut).
		Run(func(string, api.ShipConnectionDataWriterInterface) {
			setupDuringReport = reportingShipID
		}).
		Return(reader).
		Once()
	s.sut.remoteShipID = ""
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{
		AccessMethods: model.AccessMethodsType{
			Id: util.Ptr("ObservedRemoteShipID"),
		},
	}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)

	done := make(chan struct{})
	go func() {
		s.sut.handleState(false, msg)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		s.T().Fatal("synchronous approval during SHIP ID callback deadlocked")
	}
	assert.False(s.T(), setupDuringReport)
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
}

func (s *AccessSuite) Test_OutgoingPairingPublishesApprovedOnlyAfterShipIDCallbackReturns() {
	reportEntered := make(chan struct{})
	reportRelease := make(chan struct{})
	approvedPublished := make(chan struct{}, 1)
	provider := &concurrentConnectionInfoProvider{
		report: func(string, string) {
			close(reportEntered)
			<-reportRelease
		},
		state: func(_ string, state model.ShipState) {
			if state.State == model.SmeStateApproved {
				approvedPublished <- struct{}{}
			}
		},
	}
	connection, err := NewOutgoingConnectionHandler(
		provider,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	s.sut.setState(model.SmeAccessMethodsRequest, nil)
	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("ObservedRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)

	done := make(chan struct{})
	go func() {
		s.sut.handleState(false, msg)
		close(done)
	}()
	<-reportEntered
	select {
	case <-approvedPublished:
		s.T().Fatal("approved state published before SHIP ID callback completed")
	default:
	}
	close(reportRelease)
	select {
	case <-approvedPublished:
	case <-time.After(time.Second):
		s.T().Fatal("approved state was not published after SHIP ID callback completed")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		s.T().Fatal("access-method transition did not complete")
	}
}

func (s *AccessSuite) Test_OutgoingPairingHoldsBeforeSPINEUntilDurableApproval() {
	s.mockShipInfo.EXPECT().ReportServiceShipID("RemoteSKI", "ObservedRemoteShipID")
	connection, err := NewOutgoingConnectionHandler(
		s.mockShipInfo,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("ObservedRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)
	s.sut.handleState(false, msg)
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())

	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	s.mockShipInfo.EXPECT().SetupRemoteDevice("RemoteSKI", s.sut).Return(reader).Once()
	s.sut.ApprovePendingHandshake()
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
}

func (s *AccessSuite) Test_OutgoingPairingCanApproveSynchronouslyFromShipIDCallback() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	reportingShipID := false
	setupDuringReport := false
	s.mockShipInfo.EXPECT().SetupRemoteDevice("RemoteSKI", mock.Anything).
		Run(func(string, api.ShipConnectionDataWriterInterface) {
			setupDuringReport = reportingShipID
		}).
		Return(reader).
		Once()
	s.mockShipInfo.EXPECT().ReportServiceShipID("RemoteSKI", "ObservedRemoteShipID").Run(func(string, string) {
		reportingShipID = true
		s.sut.ApprovePendingHandshake()
		reportingShipID = false
	}).Once()
	connection, err := NewOutgoingConnectionHandler(
		s.mockShipInfo,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("ObservedRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)
	s.sut.handleState(false, msg)
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
	assert.False(s.T(), setupDuringReport)
}

func (s *AccessSuite) Test_KnownShipIDCanApproveSynchronouslyFromApprovedCallback() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	publishingApproved := false
	setupDuringApproved := false
	provider := &concurrentConnectionInfoProvider{
		setup: func(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
			setupDuringApproved = publishingApproved
			return reader
		},
		state: func(_ string, state model.ShipState) {
			if state.State != model.SmeStateApproved {
				return
			}
			publishingApproved = true
			s.sut.ApprovePendingHandshake()
			publishingApproved = false
		},
	}
	s.sut = NewConnectionHandler(
		provider,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"KnownRemoteShipID",
	)
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("KnownRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)
	done := make(chan struct{})
	go func() {
		s.sut.handleState(false, msg)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		s.T().Fatal("known SHIP ID approval deadlocked inside approved-state callback")
	}
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
	assert.False(s.T(), setupDuringApproved)
}

func (s *AccessSuite) Test_OutgoingPairingKeepsApprovalRequestedBeforeCommitArming() {
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	s.mockShipInfo.EXPECT().SetupRemoteDevice("RemoteSKI", mock.Anything).Return(reader).Once()
	s.mockShipInfo.EXPECT().ReportServiceShipID("RemoteSKI", "ObservedRemoteShipID").Once()
	connection, err := NewOutgoingConnectionHandler(
		s.mockShipInfo,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	commitReached := make(chan struct{})
	commitRelease := make(chan struct{})
	s.sut.testHooks = &shipConnectionTestHooks{
		beforePairingCommit: func() {
			close(commitReached)
			<-commitRelease
		},
	}
	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("ObservedRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)

	handshakeDone := make(chan struct{})
	go func() {
		s.sut.handleState(false, msg)
		close(handshakeDone)
	}()
	<-commitReached
	s.sut.ApprovePendingHandshake()
	close(commitRelease)
	select {
	case <-handshakeDone:
	case <-time.After(time.Second):
		s.T().Fatal("approval requested before commit arming was lost")
	}
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
	assert.True(s.T(), s.sut.pairingApprovalReleased)
}

func (s *AccessSuite) Test_OutgoingPairingSetupCallbackCanReenterIncomingDelivery() {
	payload := []byte(`{"datagram":{"sequence":1}}`)
	reader := &callbackSpineReader{handle: func(message []byte) {
		assert.Equal(s.T(), payload, message)
	}}
	s.mockShipInfo.EXPECT().ReportServiceShipID("RemoteSKI", "ObservedRemoteShipID").Once()
	connection, err := NewOutgoingConnectionHandler(
		s.mockShipInfo,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	s.mockShipInfo.EXPECT().SetupRemoteDevice("RemoteSKI", mock.Anything).
		Run(func(string, api.ShipConnectionDataWriterInterface) {
			s.sut.HandleIncomingWebsocketMessage(spineWebsocketMessage(s.T(), payload))
		}).
		Return(reader).
		Once()
	s.sut.setState(model.SmeAccessMethodsRequest, nil)
	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("ObservedRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)
	s.sut.handleState(false, msg)

	done := make(chan struct{})
	go func() {
		s.sut.ApprovePendingHandshake()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		s.T().Fatal("setup callback reentrant delivery deadlocked")
	}
	assert.Equal(s.T(), model.SmeStateComplete, s.sut.getState())
}

func (s *AccessSuite) Test_OutgoingPairingCloseWinsBeforeApprovalWithoutSPINESetup() {
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.setState(model.SmeStateApproved, nil)

	s.sut.CloseConnection(false, 4452, "pairing canceled")
	s.sut.ApprovePendingHandshake()

	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Nil(s.T(), s.sut.dataReader)
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())
}

func (s *AccessSuite) Test_OutgoingPairingAbortWinsBeforeApprovalWithoutSPINESetup() {
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.setState(model.SmeStateApproved, nil)

	s.sut.AbortPendingHandshake()
	s.sut.ApprovePendingHandshake()

	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Nil(s.T(), s.sut.dataReader)
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())
}

func (s *AccessSuite) Test_OutgoingPairingConcurrentCloseCancelsSPINESetup() {
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.setState(model.SmeStateApproved, nil)
	reader := mocks.NewShipConnectionDataReaderInterface(s.T())
	setupEntered := make(chan struct{})
	setupRelease := make(chan struct{})
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		setup: func(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
			close(setupEntered)
			<-setupRelease
			return reader
		},
	}

	approvalDone := make(chan struct{})
	go func() {
		s.sut.ApprovePendingHandshake()
		close(approvalDone)
	}()
	<-setupEntered

	closeDone := make(chan struct{})
	go func() {
		s.sut.CloseConnection(false, 4452, "concurrent close")
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		s.T().Fatal("close blocked behind the external SPINE setup callback")
	}

	close(setupRelease)
	<-approvalDone
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())
	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Nil(s.T(), s.sut.dataReader)
}

func (s *AccessSuite) Test_OutgoingPairingSetupCallbackCanCloseReentrantly() {
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.setState(model.SmeStateApproved, nil)
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		setup: func(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
			s.sut.CloseConnection(false, 4452, "reentrant setup close")
			return nil
		},
	}

	done := make(chan struct{})
	go func() {
		s.sut.ApprovePendingHandshake()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		s.T().Fatal("reentrant setup close deadlocked candidate approval")
	}
	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())
	assert.Nil(s.T(), s.sut.dataReader)
}

func (s *AccessSuite) Test_OutgoingPairingTerminalAdmissionSuppressesQueuedShipIDCallback() {
	connection, err := NewOutgoingConnectionHandler(
		s.mockShipInfo,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"ObservedRemoteShipID",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	reportCalled := make(chan struct{}, 1)
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		report: func(string, string) {
			reportCalled <- struct{}{}
		},
	}

	effectEntered := make(chan struct{})
	effectRelease := make(chan struct{})
	effectDone := make(chan struct{})
	go func() {
		s.sut.runPairingEffect(func() {
			close(effectEntered)
			<-effectRelease
		}, false)
		close(effectDone)
	}()
	<-effectEntered

	s.sut.CloseConnection(false, 4452, "terminal before SHIP ID report")
	reported := make(chan bool, 1)
	go func() {
		reported <- s.sut.reportServiceShipID()
	}()
	close(effectRelease)

	assert.False(s.T(), <-reported)
	<-effectDone
	select {
	case <-reportCalled:
		s.T().Fatal("terminal connection invoked queued SHIP ID callback")
	default:
	}
	assert.True(s.T(), s.sut.pairingTerminal)
}

func (s *AccessSuite) Test_OutgoingPairingTerminalAdmissionSuppressesQueuedSPINESetup() {
	s.sut.requirePairingApproval = true
	s.sut.pairingCommitStarted = true
	s.sut.pairingCommitCallbackDone = true
	s.sut.pairingApprovalRequested = true
	s.sut.setState(model.SmeStateApproved, nil)
	setupCalled := make(chan struct{}, 1)
	s.sut.infoProvider = &concurrentConnectionInfoProvider{
		setup: func(string, api.ShipConnectionDataWriterInterface) api.ShipConnectionDataReaderInterface {
			setupCalled <- struct{}{}
			return nil
		},
	}

	effectEntered := make(chan struct{})
	effectRelease := make(chan struct{})
	effectDone := make(chan struct{})
	go func() {
		s.sut.runPairingEffect(func() {
			close(effectEntered)
			<-effectRelease
		}, false)
		close(effectDone)
	}()
	<-effectEntered

	s.sut.CloseConnection(false, 4452, "terminal before SPINE setup")
	approvalDone := make(chan struct{})
	go func() {
		s.sut.approveHandshake()
		close(approvalDone)
	}()
	close(effectRelease)

	<-approvalDone
	<-effectDone
	select {
	case <-setupCalled:
		s.T().Fatal("terminal connection invoked queued SPINE setup callback")
	default:
	}
	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Nil(s.T(), s.sut.dataReader)
	assert.Equal(s.T(), model.SmeStateApproved, s.sut.getState())
}

func (s *AccessSuite) Test_OutgoingPairingShipIDCallbackCanCloseReentrantly() {
	s.mockShipInfo.EXPECT().ReportServiceShipID("RemoteSKI", "ObservedRemoteShipID").
		Run(func(string, string) {
			s.sut.CloseConnection(false, 4452, "reentrant SHIP ID close")
		}).
		Once()
	connection, err := NewOutgoingConnectionHandler(
		s.mockShipInfo,
		s.mockWSWrite,
		ShipRoleClient,
		"LocalShipID",
		"RemoteSKI",
		"",
		OutgoingAttemptConnectionConfiguration{
			Metadata:               api.OutgoingAttemptMetadata{AttemptID: "candidate-attempt", Scope: "pairing", ControlEpoch: 17},
			Context:                context.Background(),
			RequirePairingApproval: true,
		},
	)
	assert.NoError(s.T(), err)
	s.sut = connection
	s.sut.setState(model.SmeAccessMethodsRequest, nil)

	accessMsg := model.AccessMethods{AccessMethods: model.AccessMethodsType{Id: util.Ptr("ObservedRemoteShipID")}}
	msg, err := s.sut.shipMessage(model.MsgTypeControl, accessMsg)
	assert.NoError(s.T(), err)
	s.sut.handleState(false, msg)

	assert.True(s.T(), s.sut.pairingTerminal)
	assert.Equal(s.T(), model.SmeAccessMethodsRequest, s.sut.getState())
	assert.Nil(s.T(), s.sut.dataReader)
}
