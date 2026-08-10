package ws

import (
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/mocks"
	util "github.com/Project-Helianthus/helianthus-ship-go/util"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type teardownBlockingReader struct {
	writeDone <-chan error
}

func (*teardownBlockingReader) HandleIncomingWebsocketMessage([]byte) {}

func (r *teardownBlockingReader) ReportConnectionError(error) {
	select {
	case <-r.writeDone:
	case <-time.After(time.Second):
	}
}

func TestTerminalWriteFailureUnblocksFullQueueBeforeCallback(t *testing.T) {
	connection := NewWebsocketConnection(nil, "remoteSki")
	connection.shipWriteChannel <- []byte("queued")

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- connection.WriteMessageToWebsocketConnection([]byte("blocked"))
	}()

	deadline := time.Now().Add(time.Second)
	for connection.muxShipWrite.TryLock() {
		connection.muxShipWrite.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("writer did not block on the full queue")
		}
		time.Sleep(time.Millisecond)
	}

	connection.dataProcessing = &teardownBlockingReader{writeDone: writeDone}
	terminalErr := errors.New("terminal websocket write failure")
	closeDone := make(chan struct{})
	go func() {
		connection.closeWithError(terminalErr, "test terminal failure: ")
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(250 * time.Millisecond):
		// Let the blocked write complete so the failed regression does not leak goroutines.
		<-connection.shipWriteChannel
		<-closeDone
		t.Fatal("terminal failure callback remained blocked behind the full write queue")
	}

	select {
	case err := <-writeDone:
		assert.ErrorContains(t, err, connIsClosedError)
	case <-time.After(time.Second):
		t.Fatal("blocked write was not released by terminal close")
	}

	assert.ErrorIs(t, connection.connClosedError(), terminalErr)
	assert.ErrorContains(t, connection.WriteMessageToWebsocketConnection([]byte("late")), connIsClosedError)
}

func TestWebsocketSuite(t *testing.T) {
	suite.Run(t, new(WebsocketSuite))
}

type WebsocketSuite struct {
	suite.Suite

	sut *WebsocketConnection

	testServer   *httptest.Server
	testResponse *http.Response
	testWsConn   *websocket.Conn

	wsDataReader *mocks.WebsocketDataReaderInterface
}

func (s *WebsocketSuite) BeforeTest(suiteName, testName string) {
	s.wsDataReader = mocks.NewWebsocketDataReaderInterface(s.T())
	s.wsDataReader.EXPECT().ReportConnectionError(mock.Anything).Return().Maybe()
	s.wsDataReader.EXPECT().HandleIncomingWebsocketMessage(mock.Anything).Return().Maybe()

	ts := &testServer{}

	// body close is done in AfterTest
	//nolint:bodyclose
	s.testServer, s.testResponse, s.testWsConn = newWSServer(s.T(), ts)

	s.sut = NewWebsocketConnection(s.testWsConn, "remoteSki")
	s.sut.InitDataProcessing(s.wsDataReader)
}

func (s *WebsocketSuite) AfterTest(suiteName, testName string) {
	s.testResponse.Body.Close()
	_ = s.testWsConn.Close()
	s.testServer.Close()
}

func (s *WebsocketSuite) TestConnection() {
	isClosed := s.sut.isConnClosed()
	assert.Equal(s.T(), false, isClosed)

	msg := []byte{0, 0}
	err := s.sut.WriteMessageToWebsocketConnection(msg)
	assert.Nil(s.T(), err)

	// make sure we have enough time to read and write
	time.Sleep(time.Millisecond * 500)

	msg = []byte{1}
	msg = append(msg, []byte("message")...)
	err = s.sut.WriteMessageToWebsocketConnection(msg)
	assert.Nil(s.T(), err)

	// make sure we have enough time to read and write
	time.Sleep(time.Millisecond * 500)

	isConnClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isConnClosed)
	assert.Nil(s.T(), err)

	s.sut.CloseDataConnection(450, "User Close")

	isConnClosed, err = s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isConnClosed)
	assert.NotNil(s.T(), err)

	err = s.sut.WriteMessageToWebsocketConnection(msg)
	assert.NotNil(s.T(), err)
}

func (s *WebsocketSuite) TestConnectionInvalid() {
	msg := []byte{100}
	err := s.sut.WriteMessageToWebsocketConnection(msg)
	assert.Nil(s.T(), err)

	// make sure we have enough time to read and write
	time.Sleep(time.Millisecond * 500)

	isConnClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isConnClosed)
	assert.NotNil(s.T(), err)

	err = s.sut.WriteMessageToWebsocketConnection(msg)
	assert.NotNil(s.T(), err)

	s.sut.CloseDataConnection(500, "test")

	result := s.sut.writeMessage(websocket.BinaryMessage, []byte{})
	assert.Equal(s.T(), false, result)

	err = s.sut.writeMessageWithoutErrorHandling(websocket.BinaryMessage, []byte{})
	assert.NotNil(s.T(), err)

	s.sut.conn = nil

	data, err := s.sut.readWebsocketMessage()
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), data)

	err = s.sut.checkWebsocketMessage(websocket.TextMessage, []byte{})
	assert.NotNil(s.T(), err)
}

func (s *WebsocketSuite) TestConnectionClose() {
	s.sut.close()

	isClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isClosed)
	assert.NotNil(s.T(), err)
}

func (s *WebsocketSuite) TestPingPeriod() {
	isClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isClosed)
	assert.Nil(s.T(), err)

	if !util.IsRunningOnCI() {
		// test if the function is triggered correctly via the timer
		time.Sleep(time.Second * 51)
	} else {
		// speed up the test by running the method directly
		s.sut.handlePing()
	}

	isClosed, err = s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isClosed)
	assert.Nil(s.T(), err)
}

func (s *WebsocketSuite) TestCloseWithError() {
	isClosed, err := s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), false, isClosed)
	assert.Nil(s.T(), err)

	err = errors.New("test error")
	s.sut.closeWithError(err, "test error")

	isClosed, err = s.sut.IsDataConnectionClosed()
	assert.Equal(s.T(), true, isClosed)
	assert.NotNil(s.T(), err)
}

var upgrader = websocket.Upgrader{}

func newWSServer(t *testing.T, h http.Handler) (*httptest.Server, *http.Response, *websocket.Conn) {
	t.Helper()

	s := httptest.NewServer(h)
	wsURL := strings.Replace(s.URL, "http://", "ws://", -1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", -1)

	ws, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	return s, resp, ws
}

type testServer struct {
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer ws.Close()

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			return
		}

		err = ws.WriteMessage(websocket.BinaryMessage, msg)
		if err != nil {
			continue
		}
	}
}
