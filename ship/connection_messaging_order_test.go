package ship

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enbility/ship-go/model"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type spineDeliveryRecorder struct {
	connection *ShipConnection

	active     atomic.Int32
	concurrent atomic.Bool
	reenter    atomic.Bool

	mu           sync.Mutex
	deliveries   []string
	firstStarted chan struct{}
	releaseFirst chan struct{}
	allDelivered chan struct{}
	firstOnce    sync.Once
	allOnce      sync.Once
}

func newSpineDeliveryRecorder(connection *ShipConnection) *spineDeliveryRecorder {
	return &spineDeliveryRecorder{
		connection:   connection,
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
		allDelivered: make(chan struct{}),
	}
}

func (r *spineDeliveryRecorder) HandleShipPayloadMessage(message []byte) {
	if r.active.Add(1) != 1 {
		r.concurrent.Store(true)
	}
	defer r.active.Add(-1)

	marker := spinePayloadMarker(message)
	r.mu.Lock()
	r.deliveries = append(r.deliveries, marker)
	count := len(r.deliveries)
	r.mu.Unlock()

	if marker == "first" {
		r.firstOnce.Do(func() { close(r.firstStarted) })
		if r.reenter.Load() {
			done := make(chan struct{})
			go func() {
				r.connection.HandleIncomingWebsocketMessage(spineMessage(nil, "reentrant"))
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				r.concurrent.Store(true)
			}
		}
		if r.releaseFirst != nil {
			<-r.releaseFirst
		}
	}

	if count >= 2 {
		r.allOnce.Do(func() { close(r.allDelivered) })
	}
}

func (r *spineDeliveryRecorder) values() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.deliveries...)
}

func spineMessage(t *testing.T, marker string) []byte {
	if t != nil {
		t.Helper()
	}
	payload := json.RawMessage(`{"datagram":{"marker":"` + marker + `"}}`)
	encoded, err := json.Marshal(model.ShipData{Data: model.DataType{Payload: payload}})
	if t != nil {
		require.NoError(t, err)
	}
	return append([]byte{model.MsgTypeData}, encoded...)
}

func spinePayloadMarker(message []byte) string {
	text := string(message)
	start := strings.Index(text, `"marker":"`)
	if start < 0 {
		return ""
	}
	start += len(`"marker":"`)
	end := strings.IndexByte(text[start:], '"')
	if end < 0 {
		return ""
	}
	return text[start : start+end]
}

func TestApproveHandshakeSerializesReentrantSpineDelivery(t *testing.T) {
	suite := new(ConnectionSuite)
	suite.SetT(t)
	suite.BeforeTest("ConnectionSuite", t.Name())

	recorder := newSpineDeliveryRecorder(suite.sut)
	recorder.reenter.Store(true)
	close(recorder.releaseFirst)
	suite.infoProvider.EXPECT().SetupRemoteService(mock.Anything, suite.sut).Return(recorder).Once()

	suite.sut.HandleIncomingWebsocketMessage(spineMessage(t, "first"))
	suite.sut.approveHandshake()

	select {
	case <-recorder.allDelivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for reentrant SPINE delivery")
	}
	require.False(t, recorder.concurrent.Load(), "SPINE callbacks must be serialized")
	require.Equal(t, []string{"first", "reentrant"}, recorder.values())
}

func TestApproveHandshakeSerializesConcurrentArrivalWithBufferedDelivery(t *testing.T) {
	suite := new(ConnectionSuite)
	suite.SetT(t)
	suite.BeforeTest("ConnectionSuite", t.Name())

	recorder := newSpineDeliveryRecorder(suite.sut)
	suite.infoProvider.EXPECT().SetupRemoteService(mock.Anything, suite.sut).Return(recorder).Once()
	suite.sut.HandleIncomingWebsocketMessage(spineMessage(t, "first"))

	approved := make(chan struct{})
	go func() {
		suite.sut.approveHandshake()
		close(approved)
	}()

	select {
	case <-recorder.firstStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for buffered SPINE delivery")
	}
	suite.sut.HandleIncomingWebsocketMessage(spineMessage(t, "second"))
	suite.sut.HandleIncomingWebsocketMessage(spineMessage(t, "third"))
	close(recorder.releaseFirst)

	select {
	case <-approved:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for handshake approval")
	}
	require.False(t, recorder.concurrent.Load(), "SPINE callbacks must be serialized")
	require.Equal(t, []string{"first", "second", "third"}, recorder.values())
}
