package ws

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/model"
	"github.com/gorilla/websocket"
)

type issue35DeadlineTrackingConn struct {
	net.Conn
	mux      sync.Mutex
	events   []string
	deadline time.Time
}

func (connection *issue35DeadlineTrackingConn) Write(payload []byte) (int, error) {
	connection.mux.Lock()
	connection.events = append(connection.events, "write")
	connection.mux.Unlock()
	return connection.Conn.Write(payload)
}

func (connection *issue35DeadlineTrackingConn) SetWriteDeadline(deadline time.Time) error {
	connection.mux.Lock()
	connection.events = append(connection.events, "deadline")
	connection.deadline = deadline
	connection.mux.Unlock()
	return connection.Conn.SetWriteDeadline(deadline)
}

func (connection *issue35DeadlineTrackingConn) reset() {
	connection.mux.Lock()
	connection.events = nil
	connection.deadline = time.Time{}
	connection.mux.Unlock()
}

func (connection *issue35DeadlineTrackingConn) snapshot() ([]string, time.Time) {
	connection.mux.Lock()
	defer connection.mux.Unlock()
	return append([]string(nil), connection.events...), connection.deadline
}

func TestIssue35PINInputIsRedactedBeforeWebsocketLogging(t *testing.T) {
	const secret = "12aBc34D"
	message := append(
		[]byte{model.MsgTypeControl},
		[]byte(`{"connectionPinInput":[{"pin":"`+secret+`"}]}`)...,
	)

	text := (&WebsocketConnection{}).textFromMessage(message)
	if strings.Contains(text, secret) {
		t.Fatalf("PIN logging text disclosed secret: %q", text)
	}
	if text != "ship control: connectionPinInput [redacted]" {
		t.Fatalf("PIN logging text = %q, want categorical redaction", text)
	}
}

func TestIssue35PINRedactionIsSemanticAndConservative(t *testing.T) {
	const secret = "12aBc34D"
	tests := []struct {
		name    string
		payload string
	}{
		{
			name:    "escaped JSON key",
			payload: `{"connection\u0050inInput":[{"pin":"` + secret + `"}]}`,
		},
		{
			name:    "malformed ambiguous escaped frame",
			payload: `{"connection\u0050inInput":[{"pin":"` + secret,
		},
		{
			name:    "whitespace-normalized key",
			payload: `{ "connectionPinInput" : [ { "pin" : "` + secret + `" } ] }`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := append([]byte{model.MsgTypeControl}, []byte(test.payload)...)
			text := (&WebsocketConnection{}).textFromMessage(message)
			if strings.Contains(text, secret) {
				t.Fatalf("PIN logging text disclosed secret: %q", text)
			}
			if text != "ship control: connectionPinInput [redacted]" {
				t.Fatalf("PIN logging text = %q, want conservative categorical redaction", text)
			}
		})
	}
}

func TestIssue35SensitivePINWriteSetsFreshBoundedDeadlineBeforeWireWrite(t *testing.T) {
	received := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		peer, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).
			Upgrade(response, request, nil)
		if err != nil {
			received <- err
			return
		}
		defer peer.Close()
		_, _, err = peer.ReadMessage()
		received <- err
	}))
	defer server.Close()

	var tracked *issue35DeadlineTrackingConn
	dialer := websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			tracked = &issue35DeadlineTrackingConn{Conn: connection}
			return tracked, nil
		},
	}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	client, _, err := dialer.Dial(endpoint, nil)
	if err != nil {
		t.Fatalf("dial test websocket: %v", err)
	}
	defer client.Close()
	tracked.reset()

	connection := NewWebsocketConnection(client, "remote-ski")
	started := time.Now()
	if err := connection.WriteSensitiveMessageToWebsocketConnection(
		append([]byte{model.MsgTypeControl}, []byte(`{"connectionPinInput":[{"pin":"12aBc34D"}]}`)...),
	); err != nil {
		t.Fatalf("write sensitive PIN: %v", err)
	}
	events, deadline := tracked.snapshot()
	if len(events) < 2 || events[0] != "deadline" || events[1] != "write" {
		t.Fatalf("sensitive write events = %v, want deadline immediately before wire write", events)
	}
	minimum := started.Add(writeWait - time.Second)
	maximum := time.Now().Add(writeWait + time.Second)
	if deadline.Before(minimum) || deadline.After(maximum) {
		t.Fatalf("sensitive write deadline = %s, want fresh bounded interval [%s,%s]",
			deadline, minimum, maximum)
	}
	select {
	case err := <-received:
		if err != nil {
			t.Fatalf("peer read sensitive frame: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("peer did not receive sensitive frame")
	}
}
