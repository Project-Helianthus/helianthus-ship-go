package ws

import "testing"

func TestIssue22CloseBeforeDataPumpStartIsSafe(t *testing.T) {
	connection := NewWebsocketConnection(nil, "remote-ski")

	connection.CloseDataConnection(4001, "")
	connection.InitDataProcessing(nil)

	closed, err := connection.IsDataConnectionClosed()
	if !closed || err == nil {
		t.Fatalf("pre-start close state = closed:%v error:%v, want closed with terminal error", closed, err)
	}
}
