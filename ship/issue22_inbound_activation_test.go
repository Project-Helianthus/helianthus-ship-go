package ship

import (
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

type issue22ActivationWriter struct {
	mu        sync.Mutex
	initCalls int
	closed    int
}

func (w *issue22ActivationWriter) InitDataProcessing(api.WebsocketDataReaderInterface) {
	w.mu.Lock()
	w.initCalls++
	w.mu.Unlock()
}

func (*issue22ActivationWriter) WriteMessageToWebsocketConnection([]byte) error { return nil }

func (w *issue22ActivationWriter) CloseDataConnection(int, string) {
	w.mu.Lock()
	w.closed++
	w.mu.Unlock()
}

func (*issue22ActivationWriter) IsDataConnectionClosed() (bool, error) { return false, nil }

func (w *issue22ActivationWriter) snapshot() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.initCalls, w.closed
}

func TestIssue22InboundDataPumpStartsOnlyWhenConnectionRuns(t *testing.T) {
	writer := &issue22ActivationWriter{}
	connection := NewConnectionHandler(
		&attemptCallbackProvider{},
		writer,
		ShipRoleServer,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
	)

	if initCalls, _ := writer.snapshot(); initCalls != 0 {
		t.Fatalf("inbound data pump initialization count before Run = %d, want 0", initCalls)
	}

	connection.Run()
	if initCalls, _ := writer.snapshot(); initCalls != 1 {
		t.Fatalf("inbound data pump initialization count after Run = %d, want 1", initCalls)
	}
}

func TestIssue22InboundCloseBeforeRunIsTerminalAndDoesNotStartDataPump(t *testing.T) {
	provider := &attemptCallbackProvider{}
	writer := &issue22ActivationWriter{}
	connection := NewConnectionHandler(
		provider,
		writer,
		ShipRoleServer,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
	)

	connection.CloseConnection(false, 4001, "hub shutdown")
	connection.Run()
	connection.CloseConnection(false, 4001, "duplicate close")

	initCalls, closeCalls := writer.snapshot()
	if initCalls != 0 {
		t.Fatalf("inbound data pump initialization count after pre-Run close = %d, want 0", initCalls)
	}
	if closeCalls != 1 {
		t.Fatalf("data close count after repeated terminal close = %d, want 1", closeCalls)
	}
	baseClosed, _, _ := provider.snapshot()
	if baseClosed != 1 {
		t.Fatalf("terminal callback count after repeated terminal close = %d, want 1", baseClosed)
	}
}
