package hub

import (
	"crypto/tls"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

type shutdownCallbackConnection struct {
	api.ShipConnectionInterface

	ski        string
	closeCalls atomic.Int32
	closeFn    func()
}

func (c *shutdownCallbackConnection) CloseConnection(bool, int, string) {
	c.closeCalls.Add(1)
	if c.closeFn != nil {
		c.closeFn()
	}
}

func (c *shutdownCallbackConnection) RemoteSKI() string { return c.ski }

func TestHubShutdownClaimsConnectionMapBeforeCloseCallbacks(t *testing.T) {
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)

	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "shutdown-attempt",
		Scope:        "shutdown-scope",
		ControlEpoch: 1,
	}
	callbackDone := make(chan struct{})
	connection := &shutdownCallbackConnection{ski: "remote-ski"}
	connection.closeFn = func() {
		hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
		close(callbackDone)
	}
	hub.registerConnection(connection)

	hub.muxCon.Lock()
	shutdownStarted := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		close(shutdownStarted)
		hub.Shutdown()
		close(shutdownDone)
	}()
	<-shutdownStarted
	runtime.Gosched()
	closeCallsWhileMapLocked := connection.closeCalls.Load()
	hub.muxCon.Unlock()

	waitForShutdownTestSignal(t, callbackDone, "synchronous close callback")
	waitForShutdownTestSignal(t, shutdownDone, "first shutdown")
	hub.Shutdown()

	if closeCallsWhileMapLocked != 0 {
		t.Fatalf("Shutdown called CloseConnection %d time(s) while muxCon was held; connection-map access is outside its ownership contract", closeCallsWhileMapLocked)
	}
	if got := connection.closeCalls.Load(); got != 1 {
		t.Fatalf("CloseConnection call count after repeated Shutdown = %d, want 1", got)
	}
	if got := shutdownTestConnectionCount(hub); got != 0 {
		t.Fatalf("connection count after synchronous close callback = %d, want 0", got)
	}
	closed, _ := reader.snapshot()
	if len(closed) != 1 || closed[0] != metadata {
		t.Fatalf("exact-removal callbacks = %#v, want [%#v]", closed, metadata)
	}
}

func TestHubShutdownRejectsAsyncConnectionResurrection(t *testing.T) {
	reader := &attemptAwareHubReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    "async-shutdown-attempt",
		Scope:        "shutdown-scope",
		ControlEpoch: 2,
	}
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	callbackDone := make(chan struct{})
	connection := &shutdownCallbackConnection{ski: "remote-ski"}
	replacement := &shutdownCallbackConnection{ski: connection.ski}
	connection.closeFn = func() {
		go func() {
			close(callbackStarted)
			<-callbackRelease
			hub.HandleConnectionClosedWithAttempt(connection, false, metadata)
			hub.registerConnection(replacement)
			close(callbackDone)
		}()
		<-callbackStarted
	}
	hub.registerConnection(connection)

	shutdownDone := make(chan struct{})
	go func() {
		hub.Shutdown()
		close(shutdownDone)
	}()
	waitForShutdownTestSignal(t, callbackStarted, "asynchronous close callback start")
	waitForShutdownTestSignal(t, shutdownDone, "shutdown with asynchronous callback")
	close(callbackRelease)
	waitForShutdownTestSignal(t, callbackDone, "asynchronous close callback completion")

	if got := shutdownTestConnectionCount(hub); got != 0 {
		t.Fatalf("connection count after asynchronous close callback = %d, want 0; a connection was resurrected after Shutdown", got)
	}
	if got := connection.closeCalls.Load(); got != 1 {
		t.Fatalf("original CloseConnection call count = %d, want 1", got)
	}
	closed, _ := reader.snapshot()
	if len(closed) != 1 || closed[0] != metadata {
		t.Fatalf("asynchronous exact-removal callbacks = %#v, want [%#v]", closed, metadata)
	}
}

func shutdownTestConnectionCount(hub *Hub) int {
	hub.muxCon.Lock()
	defer hub.muxCon.Unlock()
	return len(hub.connections)
}

func waitForShutdownTestSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s; possible shutdown callback deadlock", operation)
	}
}
