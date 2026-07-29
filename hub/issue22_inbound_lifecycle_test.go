package hub

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/ship"
)

func TestIssue22ShutdownBetweenInboundRegistrationAndRunDoesNotStartPump(t *testing.T) {
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(strings.Repeat("0", 40)),
	)
	writer := &registrationTestWriter{}
	connection := ship.NewConnectionHandler(
		hub,
		writer,
		ship.ShipRoleServer,
		"local-ship-id",
		strings.Repeat("f", 40),
		"remote-ship-id",
	)

	if !hub.registerConnection(connection) {
		t.Fatal("inbound connection was rejected before shutdown")
	}
	hub.Shutdown()
	connection.Run()

	reader, closeCalls := writer.snapshot()
	if reader != nil {
		t.Fatal("inbound data pump started after shutdown closed the registered connection")
	}
	if closeCalls != 1 {
		t.Fatalf("data close count after shutdown = %d, want 1", closeCalls)
	}
}

func TestIssue22CompetingInboundReplacementBeforeRunDoesNotStartLosingPump(t *testing.T) {
	localSKI := strings.Repeat("0", 40)
	remoteSKI := strings.Repeat("f", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)
	writer := &registrationTestWriter{}
	first := ship.NewConnectionHandler(
		hub,
		writer,
		ship.ShipRoleServer,
		"local-ship-id",
		remoteSKI,
		"remote-ship-id",
	)

	if !hub.registerConnection(first) {
		t.Fatal("first inbound connection was rejected")
	}
	if !hub.keepThisConnection(nil, true, remote) {
		t.Fatal("higher-SKI remote inbound replacement was rejected")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, closeCalls := writer.snapshot()
		if closeCalls == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for competing inbound to close the registered loser")
		}
		time.Sleep(time.Millisecond)
	}
	first.Run()

	reader, closeCalls := writer.snapshot()
	if reader != nil {
		t.Fatal("losing inbound data pump started after competing replacement closed it")
	}
	if closeCalls != 1 {
		t.Fatalf("losing inbound data close count = %d, want 1", closeCalls)
	}
}
