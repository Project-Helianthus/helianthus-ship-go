package ship

import "testing"

func TestIssue22InboundDataPumpStartsOnlyWhenConnectionRuns(t *testing.T) {
	writer := &attemptCallbackWriter{}
	connection := NewConnectionHandler(
		&attemptCallbackProvider{},
		writer,
		ShipRoleServer,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
	)

	if writer.reader != nil {
		t.Fatal("inbound data pump started before the Hub could register the connection")
	}

	connection.Run()
	if writer.reader == nil {
		t.Fatal("inbound data pump did not start when the registered connection ran")
	}
}
