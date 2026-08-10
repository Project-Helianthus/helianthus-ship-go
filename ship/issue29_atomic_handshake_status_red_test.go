package ship

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/model"
)

func TestIssue29ShipHandshakeStateReturnsAtomicSnapshot(t *testing.T) {
	connection := newConnectionHandler(
		&concurrentConnectionInfoProvider{},
		nil,
		ShipRoleServer,
		"local-ship-id",
		"remote-ski",
		"remote-ship-id",
		false,
	)
	transitionErr := errors.New("handshake transition failed")

	const transitionCount = 1000
	start := make(chan struct{})
	invalidSnapshot := make(chan string, 1)
	var workers sync.WaitGroup
	workers.Add(2)

	go func() {
		defer workers.Done()
		<-start
		for range transitionCount {
			connection.setState(model.SmeStateError, transitionErr)
			connection.setState(model.CmiStateInitStart, nil)
		}
	}()

	go func() {
		defer workers.Done()
		<-start
		for range transitionCount * 2 {
			state, err := connection.ShipHandshakeState()
			if state == model.CmiStateInitStart && err == nil {
				continue
			}
			if state == model.SmeStateError && errors.Is(err, transitionErr) {
				continue
			}
			invalidSnapshot <- fmt.Sprintf("state=%v error=%v", state, err)
			return
		}
	}()

	close(start)
	workers.Wait()
	close(invalidSnapshot)
	if snapshot, ok := <-invalidSnapshot; ok {
		t.Fatalf("ShipHandshakeState returned torn snapshot: %s", snapshot)
	}
}
