package hub

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

func TestIssue22TrustedInboundLoserDoesNotEnterSHIPWhileOutboundIsInitiating(t *testing.T) {
	localSKI := strings.Repeat("f", 40)
	remoteSKI := strings.Repeat("0", 40)
	hub := NewHub(
		&attemptAwareGateTestHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails(localSKI),
	)
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)

	hub.muxCon.Lock()
	hub.connectionsInitiating[remoteSKI] = true
	hub.muxCon.Unlock()

	if hub.keepThisConnection(nil, true, remote) {
		t.Fatal("trusted inbound loser entered SHIP while the winning outbound attempt was initiating")
	}
}

func TestIssue22TrustedInboundWinnerSurvivesWhileOutboundIsInitiating(t *testing.T) {
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

	hub.muxCon.Lock()
	hub.connectionsInitiating[remoteSKI] = true
	hub.muxCon.Unlock()

	if !hub.keepThisConnection(nil, true, remote) {
		t.Fatal("trusted inbound winner was rejected because an outbound attempt was initiating")
	}
}
