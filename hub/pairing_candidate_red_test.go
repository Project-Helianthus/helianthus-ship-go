package hub

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

const pairingCandidateTestSKI = "b1b7197b064084e4cfef2365105d8d36ff185e5b"

type pairingCandidateMDNS struct {
	*attemptTestMdns
	registration []bool
	err          error
}

func (m *pairingCandidateMDNS) SetPairingRegistration(value bool) error {
	if m.err != nil {
		return m.err
	}
	m.registration = append(m.registration, value)
	return nil
}

func newPairingCandidateHub(t *testing.T, withGate bool) (*Hub, *pairingCandidateMDNS) {
	t.Helper()
	reader := &attemptAwareGateTestHubReader{}
	mdns := &pairingCandidateMDNS{attemptTestMdns: &attemptTestMdns{}}
	hub := NewHub(reader, mdns, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	if withGate {
		if err := hub.SetOutgoingAttemptGate(newScriptedAttemptGate(gatePermit)); err != nil {
			t.Fatalf("install outgoing attempt gate: %v", err)
		}
	}
	hub.hasStarted = true
	return hub, mdns
}

func TestHubExposesDiscoveredPairingCandidateQueue(t *testing.T) {
	var _ api.PairingCandidateQueuer = (*Hub)(nil)
}

func TestPairingCandidateRequiresOpenRegistrationAndAttemptGate(t *testing.T) {
	hub, _ := newPairingCandidateHub(t, true)
	if err := hub.QueuePairingCandidate(pairingCandidateTestSKI); !errors.Is(err, api.ErrPairingRegistrationClosed) {
		t.Fatalf("closed pairing queue error = %v, want %v", err, api.ErrPairingRegistrationClosed)
	}

	hub, _ = newPairingCandidateHub(t, false)
	if err := hub.SetPairingRegistration(true); err != nil {
		t.Fatalf("open pairing registration: %v", err)
	}
	if err := hub.QueuePairingCandidate(pairingCandidateTestSKI); !errors.Is(err, api.ErrOutgoingAttemptGateRequired) {
		t.Fatalf("ungated pairing queue error = %v, want %v", err, api.ErrOutgoingAttemptGateRequired)
	}
}

func TestPairingCandidateQueuesWithoutGrantingTrustOrEndpoint(t *testing.T) {
	hub, mdns := newPairingCandidateHub(t, true)
	if err := hub.SetPairingRegistration(true); err != nil {
		t.Fatalf("open pairing registration: %v", err)
	}
	if err := hub.QueuePairingCandidate(pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}

	service := hub.ServiceForSKI(pairingCandidateTestSKI)
	if service.Trusted() {
		t.Fatal("queueing a discovered candidate granted durable trust")
	}
	if got := service.ConnectionStateDetail().State(); got != api.ConnectionStateQueued {
		t.Fatalf("candidate state = %v, want %v", got, api.ConnectionStateQueued)
	}
	_, requests := mdns.counts()
	if requests != 1 {
		t.Fatalf("mDNS requests = %d, want 1", requests)
	}
}

func TestClosingPairingRegistrationRetiresUntrustedCandidate(t *testing.T) {
	hub, mdns := newPairingCandidateHub(t, true)
	if err := hub.SetPairingRegistration(true); err != nil {
		t.Fatalf("open pairing registration: %v", err)
	}
	if err := hub.QueuePairingCandidate(pairingCandidateTestSKI); err != nil {
		t.Fatalf("queue pairing candidate: %v", err)
	}
	if err := hub.SetPairingRegistration(false); err != nil {
		t.Fatalf("close pairing registration: %v", err)
	}

	service := hub.ServiceForSKI(pairingCandidateTestSKI)
	if service.Trusted() {
		t.Fatal("retiring a candidate changed trust")
	}
	if got := service.ConnectionStateDetail().State(); got != api.ConnectionStateNone {
		t.Fatalf("retired candidate state = %v, want %v", got, api.ConnectionStateNone)
	}
	wantRegistration := []bool{true, false}
	if len(mdns.registration) != len(wantRegistration) || mdns.registration[0] != true || mdns.registration[1] != false {
		t.Fatalf("registration transitions = %v, want %v", mdns.registration, wantRegistration)
	}
}

func TestPairingCandidateRejectsInvalidOrTrustedSKI(t *testing.T) {
	hub, _ := newPairingCandidateHub(t, true)
	if err := hub.SetPairingRegistration(true); err != nil {
		t.Fatalf("open pairing registration: %v", err)
	}
	if err := hub.QueuePairingCandidate("not-a-ski"); !errors.Is(err, api.ErrInvalidRemoteSKI) {
		t.Fatalf("invalid SKI error = %v, want %v", err, api.ErrInvalidRemoteSKI)
	}

	service := hub.ServiceForSKI(pairingCandidateTestSKI)
	service.SetTrusted(true)
	if err := hub.QueuePairingCandidate(pairingCandidateTestSKI); !errors.Is(err, api.ErrRemoteAlreadyTrusted) {
		t.Fatalf("trusted candidate error = %v, want %v", err, api.ErrRemoteAlreadyTrusted)
	}
}
