package hub

import (
	"errors"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

const issue33TrustedRemoteSKI = "0123456789abcdef0123456789abcdef01234567"

func TestIssue33HubExposesTargetedTrustedRemoteRetry(t *testing.T) {
	var _ api.TrustedRemoteRetryController = (*Hub)(nil)
}

func TestIssue33TrustedRemoteRetryRequiresExactNormalizedSKI(t *testing.T) {
	hub, _, _ := newAttemptTestHub(t, newScriptedAttemptGate(gatePermit), &fakePeerDialer{err: errAttemptTestDial})

	for _, invalid := range []string{
		"",
		"0123456789abcdef0123456789abcdef0123456",
		"0123456789abcdef0123456789abcdef012345678",
		"0123456789ABCDEF0123456789ABCDEF01234567",
		"01-23-45-67-89-ab-cd-ef-01-23-45-67-89-ab-cd-ef-01-23-45-67",
		"g123456789abcdef0123456789abcdef01234567",
	} {
		if err := hub.RetryTrustedRemote(invalid); !errors.Is(err, api.ErrInvalidRemoteSKI) {
			t.Errorf("RetryTrustedRemote(%q) error = %v, want %v", invalid, err, api.ErrInvalidRemoteSKI)
		}
	}
}

func TestIssue33TrustedRemoteRetryUsesCurrentLibraryOwnedObservationAtMostOnce(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub, _, _ := newAttemptTestHub(t, gate, dialer)
	entry := issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.33")
	service := hub.ServiceForSKI(issue33TrustedRemoteSKI)
	service.SetTrusted(true)
	service.ConnectionStateDetail().SetState(api.ConnectionStateNone)

	var launches []func()
	hub.testHooks = &hubTestHooks{
		launchTrustedRemoteRetry: func(run func()) { launches = append(launches, run) },
	}
	if err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI); err != nil {
		t.Fatalf("retry trusted remote: %v", err)
	}
	if len(launches) != 1 {
		t.Fatalf("retry launches = %d, want 1", len(launches))
	}
	if err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI); !errors.Is(err, api.ErrTrustedRemoteRetryBusy) {
		t.Fatalf("duplicate retry error = %v, want %v", err, api.ErrTrustedRemoteRetryBusy)
	}
	if requests, _, _, _ := gate.snapshot(); len(requests) != 0 {
		t.Fatalf("retry reached gate before scheduled launch: %d requests", len(requests))
	}

	launches[0]()
	requests, _, _, _ := gate.snapshot()
	calls, _ := dialer.snapshot()
	if len(requests) != 1 || len(calls) != 1 {
		t.Fatalf("retry gate/dial counts = %d/%d, want 1/1", len(requests), len(calls))
	}
	if request := requests[0]; request.RemoteSKI != issue33TrustedRemoteSKI || request.Endpoint.Host != "192.0.2.33" || request.Endpoint.Port != uint16(entry.Port) || request.Path != entry.Path {
		t.Fatalf("retry request did not use the retained observation: %#v", request)
	}
	if !service.Trusted() {
		t.Fatal("retry changed durable trust")
	}
	if err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI); err != nil {
		t.Fatalf("sequential retry after completed failed path: %v", err)
	}
	if len(launches) != 2 {
		t.Fatalf("sequential retry launches = %d, want 2", len(launches))
	}
}

func TestIssue33TrustedRemoteRetryFailsClosedForIneligibleState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Hub)
		want    error
	}{
		{
			name: "no current observation",
			prepare: func(hub *Hub) {
				hub.ServiceForSKI(issue33TrustedRemoteSKI).SetTrusted(true)
			},
			want: api.ErrTrustedRemoteRetryUnavailable,
		},
		{
			name: "not trusted",
			prepare: func(hub *Hub) {
				issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.33")
			},
			want: api.ErrTrustedRemoteRetryNotTrusted,
		},
		{
			name: "connected",
			prepare: func(hub *Hub) {
				issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.33")
				hub.ServiceForSKI(issue33TrustedRemoteSKI).SetTrusted(true)
				hub.muxCon.Lock()
				hub.connections[issue33TrustedRemoteSKI] = &attemptCallbackConnection{ski: issue33TrustedRemoteSKI}
				hub.muxCon.Unlock()
			},
			want: api.ErrTrustedRemoteRetryConnected,
		},
		{
			name: "connection already initiating",
			prepare: func(hub *Hub) {
				issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.33")
				hub.ServiceForSKI(issue33TrustedRemoteSKI).SetTrusted(true)
				hub.muxCon.Lock()
				hub.connectionsInitiating[issue33TrustedRemoteSKI] = true
				hub.muxCon.Unlock()
			},
			want: api.ErrTrustedRemoteRetryBusy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(gatePermit)
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, _, _ := newAttemptTestHub(t, gate, dialer)
			var launches int
			hub.testHooks = &hubTestHooks{launchTrustedRemoteRetry: func(func()) { launches++ }}
			test.prepare(hub)

			err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI)
			if !errors.Is(err, test.want) {
				t.Fatalf("retry error = %v, want %v", err, test.want)
			}
			if launches != 0 {
				t.Fatalf("ineligible retry scheduled %d launches", launches)
			}
			if requests, _, _, _ := gate.snapshot(); len(requests) != 0 {
				t.Fatalf("ineligible retry reached gate: %d requests", len(requests))
			}
			if calls, _ := dialer.snapshot(); len(calls) != 0 {
				t.Fatalf("ineligible retry dialed: %d calls", len(calls))
			}
		})
	}
}

func TestIssue33SnapshotChangeOrUntrustInvalidatesScheduledRetry(t *testing.T) {
	for _, test := range []struct {
		name       string
		invalidate func(*Hub)
	}{
		{
			name: "observation withdrawn",
			invalidate: func(hub *Hub) {
				hub.ReportMdnsEntries(map[string]*api.MdnsEntry{}, true)
			},
		},
		{
			name: "observation replaced",
			invalidate: func(hub *Hub) {
				issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.99")
			},
		},
		{
			name: "trust revoked",
			invalidate: func(hub *Hub) {
				hub.UnregisterRemoteSKI(issue33TrustedRemoteSKI)
			},
		},
		{
			name: "outgoing gate changed",
			invalidate: func(hub *Hub) {
				_ = hub.SetOutgoingAttemptGate(newScriptedAttemptGate(gatePermit))
			},
		},
		{
			name: "hub shutdown",
			invalidate: func(hub *Hub) {
				_, _, _ = hub.beginShutdown()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			gate := newScriptedAttemptGate(gatePermit)
			dialer := &fakePeerDialer{err: errAttemptTestDial}
			hub, _, _ := newAttemptTestHub(t, gate, dialer)
			issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.33")
			hub.ServiceForSKI(issue33TrustedRemoteSKI).SetTrusted(true)
			var launch func()
			hub.testHooks = &hubTestHooks{launchTrustedRemoteRetry: func(run func()) { launch = run }}

			if err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI); err != nil {
				t.Fatalf("schedule retry: %v", err)
			}
			test.invalidate(hub)
			launch()

			if requests, _, _, _ := gate.snapshot(); len(requests) != 0 {
				t.Fatalf("invalidated retry reached gate: %d requests", len(requests))
			}
			if calls, _ := dialer.snapshot(); len(calls) != 0 {
				t.Fatalf("invalidated retry dialed: %d calls", len(calls))
			}
		})
	}
}

func TestIssue33QueuedNewerMdnsSnapshotInvalidatesAcceptedRetryBeforeDial(t *testing.T) {
	gate := newScriptedAttemptGate(gatePermit)
	hub, gate, reader := newPairingCandidateHub(t, gate)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub.dialer = dialer
	firstCallback := make(chan struct{})
	releaseFirst := make(chan struct{})
	var blockOnce sync.Once
	reader.setVisibleUpdate(func(entries []api.RemoteService) {
		if len(entries) == 0 {
			return
		}
		blockOnce.Do(func() {
			close(firstCallback)
			<-releaseFirst
		})
	})

	firstDone := make(chan struct{})
	go func() {
		issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.33")
		close(firstDone)
	}()
	waitForPairingCandidateSignal(t, firstCallback, "first trusted-remote mDNS callback")
	hub.ServiceForSKI(issue33TrustedRemoteSKI).SetTrusted(true)
	var launch func()
	hub.testHooks.launchTrustedRemoteRetry = func(run func()) { launch = run }
	if err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI); err != nil {
		t.Fatalf("schedule retry from applied observation: %v", err)
	}

	issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "192.0.2.99")
	if err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI); !errors.Is(err, api.ErrTrustedRemoteObservationStale) {
		t.Fatalf("retry while newer snapshot queued error = %v, want %v", err, api.ErrTrustedRemoteObservationStale)
	}
	launch()
	if requests, _, _, _ := gate.snapshot(); len(requests) != 0 {
		t.Fatalf("queued-snapshot retry reached gate: %d requests", len(requests))
	}
	if calls, _ := dialer.snapshot(); len(calls) != 0 {
		t.Fatalf("queued-snapshot retry dialed: %d calls", len(calls))
	}

	close(releaseFirst)
	waitForPairingCandidateSignal(t, firstDone, "trusted-remote mDNS queue drain")
}

func TestIssue33RetryErrorsDoNotExposeRetainedEndpoint(t *testing.T) {
	hub, _, _ := newAttemptTestHub(t, newScriptedAttemptGate(gatePermit), &fakePeerDialer{err: errAttemptTestDial})
	issue33ReportUntrustedObservation(hub, issue33TrustedRemoteSKI, "secret-peer.internal")

	err := hub.RetryTrustedRemote(issue33TrustedRemoteSKI)
	if !errors.Is(err, api.ErrTrustedRemoteRetryNotTrusted) {
		t.Fatalf("retry error = %v, want %v", err, api.ErrTrustedRemoteRetryNotTrusted)
	}
	if strings.Contains(err.Error(), "secret-peer.internal") {
		t.Fatalf("retry error leaks retained endpoint: %v", err)
	}
}

func issue33ReportUntrustedObservation(hub *Hub, ski, address string) *api.MdnsEntry {
	entry := &api.MdnsEntry{
		Name:       "VR940",
		Ski:        ski,
		Identifier: "vr940-ship",
		Path:       "/ship/",
		Host:       "vr940.local",
		Port:       4712,
		Addresses:  []net.IP{net.ParseIP(address)},
	}
	hub.ReportMdnsEntries(map[string]*api.MdnsEntry{ski: entry}, true)
	return entry
}
