package hub

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

var _ api.PairingCandidatePINController = (*Hub)(nil)

func TestIssue35ScopedLinkLocalReachesAttemptGateAndDialer(t *testing.T) {
	entry := &api.MdnsEntry{
		Ski:             "1111111111111111111111111111111111111111",
		Port:            12480,
		Path:            "/ship/",
		ScopedAddresses: []netip.Addr{netip.MustParseAddr("fe80::21").WithZone("en7")},
	}

	assertIssue20EndpointSweep(t, entry, []string{"fe80::21%en7"})
}

func TestIssue35ScopedLinkLocalUsesRFC6874URLButRawGateHost(t *testing.T) {
	const (
		remoteSKI = "1111111111111111111111111111111111111111"
		host      = "fe80::21%en7"
	)
	hub := NewHub(
		&attemptAwareHubReader{},
		&attemptTestMdns{},
		0,
		tls.Certificate{},
		api.NewServiceDetails("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
	)
	t.Cleanup(hub.Shutdown)
	gate := newScriptedAttemptGate(gatePermit)
	if err := hub.SetOutgoingAttemptGate(gate); err != nil {
		t.Fatalf("install outgoing attempt gate: %v", err)
	}
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)
	hub.dialer = &fakePeerDialer{err: errAttemptTestDial}

	_, _, _, err := hub.gatedDialContextWithExpectedSKI(
		remote,
		host,
		"12480",
		"/ship/",
		"",
		nil,
	)
	if !errors.Is(err, errAttemptTestDial) {
		t.Fatalf("scoped dial error = %v, want %v", err, errAttemptTestDial)
	}
	requests, _, _, _ := gate.snapshot()
	if len(requests) != 1 || requests[0].Endpoint.Host != host {
		t.Fatalf("gate host = %#v, want raw scoped host %q", requests, host)
	}
	calls, _ := hub.dialer.(*fakePeerDialer).snapshot()
	if len(calls) != 1 {
		t.Fatalf("dial calls = %d, want 1", len(calls))
	}
	const wantURL = "wss://[fe80::21%25en7]:12480/ship/"
	if calls[0].url != wantURL {
		t.Fatalf("dial URL = %q, want RFC6874 %q", calls[0].url, wantURL)
	}
	parsed, parseErr := url.Parse(calls[0].url)
	if parseErr != nil || parsed.Hostname() != host {
		t.Fatalf("Gorilla-compatible URL parse = host:%q err:%v, want %q/nil",
			parsed.Hostname(), parseErr, host)
	}
}

func TestIssue35UnscopedLinkLocalNeverReachesAttemptGateOrDialer(t *testing.T) {
	tests := []struct {
		name  string
		entry *api.MdnsEntry
	}{
		{
			name: "new scoped field without zone",
			entry: &api.MdnsEntry{
				Ski:             "1111111111111111111111111111111111111111",
				Host:            "must-not-fallback.local",
				Port:            12480,
				Path:            "/ship/",
				ScopedAddresses: []netip.Addr{netip.MustParseAddr("fe80::22")},
			},
		},
		{
			name: "normalized observation marker suppresses host fallback",
			entry: &api.MdnsEntry{
				Ski:                       "1111111111111111111111111111111111111111",
				Host:                      "must-not-fallback.local",
				Port:                      12480,
				Path:                      "/ship/",
				UnscopedLinkLocalObserved: true,
			},
		},
		{
			name: "legacy address cannot carry zone",
			entry: &api.MdnsEntry{
				Ski:       "1111111111111111111111111111111111111111",
				Host:      "must-not-fallback.local",
				Port:      12480,
				Path:      "/ship/",
				Addresses: []net.IP{net.ParseIP("fe80::23")},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertIssue20EndpointSweep(t, test.entry, nil)
		})
	}
}

func TestIssue35TrustedRetrySuppressesHostFallbackForUnscopedLinkLocal(t *testing.T) {
	entry := &api.MdnsEntry{
		Host:                      "must-not-fallback.local",
		UnscopedLinkLocalObserved: true,
	}
	if host, ok := trustedRemoteRetryHost(entry); ok {
		t.Fatalf("trusted retry admitted hostname %q after unscoped link-local observation", host)
	}
}

func TestIssue35ScopedAddressPathPreservesIPv4AndGlobalIPv6(t *testing.T) {
	entry := &api.MdnsEntry{
		Ski:  "1111111111111111111111111111111111111111",
		Port: 12480,
		Path: "/ship/",
		ScopedAddresses: []netip.Addr{
			netip.MustParseAddr("2001:db8::24"),
			netip.MustParseAddr("192.0.2.24"),
		},
	}

	assertIssue20EndpointSweep(t, entry, []string{"192.0.2.24", "2001:db8::24"})
}

func TestIssue35AdditiveScopedRouteDoesNotStaleFrozenSelection(t *testing.T) {
	const ski = "1111111111111111111111111111111111111111"
	active := &activePairingCandidate{
		service:  api.NewServiceDetails(ski),
		revision: 7,
		host:     "fe80::35%en8",
		port:     "12480",
		path:     "/ship/",
	}
	additive := pairingCandidateObservation{
		ski:      ski,
		revision: 8,
		port:     12480,
		path:     "/ship/",
		scopedAddresses: []netip.Addr{
			netip.MustParseAddr("fe80::35").WithZone("en7"),
			netip.MustParseAddr("fe80::35").WithZone("en8"),
		},
	}
	if !pairingCandidateObservationMatchesActive(additive, active) {
		t.Fatal("additive scoped route staled a frozen endpoint that remains observable")
	}

	withdrawn := additive
	withdrawn.revision++
	withdrawn.scopedAddresses = []netip.Addr{
		netip.MustParseAddr("fe80::35").WithZone("en7"),
	}
	if pairingCandidateObservationMatchesActive(withdrawn, active) {
		t.Fatal("frozen selection survived withdrawal of its exact scoped endpoint")
	}
}
