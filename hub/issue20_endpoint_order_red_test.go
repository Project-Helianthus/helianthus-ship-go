package hub

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

func TestIssue20ReconnectEndpointsPreferConcreteAddresses(t *testing.T) {
	const (
		remoteSKI = "1111111111111111111111111111111111111111"
		host      = "peer.local"
		port      = 12480
		path      = "/ship/"
		ipv4A     = "192.0.2.10"
		ipv4B     = "192.0.2.11"
		ipv6A     = "2001:db8::10"
		ipv6B     = "2001:db8::11"
	)

	entry := &api.MdnsEntry{
		Ski:  remoteSKI,
		Host: host,
		Port: port,
		Path: path,
		Addresses: []net.IP{
			net.ParseIP(ipv6A),
			net.ParseIP(ipv4A),
			net.ParseIP(ipv6B),
			net.ParseIP(ipv4B),
		},
	}
	originalAddresses := cloneIssue20Addresses(entry.Addresses)

	assertIssue20EndpointSweep(t, entry, []string{ipv4A, ipv4B, ipv6A, ipv6B, host})

	if !reflect.DeepEqual(entry.Addresses, originalAddresses) {
		t.Fatalf("endpoint sweep mutated mDNS addresses: got %v, want %v", entry.Addresses, originalAddresses)
	}
}

func TestIssue20ReconnectUsesObservedMdnsEndpoints(t *testing.T) {
	const (
		remoteSKI = "1111111111111111111111111111111111111111"
		staleIPv4 = "198.51.100.99"
	)
	entry := &api.MdnsEntry{
		Ski:       remoteSKI,
		Host:      "peer.local",
		Port:      12480,
		Path:      "/ship/",
		Addresses: []net.IP{net.ParseIP("2001:db8::50"), net.ParseIP("192.0.2.50")},
	}
	originalAddresses := cloneIssue20Addresses(entry.Addresses)

	reader := &attemptAwareHubReader{}
	mdns := &attemptTestMdns{}
	hub := NewHub(
		reader,
		mdns,
		0,
		tls.Certificate{},
		api.NewServiceDetails("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
	)
	t.Cleanup(hub.Shutdown)
	gate := newScriptedAttemptGate(gatePermit)
	if err := hub.SetOutgoingAttemptGate(gate); err != nil {
		t.Fatalf("install outgoing attempt gate: %v", err)
	}
	service := hub.ServiceForSKI(remoteSKI)
	service.SetTrusted(true)
	service.SetIPv4(staleIPv4)
	service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub.dialer = dialer

	hub.ReportMdnsEntries(map[string]*api.MdnsEntry{remoteSKI: entry}, true)
	waitIssue20MdnsEffects(t, reader, gate, dialer, mdns, 6)

	calls, _ := dialer.snapshot()
	requests, _, _, _ := gate.snapshot()
	expectedHosts := []string{
		"192.0.2.50", "192.0.2.50",
		"2001:db8::50", "2001:db8::50",
		"peer.local", "peer.local",
	}
	for index, expectedHost := range expectedHosts {
		expectedPath := "/ship/"
		if index%2 != 0 {
			expectedPath = ""
		}
		expectedURL := "wss://" + net.JoinHostPort(expectedHost, "12480") + expectedPath
		if requests[index].Endpoint.Host != expectedHost || requests[index].Path != expectedPath {
			t.Fatalf("gate[%d] = %#v, want host=%q path=%q",
				index, requests[index], expectedHost, expectedPath)
		}
		if calls[index].url != expectedURL {
			t.Fatalf("dial[%d] = %q, want %q", index, calls[index].url, expectedURL)
		}
	}
	if !reflect.DeepEqual(entry.Addresses, originalAddresses) {
		t.Fatalf("mDNS reconnect mutated observed addresses: got %v, want %v", entry.Addresses, originalAddresses)
	}
	if service.IPv4() != staleIPv4 {
		t.Fatalf("reconnect changed configured IPv4 to %q, want %q", service.IPv4(), staleIPv4)
	}
}

func TestIssue20ReconnectEndpointFallbacks(t *testing.T) {
	const remoteSKI = "1111111111111111111111111111111111111111"
	tests := []struct {
		name          string
		entry         *api.MdnsEntry
		expectedHosts []string
	}{
		{
			name: "addresses without host",
			entry: &api.MdnsEntry{
				Ski:       remoteSKI,
				Port:      12480,
				Path:      "/ship/",
				Addresses: []net.IP{net.ParseIP("2001:db8::20"), net.ParseIP("192.0.2.20")},
			},
			expectedHosts: []string{"192.0.2.20", "2001:db8::20"},
		},
		{
			name: "host without addresses",
			entry: &api.MdnsEntry{
				Ski:  remoteSKI,
				Host: "peer.local",
				Port: 12480,
				Path: "/ship/",
			},
			expectedHosts: []string{"peer.local"},
		},
		{
			name: "concrete host duplicates address",
			entry: &api.MdnsEntry{
				Ski:       remoteSKI,
				Host:      "192.0.2.30",
				Port:      12480,
				Path:      "/ship/",
				Addresses: []net.IP{net.ParseIP("2001:db8::30"), net.ParseIP("192.0.2.30")},
			},
			expectedHosts: []string{"192.0.2.30", "2001:db8::30"},
		},
		{
			name: "invalid addresses have no effects",
			entry: &api.MdnsEntry{
				Ski:       remoteSKI,
				Port:      12480,
				Path:      "/ship/",
				Addresses: []net.IP{nil, {}, {0x01, 0x02, 0x03}},
			},
		},
		{
			name: "canonical duplicates keep first family occurrence",
			entry: &api.MdnsEntry{
				Ski:  remoteSKI,
				Host: "[2001:db8::40]",
				Port: 12480,
				Path: "/ship/",
				Addresses: []net.IP{
					net.ParseIP("2001:db8::40"),
					net.IPv4(192, 0, 2, 40),
					net.IP{192, 0, 2, 40},
					net.ParseIP("2001:db8::40"),
					net.IP{192, 0, 2, 41},
					net.IPv4(192, 0, 2, 41),
					net.ParseIP("2001:db8::41"),
					net.ParseIP("2001:db8::41"),
				},
			},
			expectedHosts: []string{"192.0.2.40", "192.0.2.41", "2001:db8::40", "2001:db8::41"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			originalAddresses := cloneIssue20Addresses(test.entry.Addresses)
			assertIssue20EndpointSweep(t, test.entry, test.expectedHosts)
			if !reflect.DeepEqual(test.entry.Addresses, originalAddresses) {
				t.Fatalf("endpoint sweep mutated mDNS addresses: got %v, want %v",
					test.entry.Addresses, originalAddresses)
			}
		})
	}
}

func waitIssue20MdnsEffects(
	t *testing.T,
	reader *attemptAwareHubReader,
	gate *scriptedAttemptGate,
	dialer *fakePeerDialer,
	mdns *attemptTestMdns,
	expected int,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		calls, _ := dialer.snapshot()
		requests, authorized, permits, _ := gate.snapshot()
		terminals, _ := reader.snapshot()
		announced, requested := mdns.counts()
		if len(calls) == expected && len(requests) == expected &&
			len(authorized) == expected && len(permits) == expected &&
			len(terminals) == expected && announced == 1 && requested == 1 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	calls, _ := dialer.snapshot()
	requests, authorized, permits, _ := gate.snapshot()
	terminals, _ := reader.snapshot()
	announced, requested := mdns.counts()
	t.Fatalf("dial/gate/authorize/permit/terminal/announce/request = %d/%d/%d/%d/%d/%d/%d, want %d each and 1/1",
		len(calls), len(requests), len(authorized), len(permits), len(terminals),
		announced, requested, expected)
}

func assertIssue20EndpointSweep(t *testing.T, entry *api.MdnsEntry, expectedHosts []string) {
	t.Helper()
	reader := &attemptAwareHubReader{}
	hub := NewHub(
		reader,
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
	remote := hub.ServiceForSKI(entry.Ski)
	remote.SetTrusted(true)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub.dialer = dialer

	success, err := hub.initateConnectionWithError(remote, entry)
	if len(expectedHosts) == 0 {
		if success || err != nil {
			t.Fatalf("empty endpoint sweep = success:%t err:%v, want false/nil", success, err)
		}
	} else if success || !errors.Is(err, errAttemptTestDial) {
		t.Fatalf("failed endpoint sweep = success:%t err:%v, want false/%v", success, err, errAttemptTestDial)
	}

	calls, _ := dialer.snapshot()
	requests, authorized, permits, _ := gate.snapshot()
	terminals, _ := reader.snapshot()
	expectedCount := len(expectedHosts) * 2
	if len(calls) != expectedCount || len(requests) != expectedCount ||
		len(authorized) != expectedCount || len(permits) != expectedCount ||
		len(terminals) != expectedCount {
		t.Fatalf(
			"dial/gate/authorize/permit/terminal counts = %d/%d/%d/%d/%d, want %d each",
			len(calls),
			len(requests),
			len(authorized),
			len(permits),
			len(terminals),
			expectedCount,
		)
	}

	for endpointIndex, expectedHost := range expectedHosts {
		for fallbackIndex, expectedPath := range []string{entry.Path, ""} {
			index := endpointIndex*2 + fallbackIndex
			expectedURL := "wss://" + net.JoinHostPort(expectedHost, fmt.Sprint(entry.Port)) + expectedPath
			if calls[index].url != expectedURL {
				t.Fatalf("dial[%d] = %q, want %q", index, calls[index].url, expectedURL)
			}
			request := requests[index]
			if request.RemoteSKI != entry.Ski ||
				request.Endpoint.Host != expectedHost ||
				request.Endpoint.Port != uint16(entry.Port) ||
				request.Path != expectedPath {
				t.Fatalf("gate[%d] = %#v, want SKI=%s endpoint=%s:%d path=%q",
					index, request, entry.Ski, expectedHost, entry.Port, expectedPath)
			}
		}
	}
}

func cloneIssue20Addresses(addresses []net.IP) []net.IP {
	if addresses == nil {
		return nil
	}
	cloned := make([]net.IP, len(addresses))
	for index, address := range addresses {
		if address == nil {
			continue
		}
		cloned[index] = make(net.IP, len(address))
		copy(cloned[index], address)
	}
	return cloned
}
