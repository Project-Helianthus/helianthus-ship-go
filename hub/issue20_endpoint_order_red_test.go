package hub

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"testing"

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
	remote := hub.ServiceForSKI(remoteSKI)
	remote.SetTrusted(true)
	dialer := &fakePeerDialer{err: errAttemptTestDial}
	hub.dialer = dialer

	success, err := hub.initateConnectionWithError(remote, entry)
	if success || !errors.Is(err, errAttemptTestDial) {
		t.Fatalf("failed endpoint sweep = success:%t err:%v, want false/%v", success, err, errAttemptTestDial)
	}

	calls, _ := dialer.snapshot()
	requests, authorized, permits, _ := gate.snapshot()
	expectedHosts := []string{ipv4A, ipv4B, ipv6A, ipv6B, host}
	expectedCount := len(expectedHosts) * 2
	if len(calls) != expectedCount || len(requests) != expectedCount ||
		len(authorized) != expectedCount || len(permits) != expectedCount {
		t.Fatalf(
			"dial/gate/authorize/permit counts = %d/%d/%d/%d, want %d each",
			len(calls),
			len(requests),
			len(authorized),
			len(permits),
			expectedCount,
		)
	}

	for endpointIndex, expectedHost := range expectedHosts {
		for fallbackIndex, expectedPath := range []string{path, ""} {
			index := endpointIndex*2 + fallbackIndex
			expectedURL := "wss://" + net.JoinHostPort(expectedHost, fmt.Sprint(port)) + expectedPath
			if calls[index].url != expectedURL {
				t.Fatalf("dial[%d] = %q, want %q", index, calls[index].url, expectedURL)
			}
			request := requests[index]
			if request.RemoteSKI != remoteSKI ||
				request.Endpoint.Host != expectedHost ||
				request.Endpoint.Port != port ||
				request.Path != expectedPath {
				t.Fatalf("gate[%d] = %#v, want SKI=%s endpoint=%s:%d path=%q",
					index, request, remoteSKI, expectedHost, port, expectedPath)
			}
		}
	}

	if !reflect.DeepEqual(entry.Addresses, originalAddresses) {
		t.Fatalf("endpoint sweep mutated mDNS addresses: got %v, want %v", entry.Addresses, originalAddresses)
	}
}

func cloneIssue20Addresses(addresses []net.IP) []net.IP {
	cloned := make([]net.IP, len(addresses))
	for index, address := range addresses {
		cloned[index] = append(net.IP(nil), address...)
	}
	return cloned
}
