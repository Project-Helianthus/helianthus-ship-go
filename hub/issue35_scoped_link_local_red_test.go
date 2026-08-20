package hub

import (
	"net"
	"net/netip"
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

func TestIssue35UnscopedLinkLocalNeverReachesAttemptGateOrDialer(t *testing.T) {
	tests := []struct {
		name  string
		entry *api.MdnsEntry
	}{
		{
			name: "new scoped field without zone",
			entry: &api.MdnsEntry{
				Ski:             "1111111111111111111111111111111111111111",
				Port:            12480,
				Path:            "/ship/",
				ScopedAddresses: []netip.Addr{netip.MustParseAddr("fe80::22")},
			},
		},
		{
			name: "legacy address cannot carry zone",
			entry: &api.MdnsEntry{
				Ski:       "1111111111111111111111111111111111111111",
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
