package mdns

import (
	"net"
	"net/netip"
	"testing"
)

func TestIssue35ScopedLinkLocalObservationPreservesZone(t *testing.T) {
	manager := NewMDNS(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"Helianthus",
		"Gateway",
		"HEMS",
		"local-ship-id",
		"helianthus",
		4712,
		nil,
		MdnsProviderSelectionGoZeroConfOnly,
	)
	elements := issue35MDNSText("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	linkLocal := netip.MustParseAddr("fe80::21").WithZone("en7")
	ipv4 := netip.MustParseAddr("192.0.2.21")
	globalIPv6 := netip.MustParseAddr("2001:db8::21")

	manager.processScopedMdnsEntry(
		elements,
		"VR940",
		"vr940.local",
		[]netip.Addr{linkLocal, ipv4, globalIPv6},
		12480,
		false,
	)

	entries, candidates, _ := manager.copyMdnsSnapshot()
	entry := entries[elements["ski"]]
	if entry == nil {
		t.Fatal("scoped mDNS observation was not retained")
	}
	assertIssue35ScopedAddresses(t, entry.ScopedAddresses, []netip.Addr{linkLocal, ipv4, globalIPv6})
	if len(entry.Addresses) != 2 || !entry.Addresses[0].Equal(net.ParseIP(ipv4.String())) ||
		!entry.Addresses[1].Equal(net.ParseIP(globalIPv6.String())) {
		t.Fatalf("legacy addresses = %v, want IPv4/global IPv6 only", entry.Addresses)
	}
	if len(candidates) != 1 {
		t.Fatalf("pairing candidates = %d, want 1", len(candidates))
	}
	if candidates[0].Host != "vr940.local" || candidates[0].Port != 12480 || !candidates[0].Register {
		t.Fatalf("candidate native endpoint context = %#v", candidates[0])
	}
	assertIssue35ScopedAddresses(t, candidates[0].ScopedAddresses, []netip.Addr{linkLocal, ipv4, globalIPv6})
}

func TestIssue35UnscopedLinkLocalObservationFailsClosed(t *testing.T) {
	manager := NewMDNS(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"Helianthus",
		"Gateway",
		"HEMS",
		"local-ship-id",
		"helianthus",
		4712,
		nil,
		MdnsProviderSelectionGoZeroConfOnly,
	)
	elements := issue35MDNSText("cccccccccccccccccccccccccccccccccccccccc")

	manager.processScopedMdnsEntry(
		elements,
		"VR940",
		"vr940.local",
		[]netip.Addr{netip.MustParseAddr("fe80::22")},
		12480,
		false,
	)

	entries, candidates, _ := manager.copyMdnsSnapshot()
	entry := entries[elements["ski"]]
	if entry == nil {
		t.Fatal("identity observation should remain visible when its only address is unusable")
	}
	if len(entry.Addresses) != 0 || len(entry.ScopedAddresses) != 0 {
		t.Fatalf("unscoped link-local escaped fail-closed filtering: legacy=%v scoped=%v",
			entry.Addresses, entry.ScopedAddresses)
	}
	if !entry.UnscopedLinkLocalObserved {
		t.Fatal("normalized mDNS entry lost fail-closed unscoped link-local evidence")
	}
	if len(candidates) != 1 || len(candidates[0].ScopedAddresses) != 0 {
		t.Fatalf("candidate retained an unscoped link-local address: %#v", candidates)
	}
	if !candidates[0].UnscopedLinkLocalObserved {
		t.Fatal("candidate lost fail-closed unscoped link-local evidence")
	}
}

func issue35MDNSText(ski string) map[string]string {
	return map[string]string{
		"txtvers":  "1",
		"id":       "vr940-ship-id",
		"path":     "/ship/",
		"ski":      ski,
		"register": "true",
	}
}

func assertIssue35ScopedAddresses(t *testing.T, got, want []netip.Addr) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("scoped address count = %d, want %d: %v", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("scoped address[%d] = %s, want %s", index, got[index], want[index])
		}
	}
}
