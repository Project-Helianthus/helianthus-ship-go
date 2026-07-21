package mdns

import (
	"net"
	"testing"
)

func pairingCandidateElements(ski string) map[string]string {
	return map[string]string{
		"txtvers":  "1",
		"id":       "vr940-ship-id",
		"path":     "/ship/",
		"ski":      ski,
		"register": "false",
		"brand":    "Vaillant",
		"type":     "Gateway",
		"model":    "VR940",
	}
}

func TestMDNSCandidateReferencesPreserveSameSKICollisionsAndGeneration(t *testing.T) {
	const ski = "b1b7197b064084e4cfef2365105d8d36ff185e5b"
	manager := NewMDNS("local-ski", "Helianthus", "eebusreg", "EnergyManagementSystem", "local-id", "local", 4712, nil, MdnsProviderSelectionGoZeroConfOnly)
	elements := pairingCandidateElements(ski)

	manager.processMdnsEntry(elements, "VR940-A", "vr940-a.local", []net.IP{net.ParseIP("192.168.100.21")}, 12480, false)
	manager.processMdnsEntry(elements, "VR940-B", "vr940-b.local", []net.IP{net.ParseIP("192.168.100.22")}, 12480, false)
	entries := manager.copyMdnsEntries()
	if len(entries) != 2 {
		t.Fatalf("same-SKI candidate count = %d, want 2", len(entries))
	}
	refs := make(map[string]struct{}, 2)
	for _, entry := range entries {
		if entry.CandidateRef == "" || entry.ObservationRevision == 0 {
			t.Fatalf("candidate identity missing: %#v", entry)
		}
		refs[entry.CandidateRef] = struct{}{}
	}
	if len(refs) != 2 {
		t.Fatalf("candidate refs are not unique: %v", refs)
	}

	manager.processMdnsEntry(elements, "VR940-A", "vr940-a.local", []net.IP{net.ParseIP("192.168.100.21")}, 12480, true)
	manager.processMdnsEntry(elements, "VR940-A", "vr940-a.local", []net.IP{net.ParseIP("192.168.100.21")}, 12480, false)
	readded := manager.copyMdnsEntries()
	if len(readded) != 2 {
		t.Fatalf("candidate count after re-add = %d, want 2", len(readded))
	}
	for _, entry := range readded {
		if entry.Name == "VR940-A" {
			if _, reused := refs[entry.CandidateRef]; reused {
				t.Fatalf("re-added observation reused candidate ref %q", entry.CandidateRef)
			}
		}
	}
}
