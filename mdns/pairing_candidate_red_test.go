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
	stable, candidates, revision := manager.copyMdnsSnapshot()
	if len(stable) != 1 || stable[ski] == nil {
		t.Fatalf("stable same-SKI services = %#v, want one service keyed by SKI", stable)
	}
	if len(candidates) != 2 {
		t.Fatalf("same-SKI candidate count = %d, want 2", len(candidates))
	}
	refs := make(map[string]struct{}, 2)
	for _, candidate := range candidates {
		if candidate.CandidateRef == "" || revision == 0 {
			t.Fatalf("candidate identity missing: %#v revision=%d", candidate, revision)
		}
		refs[candidate.CandidateRef] = struct{}{}
	}
	if len(refs) != 2 {
		t.Fatalf("candidate refs are not unique: %v", refs)
	}

	manager.processMdnsEntry(elements, "VR940-A", "vr940-a.local", []net.IP{net.ParseIP("192.168.100.21")}, 12480, true)
	manager.processMdnsEntry(elements, "VR940-A", "vr940-a.local", []net.IP{net.ParseIP("192.168.100.21")}, 12480, false)
	_, readded, _ := manager.copyMdnsSnapshot()
	if len(readded) != 2 {
		t.Fatalf("candidate count after re-add = %d, want 2", len(readded))
	}
	for _, candidate := range readded {
		if candidate.Name == "VR940-A" {
			if _, reused := refs[candidate.CandidateRef]; reused {
				t.Fatalf("re-added observation reused candidate ref %q", candidate.CandidateRef)
			}
		}
	}
}

func TestMDNSObservationUpdateReplacesWithdrawnInterfaceAddresses(t *testing.T) {
	const ski = "b1b7197b064084e4cfef2365105d8d36ff185e5b"
	manager := NewMDNS("local-ski", "Helianthus", "eebusreg", "EnergyManagementSystem", "local-id", "local", 4712, nil, MdnsProviderSelectionGoZeroConfOnly)
	elements := pairingCandidateElements(ski)
	first := net.ParseIP("192.168.100.21")
	second := net.ParseIP("192.168.101.21")

	manager.processMdnsEntry(elements, "VR940", "vr940.local", []net.IP{first, second}, 12480, false)
	_, before, _ := manager.copyMdnsSnapshot()
	if len(before) != 1 {
		t.Fatalf("candidate count before interface withdrawal = %d, want 1", len(before))
	}
	var originalRef string
	for _, candidate := range before {
		originalRef = candidate.CandidateRef
	}

	manager.processMdnsEntry(elements, "VR940", "vr940.local", []net.IP{second}, 12480, false)
	_, after, _ := manager.copyMdnsSnapshot()
	if len(after) != 1 {
		t.Fatalf("candidate count after one interface withdrawal = %d, want 1", len(after))
	}
	for _, candidate := range after {
		if len(candidate.Addresses) != 1 || !candidate.Addresses[0].Equal(second) {
			t.Fatalf("candidate addresses after withdrawal = %v, want only %s", candidate.Addresses, second)
		}
		if candidate.CandidateRef == originalRef {
			t.Fatalf("address withdrawal reused candidate ref %q", candidate.CandidateRef)
		}
	}

	manager.processMdnsEntry(elements, "VR940", "vr940.local", nil, 12480, true)
	if _, remaining, _ := manager.copyMdnsSnapshot(); len(remaining) != 0 {
		t.Fatalf("candidate count after final withdrawal = %d, want 0", len(remaining))
	}
}
