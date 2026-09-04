package hub

import (
	"crypto/tls"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

type issue41DiscoveryReader struct {
	pairingCandidateReader

	mu41      sync.Mutex
	snapshots []api.PairingCandidateDiscoverySnapshotV1
	onUpdate  func(api.PairingCandidateDiscoverySnapshotV1)
}

func (reader *issue41DiscoveryReader) VisiblePairingCandidateDiscoverySnapshotUpdated(
	snapshot api.PairingCandidateDiscoverySnapshotV1,
) {
	reader.mu41.Lock()
	reader.snapshots = append(reader.snapshots, snapshot)
	onUpdate := reader.onUpdate
	reader.mu41.Unlock()
	if onUpdate != nil {
		onUpdate(snapshot)
	}
}

func (reader *issue41DiscoveryReader) discoverySnapshots() []api.PairingCandidateDiscoverySnapshotV1 {
	reader.mu41.Lock()
	defer reader.mu41.Unlock()
	return append([]api.PairingCandidateDiscoverySnapshotV1(nil), reader.snapshots...)
}

func newIssue41Hub(t *testing.T) (*Hub, *issue41DiscoveryReader) {
	t.Helper()
	reader := &issue41DiscoveryReader{}
	hub := NewHub(reader, &attemptTestMdns{}, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	hub.testHooks = &hubTestHooks{}
	hub.hasStarted = true
	return hub, reader
}

func TestIssue41DiscoverySnapshotRoundTripsNativeObservationAndPreservesLegacyReader(t *testing.T) {
	hub, reader := newIssue41Hub(t)
	want := api.PairingCandidateDiscoveryObservationV1{
		CandidateRef: "shipc-native-v1",
		Name:         "Synthetic SHIP service",
		SKI:          pairingCandidateTestSKI,
		Identifier:   "synthetic-ship-id",
		Brand:        "Synthetic Brand",
		Type:         "Gateway",
		Model:        "Model 1",
		Path:         "/ship/",
		Host:         "synthetic.local",
		Port:         4712,
		Register:     true,
		Addresses:    []net.IP{net.ParseIP("192.0.2.41")},
		ScopedAddresses: []netip.Addr{
			netip.MustParseAddr("fe80::41").WithZone("test0"),
			netip.MustParseAddr("192.0.2.41"),
		},
		UnscopedLinkLocalObserved: true,
	}
	hub.ReportMdnsEntriesWithCandidates(nil, true, []api.PairingCandidateObservation{{
		CandidateRef: want.CandidateRef,
		Name:         want.Name, SKI: want.SKI, Identifier: want.Identifier,
		Brand: want.Brand, Type: want.Type, Model: want.Model,
		Path: want.Path, Host: want.Host, Port: want.Port, Register: want.Register,
		Addresses: want.Addresses, ScopedAddresses: want.ScopedAddresses,
		UnscopedLinkLocalObserved: want.UnscopedLinkLocalObserved,
	}}, 41)

	snapshots := reader.discoverySnapshots()
	if len(snapshots) != 1 {
		t.Fatalf("discovery snapshots = %d, want 1", len(snapshots))
	}
	got := snapshots[0]
	if got.ObservationRevision != 41 || !got.NewEntries || len(got.Candidates) != 1 {
		t.Fatalf("discovery snapshot context = %#v", got)
	}
	if !reflect.DeepEqual(got.Candidates[0], want) {
		t.Fatalf("discovery candidate = %#v, want %#v", got.Candidates[0], want)
	}
	legacy := reader.candidateSnapshot()
	if len(legacy) != 1 || legacy[0].CandidateRef != want.CandidateRef || legacy[0].SKI != want.SKI {
		t.Fatalf("legacy candidate refs = %#v", legacy)
	}
}

func TestIssue41DiscoverySnapshotMakesAbsenceAndClearExplicit(t *testing.T) {
	hub, reader := newIssue41Hub(t)
	hub.ReportMdnsEntriesWithCandidates(nil, false, []api.PairingCandidateObservation{{
		CandidateRef: "shipc-partial-v1",
		SKI:          pairingCandidateTestSKI,
	}}, 42)
	hub.ReportMdnsEntriesWithCandidates(nil, false, nil, 43)

	snapshots := reader.discoverySnapshots()
	if len(snapshots) != 2 {
		t.Fatalf("discovery snapshots = %d, want 2", len(snapshots))
	}
	partial := snapshots[0].Candidates[0]
	if partial.Host != "" || partial.Port != 0 || partial.Register ||
		partial.Addresses != nil || partial.ScopedAddresses != nil || partial.UnscopedLinkLocalObserved {
		t.Fatalf("partial observation synthesized unavailable fields: %#v", partial)
	}
	clear := snapshots[1]
	if clear.ObservationRevision != 43 || clear.NewEntries || clear.Candidates == nil || len(clear.Candidates) != 0 {
		t.Fatalf("authoritative clear snapshot = %#v", clear)
	}
}

func TestIssue41DiscoverySnapshotIsDetachedFromInputAndHubState(t *testing.T) {
	hub, reader := newIssue41Hub(t)
	legacyAddress := net.IP{192, 0, 2, 41}
	scopedAddress := netip.MustParseAddr("fe80::41").WithZone("test0")
	candidates := []api.PairingCandidateObservation{{
		CandidateRef: "shipc-detached-v1",
		SKI:          pairingCandidateTestSKI,
		Path:         "/ship/",
		Port:         4712,
		Addresses:    []net.IP{legacyAddress},
		ScopedAddresses: []netip.Addr{
			scopedAddress,
		},
	}}
	hub.ReportMdnsEntriesWithCandidates(nil, true, candidates, 44)
	candidates[0].Addresses[0][0] = 198
	candidates[0].ScopedAddresses[0] = netip.MustParseAddr("2001:db8::42")
	candidates[0].CandidateRef = "source-mutated"

	got := reader.discoverySnapshots()[0].Candidates[0]
	if got.CandidateRef != "shipc-detached-v1" || !got.Addresses[0].Equal(net.IP{192, 0, 2, 41}) ||
		got.ScopedAddresses[0] != scopedAddress {
		t.Fatalf("callback snapshot retained source aliases: %#v", got)
	}
	reader.onUpdate = func(snapshot api.PairingCandidateDiscoverySnapshotV1) {
		snapshot.Candidates[0].Addresses[0][0] = 203
		snapshot.Candidates[0].ScopedAddresses[0] = netip.MustParseAddr("2001:db8::41")
	}
	hub.ReportMdnsEntriesWithCandidates(nil, true, []api.PairingCandidateObservation{{
		CandidateRef: "shipc-callback-mutated-v1", SKI: pairingCandidateTestSKI,
		Addresses: []net.IP{{192, 0, 2, 42}}, ScopedAddresses: []netip.Addr{scopedAddress},
	}}, 45)
	hub.muxReg.Lock()
	internal := hub.visiblePairingCandidates["shipc-callback-mutated-v1"]
	hub.muxReg.Unlock()
	if !internal.addresses[0].Equal(net.IP{192, 0, 2, 42}) || internal.scopedAddresses[0] != scopedAddress {
		t.Fatalf("callback mutation changed Hub state: %#v", internal)
	}
}

func TestIssue41ConcurrentSnapshotsKeepContextAtomic(t *testing.T) {
	hub, reader := newIssue41Hub(t)
	const reports = 32
	var reporters sync.WaitGroup
	for revision := uint64(1); revision <= reports; revision++ {
		revision := revision
		reporters.Add(1)
		go func() {
			defer reporters.Done()
			hub.ReportMdnsEntriesWithCandidates(nil, revision%2 == 0, []api.PairingCandidateObservation{{
				CandidateRef: "shipc-concurrent-v1",
				SKI:          pairingCandidateTestSKI,
				Port:         int(revision),
			}}, revision)
		}()
	}
	reporters.Wait()

	snapshots := reader.discoverySnapshots()
	if len(snapshots) == 0 {
		t.Fatal("no concurrent discovery snapshots delivered")
	}
	var sawHighest bool
	for _, snapshot := range snapshots {
		if len(snapshot.Candidates) != 1 || snapshot.Candidates[0].Port != int(snapshot.ObservationRevision) ||
			snapshot.NewEntries != (snapshot.ObservationRevision%2 == 0) {
			t.Fatalf("torn discovery snapshot = %#v", snapshot)
		}
		if snapshot.ObservationRevision == reports {
			sawHighest = true
		}
	}
	if !sawHighest {
		t.Fatalf("highest revision was not delivered: %#v", snapshots)
	}
}
