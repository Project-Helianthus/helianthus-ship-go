package hub

import (
	"net"
	"sort"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

var _ api.MdnsReportInterface = (*Hub)(nil)
var _ api.PairingCandidateMdnsReportInterface = (*Hub)(nil)

// ReportMdnsEntries preserves the legacy callback while assigning an ordered
// local revision when a provider cannot supply one.
func (h *Hub) ReportMdnsEntries(entries map[string]*api.MdnsEntry, newEntries bool) {
	h.enqueueMdnsSnapshot(entries, newEntries, nil, 0)
}

// ReportMdnsEntriesWithCandidates is the experimental dependency callback that
// keeps candidate capabilities out of stable discovery values.
func (h *Hub) ReportMdnsEntriesWithCandidates(
	entries map[string]*api.MdnsEntry,
	newEntries bool,
	candidates []api.PairingCandidateObservation,
	revision uint64,
) {
	h.enqueueMdnsSnapshot(entries, newEntries, candidates, revision)
}

func (h *Hub) enqueueMdnsSnapshot(
	entries map[string]*api.MdnsEntry,
	newEntries bool,
	candidates []api.PairingCandidateObservation,
	revision uint64,
) {
	entries = cloneMdnsEntries(entries)
	candidates = clonePairingCandidateObservations(candidates)
	h.mdnsSnapshotMux.Lock()
	if revision == 0 {
		h.mdnsSnapshotRevision++
		if h.mdnsSnapshotRevision == 0 {
			h.mdnsSnapshotRevision++
		}
		revision = h.mdnsSnapshotRevision
	} else if revision > h.mdnsSnapshotRevision {
		h.mdnsSnapshotRevision = revision
	}
	admission := h.mdnsSnapshotAdmission.Add(1)
	h.mdnsSnapshotQueue = append(h.mdnsSnapshotQueue, func() {
		h.reportMdnsSnapshot(entries, newEntries, candidates, revision, admission)
	})
	if h.mdnsSnapshotDraining {
		h.mdnsSnapshotMux.Unlock()
		return
	}
	h.mdnsSnapshotDraining = true
	h.mdnsSnapshotMux.Unlock()
	h.drainMdnsSnapshots()
}

func cloneMdnsEntries(entries map[string]*api.MdnsEntry) map[string]*api.MdnsEntry {
	cloned := make(map[string]*api.MdnsEntry, len(entries))
	for key, entry := range entries {
		if entry == nil {
			cloned[key] = nil
			continue
		}
		value := *entry
		value.Addresses = cloneIPAddresses(entry.Addresses)
		cloned[key] = &value
	}
	return cloned
}

func clonePairingCandidateObservations(
	candidates []api.PairingCandidateObservation,
) []api.PairingCandidateObservation {
	cloned := make([]api.PairingCandidateObservation, len(candidates))
	for index, candidate := range candidates {
		cloned[index] = candidate
		cloned[index].Addresses = cloneIPAddresses(candidate.Addresses)
	}
	return cloned
}

func cloneIPAddresses(addresses []net.IP) []net.IP {
	cloned := make([]net.IP, len(addresses))
	for index, address := range addresses {
		cloned[index] = append(net.IP(nil), address...)
	}
	return cloned
}

func (h *Hub) drainMdnsSnapshots() {
	for {
		h.mdnsSnapshotMux.Lock()
		if len(h.mdnsSnapshotQueue) == 0 {
			h.mdnsSnapshotDraining = false
			h.mdnsSnapshotMux.Unlock()
			return
		}
		task := h.mdnsSnapshotQueue[0]
		h.mdnsSnapshotQueue[0] = nil
		h.mdnsSnapshotQueue = h.mdnsSnapshotQueue[1:]
		h.mdnsSnapshotMux.Unlock()
		task()
	}
}

// lockPairingCandidateAdmission linearizes candidate authority with every mDNS
// snapshot already accepted by enqueueMdnsSnapshot. The atomic load is the
// action's ordering point relative to a concurrent later admission.
func (h *Hub) lockPairingCandidateAdmission() bool {
	h.muxReg.Lock()
	if h.mdnsAppliedAdmission != h.mdnsSnapshotAdmission.Load() {
		h.muxReg.Unlock()
		return false
	}
	return true
}

func (h *Hub) unlockPairingCandidateAdmission() {
	h.muxReg.Unlock()
}

func (h *Hub) reportMdnsSnapshot(
	entries map[string]*api.MdnsEntry,
	_ bool,
	candidates []api.PairingCandidateObservation,
	revision uint64,
	admission uint64,
) {
	h.muxReg.Lock()
	if revision < h.latestPairingObservationRevision {
		h.mdnsAppliedAdmission = admission
		h.muxReg.Unlock()
		return
	}
	h.latestPairingObservationRevision = revision
	h.mdnsAppliedAdmission = admission
	retainedConsumed := make(map[string]struct{})
	for _, candidate := range candidates {
		if _, consumed := h.consumedPairingCandidates[candidate.CandidateRef]; consumed {
			retainedConsumed[candidate.CandidateRef] = struct{}{}
		}
	}
	h.consumedPairingCandidates = retainedConsumed
	h.visiblePairingCandidates = make(map[string]pairingCandidateObservation, len(candidates))
	for _, candidate := range candidates {
		if candidate.CandidateRef == "" || candidate.SKI == "" {
			continue
		}
		h.visiblePairingCandidates[candidate.CandidateRef] = pairingCandidateObservation{
			ski:       candidate.SKI,
			revision:  revision,
			path:      candidate.Path,
			port:      candidate.Port,
			addresses: append([]net.IP(nil), candidate.Addresses...),
		}
	}
	h.muxAttemptGate.Lock()
	retirements := make([]pairingCandidateRetirement, 0)
	for ski, active := range h.activePairingCandidates {
		if active == nil || active.connectIssued {
			continue
		}
		current, exists := h.visiblePairingCandidates[active.candidateRef]
		if exists && pairingCandidateObservationMatchesActive(current, active) {
			continue
		}
		if retired := h.retireActivePairingCandidateLocked(ski, active, active.authority); retired != nil {
			retirements = append(retirements, *retired)
		}
	}
	h.muxAttemptGate.Unlock()
	h.muxReg.Unlock()
	h.finishPairingCandidateRetirements(retirements)

	// Only durable trust can enter the normal reconnect path. A selected but
	// untrusted candidate uses its frozen, exact one-dial path below this layer.
	for _, entry := range entries {
		if entry == nil || entry.Ski == "" || h.isSkiConnected(entry.Ski) {
			continue
		}
		service := h.ServiceForSKI(entry.Ski)
		if !h.IsRemoteServiceForSKIPaired(entry.Ski) {
			continue
		}

		service.SetAutoAccept(entry.Register)
		h.coordinateConnectionInitations(entry.Ski, entry)
	}

	remoteServices := make([]api.RemoteService, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.Ski == "" {
			continue
		}
		remoteServices = append(remoteServices, api.RemoteService{
			Name:       entry.Name,
			Ski:        entry.Ski,
			Identifier: entry.Identifier,
			Brand:      entry.Brand,
			Type:       entry.Type,
			Model:      entry.Model,
		})
	}
	sort.Slice(remoteServices, func(left, right int) bool {
		if remoteServices[left].Ski != remoteServices[right].Ski {
			return remoteServices[left].Ski < remoteServices[right].Ski
		}
		if remoteServices[left].Name != remoteServices[right].Name {
			return remoteServices[left].Name < remoteServices[right].Name
		}
		return remoteServices[left].Identifier < remoteServices[right].Identifier
	})
	if h.hubReader != nil {
		h.hubReader.VisibleRemoteServicesUpdated(remoteServices)
	}

	candidateRefs := make([]api.PairingCandidateRef, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.CandidateRef == "" || candidate.SKI == "" {
			continue
		}
		candidateRefs = append(candidateRefs, api.PairingCandidateRef{
			CandidateRef: candidate.CandidateRef,
			Name:         candidate.Name,
			SKI:          candidate.SKI,
			Identifier:   candidate.Identifier,
			Brand:        candidate.Brand,
			Type:         candidate.Type,
			Model:        candidate.Model,
		})
	}
	sort.Slice(candidateRefs, func(left, right int) bool {
		if candidateRefs[left].SKI != candidateRefs[right].SKI {
			return candidateRefs[left].SKI < candidateRefs[right].SKI
		}
		return candidateRefs[left].CandidateRef < candidateRefs[right].CandidateRef
	})
	if reader, ok := h.hubReader.(api.PairingCandidateHubReaderInterface); ok {
		reader.VisiblePairingCandidatesUpdated(candidateRefs)
	}
}
