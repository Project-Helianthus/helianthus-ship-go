package hub

import (
	"net"
	"net/netip"
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
		value.ScopedAddresses = cloneScopedIPAddresses(entry.ScopedAddresses)
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
		cloned[index].ScopedAddresses = cloneScopedIPAddresses(candidate.ScopedAddresses)
	}
	return cloned
}

func cloneScopedIPAddresses(addresses []netip.Addr) []netip.Addr {
	if addresses == nil {
		return nil
	}
	return append([]netip.Addr(nil), addresses...)
}

func cloneIPAddresses(addresses []net.IP) []net.IP {
	if addresses == nil {
		return nil
	}
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
	newEntries bool,
	candidates []api.PairingCandidateObservation,
	revision uint64,
	admission uint64,
) {
	h.muxReg.Lock()
	if revision < h.latestPairingObservationRevision {
		h.mdnsAppliedAdmission = admission
		h.muxAttemptGate.Lock()
		cancellations, retriedSKIs := h.invalidateTrustedRemoteRetriesLocked(nil)
		h.muxAttemptGate.Unlock()
		h.removeOutboundAttemptConnections(cancellations)
		h.muxReg.Unlock()
		cancelOutboundAttemptRegistrations(cancellations)
		h.clearTrustedRemoteRetryRunning(retriedSKIs)
		return
	}
	h.latestPairingObservationRevision = revision
	h.mdnsAppliedAdmission = admission
	trustedObservations := trustedRemoteObservations(entries, revision, admission)
	h.visibleTrustedRemoteObservations = trustedObservations
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
			scopedAddresses: append(
				[]netip.Addr(nil),
				candidate.ScopedAddresses...,
			),
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
	cancellations, retriedSKIs := h.invalidateTrustedRemoteRetriesLocked(trustedObservations)
	h.muxAttemptGate.Unlock()
	h.removeOutboundAttemptConnections(cancellations)
	h.muxReg.Unlock()
	h.finishPairingCandidateRetirements(retirements)
	cancelOutboundAttemptRegistrations(cancellations)
	h.clearTrustedRemoteRetryRunning(retriedSKIs)

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
	if reader, ok := h.hubReader.(api.PairingCandidateDiscoverySnapshotHubReaderInterface); ok {
		observations := make([]api.PairingCandidateDiscoveryObservationV1, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.CandidateRef == "" || candidate.SKI == "" {
				continue
			}
			observations = append(observations, api.PairingCandidateDiscoveryObservationV1{
				CandidateRef: candidate.CandidateRef, Name: candidate.Name, SKI: candidate.SKI,
				Identifier: candidate.Identifier, Brand: candidate.Brand, Type: candidate.Type,
				Model: candidate.Model, Path: candidate.Path, Host: candidate.Host,
				Port: candidate.Port, Register: candidate.Register,
				Addresses:                 cloneIPAddresses(candidate.Addresses),
				ScopedAddresses:           cloneScopedIPAddresses(candidate.ScopedAddresses),
				UnscopedLinkLocalObserved: candidate.UnscopedLinkLocalObserved,
			})
		}
		sort.Slice(observations, func(left, right int) bool {
			if observations[left].SKI != observations[right].SKI {
				return observations[left].SKI < observations[right].SKI
			}
			return observations[left].CandidateRef < observations[right].CandidateRef
		})
		reader.VisiblePairingCandidateDiscoverySnapshotUpdated(api.PairingCandidateDiscoverySnapshotV1{
			ObservationRevision: revision,
			NewEntries:          newEntries,
			Candidates:          observations,
		})
	}
}

func trustedRemoteObservations(
	entries map[string]*api.MdnsEntry,
	revision uint64,
	admission uint64,
) map[string]trustedRemoteObservation {
	observations := make(map[string]trustedRemoteObservation)
	ambiguous := make(map[string]struct{})
	for _, entry := range entries {
		if entry == nil || entry.Port <= 0 || entry.Port > 65535 {
			continue
		}
		ski, err := validPairingCandidateSKI(entry.Ski)
		if err != nil {
			continue
		}
		if _, duplicate := observations[ski]; duplicate {
			delete(observations, ski)
			ambiguous[ski] = struct{}{}
			continue
		}
		if _, duplicate := ambiguous[ski]; duplicate {
			continue
		}
		host, ok := trustedRemoteRetryHost(entry)
		if !ok {
			continue
		}
		observations[ski] = trustedRemoteObservation{
			revision:  revision,
			admission: admission,
			host:      host,
			port:      entry.Port,
			path:      entry.Path,
		}
	}
	return observations
}

// invalidateTrustedRemoteRetriesLocked requires muxReg and muxAttemptGate.
// Each retry is bound to one exact applied mDNS observation. A later admitted
// observation rotates its outbound authority and cancels any registered dial.
func (h *Hub) invalidateTrustedRemoteRetriesLocked(
	current map[string]trustedRemoteObservation,
) ([]*outboundAttemptRegistration, []string) {
	var cancellations []*outboundAttemptRegistration
	var retriedSKIs []string
	for ski, active := range h.activeTrustedRemoteRetries {
		observation, exists := current[ski]
		if exists && active != nil &&
			observation.revision == active.observation.revision &&
			observation.admission == active.observation.admission {
			continue
		}
		h.rotateOutboundAuthorityLocked(ski)
		cancellations = append(cancellations, h.removeOutboundAttemptRegistrationsLocked(ski)...)
		delete(h.activeTrustedRemoteRetries, ski)
		retriedSKIs = append(retriedSKIs, ski)
	}
	return cancellations, retriedSKIs
}

func (h *Hub) clearTrustedRemoteRetryRunning(skis []string) {
	for _, ski := range skis {
		h.setConnectionAttemptRunning(ski, false)
	}
}
