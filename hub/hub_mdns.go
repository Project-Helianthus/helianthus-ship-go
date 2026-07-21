package hub

import (
	"net"
	"sort"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

var _ api.MdnsReportInterface = (*Hub)(nil)
var _ api.MdnsRevisionReportInterface = (*Hub)(nil)

// ReportMdnsEntries preserves the legacy callback while assigning an ordered
// local revision when a provider cannot supply one.
func (h *Hub) ReportMdnsEntries(entries map[string]*api.MdnsEntry, newEntries bool) {
	var revision uint64
	for _, entry := range entries {
		if entry != nil && entry.ObservationRevision > revision {
			revision = entry.ObservationRevision
		}
	}
	if revision == 0 {
		h.muxReg.Lock()
		revision = h.latestPairingObservationRevision + 1
		if revision == 0 {
			revision++
		}
		h.muxReg.Unlock()
	}
	h.ReportMdnsEntriesRevision(entries, newEntries, revision)
}

// ReportMdnsEntriesRevision atomically replaces the current process-local
// candidate capability set. Older asynchronous mDNS reports cannot resurrect
// an endpoint after a newer discovery generation was observed.
func (h *Hub) ReportMdnsEntriesRevision(entries map[string]*api.MdnsEntry, _ bool, revision uint64) {
	h.muxReg.Lock()
	if revision < h.latestPairingObservationRevision {
		h.muxReg.Unlock()
		return
	}
	h.latestPairingObservationRevision = revision
	h.visiblePairingCandidates = make(map[string]pairingCandidateObservation, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.CandidateRef == "" || entry.Ski == "" {
			continue
		}
		h.visiblePairingCandidates[entry.CandidateRef] = pairingCandidateObservation{
			ski:       entry.Ski,
			revision:  revision,
			path:      entry.Path,
			port:      entry.Port,
			addresses: append([]net.IP(nil), entry.Addresses...),
		}
	}
	h.muxReg.Unlock()

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
		if service.IPv4() != "" {
			if ip := net.ParseIP(service.IPv4()); ip != nil {
				entry.Addresses = []net.IP{ip}
			}
		}
		h.coordinateConnectionInitations(entry.Ski, entry)
	}

	remoteServices := make([]api.RemoteService, 0, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.Ski == "" {
			continue
		}
		remoteServices = append(remoteServices, api.RemoteService{
			CandidateRef: entry.CandidateRef,
			Name:         entry.Name,
			Ski:          entry.Ski,
			Identifier:   entry.Identifier,
			Brand:        entry.Brand,
			Type:         entry.Type,
			Model:        entry.Model,
		})
	}
	sort.Slice(remoteServices, func(left, right int) bool {
		if remoteServices[left].Ski != remoteServices[right].Ski {
			return remoteServices[left].Ski < remoteServices[right].Ski
		}
		return remoteServices[left].CandidateRef < remoteServices[right].CandidateRef
	})
	if h.hubReader != nil {
		h.hubReader.VisibleRemoteServicesUpdated(remoteServices)
	}
}
