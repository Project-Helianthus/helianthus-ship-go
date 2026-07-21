package hub

import (
	"net"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

var _ api.MdnsReportInterface = (*Hub)(nil)

// Process reported mDNS services
func (h *Hub) ReportMdnsEntries(entries map[string]*api.MdnsEntry, _ bool) {
	for ski, entry := range entries {
		// check if this ski is already connected
		if h.isSkiConnected(ski) {
			continue
		}

		// Check if the remote service is paired or queued for connection
		service := h.ServiceForSKI(ski)
		if !h.IsRemoteServiceForSKIPaired(ski) &&
			service.ConnectionStateDetail().State() != api.ConnectionStateQueued {
			continue
		}

		service.SetAutoAccept(entry.Register)

		// patch the addresses list if an IPv4 address was provided
		if service.IPv4() != "" {
			if ip := net.ParseIP(service.IPv4()); ip != nil {
				entry.Addresses = []net.IP{ip}
			}
		}

		h.coordinateConnectionInitations(ski, entry)
	}

	var remoteServices []api.RemoteService

	for _, entry := range entries {
		remoteService := api.RemoteService{
			Name:       entry.Name,
			Ski:        entry.Ski,
			Identifier: entry.Identifier,
			Brand:      entry.Brand,
			Type:       entry.Type,
			Model:      entry.Model,
		}

		remoteServices = append(remoteServices, remoteService)
	}

	h.hubReader.VisibleRemoteServicesUpdated(remoteServices)
}
