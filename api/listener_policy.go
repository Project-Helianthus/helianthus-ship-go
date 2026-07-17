package api

import "net/netip"

// ListenerPolicy defines the exact endpoint and discovery behavior for a SHIP listener.
type ListenerPolicy struct {
	ListenAddress    netip.AddrPort
	DiscoveryEnabled bool
}
