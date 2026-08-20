package api

import (
	"net"
	"net/netip"
)

/* Mdns */

type MdnsEntry struct {
	Name       string
	Ski        string
	Identifier string   // mandatory
	Path       string   // mandatory
	Register   bool     // mandatory
	Brand      string   // optional
	Type       string   // optional
	Model      string   // optional
	Host       string   // mandatory
	Port       int      // mandatory
	Addresses  []net.IP // mandatory
	// ScopedAddresses preserves an IPv6 link-local interface zone from the
	// discovery provider. IPv4 and global IPv6 addresses are also mirrored here
	// so new consumers can use one canonical address surface. Unscoped
	// link-local addresses are never admitted.
	ScopedAddresses []netip.Addr
	// UnscopedLinkLocalObserved records that discovery supplied a link-local
	// IPv6 address without an interface zone. Consumers use it to suppress DNS
	// hostname fallback without retaining or dialing the unusable address.
	UnscopedLinkLocalObserved bool
}

// implemented by Hub, used by mdns
type MdnsReportInterface interface {
	ReportMdnsEntries(entries map[string]*MdnsEntry, newEntries bool)
}

// implemented by mdns, used by Hub
type MdnsInterface interface {
	Start(cb MdnsReportInterface) error
	Shutdown()
	AnnounceMdnsEntry() error
	UnannounceMdnsEntry()
	SetAutoAccept(bool)
	RequestMdnsEntries()
}

// ListenerPolicyMdnsInterface is the optional mDNS capability required by
// discovery-enabled listener policies. Configuration must not perform network,
// filesystem, or goroutine work.
type ListenerPolicyMdnsInterface interface {
	MdnsInterface
	ConfigureListenerPolicy(ListenerPolicy) error
}

// implemented by mdns, used by Providers
type MdnsResolveCB func(elements map[string]string, name, host string, addresses []net.IP, port int, remove bool)

// MdnsScopedResolveCB preserves interface zones carried by mDNS observations.
type MdnsScopedResolveCB func(elements map[string]string, name, host string, addresses []netip.Addr, port int, remove bool)

// implemented by mdns providers, used by mdns
type MdnsProviderInterface interface {
	Start(autoReconnect bool, cb MdnsResolveCB) bool
	Shutdown()
	Announce(serviceName string, port int, txt []string) error
	Unannounce()
}

// ScopedMdnsProviderInterface is an additive provider capability. MdnsManager
// prefers it when available and falls back to the legacy unscoped callback for
// third-party providers.
type ScopedMdnsProviderInterface interface {
	MdnsProviderInterface
	StartScoped(autoReconnect bool, cb MdnsScopedResolveCB) bool
}
