package api

import "net"

/* Mdns */

type MdnsEntry struct {
	CandidateRef        string
	ObservationRevision uint64
	Name                string
	Ski                 string
	Identifier          string   // mandatory
	Path                string   // mandatory
	Register            bool     // mandatory
	Brand               string   // optional
	Type                string   // optional
	Model               string   // optional
	Host                string   // mandatory
	Port                int      // mandatory
	Addresses           []net.IP // mandatory
}

// implemented by Hub, used by mdns
type MdnsReportInterface interface {
	ReportMdnsEntries(entries map[string]*MdnsEntry, newEntries bool)
}

// MdnsRevisionReportInterface is the optional revision-aware reporting
// capability. It lets an empty discovery snapshot invalidate previously
// observed candidate capabilities without changing the legacy callback.
type MdnsRevisionReportInterface interface {
	ReportMdnsEntriesRevision(entries map[string]*MdnsEntry, newEntries bool, observationRevision uint64)
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

// implemented by mdns providers, used by mdns
type MdnsProviderInterface interface {
	Start(autoReconnect bool, cb MdnsResolveCB) bool
	Shutdown()
	Announce(serviceName string, port int, txt []string) error
	Unannounce()
}
