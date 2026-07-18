package mdns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
	"github.com/enbility/go-avahi"
)

const shipWebsocketPath = "/ship/"

type MdnsProviderSelection uint

const (
	MdnsProviderSelectionAll            MdnsProviderSelection = iota // Automatically use avahi if available, otherwise use Go native Zeroconf, default
	MdnsProviderSelectionAvahiOnly                                   // Only use avahi
	MdnsProviderSelectionGoZeroConfOnly                              // Only us Go native zeroconf
)

type MdnsManager struct {
	ski string

	// The deviceBrand of the device
	deviceBrand string

	// The device model
	deviceModel string

	// device type
	deviceType string

	// the identifier to be used for mDNS and SHIP ID
	identifier string

	// the name to be used as the mDNS service name
	serviceName string

	// Network interface to use for the service
	// Optional, if not set all detected interfaces will be used
	ifaces []string

	// The port address of the websocket server
	port int

	// Wether remote devices should be automatically accepted
	autoaccept bool

	isAnnounced bool

	// the currently available mDNS entries with the SKI as the key in the map
	entries map[string]*api.MdnsEntry

	// the registered callback, only connectionsHub is using this
	report api.MdnsReportInterface

	mdnsProvider api.MdnsProviderInterface

	shutdownOnce sync.Once
	lifecycleMu  sync.Mutex
	startClaimed bool
	terminal     bool

	listenerPolicy *api.ListenerPolicy
	signalC        chan os.Signal
	signalStop     chan struct{}
	signalDone     chan struct{}

	newAvahiProvider          func([]int32) api.MdnsProviderInterface
	newZeroconfProvider       func([]net.Interface) api.MdnsProviderInterface
	newScopedZeroconfProvider func([]net.Interface, string, netip.Addr) api.MdnsProviderInterface
	hostname                  func() (string, error)

	providerSelection MdnsProviderSelection

	mux,
	muxAnnounced sync.Mutex
}

func NewMDNS(
	ski, deviceBrand, deviceModel, deviceType, shipIdentifier, serviceName string,
	port int,
	ifaces []string,
	providerSelection MdnsProviderSelection) *MdnsManager {
	m := &MdnsManager{
		ski:               ski,
		deviceBrand:       deviceBrand,
		deviceModel:       deviceModel,
		deviceType:        deviceType,
		identifier:        shipIdentifier,
		serviceName:       serviceName,
		port:              port,
		ifaces:            ifaces,
		providerSelection: providerSelection,
		entries:           make(map[string]*api.MdnsEntry),
		newAvahiProvider: func(indexes []int32) api.MdnsProviderInterface {
			return NewAvahiProvider(indexes)
		},
		newZeroconfProvider: func(ifaces []net.Interface) api.MdnsProviderInterface {
			return NewZeroconfProvider(ifaces)
		},
		newScopedZeroconfProvider: func(ifaces []net.Interface, host string, address netip.Addr) api.MdnsProviderInterface {
			return newScopedZeroconfProvider(ifaces, host, address)
		},
		hostname: os.Hostname,
	}

	return m
}

// Return allowed interfaces for mDNS
func (m *MdnsManager) interfaces() ([]net.Interface, []int32, error) {
	var ifaces []net.Interface
	var ifaceIndexes []int32

	if len(m.ifaces) > 0 {
		ifaces = make([]net.Interface, len(m.ifaces))
		ifaceIndexes = make([]int32, len(m.ifaces))
		for i, ifaceName := range m.ifaces {
			iface, err := net.InterfaceByName(ifaceName)
			if err != nil {
				return nil, nil, err
			}
			ifaces[i] = *iface
			// conversion is safe, as the index is always positive and not higher than int32
			ifaceIndexes[i] = int32(iface.Index) // #nosec G115
		}
	}

	if len(ifaces) == 0 {
		ifaces = nil
		ifaceIndexes = []int32{avahi.InterfaceUnspec}
	}

	return ifaces, ifaceIndexes, nil
}

var _ api.MdnsInterface = (*MdnsManager)(nil)
var _ api.ListenerPolicyMdnsInterface = (*MdnsManager)(nil)

func (m *MdnsManager) Start(cb api.MdnsReportInterface) error {
	policy, scoped, err := m.claimStart(cb)
	if err != nil {
		return err
	}

	provider, err := m.startProvider(policy, scoped)
	if err != nil {
		return err
	}
	if err := m.installProvider(provider); err != nil {
		provider.Shutdown()
		return err
	}

	// on startup always start mDNS announcement
	if err := m.AnnounceMdnsEntry(); err != nil {
		return err
	}

	if err := m.installSignalHandler(); err != nil {
		return err
	}

	return nil
}

func (m *MdnsManager) claimStart(cb api.MdnsReportInterface) (api.ListenerPolicy, bool, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.terminal || m.startClaimed {
		return api.ListenerPolicy{}, false, errors.New("mDNS manager is one-shot and already used")
	}
	m.startClaimed = true
	m.report = cb
	if m.listenerPolicy == nil {
		return api.ListenerPolicy{}, false, nil
	}
	policy := *m.listenerPolicy
	return policy, true, nil
}

func (m *MdnsManager) startProvider(policy api.ListenerPolicy, scoped bool) (api.MdnsProviderInterface, error) {
	if scoped {
		if m.providerSelection == MdnsProviderSelectionAvahiOnly {
			return nil, errors.New("scoped listener discovery is unsupported by AvahiOnly")
		}
		iface, err := m.listenerPolicyInterface(policy.ListenAddress.Addr())
		if err != nil {
			return nil, err
		}
		host, err := m.hostname()
		if err != nil {
			return nil, fmt.Errorf("resolve mDNS hostname: %w", err)
		}
		provider := m.newScopedZeroconfProvider(
			[]net.Interface{iface},
			host,
			policy.ListenAddress.Addr().WithZone(""),
		)
		if !provider.Start(true, m.processMdnsEntry) {
			provider.Shutdown()
			return nil, errors.New("scoped Zeroconf provider unavailable")
		}
		return provider, nil
	}

	ifaces, ifaceIndexes, err := m.interfaces()
	if err != nil {
		return nil, err
	}

	switch m.providerSelection {
	case MdnsProviderSelectionAll:
		provider := m.newAvahiProvider(ifaceIndexes)
		if provider.Start(false, m.processMdnsEntry) {
			return provider, nil
		}
		provider.Shutdown()

		provider = m.newZeroconfProvider(ifaces)
		if !provider.Start(false, m.processMdnsEntry) {
			provider.Shutdown()
			return nil, errors.New("no mDNS provider available")
		}
		return provider, nil
	case MdnsProviderSelectionAvahiOnly:
		provider := m.newAvahiProvider(ifaceIndexes)
		if !provider.Start(true, m.processMdnsEntry) {
			provider.Shutdown()
			return nil, errors.New("avahi mDNS provider is unavailable")
		}
		return provider, nil
	case MdnsProviderSelectionGoZeroConfOnly:
		provider := m.newZeroconfProvider(ifaces)
		if !provider.Start(true, m.processMdnsEntry) {
			provider.Shutdown()
			return nil, errors.New("zeroconf mDNS provider is unavailable")
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unknown mDNS provider selection %d", m.providerSelection)
	}
}

func (m *MdnsManager) installProvider(provider api.MdnsProviderInterface) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.terminal {
		return errors.New("mDNS manager is shut down")
	}
	m.mdnsProvider = provider
	return nil
}

// Shutdown all of mDNS
func (m *MdnsManager) Shutdown() {
	m.shutdownOnce.Do(func() {
		m.lifecycleMu.Lock()
		m.terminal = true
		provider := m.mdnsProvider
		m.mdnsProvider = nil
		signalC := m.signalC
		signalStop := m.signalStop
		signalDone := m.signalDone
		m.signalC = nil
		m.signalStop = nil
		m.signalDone = nil
		m.lifecycleMu.Unlock()

		if signalC != nil {
			signal.Stop(signalC)
		}
		if signalStop != nil {
			close(signalStop)
		}
		if signalDone != nil {
			<-signalDone
		}

		if provider == nil {
			return
		}
		if m.isServiceAnnounced() {
			provider.Unannounce()
			m.setIsServiceAnnounce(false)
		}
		provider.Shutdown()
	})
}

func (m *MdnsManager) installSignalHandler() error {
	signalC := make(chan os.Signal, 1)
	signalStop := make(chan struct{})
	signalDone := make(chan struct{})
	signal.Notify(signalC, os.Interrupt, syscall.SIGTERM)

	m.lifecycleMu.Lock()
	if m.terminal {
		m.lifecycleMu.Unlock()
		signal.Stop(signalC)
		return errors.New("mDNS manager is shut down")
	}
	m.signalC = signalC
	m.signalStop = signalStop
	m.signalDone = signalDone
	m.lifecycleMu.Unlock()

	go m.runSignalHandler(signalC, signalStop, signalDone)
	return nil
}

func (m *MdnsManager) runSignalHandler(signalC <-chan os.Signal, stop <-chan struct{}, done chan<- struct{}) {
	select {
	case <-signalC:
		close(done)
		m.Shutdown()
	case <-stop:
		close(done)
	}
}

// Announces the service to the network via mDNS
// A CEM service should always invoke this on startup
// Any other service should only invoke this whenever it is not connected to a CEM service
func (m *MdnsManager) AnnounceMdnsEntry() error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()

	if m.mdnsProvider == nil {
		return nil
	}

	serviceIdentifier := m.identifier

	txt := []string{ // SHIP 7.3.2
		"txtvers=1",
		"path=" + shipWebsocketPath,
		"id=" + serviceIdentifier,
		"ski=" + m.ski,
		"brand=" + m.deviceBrand,
		"model=" + m.deviceModel,
		"type=" + m.deviceType,
		"register=" + fmt.Sprintf("%v", m.autoaccept),
	}

	logging.Log().Debug("mdns: announce")

	serviceName := m.serviceName

	if err := m.mdnsProvider.Announce(serviceName, m.port, txt); err != nil {
		logging.Log().Debug("mdns: failure announcing service", err)
		return err
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	m.setIsServiceAnnounce(true)

	return nil
}

// Stop the mDNS announcement on the network
func (m *MdnsManager) UnannounceMdnsEntry() {
	if !m.isServiceAnnounced() {
		return
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.mdnsProvider == nil {
		return
	}

	m.mdnsProvider.Unannounce()
	logging.Log().Debug("mdns: stop announcement")

	m.setIsServiceAnnounce(false)
}

func (m *MdnsManager) isServiceAnnounced() bool {
	m.muxAnnounced.Lock()
	defer m.muxAnnounced.Unlock()

	return m.isAnnounced
}

func (m *MdnsManager) setIsServiceAnnounce(value bool) {
	m.muxAnnounced.Lock()
	defer m.muxAnnounced.Unlock()

	m.isAnnounced = value
}

func (m *MdnsManager) SetAutoAccept(accept bool) {
	m.autoaccept = accept

	// if announcement is off, don't enforce a new announcement
	if !m.isServiceAnnounced() {
		return
	}

	// Update the announcement as autoaccept changed
	if err := m.AnnounceMdnsEntry(); err != nil {
		logging.Log().Debug("mdns: changing mdns entry failed", err)
	}
}

func (m *MdnsManager) mdnsEntries() map[string]*api.MdnsEntry {
	m.mux.Lock()
	defer m.mux.Unlock()

	return m.entries
}

func (m *MdnsManager) copyMdnsEntries() map[string]*api.MdnsEntry {
	m.mux.Lock()
	defer m.mux.Unlock()

	mdnsEntries := make(map[string]*api.MdnsEntry)
	for k, v := range m.entries {
		newEntry := &api.MdnsEntry{}
		util.DeepCopy[*api.MdnsEntry](v, newEntry)
		mdnsEntries[k] = newEntry
	}

	return mdnsEntries
}

func (m *MdnsManager) mdnsEntry(ski string) (*api.MdnsEntry, bool) {
	m.mux.Lock()
	defer m.mux.Unlock()

	entry, ok := m.entries[ski]
	return entry, ok
}

func (m *MdnsManager) setMdnsEntry(ski string, entry *api.MdnsEntry) {
	m.mux.Lock()
	defer m.mux.Unlock()

	m.entries[ski] = entry
}

func (m *MdnsManager) removeMdnsEntry(ski string) {
	m.mux.Lock()
	defer m.mux.Unlock()

	delete(m.entries, ski)
}

// process an mDNS entry and manage mDNS entries map
func (m *MdnsManager) processMdnsEntry(elements map[string]string, name, host string, addresses []net.IP, port int, remove bool) {
	// check for mandatory text elements
	mapItems := []string{"txtvers", "id", "path", "ski", "register"}
	for _, item := range mapItems {
		if _, ok := elements[item]; !ok {
			logging.Log().Debug("mdns: txt - missing mandatory element", item)
			return
		}
	}

	txtvers := elements["txtvers"]
	// value of mandatory txtvers has to be 1 or the response be ignored: SHIP 7.3.2
	if txtvers != "1" {
		logging.Log().Debug("mdns: txt - unknown txtvers", txtvers)
		return
	}

	identifier := elements["id"]
	path := elements["path"]
	ski := elements["ski"]

	// ignore own service
	if ski == m.ski {
		return
	}

	register := elements["register"]
	// register has to be a boolean
	if register != "true" && register != "false" {
		logging.Log().Debug("mdns: txt - register value is not a text boolean", register)
		return
	}

	// remove IPv6 local link addresses
	var newAddresses []net.IP
	for _, address := range addresses {
		if address.To4() == nil && address.IsLinkLocalUnicast() {
			continue
		}
		newAddresses = append(newAddresses, address)
	}
	addresses = newAddresses

	var deviceType, model, brand string

	if _, ok := elements["brand"]; ok {
		brand = elements["brand"]
	}
	if _, ok := elements["type"]; ok {
		deviceType = elements["type"]
	}
	if _, ok := elements["model"]; ok {
		model = elements["model"]
	}

	updated := false

	entry, exists := m.mdnsEntry(ski)

	if remove && exists {
		updated = true
		// remove
		// there will be a remove for each address with avahi, but we'll delete it right away
		m.removeMdnsEntry(ski)

		logging.Log().Debug("mdns: remove - ski:", ski, "name:", name, "brand:", brand, "model:", model, "typ:", deviceType, "identifier:", identifier, "register:", register, "host:", host, "port:", port, "addresses:", addresses)
	} else if exists {
		// avahi sends an item for each network address, merge them

		// we assume only network addresses are added
		for _, address := range addresses {
			// only add if it is not added yet
			isNewElement := true

			for _, item := range entry.Addresses {
				if item.String() == address.String() {
					isNewElement = false
					break
				}
			}

			if isNewElement {
				entry.Addresses = append(entry.Addresses, address)
				updated = true
			}
		}

		if updated {
			m.setMdnsEntry(ski, entry)

			logging.Log().Debug("mdns: update - ski:", ski, "name:", name, "brand:", brand, "model:", model, "typ:", deviceType, "identifier:", identifier, "register:", register, "host:", host, "port:", port, "addresses:", addresses)
		}
	} else if !exists && !remove {
		updated = true
		// new
		newEntry := &api.MdnsEntry{
			Name:       name,
			Ski:        ski,
			Identifier: identifier,
			Path:       path,
			Register:   register == "true",
			Brand:      brand,
			Type:       deviceType,
			Model:      model,
			Host:       host,
			Port:       port,
			Addresses:  addresses,
		}
		m.setMdnsEntry(ski, newEntry)

		logging.Log().Debug("mdns: new - ski:", ski, "name:", name, "brand:", brand, "model:", model, "typ:", deviceType, "identifier:", identifier, "register:", register, "host:", host, "port:", port, "addresses:", addresses)
	}

	if m.report == nil || !updated {
		return
	}

	entries := m.copyMdnsEntries()
	go m.report.ReportMdnsEntries(entries, true)
}

func (m *MdnsManager) RequestMdnsEntries() {
	if m.report == nil {
		return
	}

	entries := m.copyMdnsEntries()
	go m.report.ReportMdnsEntries(entries, false)
}
