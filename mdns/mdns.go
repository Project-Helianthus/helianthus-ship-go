package mdns

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
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

	// Whether a bounded, user-mediated pairing flow is currently available.
	pairingRegistration bool

	isAnnounced bool

	// The currently available DNS-SD observations, keyed by exact service
	// identity rather than SKI so colliding advertisements remain visible.
	entries map[string]*api.MdnsEntry
	// Candidate capabilities are kept out of the stable MdnsEntry shape.
	candidateRefs map[string]string
	// Candidate references are process-local capabilities. The secret and
	// generation counters are deliberately never persisted.
	candidateSecret     [32]byte
	candidateGeneration uint64
	observationRevision uint64

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
	muxAnnounced,
	muxRegistration sync.Mutex
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
		candidateRefs:     make(map[string]string),
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
	if _, err := rand.Read(m.candidateSecret[:]); err != nil {
		panic("mDNS candidate capability entropy unavailable: " + err.Error())
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
var _ api.PairingRegistrationSetter = (*MdnsManager)(nil)

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
		if !m.startProviderInstance(provider, true) {
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
		if m.startProviderInstance(provider, false) {
			return provider, nil
		}
		provider.Shutdown()

		provider = m.newZeroconfProvider(ifaces)
		if !m.startProviderInstance(provider, false) {
			provider.Shutdown()
			return nil, errors.New("no mDNS provider available")
		}
		return provider, nil
	case MdnsProviderSelectionAvahiOnly:
		provider := m.newAvahiProvider(ifaceIndexes)
		if !m.startProviderInstance(provider, true) {
			provider.Shutdown()
			return nil, errors.New("avahi mDNS provider is unavailable")
		}
		return provider, nil
	case MdnsProviderSelectionGoZeroConfOnly:
		provider := m.newZeroconfProvider(ifaces)
		if !m.startProviderInstance(provider, true) {
			provider.Shutdown()
			return nil, errors.New("zeroconf mDNS provider is unavailable")
		}
		return provider, nil
	default:
		return nil, fmt.Errorf("unknown mDNS provider selection %d", m.providerSelection)
	}
}

func (m *MdnsManager) startProviderInstance(provider api.MdnsProviderInterface, autoReconnect bool) bool {
	if scoped, ok := provider.(api.ScopedMdnsProviderInterface); ok {
		return scoped.StartScoped(autoReconnect, m.processScopedMdnsEntry)
	}
	return provider.Start(autoReconnect, m.processMdnsEntry)
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
		"register=" + fmt.Sprintf("%v", m.registrationAvailable()),
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
	m.muxRegistration.Lock()
	m.autoaccept = accept
	m.muxRegistration.Unlock()

	// if announcement is off, don't enforce a new announcement
	if !m.isServiceAnnounced() {
		return
	}

	// Update the announcement as autoaccept changed
	if err := m.AnnounceMdnsEntry(); err != nil {
		logging.Log().Debug("mdns: changing mdns entry failed", err)
	}
}

// SetPairingRegistration updates only user-mediated pairing availability and
// reports whether the effective TXT record was republished successfully.
func (m *MdnsManager) SetPairingRegistration(available bool) error {
	m.muxRegistration.Lock()
	m.pairingRegistration = available
	m.muxRegistration.Unlock()

	if !m.isServiceAnnounced() {
		return nil
	}

	return m.AnnounceMdnsEntry()
}

func (m *MdnsManager) registrationAvailable() bool {
	m.muxRegistration.Lock()
	defer m.muxRegistration.Unlock()
	return m.autoaccept || m.pairingRegistration
}

func (m *MdnsManager) copyMdnsSnapshot() (
	map[string]*api.MdnsEntry,
	[]api.PairingCandidateObservation,
	uint64,
) {
	m.mux.Lock()
	defer m.mux.Unlock()
	return m.copyMdnsEntriesLocked(), m.copyPairingCandidatesLocked(), m.observationRevision
}

func (m *MdnsManager) copyMdnsEntriesLocked() map[string]*api.MdnsEntry {
	mdnsEntries := make(map[string]*api.MdnsEntry)
	observationKeys := make([]string, 0, len(m.entries))
	for observationKey := range m.entries {
		observationKeys = append(observationKeys, observationKey)
	}
	sort.Strings(observationKeys)
	for _, observationKey := range observationKeys {
		v := m.entries[observationKey]
		if v == nil || v.Ski == "" {
			continue
		}
		if _, exists := mdnsEntries[v.Ski]; exists {
			continue
		}
		newEntry := *v
		newEntry.Addresses = cloneIPs(v.Addresses)
		newEntry.ScopedAddresses = append([]netip.Addr(nil), v.ScopedAddresses...)
		mdnsEntries[v.Ski] = &newEntry
	}

	return mdnsEntries
}

func (m *MdnsManager) copyPairingCandidatesLocked() []api.PairingCandidateObservation {
	candidates := make([]api.PairingCandidateObservation, 0, len(m.candidateRefs))
	for observationKey, candidateRef := range m.candidateRefs {
		entry := m.entries[observationKey]
		if candidateRef == "" || entry == nil {
			continue
		}
		candidates = append(candidates, api.PairingCandidateObservation{
			CandidateRef: candidateRef,
			Name:         entry.Name,
			SKI:          entry.Ski,
			Identifier:   entry.Identifier,
			Brand:        entry.Brand,
			Type:         entry.Type,
			Model:        entry.Model,
			Path:         entry.Path,
			Port:         entry.Port,
			Addresses:    append([]net.IP(nil), entry.Addresses...),
			ScopedAddresses: append(
				[]netip.Addr(nil),
				entry.ScopedAddresses...,
			),
		})
	}
	sort.Slice(candidates, func(left, right int) bool {
		return candidates[left].CandidateRef < candidates[right].CandidateRef
	})
	return candidates
}

func mdnsObservationKey(name, host string, port int, elements map[string]string) string {
	var key strings.Builder
	for _, value := range []string{name, host, strconv.Itoa(port), elements["ski"], elements["id"], elements["path"]} {
		_, _ = fmt.Fprintf(&key, "%d:", len(value))
		key.WriteString(value)
	}
	return key.String()
}

func validMdnsSKI(ski string) bool {
	if len(ski) != 40 {
		return false
	}
	decoded, err := hex.DecodeString(ski)
	return err == nil && len(decoded) == 20 && ski == fmt.Sprintf("%x", decoded)
}

func (m *MdnsManager) nextCandidateRefLocked(observationKey string) string {
	m.candidateGeneration++
	if m.candidateGeneration == 0 {
		m.candidateGeneration++
	}
	mac := hmac.New(sha256.New, m.candidateSecret[:])
	_, _ = fmt.Fprintf(mac, "%d\x00%s", m.candidateGeneration, observationKey)
	return "shipc_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func sameIPList(left, right []net.IP) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !left[index].Equal(right[index]) {
			return false
		}
	}
	return true
}

func sameScopedIPList(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func cloneIPs(addresses []net.IP) []net.IP {
	cloned := make([]net.IP, len(addresses))
	for index, address := range addresses {
		cloned[index] = append(net.IP(nil), address...)
	}
	return cloned
}

// process an mDNS entry and manage mDNS entries map
func (m *MdnsManager) processMdnsEntry(elements map[string]string, name, host string, addresses []net.IP, port int, remove bool) {
	scoped := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		value, ok := netip.AddrFromSlice(address)
		if !ok {
			continue
		}
		scoped = append(scoped, value.Unmap())
	}
	m.processScopedMdnsEntry(elements, name, host, scoped, port, remove)
}

// processScopedMdnsEntry manages one mDNS observation while preserving the
// interface zone required to dial IPv6 link-local addresses.
func (m *MdnsManager) processScopedMdnsEntry(elements map[string]string, name, host string, addresses []netip.Addr, port int, remove bool) {
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
	if !validMdnsSKI(ski) {
		logging.Log().Debug("mdns: txt - invalid ski", ski)
		return
	}

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

	addresses, legacyAddresses := normalizeMdnsAddresses(addresses)

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

	observationKey := mdnsObservationKey(name, host, port, elements)
	updated := false
	m.mux.Lock()
	entry, exists := m.entries[observationKey]
	switch {
	case remove && exists:
		delete(m.entries, observationKey)
		delete(m.candidateRefs, observationKey)
		updated = true
		logging.Log().Debug("mdns: remove - ski:", ski, "name:", name, "brand:", brand, "model:", model, "typ:", deviceType, "identifier:", identifier, "register:", register, "host:", host, "port:", port, "addresses:", addresses)
	case exists && !remove:
		if !sameIPList(entry.Addresses, legacyAddresses) ||
			!sameScopedIPList(entry.ScopedAddresses, addresses) ||
			entry.Register != (register == "true") || entry.Brand != brand || entry.Type != deviceType || entry.Model != model {
			entry.Addresses = cloneIPs(legacyAddresses)
			entry.ScopedAddresses = append([]netip.Addr(nil), addresses...)
			entry.Register = register == "true"
			entry.Brand = brand
			entry.Type = deviceType
			entry.Model = model
			m.candidateRefs[observationKey] = m.nextCandidateRefLocked(observationKey)
			updated = true
			logging.Log().Debug("mdns: update - ski:", ski, "name:", name, "brand:", brand, "model:", model, "typ:", deviceType, "identifier:", identifier, "register:", register, "host:", host, "port:", port, "addresses:", addresses)
		}
	case !exists && !remove:
		m.entries[observationKey] = &api.MdnsEntry{
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
			Addresses:  cloneIPs(legacyAddresses),
			ScopedAddresses: append(
				[]netip.Addr(nil),
				addresses...,
			),
		}
		m.candidateRefs[observationKey] = m.nextCandidateRefLocked(observationKey)
		updated = true
		logging.Log().Debug("mdns: new - ski:", ski, "name:", name, "brand:", brand, "model:", model, "typ:", deviceType, "identifier:", identifier, "register:", register, "host:", host, "port:", port, "addresses:", addresses)
	}

	if updated {
		m.observationRevision++
		if m.observationRevision == 0 {
			m.observationRevision++
		}
	}
	entries := m.copyMdnsEntriesLocked()
	candidates := m.copyPairingCandidatesLocked()
	revision := m.observationRevision
	m.mux.Unlock()

	if m.report != nil && updated {
		m.reportEntries(entries, candidates, true, revision)
	}
}

func normalizeMdnsAddresses(addresses []netip.Addr) ([]netip.Addr, []net.IP) {
	scoped := make([]netip.Addr, 0, len(addresses))
	legacy := make([]net.IP, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() {
			continue
		}
		address = address.Unmap()
		linkLocalIPv6 := address.Is6() && address.IsLinkLocalUnicast()
		if linkLocalIPv6 {
			if address.Zone() == "" {
				continue
			}
		} else if address.Zone() != "" {
			address = address.WithZone("")
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		scoped = append(scoped, address)
		if !linkLocalIPv6 {
			legacy = append(legacy, append(net.IP(nil), address.AsSlice()...))
		}
	}
	return scoped, legacy
}

func (m *MdnsManager) RequestMdnsEntries() {
	if m.report == nil {
		return
	}

	entries, candidates, revision := m.copyMdnsSnapshot()
	m.reportEntries(entries, candidates, false, revision)
}

func (m *MdnsManager) reportEntries(
	entries map[string]*api.MdnsEntry,
	candidates []api.PairingCandidateObservation,
	newEntries bool,
	revision uint64,
) {
	if candidateReport, ok := m.report.(api.PairingCandidateMdnsReportInterface); ok {
		go candidateReport.ReportMdnsEntriesWithCandidates(entries, newEntries, candidates, revision)
		return
	}
	go m.report.ReportMdnsEntries(entries, newEntries)
}
