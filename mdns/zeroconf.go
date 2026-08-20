package mdns

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
	"github.com/enbility/zeroconf/v2"
)

type ZeroconfProvider struct {
	ifaces  []net.Interface
	host    string
	address netip.Addr

	zc *zeroconf.Server

	ctx    context.Context
	cancel context.CancelFunc

	mux  sync.Mutex
	wait sync.WaitGroup

	observationMux      sync.Mutex
	serviceObservations map[string]map[zeroconfInterfaceScope][]netip.Addr

	register      func(string, string, string, int, []string, []net.Interface, ...zeroconf.ServerOption) (*zeroconf.Server, error)
	registerProxy func(string, string, string, int, string, []string, []string, []net.Interface, ...zeroconf.ServerOption) (*zeroconf.Server, error)
}

type zeroconfInterfaceScope struct {
	index int
	name  string
}

func NewZeroconfProvider(ifaces []net.Interface) *ZeroconfProvider {
	return &ZeroconfProvider{
		ifaces:              ifaces,
		serviceObservations: make(map[string]map[zeroconfInterfaceScope][]netip.Addr),
		register:            zeroconf.Register,
		registerProxy:       zeroconf.RegisterProxy,
	}
}

func newScopedZeroconfProvider(ifaces []net.Interface, host string, address netip.Addr) *ZeroconfProvider {
	provider := NewZeroconfProvider(ifaces)
	provider.host = host
	provider.address = address.WithZone("")
	return provider
}

var _ api.MdnsProviderInterface = (*ZeroconfProvider)(nil)
var _ api.ScopedMdnsProviderInterface = (*ZeroconfProvider)(nil)

func (z *ZeroconfProvider) Start(autoReconnect bool, cb api.MdnsResolveCB) bool {
	return z.start(func(
		elements map[string]string,
		name,
		host string,
		addresses []netip.Addr,
		port int,
		remove bool,
	) {
		legacy := make([]net.IP, 0, len(addresses))
		for _, address := range addresses {
			legacy = append(legacy, append(net.IP(nil), address.AsSlice()...))
		}
		cb(elements, name, host, legacy, port, remove)
	})
}

func (z *ZeroconfProvider) StartScoped(_ bool, cb api.MdnsScopedResolveCB) bool {
	return z.start(cb)
}

func (z *ZeroconfProvider) start(cb api.MdnsScopedResolveCB) bool {
	z.mux.Lock()
	if z.cancel != nil {
		z.mux.Unlock()
		return false
	}
	z.ctx, z.cancel = context.WithCancel(context.Background())
	ctx := z.ctx
	z.wait.Add(1)
	z.mux.Unlock()

	go z.chanListener(ctx, cb)

	return true
}

func (z *ZeroconfProvider) Shutdown() {
	z.Unannounce()

	z.mux.Lock()
	cancel := z.cancel
	z.cancel = nil
	z.ctx = nil
	z.mux.Unlock()
	if cancel != nil {
		cancel()
	}
	z.wait.Wait()
	z.observationMux.Lock()
	clear(z.serviceObservations)
	z.observationMux.Unlock()
}

func (z *ZeroconfProvider) Announce(serviceName string, port int, txt []string) error {
	logging.Log().Debug("mdns: using zeroconf")

	// use Zeroconf library if avahi is not available
	// Set TTL to 2 minutes as defined in SHIP chapter 7
	var mDNSServer *zeroconf.Server
	var err error
	if z.address.IsValid() {
		mDNSServer, err = z.registerProxy(
			serviceName,
			shipZeroConfServiceType,
			shipZeroConfDomain,
			port,
			z.host,
			[]string{z.address.String()},
			txt,
			z.ifaces,
			zeroconf.TTL(120),
		)
	} else {
		mDNSServer, err = z.register(
			serviceName,
			shipZeroConfServiceType,
			shipZeroConfDomain,
			port,
			txt,
			z.ifaces,
			zeroconf.TTL(120),
		)
	}
	if err != nil {
		return err
	}

	z.mux.Lock()
	previousServer := z.zc
	z.zc = mDNSServer
	z.mux.Unlock()

	if previousServer != nil {
		previousServer.Shutdown()
	}

	return nil
}

func (z *ZeroconfProvider) Unannounce() {
	z.mux.Lock()
	defer z.mux.Unlock()

	if z.zc == nil {
		return
	}

	z.zc.Shutdown()
	z.zc = nil
}

func (z *ZeroconfProvider) chanListener(ctx context.Context, cb api.MdnsScopedResolveCB) {
	defer z.wait.Done()
	available, err := net.Interfaces()
	if err != nil {
		logging.Log().Debug("mdns: zeroconf - list interfaces:", err)
		return
	}
	ifaces := z.browseInterfaces(available)
	if len(ifaces) == 0 {
		logging.Log().Debug("mdns: zeroconf - no interface available for scoped browse")
		return
	}

	var browsers sync.WaitGroup
	browsers.Add(len(ifaces))
	for _, iface := range ifaces {
		iface := iface
		go func() {
			defer browsers.Done()
			z.chanListenerForInterface(ctx, iface, cb)
		}()
	}
	browsers.Wait()
}

func (z *ZeroconfProvider) browseInterfaces(available []net.Interface) []net.Interface {
	if len(z.ifaces) > 0 {
		return append([]net.Interface(nil), z.ifaces...)
	}
	ifaces := make([]net.Interface, 0, len(available))
	for _, iface := range available {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	return ifaces
}

func (z *ZeroconfProvider) chanListenerForInterface(
	ctx context.Context,
	iface net.Interface,
	cb api.MdnsScopedResolveCB,
) {
	zcEntries := make(chan *zeroconf.ServiceEntry)
	zcRemoved := make(chan *zeroconf.ServiceEntry)
	browseDone := make(chan struct{})
	go func() {
		defer close(browseDone)
		_ = zeroconf.Browse(
			ctx,
			shipZeroConfServiceType,
			shipZeroConfDomain,
			zcEntries,
			zcRemoved,
			zeroconf.SelectIfaces([]net.Interface{iface}),
		)
	}()

	for {
		select {
		case <-ctx.Done():
			<-browseDone
			return
		case <-browseDone:
			return
		case service, ok := <-zcRemoved:
			if !ok {
				zcRemoved = nil
				continue
			}
			// Zeroconf has issues with merging mDNS data and sometimes reports incomplete records
			if service == nil || len(service.Text) == 0 {
				continue
			}

			z.processScopedServiceForInterface(iface, service, true, cb)

		case service, ok := <-zcEntries:
			if !ok {
				zcEntries = nil
				continue
			}
			// Zeroconf has issues with merging mDNS data and sometimes reports incomplete records
			if service == nil || len(service.Text) == 0 {
				continue
			}

			z.processScopedServiceForInterface(iface, service, false, cb)
		}
	}
}

func (z *ZeroconfProvider) processScopedServiceForInterface(
	iface net.Interface,
	service *zeroconf.ServiceEntry,
	remove bool,
	cb api.MdnsScopedResolveCB,
) {
	if service == nil || cb == nil {
		return
	}
	elements := parseTxt(service.Text)
	observationKey := mdnsObservationKey(service.Instance, service.HostName, service.Port, elements)
	scope := zeroconfInterfaceScope{index: iface.Index, name: iface.Name}

	z.observationMux.Lock()
	defer z.observationMux.Unlock()
	observations := z.serviceObservations[observationKey]
	if remove {
		if _, exists := observations[scope]; !exists {
			return
		}
		delete(observations, scope)
		if len(observations) == 0 {
			delete(z.serviceObservations, observationKey)
			cb(elements, service.Instance, service.HostName, nil, service.Port, true)
			return
		}
	} else {
		if observations == nil {
			observations = make(map[zeroconfInterfaceScope][]netip.Addr)
			z.serviceObservations[observationKey] = observations
		}
		observations[scope] = scopedServiceAddressesForZone(service, iface.Name)
	}
	addresses := aggregateScopedServiceAddresses(observations)
	cb(elements, service.Instance, service.HostName, addresses, service.Port, false)
}

func aggregateScopedServiceAddresses(
	observations map[zeroconfInterfaceScope][]netip.Addr,
) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	addresses := make([]netip.Addr, 0)
	for _, scoped := range observations {
		for _, address := range scoped {
			if _, exists := seen[address]; exists {
				continue
			}
			seen[address] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	sort.Slice(addresses, func(left, right int) bool {
		return addresses[left].Compare(addresses[right]) < 0
	})
	return addresses
}

func (z *ZeroconfProvider) scopedServiceAddresses(service *zeroconf.ServiceEntry) []netip.Addr {
	if service == nil {
		return nil
	}
	zone := ""
	if len(z.ifaces) == 1 {
		zone = z.ifaces[0].Name
	}
	return scopedServiceAddressesForZone(service, zone)
}

func scopedServiceAddressesForZone(service *zeroconf.ServiceEntry, zone string) []netip.Addr {
	if service == nil {
		return nil
	}
	addresses := make([]netip.Addr, 0, len(service.AddrIPv4)+len(service.AddrIPv6))
	for _, value := range append(append([]net.IP(nil), service.AddrIPv4...), service.AddrIPv6...) {
		address, ok := netip.AddrFromSlice(value)
		if !ok {
			continue
		}
		address = address.Unmap()
		if address.Is6() && address.IsLinkLocalUnicast() && zone != "" {
			address = address.WithZone(zone)
		}
		addresses = append(addresses, address)
	}
	return addresses
}
