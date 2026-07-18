package mdns

import (
	"context"
	"net"
	"net/netip"
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

	register      func(string, string, string, int, []string, []net.Interface, ...zeroconf.ServerOption) (*zeroconf.Server, error)
	registerProxy func(string, string, string, int, string, []string, []string, []net.Interface, ...zeroconf.ServerOption) (*zeroconf.Server, error)
}

func NewZeroconfProvider(ifaces []net.Interface) *ZeroconfProvider {
	return &ZeroconfProvider{
		ifaces:        ifaces,
		register:      zeroconf.Register,
		registerProxy: zeroconf.RegisterProxy,
	}
}

func newScopedZeroconfProvider(ifaces []net.Interface, host string, address netip.Addr) *ZeroconfProvider {
	provider := NewZeroconfProvider(ifaces)
	provider.host = host
	provider.address = address.WithZone("")
	return provider
}

var _ api.MdnsProviderInterface = (*ZeroconfProvider)(nil)

func (z *ZeroconfProvider) Start(autoReconnect bool, cb api.MdnsResolveCB) bool {
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
	defer z.mux.Unlock()

	z.zc = mDNSServer

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

func (z *ZeroconfProvider) chanListener(ctx context.Context, cb api.MdnsResolveCB) {
	defer z.wait.Done()
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
			zeroconf.SelectIfaces(z.ifaces),
		)
	}()

	for {
		select {
		case <-ctx.Done():
			<-browseDone
			return
		case <-browseDone:
			return
		case service := <-zcRemoved:
			// Zeroconf has issues with merging mDNS data and sometimes reports incomplete records
			if service == nil || len(service.Text) == 0 {
				continue
			}

			elements := parseTxt(service.Text)

			addresses := service.AddrIPv4
			cb(elements, service.Instance, service.HostName, addresses, service.Port, true)

		case service := <-zcEntries:
			// Zeroconf has issues with merging mDNS data and sometimes reports incomplete records
			if service == nil || len(service.Text) == 0 {
				continue
			}

			elements := parseTxt(service.Text)

			addresses := service.AddrIPv4
			addresses = append(addresses, service.AddrIPv6...)
			cb(elements, service.Instance, service.HostName, addresses, service.Port, false)
		}
	}
}
