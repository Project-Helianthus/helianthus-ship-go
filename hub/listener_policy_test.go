package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

const listenerPolicyTestTimeout = 2 * time.Second

var legacyNewHubSignature func(
	api.HubReaderInterface,
	api.MdnsInterface,
	int,
	tls.Certificate,
	*api.ServiceDetails,
) *Hub = NewHub

type legacyHubStarter interface {
	Start()
}

var _ legacyHubStarter = (*Hub)(nil)

type listenerPolicyMDNS struct {
	mu               sync.Mutex
	calls            []string
	startErr         error
	onStart          func() error
	onShutdown       func() error
	shutdownCheckErr error
}

func (m *listenerPolicyMDNS) Start(api.MdnsReportInterface) error {
	m.record("start")
	if m.onStart != nil {
		if err := m.onStart(); err != nil {
			return err
		}
	}
	return m.startErr
}

func (m *listenerPolicyMDNS) Shutdown() {
	m.record("shutdown")
	if m.onShutdown == nil {
		return
	}
	err := m.onShutdown()
	m.mu.Lock()
	m.shutdownCheckErr = err
	m.mu.Unlock()
}

func (m *listenerPolicyMDNS) AnnounceMdnsEntry() error {
	m.record("announce")
	return nil
}

func (m *listenerPolicyMDNS) UnannounceMdnsEntry() { m.record("unannounce") }
func (m *listenerPolicyMDNS) SetAutoAccept(bool)   { m.record("set-auto-accept") }
func (m *listenerPolicyMDNS) RequestMdnsEntries()  { m.record("request") }

func (m *listenerPolicyMDNS) record(call string) {
	m.mu.Lock()
	m.calls = append(m.calls, call)
	m.mu.Unlock()
}

func (m *listenerPolicyMDNS) snapshot() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.calls...), m.shutdownCheckErr
}

func TestNewHubWithListenerPolicyRejectsUnsafeEndpointsWithoutEffects(t *testing.T) {
	port := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1")).Port()
	tests := map[string]netip.AddrPort{
		"invalid":          netip.AddrPortFrom(netip.Addr{}, port),
		"zero port":        netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
		"IPv4 unspecified": netip.AddrPortFrom(netip.IPv4Unspecified(), port),
		"IPv6 unspecified": netip.AddrPortFrom(netip.IPv6Unspecified(), port),
		"IPv4 multicast":   netip.AddrPortFrom(netip.MustParseAddr("224.0.0.251"), port),
		"IPv6 multicast":   netip.AddrPortFrom(netip.MustParseAddr("ff02::fb"), port),
	}

	for name, endpoint := range tests {
		t.Run(name, func(t *testing.T) {
			mdns := &listenerPolicyMDNS{}
			hub, err := NewHubWithListenerPolicy(
				nil,
				mdns,
				int(endpoint.Port()),
				tls.Certificate{},
				api.NewServiceDetails("local-ski"),
				api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: true},
			)
			if err == nil {
				t.Fatal("NewHubWithListenerPolicy accepted an unsafe endpoint")
			}
			if hub != nil {
				t.Error("NewHubWithListenerPolicy returned a Hub for an unsafe endpoint")
			}
			if calls, _ := mdns.snapshot(); len(calls) != 0 {
				t.Errorf("validation caused mDNS effects: %v", calls)
			}
		})
	}
}

func TestNewHubWithListenerPolicyIsValidationOnlyAndOccupiedBindFailsSynchronously(t *testing.T) {
	held := listenerPolicyListen(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0))
	defer held.Close()
	endpoint := held.Addr().(*net.TCPAddr).AddrPort()
	mdns := &listenerPolicyMDNS{}
	hub := listenerPolicyNewHub(t, endpoint, true, mdns)

	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Fatalf("constructor caused mDNS effects: %v", calls)
	}
	err := listenerPolicyStart(t, hub)
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("StartWithPolicy error = %v, want address-in-use", err)
	}
	hub.Shutdown()
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Errorf("failed bind caused mDNS effects: %v", calls)
	}
}

func TestNewHubWithListenerPolicyRejectsPortMismatchWithoutEffects(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	mdns := &listenerPolicyMDNS{}
	hub, err := NewHubWithListenerPolicy(
		nil,
		mdns,
		int(endpoint.Port())+1,
		tls.Certificate{},
		api.NewServiceDetails("local-ski"),
		api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: true},
	)
	if err == nil {
		t.Fatal("NewHubWithListenerPolicy accepted conflicting ports")
	}
	if hub != nil {
		t.Error("NewHubWithListenerPolicy returned a Hub for conflicting ports")
	}
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Errorf("port validation caused mDNS effects: %v", calls)
	}
}

func TestStartWithPolicyBindsExactIPv4WithoutDiscovery(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	mdns := &listenerPolicyMDNS{}
	hub := listenerPolicyNewHub(t, endpoint, false, mdns)
	if err := listenerPolicyStart(t, hub); err != nil {
		t.Fatalf("StartWithPolicy() error = %v", err)
	}
	t.Cleanup(hub.Shutdown)

	listenerPolicyDial(t, endpoint)
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Fatalf("discovery-disabled startup caused mDNS effects: %v", calls)
	}

	alternate := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.2"), endpoint.Port())
	alternateListener := listenerPolicyListen(t, alternate)
	if err := alternateListener.Close(); err != nil {
		t.Fatalf("close alternate listener: %v", err)
	}

	listenerPolicyShutdown(t, hub)
	rebound := listenerPolicyListen(t, endpoint)
	if err := rebound.Close(); err != nil {
		t.Fatalf("close rebound listener: %v", err)
	}
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Errorf("discovery-disabled lifecycle caused mDNS effects: %v", calls)
	}
}

func TestStartWithPolicyBindsExactIPv6WhenSupported(t *testing.T) {
	probe, err := net.ListenTCP("tcp6", net.TCPAddrFromAddrPort(netip.MustParseAddrPort("[::1]:0")))
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	endpoint := probe.Addr().(*net.TCPAddr).AddrPort()
	if err := probe.Close(); err != nil {
		t.Fatalf("close IPv6 probe: %v", err)
	}

	mdns := &listenerPolicyMDNS{}
	hub := listenerPolicyNewHub(t, endpoint, false, mdns)
	if err := listenerPolicyStart(t, hub); err != nil {
		t.Fatalf("StartWithPolicy() error = %v", err)
	}
	t.Cleanup(hub.Shutdown)
	listenerPolicyDial(t, endpoint)
	listenerPolicyShutdown(t, hub)

	rebound := listenerPolicyListen(t, endpoint)
	if err := rebound.Close(); err != nil {
		t.Fatalf("close rebound IPv6 listener: %v", err)
	}
}

func TestStartWithPolicyBindsBeforeDiscoveryAndShutdownIsIdempotent(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	mdns := &listenerPolicyMDNS{
		onStart:    func() error { return listenerPolicyRequireBound(endpoint) },
		onShutdown: func() error { return listenerPolicyRequireBound(endpoint) },
	}
	hub := listenerPolicyNewHub(t, endpoint, true, mdns)
	if err := listenerPolicyStart(t, hub); err != nil {
		t.Fatalf("StartWithPolicy() error = %v", err)
	}
	listenerPolicyDial(t, endpoint)
	listenerPolicyConcurrentShutdown(t, hub, 8)

	calls, shutdownCheckErr := mdns.snapshot()
	if shutdownCheckErr != nil {
		t.Errorf("listener closed before mDNS shutdown: %v", shutdownCheckErr)
	}
	if got := listenerPolicyCount(calls, "start"); got != 1 {
		t.Errorf("mDNS Start calls = %d, want 1; calls: %v", got, calls)
	}
	if got := listenerPolicyCount(calls, "shutdown"); got != 1 {
		t.Errorf("mDNS Shutdown calls = %d, want 1; calls: %v", got, calls)
	}
	rebound := listenerPolicyListen(t, endpoint)
	if err := rebound.Close(); err != nil {
		t.Fatalf("close rebound listener: %v", err)
	}
}

func TestStartWithPolicyRollsBackListenerOnInitialDiscoveryFailure(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	discoveryErr := errors.New("discovery startup failed")
	mdns := &listenerPolicyMDNS{
		startErr:   discoveryErr,
		onStart:    func() error { return listenerPolicyRequireBound(endpoint) },
		onShutdown: func() error { return listenerPolicyRequireBound(endpoint) },
	}
	hub := listenerPolicyNewHub(t, endpoint, true, mdns)
	err := listenerPolicyStart(t, hub)
	if !errors.Is(err, discoveryErr) {
		t.Fatalf("StartWithPolicy error = %v, want discovery failure", err)
	}
	hub.Shutdown()
	hub.Shutdown()

	calls, shutdownCheckErr := mdns.snapshot()
	if shutdownCheckErr != nil {
		t.Errorf("listener closed before discovery rollback: %v", shutdownCheckErr)
	}
	if got := listenerPolicyCount(calls, "start"); got != 1 {
		t.Errorf("mDNS Start calls = %d, want 1; calls: %v", got, calls)
	}
	if got := listenerPolicyCount(calls, "shutdown"); got != 1 {
		t.Errorf("mDNS Shutdown calls = %d, want 1; calls: %v", got, calls)
	}
	rebound := listenerPolicyListen(t, endpoint)
	if err := rebound.Close(); err != nil {
		t.Fatalf("close rebound listener: %v", err)
	}
}

func TestLegacyNewHubAndStartRemainSourceCompatible(t *testing.T) {
	mdns := &listenerPolicyMDNS{}
	hub := legacyNewHubSignature(nil, mdns, 0, tls.Certificate{}, api.NewServiceDetails("local-ski"))
	if hub == nil {
		t.Fatal("NewHub returned nil")
	}
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Errorf("legacy constructor caused mDNS effects: %v", calls)
	}
}

func listenerPolicyNewHub(t *testing.T, endpoint netip.AddrPort, discovery bool, mdns api.MdnsInterface) *Hub {
	t.Helper()
	hub, err := NewHubWithListenerPolicy(
		nil,
		mdns,
		int(endpoint.Port()),
		tls.Certificate{},
		api.NewServiceDetails("local-ski"),
		api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: discovery},
	)
	if err != nil {
		t.Fatalf("NewHubWithListenerPolicy() error = %v", err)
	}
	if hub == nil {
		t.Fatal("NewHubWithListenerPolicy() returned nil Hub")
	}
	return hub
}

func listenerPolicyAvailableEndpoint(t *testing.T, address netip.Addr) netip.AddrPort {
	t.Helper()
	listener := listenerPolicyListen(t, netip.AddrPortFrom(address, 0))
	endpoint := listener.Addr().(*net.TCPAddr).AddrPort()
	if err := listener.Close(); err != nil {
		t.Fatalf("close endpoint probe: %v", err)
	}
	return endpoint
}

func listenerPolicyListen(t *testing.T, endpoint netip.AddrPort) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP(listenerPolicyNetwork(endpoint.Addr()), net.TCPAddrFromAddrPort(endpoint))
	if err != nil {
		t.Fatalf("listen on %s: %v", endpoint, err)
	}
	return listener
}

func listenerPolicyDial(t *testing.T, endpoint netip.AddrPort) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), listenerPolicyTestTimeout)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, listenerPolicyNetwork(endpoint.Addr()), endpoint.String())
	if err != nil {
		t.Fatalf("dial exact listener %s: %v", endpoint, err)
	}
	if err := connection.Close(); err != nil {
		t.Fatalf("close exact-listener connection: %v", err)
	}
}

func listenerPolicyRequireBound(endpoint netip.AddrPort) error {
	listener, err := net.ListenTCP(listenerPolicyNetwork(endpoint.Addr()), net.TCPAddrFromAddrPort(endpoint))
	if err == nil {
		_ = listener.Close()
		return fmt.Errorf("endpoint %s was not bound", endpoint)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("probe bound endpoint %s: %w", endpoint, err)
	}
	return nil
}

func listenerPolicyNetwork(address netip.Addr) string {
	if address.Is4() {
		return "tcp4"
	}
	return "tcp6"
}

func listenerPolicyStart(t *testing.T, hub *Hub) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- hub.StartWithPolicy() }()
	select {
	case err := <-result:
		return err
	case <-time.After(listenerPolicyTestTimeout):
		t.Fatal("StartWithPolicy did not return synchronously")
		return nil
	}
}

func listenerPolicyShutdown(t *testing.T, hub *Hub) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		hub.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(listenerPolicyTestTimeout):
		t.Fatal("Shutdown did not return")
	}
}

func listenerPolicyConcurrentShutdown(t *testing.T, hub *Hub, count int) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		var wait sync.WaitGroup
		wait.Add(count)
		for range count {
			go func() {
				defer wait.Done()
				hub.Shutdown()
			}()
		}
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(listenerPolicyTestTimeout):
		t.Fatal("concurrent Shutdown calls did not return")
	}
}

func listenerPolicyCount(calls []string, want string) int {
	count := 0
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}
