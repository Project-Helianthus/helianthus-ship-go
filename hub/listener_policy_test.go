package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
	"github.com/Project-Helianthus/helianthus-ship-go/mocks"
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
	configureErr     error
	configuredPolicy *api.ListenerPolicy
	onStart          func() error
	onShutdown       func() error
	shutdownCheckErr error
}

func (m *listenerPolicyMDNS) ConfigureListenerPolicy(policy api.ListenerPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	configured := policy
	m.configuredPolicy = &configured
	return m.configureErr
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

func (m *listenerPolicyMDNS) configured() *api.ListenerPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.configuredPolicy == nil {
		return nil
	}
	configured := *m.configuredPolicy
	return &configured
}

func TestNewHubWithListenerPolicyRejectsUnsafeEndpointsWithoutEffects(t *testing.T) {
	port := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1")).Port()
	tests := map[string]netip.AddrPort{
		"invalid":           netip.AddrPortFrom(netip.Addr{}, port),
		"zero port":         netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
		"IPv4 unspecified":  netip.AddrPortFrom(netip.IPv4Unspecified(), port),
		"IPv6 unspecified":  netip.AddrPortFrom(netip.IPv6Unspecified(), port),
		"IPv4 multicast":    netip.AddrPortFrom(netip.MustParseAddr("224.0.0.251"), port),
		"IPv6 multicast":    netip.AddrPortFrom(netip.MustParseAddr("ff02::fb"), port),
		"IPv4 mapped":       netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), port),
		"mapped wildcard":   netip.AddrPortFrom(netip.MustParseAddr("::ffff:0.0.0.0"), port),
		"limited broadcast": netip.AddrPortFrom(netip.MustParseAddr("255.255.255.255"), port),
		"this network":      netip.AddrPortFrom(netip.MustParseAddr("0.0.0.1"), port),
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

func TestNewHubWithListenerPolicyRejectsTypedNilMDNSWithoutEffects(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	var mdns *listenerPolicyMDNS
	hub, err := NewHubWithListenerPolicy(
		nil,
		mdns,
		int(endpoint.Port()),
		tls.Certificate{},
		api.NewServiceDetails("local-ski"),
		api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: true},
	)
	if err == nil {
		t.Fatal("NewHubWithListenerPolicy accepted typed-nil mDNS")
	}
	if hub != nil {
		t.Fatal("NewHubWithListenerPolicy returned a Hub for typed-nil mDNS")
	}

	listener := listenerPolicyListen(t, endpoint)
	if err := listener.Close(); err != nil {
		t.Fatalf("close typed-nil bind probe: %v", err)
	}
}

func TestNewHubWithListenerPolicyRequiresScopedMDNSCapability(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	hub, err := NewHubWithListenerPolicy(
		nil,
		listenerPolicyNoDiscoveryMDNS{},
		int(endpoint.Port()),
		tls.Certificate{},
		api.NewServiceDetails("local-ski"),
		api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: true},
	)
	if err == nil {
		t.Fatal("NewHubWithListenerPolicy accepted mDNS without scoped capability")
	}
	if hub != nil {
		t.Fatal("NewHubWithListenerPolicy returned a Hub without scoped mDNS capability")
	}
}

func TestNewHubWithListenerPolicyConfiguresScopedMDNSWithoutRuntimeEffects(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	policy := api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: true}
	mdns := &listenerPolicyMDNS{}
	hub := listenerPolicyNewHub(t, endpoint, true, mdns)
	if configured := mdns.configured(); configured == nil || *configured != policy {
		t.Fatalf("configured listener policy = %#v, want %#v", configured, policy)
	}
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Fatalf("constructor caused mDNS runtime effects: %v", calls)
	}

	hub.Shutdown()
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Fatalf("shutdown before startup caused mDNS effects: %v", calls)
	}
}

func TestNewHubWithListenerPolicyIsValidationOnlyAndOccupiedBindFailsSynchronously(t *testing.T) {
	held := listenerPolicyListen(t, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0))
	defer func() { _ = held.Close() }()
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
	if bound := listenerPolicyBoundEndpoint(t, hub); bound != endpoint {
		t.Fatalf("bound listener endpoint = %s, want %s", bound, endpoint)
	}
	if calls, _ := mdns.snapshot(); len(calls) != 0 {
		t.Fatalf("discovery-disabled startup caused mDNS effects: %v", calls)
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
	if bound := listenerPolicyBoundEndpoint(t, hub); bound != endpoint {
		t.Fatalf("bound IPv6 listener endpoint = %s, want %s", bound, endpoint)
	}
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
	if retryErr := listenerPolicyStart(t, hub); !errors.Is(retryErr, errListenerPolicyHubTerminal) {
		t.Fatalf("StartWithPolicy retry error = %v, want terminal error", retryErr)
	}
	hub.Start()
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

func TestUnexpectedServeTLSExitTerminalizesAndDoesNotDeadlockShutdown(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	serveStarted := make(chan struct{})
	serveRelease := make(chan struct{})
	mdnsShutdownStarted := make(chan struct{})
	mdnsShutdownRelease := make(chan struct{})
	mdns := &listenerPolicyMDNS{
		onShutdown: func() error {
			close(mdnsShutdownStarted)
			<-mdnsShutdownRelease
			return listenerPolicyRequireBound(endpoint)
		},
	}
	hub := listenerPolicyNewHub(t, endpoint, true, mdns)
	hub.listenerPolicyLifecycle.mu.Lock()
	hub.listenerPolicyLifecycle.serveTLS = func(*http.Server, net.Listener) error {
		close(serveStarted)
		<-serveRelease
		return errors.New("forced ServeTLS exit")
	}
	hub.listenerPolicyLifecycle.mu.Unlock()

	if err := listenerPolicyStart(t, hub); err != nil {
		t.Fatalf("StartWithPolicy() error = %v", err)
	}
	listenerPolicyWait(t, serveStarted, "ServeTLS start")

	connection := mocks.NewShipConnectionInterface(t)
	connection.EXPECT().RemoteSKI().Return("remote-ski").Once()
	connection.EXPECT().CloseConnection(false, 0, "").Once()
	hub.registerConnection(connection)

	close(serveRelease)
	listenerPolicyWait(t, mdnsShutdownStarted, "unexpected-exit mDNS withdrawal")
	shutdownDone := make(chan struct{})
	go func() {
		hub.Shutdown()
		close(shutdownDone)
	}()
	listenerPolicyWait(t, shutdownDone, "concurrent Shutdown")
	close(mdnsShutdownRelease)
	listenerPolicyWait(t, hub.listenerPolicyLifecycle.terminalDone, "terminal cleanup")

	calls, shutdownCheckErr := mdns.snapshot()
	if shutdownCheckErr != nil {
		t.Errorf("listener closed before mDNS withdrawal: %v", shutdownCheckErr)
	}
	if got := listenerPolicyCount(calls, "shutdown"); got != 1 {
		t.Errorf("mDNS Shutdown calls = %d, want 1; calls: %v", got, calls)
	}
	if retryErr := listenerPolicyStart(t, hub); !errors.Is(retryErr, errListenerPolicyHubTerminal) {
		t.Fatalf("StartWithPolicy after ServeTLS exit = %v, want terminal error", retryErr)
	}
	rebound := listenerPolicyListen(t, endpoint)
	if err := rebound.Close(); err != nil {
		t.Fatalf("close rebound listener: %v", err)
	}
}

func TestStartWithPolicyServesTLSOnExactListener(t *testing.T) {
	endpoint := listenerPolicyAvailableEndpoint(t, netip.MustParseAddr("127.0.0.1"))
	serverCertificate, err := cert.CreateCertificate("test-unit", "test-org", "DE", "listener-server")
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	clientCertificate, err := cert.CreateCertificate("test-unit", "test-org", "DE", "listener-client")
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	hub, err := NewHubWithListenerPolicy(
		nil,
		nil,
		int(endpoint.Port()),
		serverCertificate,
		api.NewServiceDetails("local-ski"),
		api.ListenerPolicy{ListenAddress: endpoint, DiscoveryEnabled: false},
	)
	if err != nil {
		t.Fatalf("NewHubWithListenerPolicy() error = %v", err)
	}
	if err := listenerPolicyStart(t, hub); err != nil {
		t.Fatalf("StartWithPolicy() error = %v", err)
	}
	t.Cleanup(hub.Shutdown)

	ctx, cancel := context.WithTimeout(context.Background(), listenerPolicyTestTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp4", endpoint.String())
	if err != nil {
		t.Fatalf("dial TLS listener: %v", err)
	}
	tlsConnection := tls.Client(raw, &tls.Config{
		Certificates:       []tls.Certificate{clientCertificate},
		InsecureSkipVerify: true,              // #nosec G402 -- self-signed SHIP test certificate
		CipherSuites:       cert.CipherSuites, // #nosec G402 -- required by SHIP 9.1
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = tlsConnection.Close()
		t.Fatalf("TLS handshake: %v", err)
	}
	if err := tlsConnection.Close(); err != nil {
		t.Fatalf("close TLS connection: %v", err)
	}
	listenerPolicyShutdown(t, hub)
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

func listenerPolicyBoundEndpoint(t *testing.T, hub *Hub) netip.AddrPort {
	t.Helper()
	hub.listenerPolicyLifecycle.mu.Lock()
	defer hub.listenerPolicyLifecycle.mu.Unlock()
	if hub.listenerPolicyLifecycle.listener == nil {
		t.Fatal("listener policy has no bound listener")
	}
	address, ok := hub.listenerPolicyLifecycle.listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address type = %T, want *net.TCPAddr", hub.listenerPolicyLifecycle.listener.Addr())
	}
	return address.AddrPort()
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

func listenerPolicyWait(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(listenerPolicyTestTimeout):
		t.Fatalf("timed out waiting for %s", operation)
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
