package hub

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
)

var errListenerPolicyHubTerminal = errors.New("listener policy hub is terminal")

type listenerPolicyLifecycle struct {
	mu sync.Mutex

	listener       *listenerPolicyListener
	server         *http.Server
	serveDone      chan struct{}
	terminalDone   chan struct{}
	discoveryOwned bool
	started        bool
	finishOnce     sync.Once
	serveTLS       func(*http.Server, net.Listener) error
}

type listenerPolicyResources struct {
	listener       *listenerPolicyListener
	server         *http.Server
	serveDone      <-chan struct{}
	discoveryOwned bool
}

type listenerPolicyListener struct {
	net.Listener

	closeOnce sync.Once
	closeErr  error
}

func (l *listenerPolicyListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type listenerPolicyNoDiscoveryMDNS struct{}

func (listenerPolicyNoDiscoveryMDNS) Start(api.MdnsReportInterface) error { return nil }
func (listenerPolicyNoDiscoveryMDNS) Shutdown()                           {}
func (listenerPolicyNoDiscoveryMDNS) AnnounceMdnsEntry() error            { return nil }
func (listenerPolicyNoDiscoveryMDNS) UnannounceMdnsEntry()                {}
func (listenerPolicyNoDiscoveryMDNS) SetAutoAccept(bool)                  {}
func (listenerPolicyNoDiscoveryMDNS) SetPairingRegistration(bool) error   { return nil }
func (listenerPolicyNoDiscoveryMDNS) RequestMdnsEntries()                 {}

// NewHubWithListenerPolicy creates a Hub configured for exact-address listener startup.
// Construction validates configuration but performs no network or discovery operations.
func NewHubWithListenerPolicy(
	hubReader api.HubReaderInterface,
	mdns api.MdnsInterface,
	port int,
	certificate tls.Certificate,
	localService *api.ServiceDetails,
	policy api.ListenerPolicy,
) (*Hub, error) {
	if err := validateListenerPolicy(port, policy); err != nil {
		return nil, err
	}
	if mdns != nil && isNilListenerPolicyMDNS(mdns) {
		return nil, errors.New("listener policy mDNS is a typed nil")
	}
	if policy.DiscoveryEnabled {
		policyMDNS, ok := mdns.(api.ListenerPolicyMdnsInterface)
		if mdns == nil || !ok || isNilListenerPolicyMDNS(policyMDNS) {
			return nil, errors.New("listener policy discovery requires scoped mDNS support")
		}
		if err := policyMDNS.ConfigureListenerPolicy(policy); err != nil {
			return nil, fmt.Errorf("configure scoped mDNS: %w", err)
		}
	}
	if !policy.DiscoveryEnabled {
		mdns = listenerPolicyNoDiscoveryMDNS{}
	}

	hub := NewHub(hubReader, mdns, port, certificate, localService)
	hub.listenerPolicy = &policy
	hub.listenerPolicyLifecycle = listenerPolicyLifecycle{
		terminalDone: make(chan struct{}),
		serveTLS: func(server *http.Server, listener net.Listener) error {
			return server.ServeTLS(listener, "", "")
		},
	}
	return hub, nil
}

func validateListenerPolicy(port int, policy api.ListenerPolicy) error {
	endpoint := policy.ListenAddress
	if !endpoint.IsValid() {
		return errors.New("listener policy endpoint is invalid")
	}
	if endpoint.Port() == 0 {
		return errors.New("listener policy port must be non-zero")
	}
	address := endpoint.Addr()
	if address.Is4In6() {
		return errors.New("listener policy address must not be IPv4-mapped IPv6")
	}
	if address.IsUnspecified() {
		return errors.New("listener policy address must be specified")
	}
	if address.IsMulticast() {
		return errors.New("listener policy address must not be multicast")
	}
	if !listenerPolicyAddressIsUnicast(address) {
		return errors.New("listener policy address must be unicast")
	}
	if port != int(endpoint.Port()) {
		return fmt.Errorf("listener policy port %d does not match legacy port %d", endpoint.Port(), port)
	}
	return nil
}

// StartWithPolicy synchronously binds the configured endpoint and then starts discovery.
func (h *Hub) StartWithPolicy() error {
	if h.listenerPolicy == nil {
		return errors.New("hub has no listener policy")
	}

	lifecycle := &h.listenerPolicyLifecycle
	lifecycle.mu.Lock()

	if h.listenerPolicyShutdownClaimed() {
		lifecycle.mu.Unlock()
		return errListenerPolicyHubTerminal
	}
	if lifecycle.started {
		lifecycle.mu.Unlock()
		return nil
	}

	endpoint := h.listenerPolicy.ListenAddress
	tcpListener, err := net.ListenTCP(
		listenerPolicyTCPNetwork(endpoint.Addr()),
		net.TCPAddrFromAddrPort(endpoint),
	)
	if err != nil {
		lifecycle.mu.Unlock()
		return fmt.Errorf("bind SHIP listener on %s: %w", endpoint, err)
	}

	listener := &listenerPolicyListener{Listener: tcpListener}
	server := h.newListenerPolicyHTTPServer(endpoint)
	lifecycle.listener = listener
	lifecycle.server = server

	if h.listenerPolicy.DiscoveryEnabled {
		lifecycle.discoveryOwned = true
		if err := h.mdns.Start(h); err != nil {
			resources, connections, _ := h.claimListenerPolicyTerminationLocked()
			lifecycle.mu.Unlock()
			h.cleanupListenerPolicy(resources, connections)
			h.finishListenerPolicyTermination()
			return fmt.Errorf("start mDNS discovery: %w", err)
		}
	}

	serveDone := make(chan struct{})
	lifecycle.serveDone = serveDone
	lifecycle.started = true
	h.muxStarted.Lock()
	h.hasStarted = true
	h.muxStarted.Unlock()

	serveTLS := lifecycle.serveTLS
	lifecycle.mu.Unlock()

	go h.serveListenerPolicy(server, listener, serveDone, serveTLS)
	return nil
}

func (h *Hub) newListenerPolicyHTTPServer(endpoint netip.AddrPort) *http.Server {
	return &http.Server{
		Addr:              endpoint.String(),
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates:           []tls.Certificate{h.certifciate},
			ClientAuth:             tls.RequireAnyClientCert,
			CipherSuites:           cert.CipherSuites, // #nosec G402 -- required by SHIP 9.1
			SessionTicketsDisabled: true,
			VerifyPeerCertificate:  h.verifyPeerCertificate,
			MinVersion:             tls.VersionTLS12, // SHIP 9 requires TLS 1.2 or newer
		},
	}
}

func (h *Hub) serveListenerPolicy(
	server *http.Server,
	listener net.Listener,
	done chan<- struct{},
	serveTLS func(*http.Server, net.Listener) error,
) {
	err := serveTLS(server, listener)
	close(done)

	if h.listenerPolicyShutdownClaimed() {
		return
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logging.Log().Error("websocket server error:", err)
	} else {
		logging.Log().Error("websocket server stopped unexpectedly")
	}
	h.terminateListenerPolicy()
}

func (h *Hub) shutdownWithListenerPolicy() {
	h.terminateListenerPolicy()
}

func (h *Hub) terminateListenerPolicy() {
	lifecycle := &h.listenerPolicyLifecycle
	lifecycle.mu.Lock()
	resources, connections, claimed := h.claimListenerPolicyTerminationLocked()
	lifecycle.mu.Unlock()
	if !claimed {
		return
	}

	h.cleanupListenerPolicy(resources, connections)
	h.finishListenerPolicyTermination()
}

func (h *Hub) claimListenerPolicyTerminationLocked() (
	listenerPolicyResources,
	[]api.ShipConnectionInterface,
	bool,
) {
	connections, claimed := h.beginShutdown()
	if !claimed {
		return listenerPolicyResources{}, nil, false
	}

	lifecycle := &h.listenerPolicyLifecycle
	resources := listenerPolicyResources{
		listener:       lifecycle.listener,
		server:         lifecycle.server,
		serveDone:      lifecycle.serveDone,
		discoveryOwned: lifecycle.discoveryOwned,
	}
	lifecycle.listener = nil
	lifecycle.server = nil
	lifecycle.serveDone = nil
	lifecycle.discoveryOwned = false
	lifecycle.started = false
	return resources, connections, true
}

func (h *Hub) cleanupListenerPolicy(
	resources listenerPolicyResources,
	connections []api.ShipConnectionInterface,
) {
	if resources.discoveryOwned {
		h.mdns.Shutdown()
	}
	for _, connection := range connections {
		connection.CloseConnection(false, 0, "")
	}

	if resources.server != nil {
		if err := resources.server.Close(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			logging.Log().Error("HTTP server close:", err)
		}
	}
	if resources.listener != nil {
		if err := resources.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logging.Log().Error("SHIP listener close:", err)
		}
	}
	if resources.serveDone != nil {
		<-resources.serveDone
	}
}

func (h *Hub) finishListenerPolicyTermination() {
	h.muxStarted.Lock()
	h.hasStarted = false
	h.muxStarted.Unlock()

	lifecycle := &h.listenerPolicyLifecycle
	lifecycle.finishOnce.Do(func() {
		close(lifecycle.terminalDone)
	})
}

func (h *Hub) listenerPolicyShutdownClaimed() bool {
	h.muxCon.Lock()
	defer h.muxCon.Unlock()
	return h.hasShutdown
}

func listenerPolicyTCPNetwork(address netip.Addr) string {
	if address.Is4() {
		return "tcp4"
	}
	return "tcp6"
}

func listenerPolicyAddressIsUnicast(address netip.Addr) bool {
	if address.Is4() {
		value := address.As4()
		if value[0] == 0 || value == [4]byte{255, 255, 255, 255} {
			return false
		}
	}
	return address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast()
}

func isNilListenerPolicyMDNS(value any) bool {
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
