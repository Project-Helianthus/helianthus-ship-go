package hub

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
)

type listenerPolicyLifecycle struct {
	mu sync.Mutex

	listener       *listenerPolicyListener
	server         *http.Server
	serveDone      chan struct{}
	discoveryOwned bool
	started        bool
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
	if policy.DiscoveryEnabled && mdns == nil {
		return nil, errors.New("listener policy requires mDNS when discovery is enabled")
	}
	if !policy.DiscoveryEnabled {
		mdns = listenerPolicyNoDiscoveryMDNS{}
	}

	hub := NewHub(hubReader, mdns, port, certificate, localService)
	hub.listenerPolicy = &policy
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
	if address.IsUnspecified() {
		return errors.New("listener policy address must be specified")
	}
	if address.IsMulticast() {
		return errors.New("listener policy address must not be multicast")
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
	defer lifecycle.mu.Unlock()

	if h.listenerPolicyShutdownClaimed() {
		return errors.New("hub is shut down")
	}
	if lifecycle.started {
		return nil
	}

	endpoint := h.listenerPolicy.ListenAddress
	tcpListener, err := net.ListenTCP(
		listenerPolicyTCPNetwork(endpoint.Addr()),
		net.TCPAddrFromAddrPort(endpoint),
	)
	if err != nil {
		return fmt.Errorf("bind SHIP listener on %s: %w", endpoint, err)
	}

	listener := &listenerPolicyListener{Listener: tcpListener}
	server := h.newListenerPolicyHTTPServer(endpoint)
	lifecycle.listener = listener
	lifecycle.server = server

	if h.listenerPolicy.DiscoveryEnabled {
		lifecycle.discoveryOwned = true
		if err := h.mdns.Start(h); err != nil {
			h.mdns.Shutdown()
			lifecycle.discoveryOwned = false
			if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
				logging.Log().Error("SHIP listener rollback:", closeErr)
			}
			lifecycle.listener = nil
			lifecycle.server = nil
			return fmt.Errorf("start mDNS discovery: %w", err)
		}
	}

	serveDone := make(chan struct{})
	lifecycle.serveDone = serveDone
	lifecycle.started = true
	h.muxStarted.Lock()
	h.hasStarted = true
	h.muxStarted.Unlock()

	go h.serveListenerPolicy(server, listener, serveDone)
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

func (h *Hub) serveListenerPolicy(server *http.Server, listener net.Listener, done chan<- struct{}) {
	defer close(done)
	if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logging.Log().Error("websocket server error:", err)
	}
}

func (h *Hub) shutdownWithListenerPolicy() {
	lifecycle := &h.listenerPolicyLifecycle
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()

	connections, claimed := h.beginShutdown()
	if !claimed {
		return
	}

	if lifecycle.discoveryOwned {
		h.mdns.Shutdown()
		lifecycle.discoveryOwned = false
	}
	for _, connection := range connections {
		connection.CloseConnection(false, 0, "")
	}

	if lifecycle.server != nil {
		if err := lifecycle.server.Close(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			logging.Log().Error("HTTP server close:", err)
		}
	}
	if lifecycle.listener != nil {
		if err := lifecycle.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logging.Log().Error("SHIP listener close:", err)
		}
	}
	if lifecycle.serveDone != nil {
		<-lifecycle.serveDone
	}

	lifecycle.listener = nil
	lifecycle.server = nil
	lifecycle.serveDone = nil
	lifecycle.started = false
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
