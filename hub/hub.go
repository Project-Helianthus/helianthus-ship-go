package hub

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
)

// used for randomizing the connection initiation delay
// this limits the possibility of concurrent connection attempts from both sides
type connectionInitiationDelayTimeRange struct {
	// defines the minimum and maximum wait time for when to try to initate an connection
	min, max int
}

type outboundPairingAdmission struct {
	gateGeneration uint64
	context        context.Context
	cancel         context.CancelFunc
}

// defines the delay timeframes in seconds depening on the connection attempt counter
// the last item will be re-used for higher attempt counter values
var connectionInitiationDelayTimeRanges = []connectionInitiationDelayTimeRange{
	{min: 0, max: 3},
	{min: 3, max: 10},
	{min: 10, max: 20},
}

// handling the server and all connections to remote services
type Hub struct {
	connections map[string]api.ShipConnectionInterface
	hasShutdown bool

	// which attempt is it to initate an connection to the remote SKI
	connectionAttemptCounter map[string]int
	connectionAttemptRunning map[string]bool

	port        int
	certifciate tls.Certificate

	localService *api.ServiceDetails

	hubReader api.HubReaderInterface

	dialer              outgoingAttemptDialer
	outgoingAttemptGate api.OutgoingAttemptGate
	outgoingGateEpoch   uint64
	outboundAdmissions  map[string]*outboundPairingAdmission

	autoaccept bool

	// The list of known remote services
	remoteServices map[string]*api.ServiceDetails

	// The web server for handling incoming websocket connections
	httpServer *http.Server

	listenerPolicy          *api.ListenerPolicy
	listenerPolicyLifecycle listenerPolicyLifecycle

	// Handling mDNS related tasks
	mdns api.MdnsInterface

	// list of currently known/reported mDNS entries
	knownMdnsEntries []*api.MdnsEntry

	hasStarted bool

	muxCon         sync.Mutex
	muxConAttempt  sync.Mutex
	muxReg         sync.Mutex
	muxMdns        sync.Mutex
	muxStarted     sync.Mutex
	muxAttemptGate sync.RWMutex
}

func NewHub(hubReader api.HubReaderInterface,
	mdns api.MdnsInterface,
	port int,
	certificate tls.Certificate,
	localService *api.ServiceDetails) *Hub {
	hub := &Hub{
		connections:              make(map[string]api.ShipConnectionInterface),
		connectionAttemptCounter: make(map[string]int),
		connectionAttemptRunning: make(map[string]bool),
		remoteServices:           make(map[string]*api.ServiceDetails),
		knownMdnsEntries:         make([]*api.MdnsEntry, 0),
		hubReader:                hubReader,
		port:                     port,
		certifciate:              certificate,
		localService:             localService,
		mdns:                     mdns,
		dialer:                   newOutgoingAttemptDialer(certificate),
		outboundAdmissions:       make(map[string]*outboundPairingAdmission),
	}

	return hub
}

var _ api.HubInterface = (*Hub)(nil)
var _ api.OutgoingAttemptGateSetter = (*Hub)(nil)
var _ api.PairingRegistrationSetter = (*Hub)(nil)

// SetOutgoingAttemptGate installs or removes the optional outgoing dial gate.
func (h *Hub) SetOutgoingAttemptGate(gate api.OutgoingAttemptGate) error {
	if gate != nil {
		if isNilOutgoingAttemptValue(gate) {
			return api.ErrInvalidOutgoingAttemptGate
		}
		reader, ok := h.hubReader.(api.OutgoingAttemptHubReaderInterface)
		if !ok || isNilOutgoingAttemptValue(reader) {
			return api.ErrInvalidOutgoingAttemptGate
		}
	}

	h.muxAttemptGate.Lock()
	h.outgoingAttemptGate = gate
	h.outgoingGateEpoch++
	h.invalidateAllOutboundAdmissionsLocked()
	h.muxAttemptGate.Unlock()
	return nil
}

func (h *Hub) configuredOutgoingAttemptGate() api.OutgoingAttemptGate {
	h.muxAttemptGate.RLock()
	defer h.muxAttemptGate.RUnlock()

	return h.outgoingAttemptGate
}

func (h *Hub) createOutboundAdmission(ski string) bool {
	admissionContext, cancel := context.WithCancel(context.Background())

	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	if h.outgoingAttemptGate == nil || isNilOutgoingAttemptValue(h.outgoingAttemptGate) {
		cancel()
		return false
	}
	if h.outboundAdmissions == nil {
		h.outboundAdmissions = make(map[string]*outboundPairingAdmission)
	}
	if existing := h.outboundAdmissions[ski]; existing != nil {
		existing.cancel()
	}
	h.outboundAdmissions[ski] = &outboundPairingAdmission{
		gateGeneration: h.outgoingGateEpoch,
		context:        admissionContext,
		cancel:         cancel,
	}
	return true
}

func (h *Hub) hasCurrentOutboundAdmission(ski string) bool {
	h.muxAttemptGate.RLock()
	defer h.muxAttemptGate.RUnlock()

	admission := h.outboundAdmissions[ski]
	return h.outgoingAttemptGate != nil &&
		!isNilOutgoingAttemptValue(h.outgoingAttemptGate) &&
		admission != nil &&
		admission.gateGeneration == h.outgoingGateEpoch &&
		admission.context.Err() == nil
}

func (h *Hub) invalidateOutboundAdmission(ski string) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()

	if h.outboundAdmissions == nil {
		h.outboundAdmissions = make(map[string]*outboundPairingAdmission)
	}
	admission := h.outboundAdmissions[ski]
	if admission == nil {
		admissionContext, cancel := context.WithCancel(context.Background())
		admission = &outboundPairingAdmission{
			gateGeneration: h.outgoingGateEpoch,
			context:        admissionContext,
			cancel:         cancel,
		}
		h.outboundAdmissions[ski] = admission
	}
	admission.cancel()
}

func (h *Hub) invalidateAllOutboundAdmissionsLocked() {
	for _, admission := range h.outboundAdmissions {
		admission.cancel()
	}
}

func (h *Hub) outgoingAttemptGateSnapshot(
	ski string,
	untrusted bool,
	queued bool,
) (api.OutgoingAttemptGate, uint64, *outboundPairingAdmission, bool, bool) {
	h.muxAttemptGate.RLock()
	defer h.muxAttemptGate.RUnlock()

	gate := h.outgoingAttemptGate
	generation := h.outgoingGateEpoch
	admission := h.outboundAdmissions[ski]
	requireAdmission := untrusted && (queued || admission != nil)
	if !requireAdmission {
		return gate, generation, nil, false, true
	}
	valid := gate != nil &&
		!isNilOutgoingAttemptValue(gate) &&
		admission != nil &&
		admission.gateGeneration == generation &&
		admission.context.Err() == nil
	return gate, generation, admission, true, valid
}

// lockOutboundAdmissionForLaunch leaves the read lock held on success so an
// invalidation cannot complete between the final check and DialContext.
func (h *Hub) lockOutboundAdmissionForLaunch(
	ski string,
	generation uint64,
	admission *outboundPairingAdmission,
) bool {
	h.muxAttemptGate.RLock()
	current := h.outboundAdmissions[ski]
	if h.outgoingAttemptGate == nil ||
		isNilOutgoingAttemptValue(h.outgoingAttemptGate) ||
		h.outgoingGateEpoch != generation ||
		current == nil ||
		current != admission ||
		current.context.Err() != nil {
		h.muxAttemptGate.RUnlock()
		return false
	}
	return true
}

// Start the ConnectionsHub with all its services
func (h *Hub) Start() {
	if h.listenerPolicy != nil {
		if err := h.StartWithPolicy(); err != nil {
			logging.Log().Debug("error during listener policy startup:", err)
		}
		return
	}

	h.muxStarted.Lock()
	h.hasStarted = true
	h.muxStarted.Unlock()

	// start the websocket server
	if err := h.startWebsocketServer(); err != nil {
		logging.Log().Debug("error during websocket server starting:", err)
	}

	// start mDNS
	err := h.mdns.Start(h)
	if err != nil {
		logging.Log().Debug("error during mdns setup:", err)
	}
}

// close all connections
func (h *Hub) Shutdown() {
	if h.listenerPolicy != nil {
		h.shutdownWithListenerPolicy()
		return
	}

	connections, started := h.beginShutdown()
	if !started {
		return
	}

	h.mdns.Shutdown()
	for _, c := range connections {
		c.CloseConnection(false, 0, "")
	}
	if h.httpServer == nil {
		return
	}
	if err := h.httpServer.Shutdown(context.Background()); err != nil {
		logging.Log().Error("HTTP server shutdown:", err)
	}
}

func (h *Hub) beginShutdown() ([]api.ShipConnectionInterface, bool) {
	h.muxCon.Lock()
	defer h.muxCon.Unlock()

	if h.hasShutdown {
		return nil, false
	}
	h.hasShutdown = true

	connections := make([]api.ShipConnectionInterface, 0, len(h.connections))
	for ski, connection := range h.connections {
		connections = append(connections, connection)
		delete(h.connections, ski)
	}
	return connections, true
}

// return the service for a SKI
func (h *Hub) ServiceForSKI(ski string) *api.ServiceDetails {
	h.muxReg.Lock()
	defer h.muxReg.Unlock()

	ski = util.NormalizeSKI(ski)

	service, ok := h.remoteServices[ski]
	if !ok {
		service = api.NewServiceDetails(ski)
		service.ConnectionStateDetail().SetState(api.ConnectionStateNone)
		h.remoteServices[ski] = service
	}

	return service
}

// return the number of paired services
func (h *Hub) numberPairedServices() int {
	amount := 0

	h.muxReg.Lock()
	for _, service := range h.remoteServices {
		if service.Trusted() {
			amount++
		}
	}
	h.muxReg.Unlock()

	return amount
}

// startup mDNS if a paired service is not connected
func (h *Hub) checkAutoReannounce() {
	countPairedServices := h.numberPairedServices()
	h.muxCon.Lock()
	countConnections := len(h.connections)
	h.muxCon.Unlock()

	if countPairedServices > countConnections {
		_ = h.mdns.AnnounceMdnsEntry()

		// also check currently known mDNS entries to see if they
		// already contain the not connected remote service
		h.mdns.RequestMdnsEntries()
	}
}
