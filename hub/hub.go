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

type outboundAttemptAuthority struct {
	epoch uint64
}

type outboundAttemptRegistration struct {
	authority  *outboundAttemptAuthority
	metadata   api.OutgoingAttemptMetadata
	context    context.Context
	cancel     context.CancelFunc
	connection api.ShipConnectionInterface
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
	outboundEpoch       uint64
	outboundAuthorities map[string]*outboundAttemptAuthority
	outboundAttempts    map[string]map[*outboundAttemptRegistration]struct{}

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
		outboundAuthorities:      make(map[string]*outboundAttemptAuthority),
		outboundAttempts:         make(map[string]map[*outboundAttemptRegistration]struct{}),
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
	cancellations := h.removeAllOutboundAttemptRegistrationsLocked()
	h.muxAttemptGate.Unlock()
	cancelOutboundAttemptRegistrations(cancellations)
	return nil
}

func (h *Hub) configuredOutgoingAttemptGate() api.OutgoingAttemptGate {
	h.muxAttemptGate.RLock()
	defer h.muxAttemptGate.RUnlock()

	return h.outgoingAttemptGate
}

func (h *Hub) createOutboundAdmission(ski string, service *api.ServiceDetails) bool {
	admissionContext, cancel := context.WithCancel(context.Background())

	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	if h.outgoingAttemptGate == nil || isNilOutgoingAttemptValue(h.outgoingAttemptGate) {
		cancel()
		return false
	}
	if service.Trusted() {
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
	service.ConnectionStateDetail().SetState(api.ConnectionStateQueued)
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

func (h *Hub) promoteOutboundTrust(ski string, service *api.ServiceDetails) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()

	if admission := h.outboundAdmissions[ski]; admission != nil {
		admission.cancel()
	}
	service.SetTrusted(true)
}

func (h *Hub) revokeOutboundAttempts(ski string, service *api.ServiceDetails) {
	h.muxAttemptGate.Lock()
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
	h.rotateOutboundAuthorityLocked(ski)
	cancellations := h.removeOutboundAttemptRegistrationsLocked(ski)
	service.SetTrusted(false)
	service.ConnectionStateDetail().SetState(api.ConnectionStateNone)
	h.muxAttemptGate.Unlock()

	// Cancellation may close a SHIP connection and re-enter the Hub.
	cancelOutboundAttemptRegistrations(cancellations)
}

func (h *Hub) invalidateAllOutboundAdmissionsLocked() {
	for _, admission := range h.outboundAdmissions {
		admission.cancel()
	}
}

func (h *Hub) outgoingAttemptGateSnapshot(
	remoteService *api.ServiceDetails,
) (api.OutgoingAttemptGate, uint64, *outboundAttemptAuthority, *outboundPairingAdmission, bool, bool) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()

	gate := h.outgoingAttemptGate
	generation := h.outgoingGateEpoch
	ski := remoteService.SKI()
	untrusted := !remoteService.Trusted()
	queued := remoteService.ConnectionStateDetail().State() == api.ConnectionStateQueued
	admission := h.outboundAdmissions[ski]
	requireAdmission := untrusted && (queued || admission != nil)
	if !requireAdmission {
		if gate == nil || isNilOutgoingAttemptValue(gate) {
			return gate, generation, nil, nil, false, true
		}
		return gate, generation, h.currentOutboundAuthorityLocked(ski), nil, false, true
	}
	valid := gate != nil &&
		!isNilOutgoingAttemptValue(gate) &&
		admission != nil &&
		admission.gateGeneration == generation &&
		admission.context.Err() == nil
	if !valid {
		return gate, generation, nil, admission, true, false
	}
	return gate, generation, h.currentOutboundAuthorityLocked(ski), admission, true, true
}

// registerOutboundAttemptForLaunch performs the final authority check and
// installs a Hub-owned cancellation context before DialContext is launched.
func (h *Hub) registerOutboundAttemptForLaunch(
	ski string,
	generation uint64,
	authority *outboundAttemptAuthority,
	admission *outboundPairingAdmission,
	requireAdmission bool,
	metadata api.OutgoingAttemptMetadata,
	permitContext context.Context,
) (*outboundAttemptRegistration, bool) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()

	current := h.outboundAdmissions[ski]
	if h.outgoingAttemptGate == nil ||
		isNilOutgoingAttemptValue(h.outgoingAttemptGate) ||
		h.outgoingGateEpoch != generation ||
		authority == nil ||
		h.outboundAuthorities[ski] != authority {
		return nil, false
	}
	if requireAdmission &&
		(current == nil ||
			current != admission ||
			current.gateGeneration != generation ||
			current.context.Err() != nil) {
		return nil, false
	}

	attemptContext, cancel := context.WithCancel(permitContext)
	registration := &outboundAttemptRegistration{
		authority: authority,
		metadata:  metadata,
		context:   attemptContext,
		cancel:    cancel,
	}
	registrations := h.outboundAttempts[ski]
	if registrations == nil {
		registrations = make(map[*outboundAttemptRegistration]struct{})
		h.outboundAttempts[ski] = registrations
	}
	registrations[registration] = struct{}{}
	return registration, true
}

func (h *Hub) currentOutboundAuthorityLocked(ski string) *outboundAttemptAuthority {
	authority := h.outboundAuthorities[ski]
	if authority != nil {
		return authority
	}
	return h.rotateOutboundAuthorityLocked(ski)
}

func (h *Hub) rotateOutboundAuthorityLocked(ski string) *outboundAttemptAuthority {
	h.outboundEpoch++
	if h.outboundEpoch == 0 {
		h.outboundEpoch++
	}
	authority := &outboundAttemptAuthority{epoch: h.outboundEpoch}
	h.outboundAuthorities[ski] = authority
	return authority
}

func (h *Hub) removeOutboundAttemptRegistrationsLocked(ski string) []*outboundAttemptRegistration {
	registrations := h.outboundAttempts[ski]
	if len(registrations) == 0 {
		return nil
	}
	removed := make([]*outboundAttemptRegistration, 0, len(registrations))
	for registration := range registrations {
		removed = append(removed, registration)
	}
	delete(h.outboundAttempts, ski)
	return removed
}

func (h *Hub) removeAllOutboundAttemptRegistrationsLocked() []*outboundAttemptRegistration {
	var removed []*outboundAttemptRegistration
	for ski := range h.outboundAttempts {
		removed = append(removed, h.removeOutboundAttemptRegistrationsLocked(ski)...)
	}
	return removed
}

func (h *Hub) releaseOutboundAttemptRegistration(ski string, registration *outboundAttemptRegistration) {
	if registration == nil {
		return
	}
	h.muxAttemptGate.Lock()
	registrations := h.outboundAttempts[ski]
	if _, exists := registrations[registration]; exists {
		delete(registrations, registration)
		if len(registrations) == 0 {
			delete(h.outboundAttempts, ski)
		}
	}
	h.muxAttemptGate.Unlock()
	registration.cancel()
}

func (h *Hub) bindOutboundAttemptConnection(
	ski string,
	registration *outboundAttemptRegistration,
	connection api.ShipConnectionInterface,
) bool {
	if registration == nil || connection == nil {
		return false
	}
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	if _, exists := h.outboundAttempts[ski][registration]; !exists || registration.context.Err() != nil {
		return false
	}
	registration.connection = connection
	return true
}

func (h *Hub) releaseOutboundAttemptForConnection(
	ski string,
	connection api.ShipConnectionInterface,
	metadata api.OutgoingAttemptMetadata,
) {
	// Exact connection ownership prevents a stale close from releasing a newer
	// registration if an external gate ever reuses metadata.
	h.muxAttemptGate.Lock()
	registrations := h.outboundAttempts[ski]
	var removed []*outboundAttemptRegistration
	for registration := range registrations {
		if registration.connection == connection && registration.metadata == metadata {
			delete(registrations, registration)
			removed = append(removed, registration)
		}
	}
	if len(registrations) == 0 {
		delete(h.outboundAttempts, ski)
	}
	h.muxAttemptGate.Unlock()
	cancelOutboundAttemptRegistrations(removed)
}

func cancelOutboundAttemptRegistrations(registrations []*outboundAttemptRegistration) {
	for _, registration := range registrations {
		registration.cancel()
	}
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
