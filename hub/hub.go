package hub

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
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

type pairingCandidateObservation struct {
	ski       string
	revision  uint64
	path      string
	port      int
	addresses []net.IP
}

type activePairingCandidate struct {
	service   *api.ServiceDetails
	authority *outboundAttemptAuthority
}

type pairingCandidateRetirement struct {
	ski       string
	service   *api.ServiceDetails
	authority *outboundAttemptAuthority
}

type inboundPairingReservation struct {
	replaced api.ShipConnectionInterface
}

const maximumSupersededConnections = 128

type hubTestHooks struct {
	launchPairingCandidate           func(func())
	beforePairingCandidateAdmission  func()
	beforePairingCandidateGate       func()
	beforePairingCandidateRetire     func()
	beforeOutboundAttemptRelease     func()
	afterRegisterRemoteServiceLookup func()
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
	// SKIs with an outgoing dial in flight but not yet registered.
	connectionsInitiating map[string]bool
	// Exact inbound first-trust winners reserved before a pairing callback.
	inboundPairingReservations map[string]*inboundPairingReservation
	supersededConnections      map[api.ShipConnectionInterface]struct{}

	port        int
	certifciate tls.Certificate

	localService *api.ServiceDetails

	hubReader api.HubReaderInterface

	dialer               outgoingAttemptDialer
	outgoingAttemptGate  api.OutgoingAttemptGate
	outgoingGateEpoch    uint64
	outboundEpoch        uint64
	internalAttemptEpoch uint64
	outboundAuthorities  map[string]*outboundAttemptAuthority
	outboundAttempts     map[string]map[*outboundAttemptRegistration]struct{}
	outboundShutdown     bool

	autoaccept bool

	// Outbound candidate capabilities are volatile, generation-bound mDNS
	// observations and never persist an endpoint.
	visiblePairingCandidates         map[string]pairingCandidateObservation
	consumedPairingCandidates        map[string]struct{}
	activePairingCandidates          map[string]*activePairingCandidate
	latestPairingObservationRevision uint64
	testHooks                        *hubTestHooks

	// The list of known remote services
	remoteServices map[string]*api.ServiceDetails

	// The web server for handling incoming websocket connections
	httpServer *http.Server

	listenerPolicy          *api.ListenerPolicy
	listenerPolicyLifecycle listenerPolicyLifecycle

	// Handling mDNS related tasks
	mdns api.MdnsInterface

	hasStarted bool

	muxCon         sync.Mutex
	muxConAttempt  sync.Mutex
	muxReg         sync.Mutex
	muxStarted     sync.Mutex
	muxAttemptGate sync.RWMutex

	pairingNotificationMux      sync.Mutex
	pairingNotificationQueue    []func()
	pairingNotificationDraining bool

	mdnsSnapshotMux      sync.Mutex
	mdnsSnapshotQueue    []func()
	mdnsSnapshotDraining bool
	mdnsSnapshotRevision uint64
}

func NewHub(hubReader api.HubReaderInterface,
	mdns api.MdnsInterface,
	port int,
	certificate tls.Certificate,
	localService *api.ServiceDetails) *Hub {
	hub := &Hub{
		connections:                make(map[string]api.ShipConnectionInterface),
		connectionAttemptCounter:   make(map[string]int),
		connectionAttemptRunning:   make(map[string]bool),
		connectionsInitiating:      make(map[string]bool),
		inboundPairingReservations: make(map[string]*inboundPairingReservation),
		supersededConnections:      make(map[api.ShipConnectionInterface]struct{}),
		remoteServices:             make(map[string]*api.ServiceDetails),
		visiblePairingCandidates:   make(map[string]pairingCandidateObservation),
		consumedPairingCandidates:  make(map[string]struct{}),
		activePairingCandidates:    make(map[string]*activePairingCandidate),
		hubReader:                  hubReader,
		port:                       port,
		certifciate:                certificate,
		localService:               localService,
		mdns:                       mdns,
		dialer:                     newOutgoingAttemptDialer(certificate),
		outboundAuthorities:        make(map[string]*outboundAttemptAuthority),
		outboundAttempts:           make(map[string]map[*outboundAttemptRegistration]struct{}),
	}

	return hub
}

var _ api.HubInterface = (*Hub)(nil)
var _ api.OutgoingAttemptGateSetter = (*Hub)(nil)
var _ api.PairingRegistrationSetter = (*Hub)(nil)
var _ api.PairingCandidateQueuer = (*Hub)(nil)

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

	h.muxReg.Lock()
	h.muxAttemptGate.Lock()
	h.outgoingAttemptGate = gate
	h.outgoingGateEpoch++
	retirements := make([]pairingCandidateRetirement, 0, len(h.activePairingCandidates))
	for ski := range h.activePairingCandidates {
		if retired := h.retireActivePairingCandidateLocked(ski, nil, nil); retired != nil {
			retirements = append(retirements, *retired)
		}
	}
	cancellations := h.removeAllOutboundAttemptRegistrationsLocked()
	h.muxAttemptGate.Unlock()
	h.removeOutboundAttemptConnections(cancellations)
	h.muxReg.Unlock()
	cancelOutboundAttemptRegistrations(cancellations)
	h.finishPairingCandidateRetirements(retirements)
	return nil
}

func (h *Hub) revokeOutboundAttempts(ski string, service *api.ServiceDetails) {
	h.muxReg.Lock()
	h.muxAttemptGate.Lock()
	h.rotateOutboundAuthorityLocked(ski)
	cancellations := h.removeOutboundAttemptRegistrationsLocked(ski)
	delete(h.activePairingCandidates, ski)
	service.SetTrusted(false)
	service.ConnectionStateDetail().SetState(api.ConnectionStateNone)
	h.muxAttemptGate.Unlock()
	h.removeOutboundAttemptConnections(cancellations)
	h.muxReg.Unlock()

	// Cancellation may close a SHIP connection and re-enter the Hub.
	cancelOutboundAttemptRegistrations(cancellations)
}

func (h *Hub) outgoingAttemptGateSnapshot(
	remoteService *api.ServiceDetails,
	requiredAuthority *outboundAttemptAuthority,
) (api.OutgoingAttemptGate, uint64, *outboundAttemptAuthority, bool) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	if h.outboundShutdown {
		return nil, 0, nil, false
	}

	gate := h.outgoingAttemptGate
	generation := h.outgoingGateEpoch
	authority := h.currentOutboundAuthorityLocked(remoteService.SKI())
	if requiredAuthority != nil && authority != requiredAuthority {
		return gate, generation, nil, false
	}
	if gate == nil || isNilOutgoingAttemptValue(gate) {
		return gate, generation, authority, true
	}
	return gate, generation, authority, true
}

func (h *Hub) outboundReconnectAuthority(
	remoteService *api.ServiceDetails,
) (*outboundAttemptAuthority, bool) {
	if remoteService == nil {
		return nil, false
	}
	ski := util.NormalizeSKI(remoteService.SKI())
	h.muxReg.Lock()
	defer h.muxReg.Unlock()
	service := h.remoteServices[ski]
	if service == nil || service != remoteService ||
		(!service.Trusted() && service.ConnectionStateDetail().State() != api.ConnectionStateQueued) {
		return nil, false
	}

	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	if h.outboundShutdown {
		return nil, false
	}
	return h.currentOutboundAuthorityLocked(ski), true
}

// registerOutboundAttemptForLaunch performs the final authority check and
// installs a Hub-owned cancellation context before DialContext is launched.
func (h *Hub) registerOutboundAttemptForLaunch(
	ski string,
	generation uint64,
	authority *outboundAttemptAuthority,
	metadata api.OutgoingAttemptMetadata,
	permitContext context.Context,
) (*outboundAttemptRegistration, bool) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()

	if h.outboundShutdown ||
		h.outgoingAttemptGate == nil ||
		isNilOutgoingAttemptValue(h.outgoingAttemptGate) ||
		h.outgoingGateEpoch != generation ||
		authority == nil ||
		h.outboundAuthorities[ski] != authority {
		return nil, false
	}

	// #nosec G118 -- cancellation ownership is transferred to the registration.
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

func (h *Hub) registerInternalOutboundAttemptForLaunch(
	ski string,
	authority *outboundAttemptAuthority,
) (*outboundAttemptRegistration, api.OutgoingAttemptMetadata, bool) {
	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	if h.outboundShutdown ||
		(h.outgoingAttemptGate != nil && !isNilOutgoingAttemptValue(h.outgoingAttemptGate)) ||
		authority == nil ||
		h.outboundAuthorities[ski] != authority {
		return nil, api.OutgoingAttemptMetadata{}, false
	}
	h.internalAttemptEpoch++
	if h.internalAttemptEpoch == 0 {
		h.internalAttemptEpoch++
	}
	metadata := api.OutgoingAttemptMetadata{
		AttemptID:    fmt.Sprintf("ship-internal-%d", h.internalAttemptEpoch),
		Scope:        internalOutgoingAttemptScope,
		ControlEpoch: authority.epoch,
	}
	// #nosec G118 -- cancellation ownership is transferred to the registration.
	attemptContext, cancel := context.WithCancel(context.Background())
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
	return registration, metadata, true
}

// internalOutboundAttemptActiveLocked requires muxReg and muxAttemptGate.
func (h *Hub) internalOutboundAttemptActiveLocked(
	ski string,
	metadata api.OutgoingAttemptMetadata,
) bool {
	service := h.remoteServices[ski]
	authority := h.outboundAuthorities[ski]
	if service == nil || !service.Trusted() || authority == nil ||
		metadata.Scope != internalOutgoingAttemptScope ||
		metadata.ControlEpoch != authority.epoch {
		return false
	}
	for registration := range h.outboundAttempts[ski] {
		if registration.metadata == metadata && registration.context.Err() == nil {
			return true
		}
	}
	return false
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

// releaseOutboundAttemptForConnectionLocked requires muxAttemptGate.
func (h *Hub) releaseOutboundAttemptForConnectionLocked(
	ski string,
	connection api.ShipConnectionInterface,
	metadata api.OutgoingAttemptMetadata,
) ([]*outboundAttemptRegistration, *outboundAttemptAuthority) {
	// Exact connection ownership prevents a stale close from releasing a newer
	// registration if an external gate ever reuses metadata.
	registrations := h.outboundAttempts[ski]
	var removed []*outboundAttemptRegistration
	var releasedAuthority *outboundAttemptAuthority
	for registration := range registrations {
		if registration.connection == connection && registration.metadata == metadata {
			delete(registrations, registration)
			removed = append(removed, registration)
			releasedAuthority = registration.authority
		}
	}
	if len(registrations) == 0 {
		delete(h.outboundAttempts, ski)
	}
	return removed, releasedAuthority
}

func cancelOutboundAttemptRegistrations(registrations []*outboundAttemptRegistration) {
	for _, registration := range registrations {
		registration.cancel()
	}
}

func (h *Hub) removeOutboundAttemptConnections(registrations []*outboundAttemptRegistration) {
	for _, registration := range registrations {
		if registration.connection != nil {
			h.removeExactConnection(registration.connection)
		}
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

	connections, cancellations, started := h.beginShutdown()
	if !started {
		return
	}
	cancelOutboundAttemptRegistrations(cancellations)

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

func (h *Hub) beginShutdown() (
	[]api.ShipConnectionInterface,
	[]*outboundAttemptRegistration,
	bool,
) {
	h.muxCon.Lock()
	if h.hasShutdown {
		h.muxCon.Unlock()
		return nil, nil, false
	}
	h.hasShutdown = true

	connections := make([]api.ShipConnectionInterface, 0, len(h.connections))
	for ski, connection := range h.connections {
		connections = append(connections, connection)
		delete(h.connections, ski)
	}
	h.muxCon.Unlock()

	h.muxAttemptGate.Lock()
	h.outboundShutdown = true
	h.outgoingGateEpoch++
	cancellations := h.removeAllOutboundAttemptRegistrationsLocked()
	h.muxAttemptGate.Unlock()

	return connections, cancellations, true
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
