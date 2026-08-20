package hub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/cert"
	"github.com/Project-Helianthus/helianthus-ship-go/logging"
	"github.com/Project-Helianthus/helianthus-ship-go/ship"
	"github.com/Project-Helianthus/helianthus-ship-go/ws"
	"github.com/gorilla/websocket"
)

type outgoingAttemptDialer interface {
	DialContext(context.Context, string, http.Header) (*websocket.Conn, *http.Response, error)
}

type expectedSKIOutgoingAttemptDialer interface {
	DialContextExpectedSKI(context.Context, string, http.Header, string) (*websocket.Conn, *http.Response, error)
}

type websocketOutgoingAttemptDialer struct {
	dialer *websocket.Dialer
}

func (d *websocketOutgoingAttemptDialer) DialContext(
	ctx context.Context,
	url string,
	headers http.Header,
) (*websocket.Conn, *http.Response, error) {
	return d.dialer.DialContext(ctx, url, headers)
}

func (d *websocketOutgoingAttemptDialer) DialContextExpectedSKI(
	ctx context.Context,
	url string,
	headers http.Header,
	expectedSKI string,
) (*websocket.Conn, *http.Response, error) {
	clone := *d.dialer
	tlsConfig := d.dialer.TLSClientConfig.Clone()
	previousVerifier := tlsConfig.VerifyPeerCertificate
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if previousVerifier != nil {
			if err := previousVerifier(rawCerts, verifiedChains); err != nil {
				return err
			}
		}
		if len(rawCerts) == 0 {
			return errors.New("remote certificate is missing")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse remote certificate: %w", err)
		}
		observedSKI, err := cert.SkiFromCertificate(leaf)
		if err != nil {
			return fmt.Errorf("derive remote certificate SKI: %w", err)
		}
		if observedSKI != expectedSKI {
			return errors.New("remote certificate SKI does not match selected candidate")
		}
		return nil
	}
	clone.TLSClientConfig = tlsConfig
	return clone.DialContext(ctx, url, headers)
}

type outgoingAttemptDeniedError struct{}

func (outgoingAttemptDeniedError) Error() string       { return "outgoing attempt denied" }
func (outgoingAttemptDeniedError) AttemptDenied() bool { return true }

type inboundPairingDirectionHandoffError struct{}

func (inboundPairingDirectionHandoffError) Error() string {
	return "outgoing pairing direction handed off to authenticated inbound winner"
}

type outgoingConnectionRegistrationResult uint8

const (
	outgoingConnectionRegistrationRejected outgoingConnectionRegistrationResult = iota
	outgoingConnectionRegistrationAccepted
	outgoingConnectionRegistrationInboundHandoff
)

var errOutgoingAttemptFailed = errors.New("outgoing attempt failed")

const internalOutgoingAttemptScope = "ship.internal.reconnect"

type authorizedOutgoingAttempt struct {
	remoteSKI         string
	metadata          api.OutgoingAttemptMetadata
	context           context.Context
	registration      *outboundAttemptRegistration
	internal          bool
	terminal          sync.Once
	terminalSucceeded bool
}

func (a *authorizedOutgoingAttempt) terminalFailure(h *Hub) bool {
	if a == nil {
		return true
	}
	a.terminal.Do(func() {
		h.releaseOutboundAttemptRegistration(a.remoteSKI, a.registration)
		if a.internal {
			a.terminalSucceeded = true
		} else {
			a.terminalSucceeded = h.reportOutgoingAttemptTerminalFailure(a.remoteSKI, a.metadata)
		}
	})
	return a.terminalSucceeded
}

func (h *Hub) reportOutgoingAttemptTerminalFailure(remoteSKI string, metadata api.OutgoingAttemptMetadata) (reported bool) {
	reader, ok := h.hubReader.(api.OutgoingAttemptHubReaderInterface)
	if !ok || isNilOutgoingAttemptValue(reader) {
		return false
	}
	defer func() {
		if recover() != nil {
			reported = false
		}
	}()
	reader.OutgoingAttemptConnectionClosed(remoteSKI, false, metadata)
	return true
}

func newOutgoingAttemptDialer(certificate tls.Certificate) outgoingAttemptDialer {
	return &websocketOutgoingAttemptDialer{dialer: &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			// SHIP 12.1: all certificates are locally signed
			InsecureSkipVerify: true, // #nosec G402
			// SHIP 9.1: the ciphers are reported insecure but are defined to be used by SHIP
			CipherSuites: cert.CipherSuites, // #nosec G402
		},
		Subprotocols: []string{api.ShipWebsocketSubProtocol},
	}}
}

// Websocket connection handling
func (h *Hub) verifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	skiFound := false
	for _, v := range rawCerts {
		cerificate, err := x509.ParseCertificate(v)
		if err != nil {
			return err
		}

		if _, err := cert.SkiFromCertificate(cerificate); err == nil {
			skiFound = true
			break
		}
	}
	if !skiFound {
		return errors.New("no valid SKI provided in certificate")
	}

	return nil
}

// start the ship websocket server
func (h *Hub) startWebsocketServer() error {
	addr := fmt.Sprintf(":%d", h.port)
	logging.Log().Debug("starting websocket server on", addr)

	h.httpServer = &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: time.Duration(time.Second * 10),
		TLSConfig: &tls.Config{
			Certificates:          []tls.Certificate{h.certifciate},
			ClientAuth:            tls.RequireAnyClientCert, // SHIP 9: Client authentication is required
			CipherSuites:          cert.CipherSuites,        // #nosec G402 // SHIP 9.1: the ciphers are reported insecure but are defined to be used by SHIP
			VerifyPeerCertificate: h.verifyPeerCertificate,
			MinVersion:            tls.VersionTLS12, // SHIP 9: Mandatory TLS version
		},
	}

	go func() {
		if err := h.httpServer.ListenAndServeTLS("", ""); err != nil {
			logging.Log().Error("websocket server error:", err)
			// TODO: decide how to handle this case
		}
	}()

	return nil
}

// Connection Handling

// HTTP Server callback for handling incoming connection requests
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		ReadBufferSize:  ws.MaxMessageSize,
		WriteBufferSize: ws.MaxMessageSize,
		CheckOrigin:     func(r *http.Request) bool { return true },
		Subprotocols:    []string{api.ShipWebsocketSubProtocol}, // SHIP 10.2: Sub protocol "ship" is required
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logging.Log().Debug("error during connection upgrading:", err)
		return
	}

	// check if the client supports the ship sub protocol
	if conn.Subprotocol() != api.ShipWebsocketSubProtocol {
		logging.Log().Debug("client does not support the ship sub protocol")
		_ = conn.Close()
		return
	}

	// check if the clients certificate provides a SKI
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		logging.Log().Debug("client does not provide a certificate")
		_ = conn.Close()
		return
	}

	ski, err := cert.SkiFromCertificate(r.TLS.PeerCertificates[0])
	if err != nil {
		logging.Log().Debug(err)
		_ = conn.Close()
		return
	}

	// normalize the incoming SKI
	remoteService := api.NewServiceDetails(ski)
	logging.Log().Debug("incoming connection request from", remoteService.SKI())

	// Check if the remote service is paired
	service := h.ServiceForSKI(remoteService.SKI())
	connectionStateDetail := service.ConnectionStateDetail()
	remoteService = service

	if connectionStateDetail.State() == api.ConnectionStateQueued {
		reservation := h.reserveInboundPairingConnection(remoteService.SKI())
		if reservation == nil {
			_ = conn.Close()
			return
		}

		dataHandler := ws.NewWebsocketConnection(conn, remoteService.SKI())
		shipConnection := ship.NewConnectionHandler(h, dataHandler, ship.ShipRoleServer,
			h.localService.ShipID(), remoteService.SKI(), remoteService.ShipID())
		replaced, registered := h.registerReservedInboundPairingConnection(shipConnection, reservation)
		if !registered {
			h.abandonInboundPairingReservation(remoteService.SKI(), reservation)
			_ = conn.Close()
			return
		}
		if replaced != nil {
			replaced.CloseConnection(false, 0, "replaced by SHIP SKI ordering")
		}

		connectionStateDetail.SetState(api.ConnectionStateReceivedPairingRequest)
		h.publishPairingDetail(ski, connectionStateDetail)
		shipConnection.Run()
		return
	}
	if h.hasInboundPairingReservation(remoteService.SKI()) {
		_ = conn.Close()
		return
	}

	dataHandler := ws.NewWebsocketConnection(conn, remoteService.SKI())
	shipConnection := ship.NewConnectionHandler(h, dataHandler, ship.ShipRoleServer,
		h.localService.ShipID(), remoteService.SKI(), remoteService.ShipID())
	if !h.registerInboundConnection(shipConnection) {
		_ = conn.Close()
		return
	}
	shipConnection.Run()
}

// return if there is a connection for a SKI
func (h *Hub) isSkiConnected(ski string) bool {
	h.muxCon.Lock()
	defer h.muxCon.Unlock()

	// The connection with the higher SKI should retain the connection
	_, ok := h.connections[ski]
	return ok
}

// Connect to another EEBUS service
//
// returns error contains a reason for failing the connection or nil if no further tries should be processed
func (h *Hub) connectFoundService(
	remoteService *api.ServiceDetails,
	host,
	port,
	path string,
	requiredAuthority *outboundAttemptAuthority,
) error {
	return h.connectFoundServiceWithOptions(
		remoteService,
		host,
		port,
		path,
		"",
		true,
		false,
		requiredAuthority,
	)
}

func (h *Hub) connectFoundPairingCandidate(
	remoteService *api.ServiceDetails,
	host,
	port,
	path,
	expectedSKI string,
	candidateAuthority *outboundAttemptAuthority,
) error {
	if h.testHooks != nil && h.testHooks.beforePairingCandidateGate != nil {
		h.testHooks.beforePairingCandidateGate()
	}
	return h.connectFoundServiceWithLoggingOptions(
		remoteService,
		host,
		port,
		path,
		expectedSKI,
		false,
		true,
		candidateAuthority,
		"protected SHIP connection",
	)
}

func (h *Hub) connectFoundServiceWithOptions(
	remoteService *api.ServiceDetails,
	host,
	port,
	path,
	expectedSKI string,
	allowEmptyPathFallback bool,
	requirePairingApproval bool,
	requiredAuthority *outboundAttemptAuthority,
) error {
	return h.connectFoundServiceWithLoggingOptions(
		remoteService,
		host,
		port,
		path,
		expectedSKI,
		allowEmptyPathFallback,
		requirePairingApproval,
		requiredAuthority,
		"",
	)
}

func (h *Hub) connectFoundServiceWithLoggingOptions(
	remoteService *api.ServiceDetails,
	host,
	port,
	path,
	expectedSKI string,
	allowEmptyPathFallback bool,
	requirePairingApproval bool,
	requiredAuthority *outboundAttemptAuthority,
	sanitizedLogCategory string,
) error {
	if ski := remoteService.SKI(); ski != "" {
		h.muxCon.Lock()
		if h.hasShutdown {
			h.muxCon.Unlock()
			return outgoingAttemptDeniedError{}
		}
		connection, connected := h.connections[ski]
		reservation := h.inboundPairingReservations[ski]
		if connected || h.connectionsInitiating[ski] || reservation != nil {
			inboundPairingHandoff := expectedSKI == ski &&
				reservation != nil &&
				requiredAuthority != nil &&
				reservation.authority == requiredAuthority &&
				(reservation.winner == nil || connection == reservation.winner)
			h.muxCon.Unlock()
			if inboundPairingHandoff {
				return inboundPairingDirectionHandoffError{}
			}
			if expectedSKI != "" {
				return outgoingAttemptDeniedError{}
			}
			return nil
		}
		if h.connectionsInitiating == nil {
			h.connectionsInitiating = make(map[string]bool)
		}
		h.connectionsInitiating[ski] = true
		h.muxCon.Unlock()

		defer func() {
			h.muxCon.Lock()
			delete(h.connectionsInitiating, ski)
			h.muxCon.Unlock()
		}()
	}

	if sanitizedLogCategory != "" {
		logging.Log().Debug("initiating " + sanitizedLogCategory)
	} else {
		logging.Log().Debugf("initiating connection to %s at %s:%s%s", remoteService.SKI(), host, port, path)
	}

	conn, resp, attempt, err := h.gatedDialContextWithExpectedSKI(remoteService, host, port, path, expectedSKI, requiredAuthority)
	if err == nil {
		if resp != nil && resp.Body != nil {
			defer func() {
				_ = resp.Body.Close()
			}()
		}
	} else if allowEmptyPathFallback {
		if isOutgoingAttemptDenied(err) {
			return err
		}
		if attempt != nil && resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		conn, resp, attempt, err = h.gatedDialContextWithExpectedSKI(
			remoteService,
			host,
			port,
			"",
			"",
			requiredAuthority,
		)
		if err != nil {
			return err
		}
		if resp != nil && resp.Body != nil {
			defer func() {
				_ = resp.Body.Close()
			}()
		}
	} else {
		return err
	}

	failBeforeConnection := func(connectionErr error) error {
		if conn != nil {
			_ = conn.Close()
		}
		if !attempt.terminalFailure(h) {
			return outgoingAttemptDeniedError{}
		}
		return connectionErr
	}

	if attempt != nil && attempt.context.Err() != nil {
		return failBeforeConnection(outgoingAttemptDeniedError{})
	}

	tlsConn, ok := conn.UnderlyingConn().(*tls.Conn)
	if !ok {
		return failBeforeConnection(errOutgoingAttemptFailed)
	}
	remoteCerts := tlsConn.ConnectionState().PeerCertificates

	if len(remoteCerts) == 0 || remoteCerts[0].SubjectKeyId == nil {
		// Close connection as we couldn't get the remote SKI
		errorString := fmt.Sprintf("closing connection to %s: could not get remote SKI from certificate", remoteService.SKI())
		return failBeforeConnection(errors.New(errorString))
	}

	if _, err := cert.SkiFromCertificate(remoteCerts[0]); err != nil {
		// Close connection as the remote SKI can't be correct
		errorString := fmt.Sprintf("closing connection to %s: %s", remoteService.SKI(), err)
		return failBeforeConnection(errors.New(errorString))
	}

	remoteSKI := fmt.Sprintf("%0x", remoteCerts[0].SubjectKeyId)

	if remoteSKI != remoteService.SKI() {
		errorString := fmt.Sprintf("closing connection to %s: SKI does not match %s", remoteService.SKI(), remoteSKI)
		return failBeforeConnection(errors.New(errorString))
	}

	if !h.keepThisConnection(conn, false, remoteService) {
		errorString := fmt.Sprintf("closing connection to %s: ignoring this connection", remoteService.SKI())
		if !attempt.terminalFailure(h) {
			return outgoingAttemptDeniedError{}
		}
		return errors.New(errorString)
	}

	dataHandler := ws.NewWebsocketConnection(conn, remoteService.SKI())
	if attempt.context.Err() != nil {
		return failBeforeConnection(outgoingAttemptDeniedError{})
	}
	shipConnection, configurationErr := ship.NewOutgoingConnectionHandler(
		&outgoingAttemptInfoProvider{hub: h, registration: attempt.registration},
		dataHandler,
		ship.ShipRoleClient,
		h.localService.ShipID(),
		remoteService.SKI(),
		remoteService.ShipID(),
		ship.OutgoingAttemptConnectionConfiguration{
			Metadata:               attempt.metadata,
			Context:                attempt.context,
			RequirePairingApproval: requirePairingApproval,
		},
	)
	if configurationErr != nil {
		return failBeforeConnection(errOutgoingAttemptFailed)
	}
	if !h.bindOutboundAttemptConnection(remoteService.SKI(), attempt.registration, shipConnection) {
		return failBeforeConnection(outgoingAttemptDeniedError{})
	}

	registrationResult := h.registerOutgoingConnection(
		shipConnection,
		attempt.context,
		requiredAuthority,
	)
	if registrationResult != outgoingConnectionRegistrationAccepted {
		shipConnection.CloseConnection(false, 0, "connection registration rejected")
		if registrationResult == outgoingConnectionRegistrationInboundHandoff {
			return inboundPairingDirectionHandoffError{}
		}
		return outgoingAttemptDeniedError{}
	}
	shipConnection.Run()
	if attempt.context.Err() != nil {
		return outgoingAttemptDeniedError{}
	}

	return nil
}

func (h *Hub) gatedDialContextWithExpectedSKI(
	remoteService *api.ServiceDetails,
	host,
	port,
	path,
	expectedSKI string,
	requiredAuthority *outboundAttemptAuthority,
) (connection *websocket.Conn, response *http.Response, attempt *authorizedOutgoingAttempt, err error) {
	if remoteService == nil {
		return nil, nil, nil, outgoingAttemptDeniedError{}
	}
	host, validHost := validatedOutgoingAttemptHost(host)
	parsedPort, parseErr := strconv.ParseUint(port, 10, 16)
	if !validHost || parseErr != nil || parsedPort == 0 {
		return nil, nil, nil, outgoingAttemptDeniedError{}
	}

	gate, gateGeneration, authority, active := h.outgoingAttemptGateSnapshot(remoteService, requiredAuthority)
	if !active {
		return nil, nil, nil, outgoingAttemptDeniedError{}
	}
	permit := api.OutgoingAttemptPermit{Context: context.Background()}
	address := (&url.URL{
		Scheme: "wss",
		Host:   net.JoinHostPort(host, port),
		Path:   path,
	}).String()
	defer func() {
		if recovered := recover(); recovered != nil {
			if attempt == nil {
				panic(recovered)
			}
			if connection != nil {
				_ = connection.Close()
			}
			terminalReported := attempt.terminalFailure(h)
			connection = nil
			response = nil
			if terminalReported {
				err = errOutgoingAttemptFailed
			} else {
				err = outgoingAttemptDeniedError{}
			}
		}
	}()
	if gate != nil {
		if isNilOutgoingAttemptValue(gate) {
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}

		request := api.OutgoingAttemptRequest{
			RemoteSKI: remoteService.SKI(),
			Endpoint: api.OutgoingAttemptEndpoint{
				Host: host,
				Port: uint16(parsedPort),
			},
			Path: path,
		}
		handle, prepareErr := prepareOutgoingAttempt(gate, request)
		if prepareErr != nil {
			if !isNilOutgoingAttemptValue(handle) {
				abortOutgoingAttempt(gate, handle)
			}
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}
		if isNilOutgoingAttemptValue(handle) {
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}

		expectedMetadata, expectedContext, validHandle := outgoingAttemptHandleSnapshot(handle)
		if !validHandle {
			abortOutgoingAttempt(gate, handle)
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}

		var authorizeErr error
		permit, authorizeErr = authorizeOutgoingAttempt(gate, handle)
		if authorizeErr != nil {
			abortOutgoingAttempt(gate, handle)
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}
		switch permit.Decision {
		case api.OutgoingAttemptDecisionDeny:
			return nil, nil, nil, outgoingAttemptDeniedError{}
		case api.OutgoingAttemptDecisionPermit:
			attempt = &authorizedOutgoingAttempt{
				remoteSKI: remoteService.SKI(),
				metadata:  expectedMetadata,
				context:   expectedContext,
			}
			if permit.Reason != api.OutgoingAttemptReasonAuthorized ||
				permit.Metadata != expectedMetadata ||
				!sameOutgoingAttemptContext(permit.Context, expectedContext) {
				attempt.terminalFailure(h)
				return nil, nil, attempt, outgoingAttemptDeniedError{}
			}
		default:
			abortOutgoingAttempt(gate, handle)
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}
		registration, registered := h.registerOutboundAttemptForLaunch(
			remoteService.SKI(),
			gateGeneration,
			authority,
			expectedMetadata,
			permit.Context,
		)
		if !registered {
			attempt.terminalFailure(h)
			return nil, nil, attempt, outgoingAttemptDeniedError{}
		}
		attempt.context = registration.context
		attempt.registration = registration
		permit.Context = registration.context
	} else {
		registration, metadata, registered := h.registerInternalOutboundAttemptForLaunch(
			remoteService.SKI(),
			authority,
		)
		if !registered {
			return nil, nil, nil, outgoingAttemptDeniedError{}
		}
		attempt = &authorizedOutgoingAttempt{
			remoteSKI:    remoteService.SKI(),
			metadata:     metadata,
			context:      registration.context,
			registration: registration,
			internal:     true,
		}
		permit.Context = registration.context
	}

	if expectedSKI == "" {
		connection, response, err = h.dialer.DialContext(permit.Context, address, nil)
	} else if pinnedDialer, ok := h.dialer.(expectedSKIOutgoingAttemptDialer); ok {
		connection, response, err = pinnedDialer.DialContextExpectedSKI(permit.Context, address, nil, expectedSKI)
	} else {
		err = errors.New("outgoing dialer does not support expected-SKI pinning")
	}
	if attempt == nil {
		return connection, response, nil, err
	}
	if permit.Context.Err() != nil {
		if connection != nil {
			_ = connection.Close()
		}
		attempt.terminalFailure(h)
		return nil, response, attempt, outgoingAttemptDeniedError{}
	}
	if err != nil {
		if connection != nil {
			_ = connection.Close()
		}
		if !attempt.terminalFailure(h) {
			return nil, response, attempt, outgoingAttemptDeniedError{}
		}
		return nil, response, attempt, err
	}
	if connection == nil {
		if !attempt.terminalFailure(h) {
			return nil, response, attempt, outgoingAttemptDeniedError{}
		}
		return nil, response, attempt, errOutgoingAttemptFailed
	}
	return connection, response, attempt, nil
}

func prepareOutgoingAttempt(
	gate api.OutgoingAttemptGate,
	request api.OutgoingAttemptRequest,
) (handle api.OutgoingAttemptHandle, err error) {
	defer func() {
		if recover() != nil {
			handle = nil
			err = outgoingAttemptDeniedError{}
		}
	}()
	return gate.Prepare(request)
}

func authorizeOutgoingAttempt(
	gate api.OutgoingAttemptGate,
	handle api.OutgoingAttemptHandle,
) (permit api.OutgoingAttemptPermit, err error) {
	defer func() {
		if recover() != nil {
			permit = api.OutgoingAttemptPermit{}
			err = outgoingAttemptDeniedError{}
		}
	}()
	return gate.AuthorizeLaunch(handle)
}

func abortOutgoingAttempt(gate api.OutgoingAttemptGate, handle api.OutgoingAttemptHandle) {
	defer func() {
		_ = recover()
	}()
	_, _ = gate.AbortPrepared(handle)
}

func outgoingAttemptHandleSnapshot(
	handle api.OutgoingAttemptHandle,
) (metadata api.OutgoingAttemptMetadata, attemptContext context.Context, valid bool) {
	defer func() {
		if recover() != nil {
			metadata = api.OutgoingAttemptMetadata{}
			attemptContext = nil
			valid = false
		}
	}()
	metadata = api.OutgoingAttemptMetadata{
		AttemptID:    handle.AttemptID(),
		Scope:        handle.Scope(),
		ControlEpoch: handle.ControlEpoch(),
	}
	attemptContext = handle.Context()
	valid = metadata.AttemptID != "" && metadata.Scope != "" && !isNilOutgoingAttemptValue(attemptContext)
	return metadata, attemptContext, valid
}

func sameOutgoingAttemptContext(first, second context.Context) bool {
	if isNilOutgoingAttemptValue(first) || isNilOutgoingAttemptValue(second) {
		return false
	}
	firstType := reflect.TypeOf(first)
	if firstType != reflect.TypeOf(second) || !firstType.Comparable() {
		return false
	}
	return first == second
}

func isNilOutgoingAttemptValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func normalizeOutgoingAttemptHost(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return host
}

func validatedOutgoingAttemptHost(host string) (string, bool) {
	host = normalizeOutgoingAttemptHost(host)
	if host == "" {
		return "", false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address, valid := normalizeConnectionAddress(address)
		if !valid {
			return "", false
		}
		return address.String(), true
	}
	// A percent sign is meaningful only as an IPv6 zone separator. Reject it
	// on an otherwise unparsable host instead of passing ambiguous input to URL
	// construction or DNS.
	if strings.Contains(host, "%") || strings.ContainsAny(host, "[]:") {
		return "", false
	}
	return host, true
}

func isOutgoingAttemptDenied(err error) bool {
	var denied outgoingAttemptDeniedError
	return errors.As(err, &denied)
}

// prevent double connections
// only keep the connection initiated by the higher SKI
//
// returns true if this connection is fine to be continue
// returns false if this connection should not be established or kept
func (h *Hub) keepThisConnection(conn *websocket.Conn, incomingRequest bool, remoteService *api.ServiceDetails) bool {
	// SHIP 12.2.2 defines:
	// prevent double connections with SKI Comparison
	// the node with the hight SKI value kees the most recent connection and
	// and closes all other connections to the same SHIP node
	//
	// This is hard to implement without any flaws. Therefor I chose a
	// different approach: The connection initiated by the higher SKI will be kept

	remoteSKI := remoteService.SKI()
	existingC, outgoingInitiating := h.connectionStateForSKI(remoteSKI)
	if existingC == nil && (!incomingRequest || !outgoingInitiating) {
		return true
	}

	keep := false
	if incomingRequest {
		keep = remoteSKI > h.localService.SKI()
	} else {
		keep = h.localService.SKI() > remoteSKI
	}

	if keep {
		if existingC == nil {
			return true
		}
		// we have an existing connection
		// so keep the new (most recent) and close the old one
		logging.Log().Debug("closing existing double connection")
		go existingC.CloseConnection(false, 0, "")
	} else {
		connType := "incoming"
		if !incomingRequest {
			connType = "outgoing"
		}
		logging.Log().Debugf("closing %s double connection, as the existing connection will be used", connType)
		if conn != nil {
			go h.sendWSCloseMessage(conn)
		}
	}

	return keep
}

func (h *Hub) sendWSCloseMessage(conn *websocket.Conn) {
	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "double connection"))
	<-time.After(time.Millisecond * 100)
	_ = conn.Close()
}

// coordinate connection initiation attempts to a remove service
func (h *Hub) coordinateConnectionInitations(ski string, entry *api.MdnsEntry) {
	if h.isConnectionAttemptRunning(ski) {
		return
	}

	h.setConnectionAttemptRunning(ski, true)

	counter, duration := h.getConnectionInitiationDelayTime(ski)

	service := h.ServiceForSKI(ski)
	if service.ConnectionStateDetail().State() == api.ConnectionStateQueued {
		go h.prepareConnectionInitation(ski, counter, entry)
		return
	}

	logging.Log().Debugf("delaying connection to %s by %s to minimize double connection probability", ski, duration)

	// we do not stop this thread and just let the timer run out
	// otherwise we would need a stop channel for each ski
	go func() {
		// wait
		<-time.After(duration)

		h.prepareConnectionInitation(ski, counter, entry)
	}()
}

// invoked by coordinateConnectionInitations either with a delay or directly
// when initating a pairing process
func (h *Hub) prepareConnectionInitation(ski string, counter int, entry *api.MdnsEntry) {
	h.setConnectionAttemptRunning(ski, false)

	// check if the current counter is still the same, otherwise this counter is irrelevant
	currentCounter, exists := h.getCurrentConnectionAttemptCounter(ski)
	if !exists || currentCounter != counter {
		return
	}

	// connection attempt is not relevant if the device is no longer paired
	// or it is not queued for pairing
	pairingState := h.ServiceForSKI(ski).ConnectionStateDetail().State()
	if !h.IsRemoteServiceForSKIPaired(ski) && pairingState != api.ConnectionStateQueued {
		return
	}

	// connection attempt is not relevant if the device is already connected
	if h.isSkiConnected(ski) {
		return
	}

	// now initiate the connection
	// check if the remoteService still exists
	service := h.ServiceForSKI(ski)

	if success, err := h.initateConnectionWithError(service, entry); !success && !isOutgoingAttemptDenied(err) {
		h.checkAutoReannounce()
	}
}

func (h *Hub) initateConnectionWithError(remoteService *api.ServiceDetails, entry *api.MdnsEntry) (bool, error) {
	var err error

	requiredAuthority, eligible := h.outboundReconnectAuthority(remoteService)
	if !eligible {
		return false, nil
	}

	addresses := orderedConnectionAddresses(entry.ScopedAddresses, entry.Addresses)
	for _, address := range addresses {
		logging.Log().Debug("trying to connect to", remoteService.SKI(), "at", address)
		addressValue := address.String()
		if address.Is6() {
			addressValue = "[" + address.String() + "]"
		}
		if err = h.connectFoundService(
			remoteService,
			addressValue,
			strconv.Itoa(entry.Port),
			entry.Path,
			requiredAuthority,
		); err != nil {
			if isOutgoingAttemptDenied(err) {
				return false, err
			}
			logging.Log().Debug("connection to", remoteService.SKI(), "failed: ", err)
		} else {
			return true, nil
		}
	}

	if entry.Host != "" &&
		!mdnsEntryHasUnscopedLinkLocal(entry) &&
		!hostMatchesConnectionAddress(entry.Host, addresses) {
		logging.Log().Debug("trying to connect to", remoteService.SKI(), "at", entry.Host)
		if err = h.connectFoundService(
			remoteService,
			entry.Host,
			strconv.Itoa(entry.Port),
			entry.Path,
			requiredAuthority,
		); err != nil {
			if isOutgoingAttemptDenied(err) {
				return false, err
			}
			logging.Log().Debugf("connection to %s failed: %s", remoteService.SKI(), err)
		} else {
			return true, nil
		}
	}

	return false, err
}

func orderedConnectionAddresses(scoped []netip.Addr, legacy []net.IP) []netip.Addr {
	ipv4 := make([]netip.Addr, 0, len(scoped)+len(legacy))
	ipv6 := make([]netip.Addr, 0, len(scoped)+len(legacy))
	seen := make(map[netip.Addr]struct{}, len(scoped)+len(legacy))
	appendAddress := func(address netip.Addr) {
		address, valid := normalizeConnectionAddress(address)
		if !valid {
			return
		}
		if _, exists := seen[address]; exists {
			return
		}
		seen[address] = struct{}{}
		if address.Is4() {
			ipv4 = append(ipv4, address)
		} else {
			ipv6 = append(ipv6, address)
		}
	}
	for _, address := range scoped {
		appendAddress(address)
	}
	for _, address := range legacy {
		value, ok := netip.AddrFromSlice(address)
		if ok {
			appendAddress(value)
		}
	}
	sort.Slice(ipv4, func(left, right int) bool { return ipv4[left].Compare(ipv4[right]) < 0 })
	sort.Slice(ipv6, func(left, right int) bool { return ipv6[left].Compare(ipv6[right]) < 0 })
	return append(ipv4, ipv6...)
}

func normalizeConnectionAddress(address netip.Addr) (netip.Addr, bool) {
	if !address.IsValid() {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	if address.IsUnspecified() || address.IsMulticast() {
		return netip.Addr{}, false
	}
	if address.Is6() && address.IsLinkLocalUnicast() {
		if address.Zone() == "" {
			return netip.Addr{}, false
		}
		return address, true
	}
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	return address, true
}

func hostMatchesConnectionAddress(host string, addresses []netip.Addr) bool {
	host, valid := validatedOutgoingAttemptHost(host)
	if !valid {
		return false
	}
	hostAddress, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if address == hostAddress {
			return true
		}
	}
	return false
}

// increase the connection attempt counter for the given ski
func (h *Hub) increaseConnectionAttemptCounter(ski string) int {
	h.muxConAttempt.Lock()
	defer h.muxConAttempt.Unlock()

	currentCounter := 0
	if counter, exists := h.connectionAttemptCounter[ski]; exists {
		currentCounter = counter + 1

		if currentCounter >= len(connectionInitiationDelayTimeRanges)-1 {
			currentCounter = len(connectionInitiationDelayTimeRanges) - 1
		}
	}

	h.connectionAttemptCounter[ski] = currentCounter

	return currentCounter
}

// remove the connection attempt counter for the given ski
func (h *Hub) removeConnectionAttemptCounter(ski string) {
	h.muxConAttempt.Lock()
	defer h.muxConAttempt.Unlock()

	delete(h.connectionAttemptCounter, ski)
}

// get the current attempt counter
func (h *Hub) getCurrentConnectionAttemptCounter(ski string) (int, bool) {
	h.muxConAttempt.Lock()
	defer h.muxConAttempt.Unlock()

	counter, exists := h.connectionAttemptCounter[ski]

	return counter, exists
}

// get the connection initiation delay time range for a given ski
// returns the current counter and the duration
func (h *Hub) getConnectionInitiationDelayTime(ski string) (int, time.Duration) {
	counter := h.increaseConnectionAttemptCounter(ski)

	h.muxConAttempt.Lock()
	defer h.muxConAttempt.Unlock()

	timeRange := connectionInitiationDelayTimeRanges[counter]

	// get range in Milliseconds
	min := timeRange.min * 1000
	max := timeRange.max * 1000

	// #nosec G404
	duration := rand.Intn(max-min) + min

	return counter, time.Duration(duration) * time.Millisecond
}

// set if a connection attempt is running/in progress
func (h *Hub) setConnectionAttemptRunning(ski string, active bool) {
	h.muxConAttempt.Lock()
	defer h.muxConAttempt.Unlock()

	h.connectionAttemptRunning[ski] = active
}

// return if a connection attempt is runnning/in progress
func (h *Hub) isConnectionAttemptRunning(ski string) bool {
	h.muxConAttempt.Lock()
	defer h.muxConAttempt.Unlock()

	running, exists := h.connectionAttemptRunning[ski]
	if !exists {
		return false
	}

	return running
}

// RetryTrustedRemote starts one explicit reconnect path for an exact trusted,
// disconnected remote. The selected endpoint is retained by the Hub from the
// latest applied mDNS snapshot; callers cannot supply or replace it.
func (h *Hub) RetryTrustedRemote(expectedSKI string) error {
	ski, err := validPairingCandidateSKI(expectedSKI)
	if err != nil {
		return err
	}

	h.muxReg.Lock()
	if h.mdnsAppliedAdmission != h.mdnsSnapshotAdmission.Load() {
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteObservationStale
	}
	observation, observed := h.visibleTrustedRemoteObservations[ski]
	if !observed {
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryUnavailable
	}
	service := h.remoteServices[ski]
	if service == nil || !service.Trusted() {
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryNotTrusted
	}
	if h.activeTrustedRemoteRetries[ski] != nil {
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryBusy
	}

	h.muxCon.Lock()
	if h.hasShutdown {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryUnavailable
	}
	if h.connections[ski] != nil {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryConnected
	}
	if h.connectionsInitiating[ski] || h.inboundPairingReservations[ski] != nil {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryBusy
	}

	h.muxConAttempt.Lock()
	if h.connectionAttemptRunning[ski] {
		h.muxConAttempt.Unlock()
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryBusy
	}
	h.connectionAttemptRunning[ski] = true

	h.muxAttemptGate.Lock()
	if h.outboundShutdown {
		h.muxAttemptGate.Unlock()
		h.connectionAttemptRunning[ski] = false
		h.muxConAttempt.Unlock()
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return api.ErrTrustedRemoteRetryUnavailable
	}
	active := &activeTrustedRemoteRetry{
		service:     service,
		authority:   h.currentOutboundAuthorityLocked(ski),
		observation: observation,
	}
	h.activeTrustedRemoteRetries[ski] = active
	h.muxAttemptGate.Unlock()
	h.muxConAttempt.Unlock()
	h.muxCon.Unlock()
	h.muxReg.Unlock()

	h.launchTrustedRemoteRetry(active)
	return nil
}

func (h *Hub) launchTrustedRemoteRetry(active *activeTrustedRemoteRetry) {
	run := func() { h.runTrustedRemoteRetry(active) }
	if h.testHooks != nil && h.testHooks.launchTrustedRemoteRetry != nil {
		h.testHooks.launchTrustedRemoteRetry(run)
		return
	}
	go run()
}

func (h *Hub) runTrustedRemoteRetry(active *activeTrustedRemoteRetry) {
	if active == nil || active.service == nil {
		return
	}
	ski := active.service.SKI()
	if !h.trustedRemoteRetryStillCurrent(ski, active) {
		h.finishTrustedRemoteRetry(ski, active)
		return
	}

	if active.observation.host != "" {
		_ = h.connectFoundServiceWithLoggingOptions(
			active.service,
			active.observation.host,
			strconv.Itoa(active.observation.port),
			active.observation.path,
			"",
			false,
			false,
			active.authority,
			"trusted remote retry",
		)
	}
	h.finishTrustedRemoteRetry(ski, active)
}

func (h *Hub) trustedRemoteRetryStillCurrent(ski string, active *activeTrustedRemoteRetry) bool {
	h.muxReg.Lock()
	defer h.muxReg.Unlock()
	if h.activeTrustedRemoteRetries[ski] != active ||
		h.mdnsAppliedAdmission != h.mdnsSnapshotAdmission.Load() ||
		active.service != h.remoteServices[ski] ||
		!active.service.Trusted() {
		return false
	}
	observation, exists := h.visibleTrustedRemoteObservations[ski]
	if !exists || observation.revision != active.observation.revision ||
		observation.admission != active.observation.admission {
		return false
	}

	h.muxCon.Lock()
	defer h.muxCon.Unlock()
	if h.hasShutdown || h.connections[ski] != nil ||
		h.connectionsInitiating[ski] || h.inboundPairingReservations[ski] != nil {
		return false
	}

	h.muxAttemptGate.Lock()
	defer h.muxAttemptGate.Unlock()
	return !h.outboundShutdown && h.outboundAuthorities[ski] == active.authority
}

func trustedRemoteRetryHost(entry *api.MdnsEntry) (string, bool) {
	if entry == nil {
		return "", false
	}
	if address, ok := pairingCandidateAddress(entry.ScopedAddresses, entry.Addresses); ok {
		return address, true
	}
	if mdnsEntryHasUnscopedLinkLocal(entry) {
		return "", false
	}
	host, valid := validatedOutgoingAttemptHost(entry.Host)
	if !valid {
		return "", false
	}
	return host, true
}

func mdnsEntryHasUnscopedLinkLocal(entry *api.MdnsEntry) bool {
	if entry == nil {
		return false
	}
	if entry.UnscopedLinkLocalObserved {
		return true
	}
	for _, address := range entry.ScopedAddresses {
		if address.Is6() && address.IsLinkLocalUnicast() && address.Zone() == "" {
			return true
		}
	}
	for _, address := range entry.Addresses {
		if address != nil && address.To4() == nil && address.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func (h *Hub) finishTrustedRemoteRetry(ski string, active *activeTrustedRemoteRetry) {
	h.muxReg.Lock()
	if h.activeTrustedRemoteRetries[ski] != active {
		h.muxReg.Unlock()
		return
	}
	delete(h.activeTrustedRemoteRetries, ski)
	h.muxReg.Unlock()
	h.setConnectionAttemptRunning(ski, false)
}

// register a new ship Connection
func (h *Hub) registerConnection(connection api.ShipConnectionInterface) bool {
	remoteSKI := connection.RemoteSKI()

	h.muxCon.Lock()
	if h.hasShutdown {
		h.muxCon.Unlock()
		connection.CloseConnection(false, 0, "hub shutdown")
		return false
	}
	h.connections[remoteSKI] = connection
	h.muxCon.Unlock()
	return true
}

func (h *Hub) registerInboundConnection(connection api.ShipConnectionInterface) bool {
	remoteSKI := connection.RemoteSKI()

	h.muxCon.Lock()
	if h.hasShutdown {
		h.muxCon.Unlock()
		return false
	}
	existing := h.connections[remoteSKI]
	if (existing != nil || h.connectionsInitiating[remoteSKI]) &&
		remoteSKI <= h.localService.SKI() {
		h.muxCon.Unlock()
		return false
	}
	if existing != nil &&
		h.supersededConnectionCountForSKILocked(remoteSKI) >= maximumSupersededConnectionsPerSKI {
		h.muxCon.Unlock()
		return false
	}
	h.connections[remoteSKI] = connection
	if existing != nil {
		h.supersededConnections[existing] = struct{}{}
	}
	h.muxCon.Unlock()

	if existing != nil {
		h.blockOutboundAttemptCallbacks(existing)
		existing.CloseConnection(false, 0, "replaced by SHIP SKI ordering")
	}
	return true
}

func (h *Hub) reserveInboundPairingConnection(ski string) *inboundPairingReservation {
	h.muxReg.Lock()
	h.muxCon.Lock()
	if h.hasShutdown || h.inboundPairingReservations[ski] != nil {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return nil
	}
	if h.connectionsInitiating[ski] && ski <= h.localService.SKI() {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return nil
	}
	existing := h.connections[ski]
	if existing != nil && ski <= h.localService.SKI() {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return nil
	}
	activeCandidate := h.activePairingCandidates[ski]
	reservation := &inboundPairingReservation{
		replaced:  existing,
		candidate: activeCandidate,
	}
	if activeCandidate != nil {
		reservation.authority = activeCandidate.authority
	}
	h.inboundPairingReservations[ski] = reservation
	h.muxCon.Unlock()
	h.muxReg.Unlock()
	return reservation
}

func (h *Hub) registerReservedInboundPairingConnection(
	connection api.ShipConnectionInterface,
	reservation *inboundPairingReservation,
) (api.ShipConnectionInterface, bool) {
	if reservation == nil {
		return nil, false
	}
	remoteSKI := connection.RemoteSKI()
	h.muxReg.Lock()
	if reservation.candidate != nil && h.mdnsAppliedAdmission != h.mdnsSnapshotAdmission.Load() {
		h.muxReg.Unlock()
		return nil, false
	}
	h.muxCon.Lock()
	activeCandidate := h.activePairingCandidates[remoteSKI]
	candidateCurrent := reservation.candidate == nil ||
		(activeCandidate == reservation.candidate && activeCandidate != nil &&
			activeCandidate.authority == reservation.authority)
	if h.hasShutdown || h.inboundPairingReservations[remoteSKI] != reservation ||
		!candidateCurrent ||
		reservation.winner != nil ||
		h.connections[remoteSKI] != reservation.replaced ||
		(reservation.replaced != nil &&
			h.supersededConnectionCountForSKILocked(remoteSKI) >= maximumSupersededConnectionsPerSKI) {
		h.muxCon.Unlock()
		h.muxReg.Unlock()
		return nil, false
	}
	existing := h.connections[remoteSKI]
	h.connections[remoteSKI] = connection
	reservation.winner = connection
	if existing != nil {
		h.supersededConnections[existing] = struct{}{}
	}
	h.muxCon.Unlock()
	h.muxReg.Unlock()
	h.blockOutboundAttemptCallbacks(existing)
	return existing, true
}

func (h *Hub) supersededConnectionCountForSKILocked(ski string) int {
	count := 0
	for connection := range h.supersededConnections {
		if connection.RemoteSKI() == ski {
			count++
		}
	}
	return count
}

func (h *Hub) blockOutboundAttemptCallbacks(
	connection api.ShipConnectionInterface,
) {
	if connection == nil {
		return
	}
	remoteSKI := connection.RemoteSKI()
	h.muxAttemptGate.RLock()
	registrations := make([]*outboundAttemptRegistration, 0, len(h.outboundAttempts[remoteSKI]))
	for registration := range h.outboundAttempts[remoteSKI] {
		if registration.connection == connection {
			registrations = append(registrations, registration)
		}
	}
	h.muxAttemptGate.RUnlock()
	for _, registration := range registrations {
		registration.blockCallbacksAndWait()
	}
}

func (h *Hub) hasInboundPairingReservation(ski string) bool {
	h.muxCon.Lock()
	defer h.muxCon.Unlock()
	return h.inboundPairingReservations[ski] != nil
}

func (h *Hub) abandonInboundPairingReservation(ski string, reservation *inboundPairingReservation) {
	var retiredCandidate *activePairingCandidate
	var retiredAuthority *outboundAttemptAuthority
	h.muxCon.Lock()
	if h.inboundPairingReservations[ski] == reservation && reservation.winner == nil {
		delete(h.inboundPairingReservations, ski)
		replacedStillCurrent := reservation.replaced != nil &&
			h.connections[ski] == reservation.replaced
		if !replacedStillCurrent {
			retiredCandidate = reservation.candidate
			retiredAuthority = reservation.authority
		}
	}
	h.muxCon.Unlock()
	if retiredCandidate != nil && retiredAuthority != nil {
		h.retirePairingCandidate(ski, retiredCandidate, retiredAuthority)
	}
}

func (h *Hub) registerOutgoingConnection(
	connection api.ShipConnectionInterface,
	attemptContext context.Context,
	requiredAuthority *outboundAttemptAuthority,
) outgoingConnectionRegistrationResult {
	remoteSKI := connection.RemoteSKI()

	h.muxCon.Lock()
	if h.hasShutdown || attemptContext.Err() != nil {
		h.muxCon.Unlock()
		return outgoingConnectionRegistrationRejected
	}
	if reservation := h.inboundPairingReservations[remoteSKI]; reservation != nil {
		if requiredAuthority != nil && reservation.authority == requiredAuthority {
			h.supersededConnections[connection] = struct{}{}
			h.muxCon.Unlock()
			return outgoingConnectionRegistrationInboundHandoff
		}
		h.muxCon.Unlock()
		return outgoingConnectionRegistrationRejected
	}
	existing := h.connections[remoteSKI]
	if existing != nil {
		if h.localService.SKI() <= remoteSKI {
			h.supersededConnections[connection] = struct{}{}
			h.muxCon.Unlock()
			return outgoingConnectionRegistrationInboundHandoff
		}
		if h.supersededConnectionCountForSKILocked(remoteSKI) >= maximumSupersededConnectionsPerSKI {
			h.muxCon.Unlock()
			return outgoingConnectionRegistrationRejected
		}
		h.supersededConnections[existing] = struct{}{}
	}
	h.connections[remoteSKI] = connection
	h.muxCon.Unlock()
	if existing != nil {
		h.blockOutboundAttemptCallbacks(existing)
		existing.CloseConnection(false, 0, "replaced by SHIP SKI ordering")
	}
	return outgoingConnectionRegistrationAccepted
}

// return the connection for a specific SKI
func (h *Hub) connectionForSKI(ski string) api.ShipConnectionInterface {
	connection, _ := h.connectionStateForSKI(ski)
	return connection
}

func (h *Hub) connectionStateForSKI(ski string) (api.ShipConnectionInterface, bool) {
	h.muxCon.Lock()
	defer h.muxCon.Unlock()

	return h.connections[ski], h.connectionsInitiating[ski]
}
