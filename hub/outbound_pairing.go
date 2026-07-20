package hub

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
)

var (
	errInvalidRemoteSKI      = errors.New("remote SKI must contain 40 hexadecimal characters")
	errInvalidRemoteEndpoint = errors.New("remote endpoint is invalid")
	errRemoteNotAdmitted     = errors.New("remote is neither queued nor trusted")
	errOutboundGateRequired  = errors.New("outbound pairing requires an attempt gate")
)

var _ api.OutboundPairingController = (*Hub)(nil)

// QueueRemoteSKI admits one untrusted peer for a locally initiated pairing
// attempt. Durable trust remains owned by RegisterRemoteSKI.
func (h *Hub) QueueRemoteSKI(ski string) error {
	if h.configuredOutgoingAttemptGate() == nil {
		return errOutboundGateRequired
	}
	normalized, err := validOutboundSKI(ski)
	if err != nil {
		return err
	}
	service := h.ServiceForSKI(normalized)
	if service.Trusted() {
		return errors.New("remote is already trusted")
	}
	if !h.createOutboundAdmission(normalized, service) {
		return errOutboundGateRequired
	}
	if h.hubReader != nil {
		h.hubReader.ServicePairingDetailUpdate(normalized, service.ConnectionStateDetail())
	}
	if h.checkHasStarted() && h.mdns != nil {
		h.mdns.RequestMdnsEntries()
	}
	return nil
}

// ReportRemoteEndpoint provides endpoint evidence without changing pairing or
// trust state. Existing admission checks still gate connection initiation.
func (h *Hub) ReportRemoteEndpoint(ski string, endpoint api.RemoteEndpoint) error {
	if h.configuredOutgoingAttemptGate() == nil {
		return errOutboundGateRequired
	}
	normalized, err := validOutboundSKI(ski)
	if err != nil {
		return err
	}
	endpoint, err = validRemoteEndpoint(endpoint)
	if err != nil {
		return err
	}
	service := h.ServiceForSKI(normalized)
	if !service.Trusted() && service.ConnectionStateDetail().State() != api.ConnectionStateQueued {
		return errRemoteNotAdmitted
	}
	if !service.Trusted() && !h.hasCurrentOutboundAdmission(normalized) {
		return errRemoteNotAdmitted
	}
	entry := &api.MdnsEntry{
		Ski:  normalized,
		Host: endpoint.Host,
		Port: int(endpoint.Port),
		Path: endpoint.Path,
	}
	h.cacheRemoteEndpoint(entry)
	if !h.isSkiConnected(normalized) {
		h.coordinateConnectionInitations(normalized, entry)
	}
	return nil
}

func (h *Hub) cacheRemoteEndpoint(entry *api.MdnsEntry) {
	h.muxMdns.Lock()
	defer h.muxMdns.Unlock()
	for index, known := range h.knownMdnsEntries {
		if known != nil && util.NormalizeSKI(known.Ski) == entry.Ski {
			h.knownMdnsEntries[index] = entry
			return
		}
	}
	h.knownMdnsEntries = append(h.knownMdnsEntries, entry)
}

func validOutboundSKI(ski string) (string, error) {
	normalized := util.NormalizeSKI(strings.TrimSpace(ski))
	if len(normalized) != 40 {
		return "", errInvalidRemoteSKI
	}
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != 20 {
		return "", errInvalidRemoteSKI
	}
	return normalized, nil
}

func validRemoteEndpoint(endpoint api.RemoteEndpoint) (api.RemoteEndpoint, error) {
	endpoint.Host = normalizeOutgoingAttemptHost(strings.TrimSpace(endpoint.Host))
	endpoint.Path = strings.TrimSpace(endpoint.Path)
	if endpoint.Host == "" || endpoint.Port == 0 || !strings.HasPrefix(endpoint.Path, "/") {
		return api.RemoteEndpoint{}, errInvalidRemoteEndpoint
	}
	if strings.ContainsAny(endpoint.Host, "\x00/\\?#@") || strings.Contains(endpoint.Host, "://") ||
		strings.ContainsAny(endpoint.Path, "\x00\\?#") {
		return api.RemoteEndpoint{}, errInvalidRemoteEndpoint
	}
	for _, segment := range strings.Split(endpoint.Path, "/") {
		if segment == ".." {
			return api.RemoteEndpoint{}, errInvalidRemoteEndpoint
		}
	}
	if ip := net.ParseIP(endpoint.Host); ip != nil && (ip.IsUnspecified() || ip.IsMulticast()) {
		return api.RemoteEndpoint{}, errInvalidRemoteEndpoint
	}
	return endpoint, nil
}
