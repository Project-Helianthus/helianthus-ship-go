package mdns

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

// ConfigureListenerPolicy stores a validated scoped-discovery policy without
// performing interface lookup, network I/O, or starting goroutines.
func (m *MdnsManager) ConfigureListenerPolicy(policy api.ListenerPolicy) error {
	if err := m.validateListenerPolicy(policy); err != nil {
		return err
	}

	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	if m.startClaimed || m.terminal {
		return errors.New("mDNS manager is one-shot and already used")
	}
	configured := policy
	m.listenerPolicy = &configured
	return nil
}

func (m *MdnsManager) validateListenerPolicy(policy api.ListenerPolicy) error {
	if !policy.DiscoveryEnabled {
		return errors.New("scoped mDNS requires discovery to be enabled")
	}
	endpoint := policy.ListenAddress
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return errors.New("scoped mDNS listener endpoint is invalid")
	}
	address := endpoint.Addr()
	if address.Is4In6() {
		return errors.New("scoped mDNS address must not be IPv4-mapped IPv6")
	}
	if address.IsUnspecified() || address.IsMulticast() || !listenerPolicyAddressIsUnicast(address) {
		return errors.New("scoped mDNS address must be unicast")
	}
	if int(endpoint.Port()) != m.port {
		return fmt.Errorf("scoped mDNS port %d does not match configured port %d", endpoint.Port(), m.port)
	}
	if m.providerSelection == MdnsProviderSelectionAvahiOnly {
		return errors.New("scoped listener discovery is unsupported by AvahiOnly")
	}
	return nil
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

func (m *MdnsManager) listenerPolicyInterface(address netip.Addr) (net.Interface, error) {
	ifaces, err := m.allowedListenerPolicyInterfaces()
	if err != nil {
		return net.Interface{}, err
	}

	zone := address.Zone()
	target := address.WithZone("")
	for _, iface := range ifaces {
		if zone != "" && iface.Name != zone {
			continue
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		matches, err := interfaceHasAddress(iface, target)
		if err != nil {
			return net.Interface{}, fmt.Errorf("inspect mDNS interface %s: %w", iface.Name, err)
		}
		if matches {
			return iface, nil
		}
	}

	return net.Interface{}, fmt.Errorf("listener address %s is not assigned to an allowed multicast interface", address)
}

func (m *MdnsManager) allowedListenerPolicyInterfaces() ([]net.Interface, error) {
	if len(m.ifaces) == 0 {
		return net.Interfaces()
	}

	ifaces := make([]net.Interface, 0, len(m.ifaces))
	for _, name := range m.ifaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("resolve allowed mDNS interface %s: %w", name, err)
		}
		ifaces = append(ifaces, *iface)
	}
	return ifaces, nil
}

func interfaceHasAddress(iface net.Interface, target netip.Addr) (bool, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return false, err
	}
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		candidate, ok := netip.AddrFromSlice(ip)
		if ok && candidate.Unmap() == target {
			return true, nil
		}
	}
	return false, nil
}
