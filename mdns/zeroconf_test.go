package mdns

import (
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/enbility/zeroconf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

func TestZeroconf(t *testing.T) {
	suite.Run(t, new(ZeroconfSuite))
}

type ZeroconfSuite struct {
	suite.Suite

	sut *ZeroconfProvider

	mux sync.Mutex
}

func (z *ZeroconfSuite) BeforeTest(suiteName, testName string) {
	z.sut = NewZeroconfProvider([]net.Interface{})
}

func (z *ZeroconfSuite) AfterTest(suiteName, testName string) {
	z.sut.Shutdown()
}

type mDNSEntry struct {
	elements   map[string]string
	name, host string
	addresses  []net.IP
	port       int
}

func searchElement(list []mDNSEntry, name string) (mDNSEntry, bool) {
	for _, item := range list {
		if item.name == name {
			return item, true
		}
	}
	return mDNSEntry{}, false
}

func (z *ZeroconfSuite) Test_Shutdown() {
	z.sut.Shutdown()
}

func TestScopedZeroconfAnnounceUsesRegisterProxyWithOnlyConfiguredAddress(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.10")
	iface := net.Interface{Index: 7, Name: "exact-test"}
	provider := newScopedZeroconfProvider([]net.Interface{iface}, "exact-host", address)
	registrationErr := errors.New("registration intercepted")
	legacyCalled := false
	provider.register = func(
		string,
		string,
		string,
		int,
		[]string,
		[]net.Interface,
		...zeroconf.ServerOption,
	) (*zeroconf.Server, error) {
		legacyCalled = true
		return nil, registrationErr
	}
	provider.registerProxy = func(
		instance string,
		service string,
		domain string,
		port int,
		host string,
		ips []string,
		txt []string,
		ifaces []net.Interface,
		options ...zeroconf.ServerOption,
	) (*zeroconf.Server, error) {
		if instance != "exact-service" || service != shipZeroConfServiceType || domain != shipZeroConfDomain {
			t.Fatalf("RegisterProxy service tuple = %q %q %q", instance, service, domain)
		}
		if port != 4712 || host != "exact-host" {
			t.Fatalf("RegisterProxy endpoint = %s:%d, want exact-host:4712", host, port)
		}
		if len(ips) != 1 || ips[0] != address.String() {
			t.Fatalf("RegisterProxy IPs = %v, want only %s", ips, address)
		}
		if len(ifaces) != 1 || ifaces[0].Index != iface.Index {
			t.Fatalf("RegisterProxy interfaces = %#v, want only %#v", ifaces, iface)
		}
		if len(txt) != 1 || txt[0] != "register=true" {
			t.Fatalf("RegisterProxy TXT = %v", txt)
		}
		if len(options) != 1 {
			t.Fatalf("RegisterProxy options = %d, want TTL option", len(options))
		}
		return nil, registrationErr
	}

	err := provider.Announce("exact-service", 4712, []string{"register=true"})
	if !errors.Is(err, registrationErr) {
		t.Fatalf("Announce() error = %v, want intercepted registration", err)
	}
	if legacyCalled {
		t.Fatal("scoped Announce called stock Register")
	}
}

func TestIssue35ScopedZeroconfObservationAppliesConfiguredInterfaceZone(t *testing.T) {
	provider := NewZeroconfProvider([]net.Interface{{Index: 7, Name: "en7"}})
	entry := &zeroconf.ServiceEntry{
		AddrIPv4: []net.IP{net.ParseIP("192.0.2.35")},
		AddrIPv6: []net.IP{
			net.ParseIP("fe80::35"),
			net.ParseIP("2001:db8::35"),
		},
	}

	addresses := provider.scopedServiceAddresses(entry)
	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.35"),
		netip.MustParseAddr("fe80::35").WithZone("en7"),
		netip.MustParseAddr("2001:db8::35"),
	}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("scoped Zeroconf addresses = %v, want %v", addresses, want)
	}
}

type issue35ZeroconfInterfaceRouter interface {
	browseInterfaces(available []net.Interface) []net.Interface
	processScopedServiceForInterface(
		iface net.Interface,
		service *zeroconf.ServiceEntry,
		remove bool,
		cb api.MdnsScopedResolveCB,
	)
}

func TestIssue35DefaultAndMultiInterfaceZeroconfRouteReceiveScopeToCandidate(t *testing.T) {
	available := []net.Interface{
		{Index: 7, Name: "en7", Flags: net.FlagUp | net.FlagMulticast},
		{Index: 8, Name: "en8", Flags: net.FlagUp | net.FlagMulticast},
	}
	for _, test := range []struct {
		name     string
		provider *ZeroconfProvider
		want     []net.Interface
		received net.Interface
	}{
		{
			name:     "default provider browses each available interface",
			provider: NewZeroconfProvider(nil),
			want:     available,
			received: available[0],
		},
		{
			name:     "multi-interface provider keeps exact receiving interface",
			provider: NewZeroconfProvider(available),
			want:     available,
			received: available[1],
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			router, ok := any(test.provider).(issue35ZeroconfInterfaceRouter)
			if !ok {
				t.Fatal("Zeroconf provider has no per-interface browse routing seam")
			}
			if got := router.browseInterfaces(available); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("browse interfaces = %#v, want %#v", got, test.want)
			}

			manager := NewMDNS(
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"Helianthus",
				"Gateway",
				"HEMS",
				"local-ship-id",
				"helianthus",
				4712,
				nil,
				MdnsProviderSelectionGoZeroConfOnly,
			)
			service := &zeroconf.ServiceEntry{
				ServiceRecord: zeroconf.ServiceRecord{Instance: "VR940"},
				HostName:      "vr940.local",
				Port:          12480,
				Text: []string{
					"txtvers=1",
					"id=vr940-ship-id",
					"path=/ship/",
					"ski=3535353535353535353535353535353535353535",
					"register=true",
				},
				AddrIPv6: []net.IP{net.ParseIP("fe80::35")},
			}
			router.processScopedServiceForInterface(
				test.received,
				service,
				false,
				manager.processScopedMdnsEntry,
			)
			_, candidates, _ := manager.copyMdnsSnapshot()
			wantAddress := netip.MustParseAddr("fe80::35").WithZone(test.received.Name)
			if len(candidates) != 1 || len(candidates[0].ScopedAddresses) != 1 ||
				candidates[0].ScopedAddresses[0] != wantAddress {
				t.Fatalf("provider→candidate scoped addresses = %#v, want %s",
					candidates, wantAddress)
			}
		})
	}
}

func TestIssue35SameSHIPPublicationRetainsAllInterfaceRoutesWithoutCandidateRotation(t *testing.T) {
	interfaces := []net.Interface{
		{Index: 7, Name: "en7", Flags: net.FlagUp | net.FlagMulticast},
		{Index: 8, Name: "en8", Flags: net.FlagUp | net.FlagMulticast},
	}
	wantAddresses := []netip.Addr{
		netip.MustParseAddr("fe80::35").WithZone("en7"),
		netip.MustParseAddr("fe80::35").WithZone("en8"),
	}
	for _, order := range [][]int{{1, 0}, {0, 1}} {
		name := interfaces[order[0]].Name + "_then_" + interfaces[order[1]].Name
		t.Run(name, func(t *testing.T) {
			provider := NewZeroconfProvider(interfaces)
			router, ok := any(provider).(issue35ZeroconfInterfaceRouter)
			if !ok {
				t.Fatal("Zeroconf provider has no per-interface browse routing seam")
			}
			manager := NewMDNS(
				"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"Helianthus",
				"Gateway",
				"HEMS",
				"local-ship-id",
				"helianthus",
				4712,
				nil,
				MdnsProviderSelectionGoZeroConfOnly,
			)
			service := &zeroconf.ServiceEntry{
				ServiceRecord: zeroconf.ServiceRecord{Instance: "VR940"},
				HostName:      "vr940.local",
				Port:          12480,
				Text: []string{
					"txtvers=1",
					"id=vr940-ship-id",
					"path=/ship/",
					"ski=3535353535353535353535353535353535353535",
					"register=true",
				},
				AddrIPv6: []net.IP{net.ParseIP("fe80::35")},
			}

			router.processScopedServiceForInterface(
				interfaces[order[0]], service, false, manager.processScopedMdnsEntry,
			)
			_, firstCandidates, _ := manager.copyMdnsSnapshot()
			if len(firstCandidates) != 1 || firstCandidates[0].CandidateRef == "" {
				t.Fatalf("first scoped observation candidates = %#v, want one stable capability", firstCandidates)
			}
			candidateRef := firstCandidates[0].CandidateRef

			router.processScopedServiceForInterface(
				interfaces[order[1]], service, false, manager.processScopedMdnsEntry,
			)
			_, candidates, _ := manager.copyMdnsSnapshot()
			if len(candidates) != 1 {
				t.Fatalf("combined scoped observations candidates = %#v, want one", candidates)
			}
			if candidates[0].CandidateRef != candidateRef {
				t.Errorf("CandidateRef rotated without remove: got %q, want %q",
					candidates[0].CandidateRef, candidateRef)
			}
			if !reflect.DeepEqual(candidates[0].ScopedAddresses, wantAddresses) {
				t.Errorf("combined scoped routes = %v, want deterministic %v",
					candidates[0].ScopedAddresses, wantAddresses)
			}

			// A repeated add from an already-observed interface is idempotent and
			// must neither duplicate routes nor stale the existing selection.
			router.processScopedServiceForInterface(
				interfaces[order[0]], service, false, manager.processScopedMdnsEntry,
			)
			_, repeated, _ := manager.copyMdnsSnapshot()
			if len(repeated) != 1 || repeated[0].CandidateRef != candidateRef ||
				!reflect.DeepEqual(repeated[0].ScopedAddresses, wantAddresses) {
				t.Fatalf("repeated scoped add changed stable selection: %#v", repeated)
			}
		})
	}
}

func TestScopedZeroconfReannounceShutsDownPreviousServer(t *testing.T) {
	iface, address := localMulticastAddress(t)
	provider := newScopedZeroconfProvider([]net.Interface{iface}, "repeat-test-host", address)
	defer provider.Shutdown()

	if err := provider.Announce("repeat-test", 4712, []string{"register=true"}); err != nil {
		t.Fatalf("first Announce() error = %v", err)
	}
	first := provider.zc
	defer first.Shutdown()

	if err := provider.Announce("repeat-test", 4712, []string{"register=false"}); err != nil {
		t.Fatalf("second Announce() error = %v", err)
	}
	if first == provider.zc {
		t.Fatal("second Announce() did not replace the Zeroconf server")
	}

	shutdown := reflect.ValueOf(first).Elem().FieldByName("isShutdown")
	if !shutdown.IsValid() || !shutdown.Bool() {
		t.Fatal("second Announce() left the previous Zeroconf server active")
	}
}

func (z *ZeroconfSuite) Test_ZeroConf() {
	var addedEntries, removedEntries []mDNSEntry

	cb := func(elements map[string]string, name, host string, addresses []net.IP, port int, remove bool) {
		// we expect at least one entry
		assert.NotEqual(z.T(), "", name)

		entry := mDNSEntry{
			elements:  elements,
			name:      name,
			host:      host,
			addresses: addresses,
			port:      port,
		}

		z.mux.Lock()
		if remove {
			removedEntries = append(removedEntries, entry)
		} else {
			addedEntries = append(addedEntries, entry)
		}
		z.mux.Unlock()
	}

	boolV := z.sut.Start(false, cb)
	assert.Equal(z.T(), true, boolV)

	err := z.sut.Announce("dummytest", 4289, []string{"more=more"})
	assert.Nil(z.T(), err)

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found := searchElement(addedEntries, "dummytest")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	z.sut.Unannounce()

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found = searchElement(removedEntries, "dummytest")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	err = z.sut.Announce("test", 4289, []string{"test=test"})
	assert.Nil(z.T(), err)

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found = searchElement(addedEntries, "test")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	z.sut.Unannounce()

	time.Sleep(time.Second * 2)

	z.mux.Lock()
	_, found = searchElement(removedEntries, "test")
	z.mux.Unlock()
	assert.Equal(z.T(), true, found)

	err = z.sut.Announce("", 4289, []string{"test=test"})
	assert.NotNil(z.T(), err)

	z.sut.Unannounce()
}
