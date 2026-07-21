package mdns

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
	"github.com/Project-Helianthus/helianthus-ship-go/mocks"
	"github.com/Project-Helianthus/helianthus-ship-go/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

func TestMdnsSuite(t *testing.T) {
	suite.Run(t, new(MdnsSuite))
}

type MdnsSuite struct {
	suite.Suite

	sut           *MdnsManager
	announcements [][]string

	mdnsService  *mocks.MdnsInterface
	mdnsSearch   *mocks.MdnsReportInterface
	mdnsProvider *mocks.MdnsProviderInterface
}

func (s *MdnsSuite) BeforeTest(suiteName, testName string) {
	s.mdnsService = mocks.NewMdnsInterface(s.T())

	s.mdnsSearch = mocks.NewMdnsReportInterface(s.T())
	s.mdnsSearch.On("ReportMdnsEntries", mock.Anything, mock.Anything).Maybe().Return()

	s.mdnsProvider = mocks.NewMdnsProviderInterface(s.T())
	s.mdnsProvider.On("ResolveEntries", mock.Anything, mock.Anything).Maybe().Return()
	s.mdnsProvider.On("Start", mock.Anything, mock.Anything).Maybe().Return(true)
	s.mdnsProvider.On("Announce", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			txt := append([]string(nil), args.Get(2).([]string)...)
			s.announcements = append(s.announcements, txt)
		}).
		Maybe().
		Return(nil)
	s.mdnsProvider.On("Unannounce").Maybe().Return()
	s.mdnsProvider.On("Shutdown").Maybe().Return()

	s.sut = NewMDNS("test", "brand", "model", "EnergyManagementSystem", "shipid", "serviceName", 4729, nil, MdnsProviderSelectionAll)
	s.useMockProvider()
}

func (s *MdnsSuite) useMockProvider() {
	s.sut.newAvahiProvider = func([]int32) api.MdnsProviderInterface { return s.mdnsProvider }
	s.sut.newZeroconfProvider = func([]net.Interface) api.MdnsProviderInterface { return s.mdnsProvider }
	s.sut.newScopedZeroconfProvider = func([]net.Interface, string, netip.Addr) api.MdnsProviderInterface {
		return s.mdnsProvider
	}
	s.sut.hostname = func() (string, error) { return "test-host", nil }
}

func (s *MdnsSuite) AfterTest(suiteName, testName string) {
	s.sut.Shutdown()
}

func (s *MdnsSuite) Test_AvahiOnly() {
	s.sut.Shutdown()

	s.sut = NewMDNS("test", "brand", "model", "EnergyManagementSystem", "shipid", "serviceName", 4729, nil, MdnsProviderSelectionAvahiOnly)
	s.useMockProvider()

	_ = s.sut.Start(s.mdnsSearch)
	// Can't do an assertion check, as the result depends on the
	// system this test is being ran on
}

func (s *MdnsSuite) Test_GoZeroConfOnly() {
	s.sut.Shutdown()

	s.sut = NewMDNS("test", "brand", "model", "EnergyManagementSystem", "shipid", "serviceName", 4729, nil, MdnsProviderSelectionGoZeroConfOnly)
	s.useMockProvider()

	err := s.sut.Start(s.mdnsSearch)
	assert.Nil(s.T(), err)
	assert.False(s.T(), s.sut.autoaccept)

	s.sut.SetAutoAccept(true)
	assert.True(s.T(), s.sut.autoaccept)
}

func (s *MdnsSuite) Test_PairingRegistrationComposesWithAutoAccept() {
	err := s.sut.Start(s.mdnsSearch)
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), s.announcements[len(s.announcements)-1], "register=false")

	err = s.sut.SetPairingRegistration(true)
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), s.announcements[len(s.announcements)-1], "register=true")

	s.sut.SetAutoAccept(false)
	assert.Contains(s.T(), s.announcements[len(s.announcements)-1], "register=true")

	s.sut.SetAutoAccept(true)
	err = s.sut.SetPairingRegistration(false)
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), s.announcements[len(s.announcements)-1], "register=true")

	s.sut.SetAutoAccept(false)
	assert.Contains(s.T(), s.announcements[len(s.announcements)-1], "register=false")
}

func TestMdnsManagerScopedPolicyUsesOneExactInterfaceAndAddress(t *testing.T) {
	iface, address := localMulticastAddress(t)
	const port = 4729
	manager := NewMDNS(
		"test", "brand", "model", "EnergyManagementSystem", "shipid", "serviceName",
		port, []string{iface.Name}, MdnsProviderSelectionAll,
	)
	provider := mocks.NewMdnsProviderInterface(t)
	provider.EXPECT().Start(true, mock.Anything).Return(true).Once()
	provider.EXPECT().Announce(mock.Anything, port, mock.Anything).Return(nil).Once()
	provider.EXPECT().Unannounce().Return().Once()
	provider.EXPECT().Shutdown().Return().Once()

	factoryCalls := 0
	manager.newScopedZeroconfProvider = func(ifaces []net.Interface, host string, configuredAddress netip.Addr) api.MdnsProviderInterface {
		factoryCalls++
		if len(ifaces) != 1 || ifaces[0].Index != iface.Index {
			t.Fatalf("scoped interfaces = %#v, want only %s", ifaces, iface.Name)
		}
		if host != "scoped-test-host" {
			t.Fatalf("scoped host = %q, want scoped-test-host", host)
		}
		if configuredAddress != address.WithZone("") {
			t.Fatalf("scoped address = %s, want %s", configuredAddress, address.WithZone(""))
		}
		return provider
	}
	manager.newAvahiProvider = func([]int32) api.MdnsProviderInterface {
		t.Fatal("scoped startup attempted Avahi")
		return nil
	}
	manager.hostname = func() (string, error) { return "scoped-test-host", nil }
	policy := api.ListenerPolicy{
		ListenAddress:    netip.AddrPortFrom(address, port),
		DiscoveryEnabled: true,
	}

	if err := manager.ConfigureListenerPolicy(policy); err != nil {
		t.Fatalf("ConfigureListenerPolicy() error = %v", err)
	}
	if factoryCalls != 0 || manager.mdnsProvider != nil || manager.signalDone != nil {
		t.Fatal("ConfigureListenerPolicy caused runtime effects")
	}
	if err := manager.Start(nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if factoryCalls != 1 {
		t.Fatalf("scoped Zeroconf factory calls = %d, want 1", factoryCalls)
	}
	manager.Shutdown()
}

func TestMdnsManagerScopedPolicyRejectsAvahiOnlyBeforeStartup(t *testing.T) {
	_, address := localMulticastAddress(t)
	manager := NewMDNS(
		"test", "brand", "model", "EnergyManagementSystem", "shipid", "serviceName",
		4729, nil, MdnsProviderSelectionAvahiOnly,
	)
	err := manager.ConfigureListenerPolicy(api.ListenerPolicy{
		ListenAddress:    netip.AddrPortFrom(address, 4729),
		DiscoveryEnabled: true,
	})
	if err == nil {
		t.Fatal("ConfigureListenerPolicy accepted AvahiOnly")
	}
	if manager.startClaimed || manager.mdnsProvider != nil || manager.signalDone != nil {
		t.Fatal("AvahiOnly rejection caused startup effects")
	}
}

func TestMdnsManagerSignalHandlerStopsOnShutdownAndSignal(t *testing.T) {
	for _, signalDriven := range []bool{false, true} {
		name := "shutdown"
		if signalDriven {
			name = "signal"
		}
		t.Run(name, func(t *testing.T) {
			manager := NewMDNS(
				"test", "brand", "model", "EnergyManagementSystem", "shipid", "serviceName",
				4729, nil, MdnsProviderSelectionGoZeroConfOnly,
			)
			provider := mocks.NewMdnsProviderInterface(t)
			provider.EXPECT().Start(true, mock.Anything).Return(true).Once()
			provider.EXPECT().Announce(mock.Anything, 4729, mock.Anything).Return(nil).Once()
			provider.EXPECT().Unannounce().Return().Once()
			providerShutdown := make(chan struct{})
			provider.EXPECT().Shutdown().Run(func() { close(providerShutdown) }).Return().Once()
			manager.newZeroconfProvider = func([]net.Interface) api.MdnsProviderInterface { return provider }

			if err := manager.Start(nil); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			manager.lifecycleMu.Lock()
			signalC := manager.signalC
			signalDone := manager.signalDone
			manager.lifecycleMu.Unlock()
			if signalC == nil || signalDone == nil {
				t.Fatal("signal handler was not installed")
			}

			shutdownReturned := make(chan struct{})
			if signalDriven {
				signalC <- os.Interrupt
			} else {
				go func() {
					manager.Shutdown()
					close(shutdownReturned)
				}()
			}
			waitMdnsSignal(t, signalDone, "signal handler completion")
			waitMdnsSignal(t, providerShutdown, "provider shutdown")
			if !signalDriven {
				waitMdnsSignal(t, shutdownReturned, "Shutdown return")
			}
			manager.Shutdown()
		})
	}
}

func localMulticastAddress(t *testing.T) (net.Interface, netip.Addr) {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	var fallbackInterface net.Interface
	var fallbackAddress netip.Addr
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			t.Fatalf("list addresses for %s: %v", iface.Name, err)
		}
		for _, rawAddress := range addresses {
			ipNet, ok := rawAddress.(*net.IPNet)
			if !ok {
				continue
			}
			address, ok := netip.AddrFromSlice(ipNet.IP)
			if !ok {
				continue
			}
			address = address.Unmap()
			if !listenerPolicyAddressIsUnicast(address) {
				continue
			}
			if address.Is4() {
				return iface, address
			}
			if address.IsLinkLocalUnicast() {
				address = address.WithZone(iface.Name)
			}
			fallbackInterface = iface
			fallbackAddress = address
		}
	}
	if fallbackAddress.IsValid() {
		return fallbackInterface, fallbackAddress
	}
	t.Skip("no assigned multicast-capable interface address")
	return net.Interface{}, netip.Addr{}
}

func waitMdnsSignal(t *testing.T, signal <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func (s *MdnsSuite) Test_Start() {
	err := s.sut.Start(s.mdnsSearch)
	assert.Nil(s.T(), err)

	assert.Equal(s.T(), true, s.sut.isAnnounced)

	s.sut.UnannounceMdnsEntry()
	assert.Equal(s.T(), false, s.sut.isAnnounced)

	s.sut.UnannounceMdnsEntry()
	assert.Equal(s.T(), false, s.sut.isAnnounced)
}

func (s *MdnsSuite) Test_Start_IFaces() {
	// we don't have access to iface names on CI
	if util.IsRunningOnCI() {
		return
	}

	ifaces, err := net.Interfaces()
	assert.NotEqual(s.T(), 0, len(ifaces))
	assert.Nil(s.T(), err)

	s.sut.ifaces = []string{ifaces[0].Name}
	err = s.sut.Start(s.mdnsSearch)
	assert.Nil(s.T(), err)
}

func (s *MdnsSuite) Test_Start_IFaces_Invalid() {
	s.sut.ifaces = []string{"noifacename"}
	err := s.sut.Start(s.mdnsSearch)
	assert.NotNil(s.T(), err)

	s.sut.SetAutoAccept(true)
	assert.Equal(s.T(), true, s.sut.autoaccept)
}

func (s *MdnsSuite) Test_Shutdown_Start() {
	err := s.sut.Start(s.mdnsSearch)
	assert.Nil(s.T(), err)

	s.sut.Shutdown()
	assert.Nil(s.T(), s.sut.mdnsProvider)

	s.sut.Shutdown()
}

func (s *MdnsSuite) Test_Shutdown_NoStart() {
	s.sut.Shutdown()
	assert.Nil(s.T(), s.sut.mdnsProvider)

	s.sut.Shutdown()
}

func (s *MdnsSuite) Test_MdnsEntry() {
	testSki := "test"

	entries := s.sut.mdnsEntries()
	assert.Equal(s.T(), 0, len(entries))

	entry := &api.MdnsEntry{
		Ski: testSki,
	}

	s.sut.setMdnsEntry(testSki, entry)
	entries = s.sut.mdnsEntries()
	assert.Equal(s.T(), 1, len(entries))

	theEntry, ok := s.sut.mdnsEntry(testSki)
	assert.Equal(s.T(), true, ok)
	assert.NotNil(s.T(), theEntry)

	copyEntries := s.sut.copyMdnsEntries()
	assert.Equal(s.T(), 1, len(copyEntries))

	s.sut.removeMdnsEntry(testSki)
	entries = s.sut.mdnsEntries()
	assert.Equal(s.T(), 0, len(entries))
	assert.Equal(s.T(), 1, len(copyEntries))
}

func (s *MdnsSuite) Test_MdnsEntries() {
	testSki := "test"

	entry := &api.MdnsEntry{
		Ski: testSki,
	}
	s.sut.setMdnsEntry(testSki, entry)
	entries := s.sut.mdnsEntries()
	assert.Equal(s.T(), 1, len(entries))

	err := s.sut.Start(s.mdnsSearch)
	assert.Nil(s.T(), err)

	s.mdnsSearch.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe()

	s.sut.RequestMdnsEntries()

	time.Sleep(time.Millisecond * 500)
}

func (s *MdnsSuite) Test_ProcessMdnsEntry() {
	const remoteSKI = "0123456789abcdef0123456789abcdef01234567"

	err := s.sut.Start(s.mdnsSearch)
	assert.Nil(s.T(), err)

	s.mdnsSearch.EXPECT().ReportMdnsEntries(mock.Anything, mock.Anything).Maybe()

	elements := make(map[string]string, 1)

	name := "name"
	host := "host"
	ips := []net.IP{}
	port := 4567

	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 0, len(s.sut.mdnsEntries()))

	elements["txtvers"] = "2"
	elements["id"] = "id"
	elements["path"] = "/ship"
	elements["ski"] = remoteSKI
	elements["register"] = "falsee"

	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 0, len(s.sut.mdnsEntries()))

	elements["txtvers"] = "1"
	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 0, len(s.sut.mdnsEntries()))

	elements["ski"] = s.sut.ski
	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 0, len(s.sut.mdnsEntries()))

	elements["ski"] = remoteSKI
	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 0, len(s.sut.mdnsEntries()))

	elements["register"] = "false"
	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 1, len(s.sut.mdnsEntries()))

	elements["brand"] = "brand"
	elements["type"] = "type"
	elements["model"] = "model"
	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 1, len(s.sut.mdnsEntries()))

	ips = []net.IP{[]byte("127.0.0.1"), []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}
	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 1, len(s.sut.mdnsEntries()))

	s.sut.processMdnsEntry(elements, name, host, ips, port, false)
	assert.Equal(s.T(), 1, len(s.sut.mdnsEntries()))

	s.sut.processMdnsEntry(elements, name, host, ips, port, true)
	assert.Equal(s.T(), 0, len(s.sut.mdnsEntries()))
}
