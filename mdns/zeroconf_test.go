package mdns

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

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
