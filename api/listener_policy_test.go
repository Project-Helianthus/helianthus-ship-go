package api_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/Project-Helianthus/helianthus-ship-go/api"
)

func TestListenerPolicyHasMinimalDependencyFreeShape(t *testing.T) {
	typeOfPolicy := reflect.TypeOf(api.ListenerPolicy{})
	want := map[string]reflect.Type{
		"ListenAddress":    reflect.TypeOf(netip.AddrPort{}),
		"DiscoveryEnabled": reflect.TypeOf(false),
	}

	if typeOfPolicy.NumField() != len(want) {
		t.Fatalf("ListenerPolicy has %d fields, want exactly %d", typeOfPolicy.NumField(), len(want))
	}
	for name, wantType := range want {
		field, ok := typeOfPolicy.FieldByName(name)
		if !ok {
			t.Errorf("ListenerPolicy is missing %s", name)
			continue
		}
		if field.Type != wantType {
			t.Errorf("ListenerPolicy.%s has type %v, want %v", name, field.Type, wantType)
		}
	}
}
