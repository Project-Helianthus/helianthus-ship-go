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

func TestListenerPolicyMdnsInterfaceIsAdditive(t *testing.T) {
	legacy := reflect.TypeOf((*api.MdnsInterface)(nil)).Elem()
	scoped := reflect.TypeOf((*api.ListenerPolicyMdnsInterface)(nil)).Elem()
	if scoped.NumMethod() != legacy.NumMethod()+1 {
		t.Fatalf("ListenerPolicyMdnsInterface has %d methods, want %d", scoped.NumMethod(), legacy.NumMethod()+1)
	}
	for index := range legacy.NumMethod() {
		method := legacy.Method(index)
		if _, ok := scoped.MethodByName(method.Name); !ok {
			t.Errorf("ListenerPolicyMdnsInterface does not embed MdnsInterface.%s", method.Name)
		}
	}
	configure, ok := scoped.MethodByName("ConfigureListenerPolicy")
	if !ok {
		t.Fatal("ListenerPolicyMdnsInterface is missing ConfigureListenerPolicy")
	}
	want := reflect.TypeOf(func(api.ListenerPolicy) error { return nil })
	if configure.Type != want {
		t.Fatalf("ConfigureListenerPolicy type = %v, want %v", configure.Type, want)
	}
}
