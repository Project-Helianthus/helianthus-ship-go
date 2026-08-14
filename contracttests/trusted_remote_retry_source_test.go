package contracttests

import (
	"go/ast"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestTrustedRemoteRetryAPIAcceptsIdentityOnly(t *testing.T) {
	root, fset, files := loadProductionFiles(t)
	assertInterfaceMethods(t, root, fset, files, "api", "TrustedRemoteRetryController", []string{
		"RetryTrustedRemote",
	})
	assertInterfaceMethodTypes(t, root, fset, files, "api", "TrustedRemoteRetryController", map[string]string{
		"RetryTrustedRemote": "func(expectedSKI string) error",
	})
	assertStructFields(t, root, fset, files, "hub", "trustedRemoteObservation", []string{
		"admission", "host", "path", "port", "revision",
	})
}

func TestTrustedRemoteRetrySnapshotHasOneMdnsConstructionAndWritePath(t *testing.T) {
	root, _, files := loadProductionFiles(t)
	var constructors []string
	var snapshotWrites []string

	for _, parsed := range files {
		directory, err := filepath.Rel(root, filepath.Dir(parsed.path))
		if err != nil || directory != "hub" {
			continue
		}
		for _, declaration := range parsed.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch item := node.(type) {
				case *ast.CompositeLit:
					identifier, ok := item.Type.(*ast.Ident)
					if ok && identifier.Name == "trustedRemoteObservation" {
						constructors = append(constructors, filepath.Base(parsed.path)+":"+function.Name.Name)
					}
				case *ast.AssignStmt:
					for _, expression := range item.Lhs {
						selector, ok := expression.(*ast.SelectorExpr)
						if ok && selector.Sel.Name == "visibleTrustedRemoteObservations" {
							snapshotWrites = append(snapshotWrites, filepath.Base(parsed.path)+":"+function.Name.Name)
						}
					}
				}
				return true
			})
		}
	}

	sort.Strings(constructors)
	sort.Strings(snapshotWrites)
	if got := strings.Join(constructors, ","); got != "hub_mdns.go:trustedRemoteObservations" {
		t.Fatalf("trusted retry observation constructors = %v, want only the mDNS snapshot reducer", constructors)
	}
	if got := strings.Join(snapshotWrites, ","); got != "hub_mdns.go:reportMdnsSnapshot" {
		t.Fatalf("trusted retry snapshot writes = %v, want only reportMdnsSnapshot", snapshotWrites)
	}
}
