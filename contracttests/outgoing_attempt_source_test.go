package contracttests

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

type productionFile struct {
	path string
	file *ast.File
}

func TestOutgoingAttemptAPIIsClosedAndAdditive(t *testing.T) {
	root, fset, files := loadProductionFiles(t)

	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptGate", []string{
		"AbortPrepared", "AuthorizeLaunch", "Prepare",
	})
	assertInterfaceMethodTypes(t, root, fset, files, "api", "OutgoingAttemptGate", map[string]string{
		"Prepare":         "func(OutgoingAttemptRequest) (OutgoingAttemptHandle, error)",
		"AuthorizeLaunch": "func(OutgoingAttemptHandle) (OutgoingAttemptPermit, error)",
		"AbortPrepared":   "func(OutgoingAttemptHandle) (OutgoingAttemptAbortResult, error)",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptHandle", []string{
		"AttemptID", "Context", "ControlEpoch", "Scope",
	})

	assertStructFields(t, root, fset, files, "api", "OutgoingAttemptEndpoint", []string{
		"Host", "Port",
	})
	assertStructFields(t, root, fset, files, "api", "OutgoingAttemptRequest", []string{
		"Endpoint", "Path", "RemoteSKI",
	})
	assertStructFields(t, root, fset, files, "api", "OutgoingAttemptMetadata", []string{
		"AttemptID", "ControlEpoch", "Scope",
	})
	assertStructFields(t, root, fset, files, "api", "OutgoingAttemptPermit", []string{
		"Context", "Decision", "Metadata", "Reason",
	})
	assertNamedType(t, root, files, "api", "OutgoingAttemptDecision")
	assertNamedType(t, root, files, "api", "OutgoingAttemptReason")
	assertNamedType(t, root, files, "api", "OutgoingAttemptAbortResult")

	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptConnectionInterface", []string{
		"OutgoingAttemptMetadata",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptShipConnectionInfoProviderInterface", []string{
		"HandleConnectionClosedWithAttempt", "HandleShipHandshakeStateUpdateWithAttempt",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptHubReaderInterface", []string{
		"OutgoingAttemptConnectionClosed", "OutgoingAttemptHandshakeStateUpdate",
	})

	// The fork extensions are separate optional interfaces. These upstream
	// interfaces stay byte-for-byte source compatible, so existing mocks and
	// incoming-only integrations do not acquire mandatory methods.
	assertInterfaceMethods(t, root, fset, files, "api", "HubInterface", []string{
		"CancelPairingWithSKI", "DisconnectSKI", "PairingDetailForSki", "RegisterRemoteSKI",
		"ServiceForSKI", "SetAutoAccept", "Shutdown", "Start", "UnregisterRemoteSKI",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "HubReaderInterface", []string{
		"AllowWaitingForTrust", "RemoteSKIConnected", "RemoteSKIDisconnected", "ServicePairingDetailUpdate",
		"ServiceShipIDUpdate", "SetupRemoteDevice", "VisibleRemoteServicesUpdated",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "ShipConnectionInterface", []string{
		"AbortPendingHandshake", "ApprovePendingHandshake", "CloseConnection", "DataHandler", "RemoteSKI",
		"ShipHandshakeState",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "ShipConnectionInfoProviderInterface", []string{
		"AllowWaitingForTrust", "HandleConnectionClosed", "HandleShipHandshakeStateUpdate",
		"IsAutoAcceptEnabled", "IsRemoteServiceForSKIPaired", "ReportServiceShipID", "SetupRemoteDevice",
	})
}

func TestProductionDialInventoryAndAttemptPropagation(t *testing.T) {
	_, fset, files := loadProductionFiles(t)

	var directDial []string
	var directDialContext []string
	var dialContextCalls []*ast.CallExpr
	var hiddenSelectors []string
	var helperDecls []*ast.FuncDecl
	var helperCalls []*ast.CallExpr
	constructorCalls := make(map[string][]*ast.CallExpr)

	for _, parsed := range files {
		parents := parentMap(parsed.file)
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			switch item := node.(type) {
			case *ast.FuncDecl:
				if item.Name.Name == "gatedDialContext" {
					helperDecls = append(helperDecls, item)
				}
			case *ast.SelectorExpr:
				if item.Sel.Name != "Dial" && item.Sel.Name != "DialContext" {
					return true
				}

				position := fset.Position(item.Pos()).String()
				call, ok := parents[item].(*ast.CallExpr)
				if !ok || call.Fun != item {
					hiddenSelectors = append(hiddenSelectors, position)
					return true
				}

				owner := enclosingFunction(parents, item)
				if item.Sel.Name == "Dial" {
					directDial = append(directDial, position+" in "+owner)
				} else {
					directDialContext = append(directDialContext, position+" in "+owner)
					dialContextCalls = append(dialContextCalls, call)
				}
			case *ast.CallExpr:
				selector, ok := item.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				owner := enclosingFunction(parents, item)
				if selector.Sel.Name == "gatedDialContext" && owner == "connectFoundService" {
					helperCalls = append(helperCalls, item)
				}
				if selector.Sel.Name == "NewConnectionHandler" && rendered(fset, selector.X) == "ship" {
					constructorCalls[owner] = append(constructorCalls[owner], item)
				}
			}
			return true
		})
	}

	if len(directDial) != 0 {
		t.Errorf("direct Dial calls remain: %v", directDial)
	}
	if len(hiddenSelectors) != 0 {
		t.Errorf("Dial or DialContext is referenced through alias/wrapper indirection: %v", hiddenSelectors)
	}
	if len(directDialContext) != 1 || !strings.HasSuffix(directDialContext[0], " in gatedDialContext") {
		t.Errorf("DialContext inventory = %v, want exactly one call in gatedDialContext", directDialContext)
	} else {
		contextArgument := "<missing>"
		if len(dialContextCalls[0].Args) > 0 {
			contextArgument = rendered(fset, dialContextCalls[0].Args[0])
		}
		if len(dialContextCalls[0].Args) == 0 || !isPermitContextSelector(dialContextCalls[0].Args[0]) {
			t.Errorf("DialContext context argument = %q, want the permit's exact Context field", contextArgument)
		}
	}
	if len(helperDecls) != 1 || receiverName(helperDecls[0]) != "Hub" {
		t.Errorf("gatedDialContext declarations = %d with receivers %v, want one Hub method", len(helperDecls), receiverNames(helperDecls))
	}

	sort.Slice(helperCalls, func(i, j int) bool { return helperCalls[i].Pos() < helperCalls[j].Pos() })
	if len(helperCalls) != 2 {
		t.Errorf("connectFoundService gatedDialContext calls = %d, want selected path then root fallback", len(helperCalls))
	} else {
		firstPath := rendered(fset, helperCalls[0].Args[len(helperCalls[0].Args)-1])
		fallbackPath := rendered(fset, helperCalls[1].Args[len(helperCalls[1].Args)-1])
		if firstPath != "path" || fallbackPath != `""` {
			t.Errorf("gated path order = %q then %q, want path then root/no-path", firstPath, fallbackPath)
		}
	}

	assertConnectionConstructor(t, fset, constructorCalls["ServeHTTP"], 6, "ship.ShipRoleServer")
	assertConnectionConstructor(t, fset, constructorCalls["connectFoundService"], 7, "ship.ShipRoleClient")
}

func assertConnectionConstructor(t *testing.T, fset *token.FileSet, calls []*ast.CallExpr, argCount int, role string) {
	t.Helper()
	if len(calls) != 1 {
		t.Errorf("NewConnectionHandler calls for %s = %d, want one", role, len(calls))
		return
	}
	if len(calls[0].Args) != argCount {
		t.Errorf("%s NewConnectionHandler argument count = %d, want %d", role, len(calls[0].Args), argCount)
	}
	if len(calls[0].Args) < 3 || rendered(fset, calls[0].Args[2]) != role {
		t.Errorf("NewConnectionHandler role = %q, want %q", rendered(fset, calls[0].Args[2]), role)
	}
}

func assertNamedType(t *testing.T, root string, files []productionFile, packageDir, name string) {
	t.Helper()
	if findType(root, files, packageDir, name) == nil {
		t.Errorf("%s.%s is missing", packageDir, name)
	}
}

func assertStructFields(t *testing.T, root string, fset *token.FileSet, files []productionFile, packageDir, name string, want []string) {
	t.Helper()
	expr := findType(root, files, packageDir, name)
	structure, ok := expr.(*ast.StructType)
	if !ok {
		t.Errorf("%s.%s = %T, want a closed struct", packageDir, name, expr)
		return
	}

	var got []string
	for _, field := range structure.Fields.List {
		if len(field.Names) != 1 {
			t.Errorf("%s.%s contains an embedded or grouped field %q", packageDir, name, rendered(fset, field))
			continue
		}
		got = append(got, field.Names[0].Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s.%s fields = %v, want exactly %v", packageDir, name, got, want)
	}
}

func assertInterfaceMethods(t *testing.T, root string, fset *token.FileSet, files []productionFile, packageDir, name string, want []string) {
	t.Helper()
	expr := findType(root, files, packageDir, name)
	methods, ok := expr.(*ast.InterfaceType)
	if !ok {
		t.Errorf("%s.%s = %T, want an interface", packageDir, name, expr)
		return
	}

	var got []string
	for _, field := range methods.Methods.List {
		if len(field.Names) != 1 {
			t.Errorf("%s.%s contains an embedded or grouped method %q", packageDir, name, rendered(fset, field))
			continue
		}
		got = append(got, field.Names[0].Name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s.%s methods = %v, want exactly %v", packageDir, name, got, want)
	}
}

func assertInterfaceMethodTypes(t *testing.T, root string, fset *token.FileSet, files []productionFile, packageDir, name string, want map[string]string) {
	t.Helper()
	expr := findType(root, files, packageDir, name)
	methods, ok := expr.(*ast.InterfaceType)
	if !ok {
		return
	}
	for _, field := range methods.Methods.List {
		if len(field.Names) != 1 {
			continue
		}
		method := field.Names[0].Name
		if expected, exists := want[method]; exists && rendered(fset, field.Type) != expected {
			t.Errorf("%s.%s.%s has type %q, want %q", packageDir, name, method, rendered(fset, field.Type), expected)
		}
	}
}

func findType(root string, files []productionFile, packageDir, name string) ast.Expr {
	for _, parsed := range files {
		rel, err := filepath.Rel(root, filepath.Dir(parsed.path))
		if err != nil || rel != packageDir {
			continue
		}
		for _, declaration := range parsed.file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, spec := range general.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				if typeSpec.Name.Name == name {
					return typeSpec.Type
				}
			}
		}
	}
	return nil
}

func loadProductionFiles(t *testing.T) (string, *token.FileSet, []productionFile) {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Dir(filepath.Dir(currentFile))
	fset := token.NewFileSet()
	var files []productionFile

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		parsed, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return parseErr
		}
		files = append(files, productionFile{path: path, file: parsed})
		return nil
	})
	if err != nil {
		t.Fatalf("load production Go files: %v", err)
	}
	return root, fset, files
}

func parentMap(root ast.Node) map[ast.Node]ast.Node {
	parents := make(map[ast.Node]ast.Node)
	var stack []ast.Node
	ast.Inspect(root, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if len(stack) > 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	return parents
}

func enclosingFunction(parents map[ast.Node]ast.Node, node ast.Node) string {
	for current := node; current != nil; current = parents[current] {
		if declaration, ok := current.(*ast.FuncDecl); ok {
			return declaration.Name.Name
		}
	}
	return "<package>"
}

func receiverName(declaration *ast.FuncDecl) string {
	if declaration == nil || declaration.Recv == nil || len(declaration.Recv.List) != 1 {
		return ""
	}
	typeExpr := declaration.Recv.List[0].Type
	if pointer, ok := typeExpr.(*ast.StarExpr); ok {
		typeExpr = pointer.X
	}
	identifier, _ := typeExpr.(*ast.Ident)
	if identifier == nil {
		return ""
	}
	return identifier.Name
}

func receiverNames(declarations []*ast.FuncDecl) []string {
	names := make([]string, 0, len(declarations))
	for _, declaration := range declarations {
		names = append(names, receiverName(declaration))
	}
	return names
}

func isPermitContextSelector(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Context" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && strings.Contains(strings.ToLower(identifier.Name), "permit")
}

func rendered(fset *token.FileSet, node ast.Node) string {
	if node == nil {
		return ""
	}
	var buffer bytes.Buffer
	if err := format.Node(&buffer, fset, node); err != nil {
		return "<format-error>"
	}
	return buffer.String()
}
