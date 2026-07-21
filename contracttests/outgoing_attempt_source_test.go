package contracttests

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

type productionFile struct {
	path string
	file *ast.File
}

func TestOutboundPairingAPIIsAbsentFromProductionTree(t *testing.T) {
	_, fset, files := loadProductionFiles(t)
	forbidden := map[string]struct{}{
		"OutboundPairingController":             {},
		"QueueRemoteSKI":                        {},
		"RemoteEndpoint":                        {},
		"ReportRemoteEndpoint":                  {},
		"cacheRemoteEndpoint":                   {},
		"createOutboundAdmission":               {},
		"hasCurrentOutboundAdmission":           {},
		"invalidateAllOutboundAdmissionsLocked": {},
		"outboundAdmissions":                    {},
		"outboundPairingAdmission":              {},
		"promoteOutboundTrust":                  {},
		"validOutboundSKI":                      {},
		"validRemoteEndpoint":                   {},
	}

	var declarations []string
	for _, parsed := range files {
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			var names []*ast.Ident
			switch declaration := node.(type) {
			case *ast.FuncDecl:
				names = []*ast.Ident{declaration.Name}
			case *ast.TypeSpec:
				names = []*ast.Ident{declaration.Name}
			case *ast.ValueSpec:
				names = declaration.Names
			case *ast.Field:
				names = declaration.Names
			}
			for _, name := range names {
				if _, found := forbidden[name.Name]; found {
					declarations = append(declarations, fset.Position(name.Pos()).String())
				}
			}
			return true
		})
	}

	sort.Strings(declarations)
	if len(declarations) != 0 {
		t.Errorf("removed outbound pairing declarations remain: %v", declarations)
	}
}

func TestOutgoingAttemptAPIIsClosedAndAdditive(t *testing.T) {
	root, fset, files := loadProductionFiles(t)

	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptGate", []string{
		"AbortPrepared", "AuthorizeLaunch", "Prepare",
	})
	assertInterfaceMethods(t, root, fset, files, "api", "OutgoingAttemptGateSetter", []string{
		"SetOutgoingAttemptGate",
	})
	assertInterfaceMethodTypes(t, root, fset, files, "api", "OutgoingAttemptGateSetter", map[string]string{
		"SetOutgoingAttemptGate": "func(OutgoingAttemptGate) error",
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
	assertStructFields(t, root, fset, files, "ship", "OutgoingAttemptConnectionConfiguration", []string{
		"Context", "Metadata",
	})
	assertFunctionType(t, root, fset, files, "ship", "NewConnectionHandler",
		"func(dataProvider api.ShipConnectionInfoProviderInterface, dataHandler api.WebsocketDataWriterInterface, role shipRole, localShipID, remoteSki, remoteShipId string) *ShipConnection")
	assertFunctionType(t, root, fset, files, "ship", "NewOutgoingConnectionHandler",
		"func(dataProvider api.ShipConnectionInfoProviderInterface, dataHandler api.WebsocketDataWriterInterface, role shipRole, localShipID, remoteSki, remoteShipId string, configuration OutgoingAttemptConnectionConfiguration) (*ShipConnection, error)")

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

func TestCanonicalModuleIdentityAndSelfImports(t *testing.T) {
	root, _, _ := loadProductionFiles(t)
	goModPath := filepath.Join(root, "go.mod")
	goMod, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	parsed, err := modfile.Parse(goModPath, goMod, nil)
	if err != nil {
		t.Fatalf("parse go.mod: %v", err)
	}
	const canonicalModule = "github.com/Project-Helianthus/helianthus-ship-go"
	if parsed.Module == nil || parsed.Module.Mod.Path != canonicalModule {
		got := "<missing>"
		if parsed.Module != nil {
			got = parsed.Module.Mod.Path
		}
		t.Errorf("module path = %q, want %q", got, canonicalModule)
	}

	fset := token.NewFileSet()
	var upstreamImports []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imported := range file.Imports {
			pathValue := strings.Trim(imported.Path.Value, `"`)
			if pathValue == "github.com/enbility/ship-go" || strings.HasPrefix(pathValue, "github.com/enbility/ship-go/") {
				position := fset.Position(imported.Pos()).String()
				upstreamImports = append(upstreamImports, position+" -> "+pathValue)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan self-imports: %v", err)
	}
	if len(upstreamImports) != 0 {
		t.Errorf("upstream self-imports remain: %v", upstreamImports)
	}
}

func TestProductionDialInventoryAndAttemptPropagation(t *testing.T) {
	_, fset, files := loadProductionFiles(t)

	var directDial []string
	var directDialContext []string
	var dialContextCalls []*ast.CallExpr
	var hiddenSelectors []string
	var helperDecls []*ast.FuncDecl
	var helperCalls []*ast.CallExpr
	var directAuthorize []string
	var authorizeCalls []*ast.CallExpr
	legacyConstructorCalls := make(map[string][]*ast.CallExpr)
	outgoingConstructorCalls := make(map[string][]*ast.CallExpr)

	for _, parsed := range files {
		parents := parentMap(parsed.file)
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			switch item := node.(type) {
			case *ast.FuncDecl:
				if item.Name.Name == "gatedDialContext" {
					helperDecls = append(helperDecls, item)
				}
			case *ast.SelectorExpr:
				if item.Sel.Name == "AuthorizeLaunch" {
					directAuthorize = append(directAuthorize, fset.Position(item.Pos()).String()+" in "+enclosingFunction(parents, item))
					return true
				}
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
				if identifier, ok := item.Fun.(*ast.Ident); ok && identifier.Name == "authorizeOutgoingAttempt" {
					authorizeCalls = append(authorizeCalls, item)
					return true
				}
				selector, ok := item.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				owner := enclosingFunction(parents, item)
				if selector.Sel.Name == "gatedDialContext" && owner == "connectFoundService" {
					helperCalls = append(helperCalls, item)
				}
				if selector.Sel.Name == "NewConnectionHandler" && rendered(fset, selector.X) == "ship" {
					legacyConstructorCalls[owner] = append(legacyConstructorCalls[owner], item)
				}
				if selector.Sel.Name == "NewOutgoingConnectionHandler" && rendered(fset, selector.X) == "ship" {
					outgoingConstructorCalls[owner] = append(outgoingConstructorCalls[owner], item)
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
	} else {
		assertGateBranchImmediatelyPrecedesDial(t, fset, helperDecls[0])
	}
	if len(directAuthorize) != 1 || !strings.HasSuffix(directAuthorize[0], " in authorizeOutgoingAttempt") {
		t.Errorf("AuthorizeLaunch inventory = %v, want one direct call in authorizeOutgoingAttempt", directAuthorize)
	}
	if len(authorizeCalls) != 1 || len(helperDecls) != 1 {
		t.Errorf("authorizeOutgoingAttempt call count = %d, want one in gatedDialContext", len(authorizeCalls))
	} else if enclosingFunction(parentMap(helperDecls[0]), authorizeCalls[0]) != "gatedDialContext" {
		t.Error("authorizeOutgoingAttempt is not called from gatedDialContext")
	} else if len(dialContextCalls) == 1 && authorizeCalls[0].Pos() >= dialContextCalls[0].Pos() {
		t.Error("AuthorizeLaunch path does not precede the sole DialContext call")
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

	assertConnectionConstructor(t, fset, "NewConnectionHandler", legacyConstructorCalls["ServeHTTP"], 6, "ship.ShipRoleServer")
	if len(legacyConstructorCalls["connectFoundService"]) != 1 {
		t.Errorf("ungated NewConnectionHandler calls in connectFoundService = %d, want one", len(legacyConstructorCalls["connectFoundService"]))
	}
	assertConnectionConstructor(t, fset, "NewOutgoingConnectionHandler", outgoingConstructorCalls["connectFoundService"], 7, "ship.ShipRoleClient")
}

func assertGateBranchImmediatelyPrecedesDial(t *testing.T, fset *token.FileSet, declaration *ast.FuncDecl) {
	t.Helper()
	for index, statement := range declaration.Body.List {
		conditional, ok := statement.(*ast.IfStmt)
		if !ok || rendered(fset, conditional.Cond) != "gate != nil" {
			continue
		}
		if index+1 >= len(declaration.Body.List) {
			t.Fatal("gated authorization branch has no immediate DialContext successor")
		}
		assignment, ok := declaration.Body.List[index+1].(*ast.AssignStmt)
		if !ok || len(assignment.Rhs) != 1 {
			t.Fatalf("statement immediately after gated authorization = %T, want DialContext assignment", declaration.Body.List[index+1])
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			t.Fatalf("statement immediately after gated authorization = %q, want DialContext call", rendered(fset, assignment))
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "DialContext" {
			t.Fatalf("statement immediately after gated authorization = %q, want sole DialContext", rendered(fset, assignment))
		}
		return
	}
	t.Fatal("gatedDialContext is missing its top-level gate authorization branch")
}

func assertConnectionConstructor(t *testing.T, fset *token.FileSet, name string, calls []*ast.CallExpr, argCount int, role string) {
	t.Helper()
	if len(calls) != 1 {
		t.Errorf("%s calls for %s = %d, want one", name, role, len(calls))
		return
	}
	if len(calls[0].Args) != argCount {
		t.Errorf("%s %s argument count = %d, want %d", role, name, len(calls[0].Args), argCount)
	}
	if len(calls[0].Args) < 3 || rendered(fset, calls[0].Args[2]) != role {
		t.Errorf("%s role = %q, want %q", name, rendered(fset, calls[0].Args[2]), role)
	}
}

func assertNamedType(t *testing.T, root string, files []productionFile, packageDir, name string) {
	t.Helper()
	if findType(root, files, packageDir, name) == nil {
		t.Errorf("%s.%s is missing", packageDir, name)
	}
}

func assertFunctionType(
	t *testing.T,
	root string,
	fset *token.FileSet,
	files []productionFile,
	packageDir,
	name,
	want string,
) {
	t.Helper()
	declaration := findFunction(root, files, packageDir, name)
	if declaration == nil {
		t.Errorf("%s.%s is missing", packageDir, name)
		return
	}
	got := strings.Join(strings.Fields(rendered(fset, declaration.Type)), " ")
	got = strings.Replace(got, "func( ", "func(", 1)
	if got != want {
		t.Errorf("%s.%s type = %q, want %q", packageDir, name, got, want)
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

func findFunction(root string, files []productionFile, packageDir, name string) *ast.FuncDecl {
	for _, parsed := range files {
		rel, err := filepath.Rel(root, filepath.Dir(parsed.path))
		if err != nil || rel != packageDir {
			continue
		}
		for _, declaration := range parsed.file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Recv == nil && function.Name.Name == name {
				return function
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
