package contracttests

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
)

const (
	canonicalModulePath = "github.com/Project-Helianthus/helianthus-ship-go"
	canonicalAPIPath    = canonicalModulePath + "/api"
)

type productionFile struct {
	path string
	file *ast.File
}

type typedProductionPackage struct {
	path   string
	fset   *token.FileSet
	syntax []*ast.File
	info   *types.Info
}

type discoverySourceAnalysis struct {
	reportCalls             []string
	unauthorizedReportCalls []string
	unauthorizedAllocations []string
	hubEndpointCollections  []string
}

func TestOutboundPairingAPIIsAbsentFromProductionTree(t *testing.T) {
	_, fset, files := loadProductionFiles(t)
	forbidden := map[string]struct{}{
		"OutboundPairingController": {},
		"QueueRemoteSKI":            {},
		"RemoteEndpoint":            {},
		"ReportRemoteEndpoint":      {},
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
				if !ast.IsExported(name.Name) {
					continue
				}
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

func TestDiscoveredMdnsEntriesAreTheOnlyConnectionInitiationSource(t *testing.T) {
	// Unknown production endpoint feeds cannot be ruled out behaviorally.
	root, fset, files := loadProductionFiles(t)
	typedPackages := loadTypedProductionPackages(t, root, fset, files)
	discovery := analyzeTypedDiscoveryPackages(typedPackages)

	t.Logf("ReportMdnsEntries production call inventory: %v", discovery.reportCalls)
	if len(discovery.reportCalls) == 0 {
		t.Error("mDNS discovery has no production report path")
	}
	if len(discovery.unauthorizedReportCalls) != 0 {
		t.Errorf("ReportMdnsEntries is called outside the real mDNS manager/provider path: %v", discovery.unauthorizedReportCalls)
	}
	if len(discovery.unauthorizedAllocations) != 0 {
		t.Errorf("MdnsEntry values are allocated outside MdnsManager discovery/report processing: %v", discovery.unauthorizedAllocations)
	}
	if len(discovery.hubEndpointCollections) != 0 {
		t.Errorf("Hub retains a separate MdnsEntry collection that could become an unobserved endpoint feed: %v", discovery.hubEndpointCollections)
	}
}

func TestDiscoverySourceAnalysisRejectsRenamedSyntheticEndpointPaths(t *testing.T) {
	tests := []struct {
		name            string
		source          string
		wantReportCalls int
		wantAllocations int
	}{
		{
			name: "renamed API forwards caller supplied entry",
			source: `package fixture
import api "github.com/Project-Helianthus/helianthus-ship-go/api"
type Hub struct{}
func (*Hub) ReportMdnsEntries(map[string]*api.MdnsEntry, bool) {}
func submitCandidate(h *Hub, candidate *api.MdnsEntry) {
	h.ReportMdnsEntries(map[string]*api.MdnsEntry{candidate.Ski: candidate}, true)
}`,
			wantReportCalls: 1,
		},
		{
			name: "alias passed to new",
			source: `package fixture
import api "github.com/Project-Helianthus/helianthus-ship-go/api"
type candidate = api.MdnsEntry
func allocateCandidate() *candidate { return new(candidate) }
`,
			wantAllocations: 1,
		},
		{
			name: "pointer to alias composite literal",
			source: `package fixture
import api "github.com/Project-Helianthus/helianthus-ship-go/api"
type candidate = api.MdnsEntry
func allocateCandidate() *candidate { return &candidate{Ski: "synthetic"} }
`,
			wantAllocations: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := loadTypedFixture(t, test.name, test.source)
			analysis := analyzeTypedDiscoveryPackages([]typedProductionPackage{fixture})
			if len(analysis.unauthorizedReportCalls) != test.wantReportCalls {
				t.Errorf("unauthorized ReportMdnsEntries calls = %v, want %d", analysis.unauthorizedReportCalls, test.wantReportCalls)
			}
			if len(analysis.unauthorizedAllocations) != test.wantAllocations {
				t.Errorf("unauthorized MdnsEntry allocations = %v, want %d", analysis.unauthorizedAllocations, test.wantAllocations)
			}
		})
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
		"Context", "Metadata", "RequirePairingApproval",
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
	// Unknown production dial paths cannot be ruled out behaviorally.
	_, fset, files := loadProductionFiles(t)

	var directDial []string
	var contextlessDial []string
	var hiddenSelectors []string
	var unprotectedClientConstructors []string
	protectedClientConstructors := 0

	for _, parsed := range files {
		parents := parentMap(parsed.file)
		ast.Inspect(parsed.file, func(node ast.Node) bool {
			switch item := node.(type) {
			case *ast.SelectorExpr:
				if item.Sel.Name != "Dial" &&
					item.Sel.Name != "DialContext" &&
					item.Sel.Name != "DialContextExpectedSKI" {
					return true
				}
				position := fset.Position(item.Pos()).String()
				call, ok := parents[item].(*ast.CallExpr)
				if !ok || call.Fun != item {
					hiddenSelectors = append(hiddenSelectors, position)
					return true
				}
				if item.Sel.Name == "Dial" {
					directDial = append(directDial, position+" in "+enclosingFunction(parents, item))
					return true
				}
				if len(call.Args) == 0 {
					contextlessDial = append(contextlessDial, position)
				}
			case *ast.CallExpr:
				selector, ok := item.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if rendered(fset, selector.X) != "ship" || len(item.Args) < 3 ||
					rendered(fset, item.Args[2]) != "ship.ShipRoleClient" {
					return true
				}
				switch selector.Sel.Name {
				case "NewConnectionHandler":
					unprotectedClientConstructors = append(
						unprotectedClientConstructors,
						fset.Position(item.Pos()).String(),
					)
				case "NewOutgoingConnectionHandler":
					protectedClientConstructors++
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
	if len(contextlessDial) != 0 {
		t.Errorf("context-aware dial calls without a context argument: %v", contextlessDial)
	}
	if len(unprotectedClientConstructors) != 0 {
		t.Errorf("unprotected SHIP client constructors remain: %v", unprotectedClientConstructors)
	}
	if protectedClientConstructors == 0 {
		t.Error("production has no protected SHIP client constructor")
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

func loadTypedProductionPackages(
	t *testing.T,
	root string,
	fset *token.FileSet,
	files []productionFile,
) []typedProductionPackage {
	t.Helper()
	exportFiles := goListExportFiles(t, root)
	exportImporter := importer.ForCompiler(fset, runtime.Compiler, func(path string) (io.ReadCloser, error) {
		exportPath, exists := exportFiles[path]
		if !exists {
			return nil, fmt.Errorf("no export data for %q", path)
		}
		return os.Open(exportPath)
	})

	filesByPackage := make(map[string][]*ast.File)
	for _, parsed := range files {
		relativeDir, err := filepath.Rel(root, filepath.Dir(parsed.path))
		if err != nil {
			t.Fatalf("resolve package path for %s: %v", parsed.path, err)
		}
		packagePath := canonicalModulePath
		if relativeDir != "." {
			packagePath += "/" + filepath.ToSlash(relativeDir)
		}
		filesByPackage[packagePath] = append(filesByPackage[packagePath], parsed.file)
	}

	packagePaths := make([]string, 0, len(filesByPackage))
	for packagePath := range filesByPackage {
		packagePaths = append(packagePaths, packagePath)
	}
	sort.Strings(packagePaths)

	typed := make([]typedProductionPackage, 0, len(packagePaths))
	for _, packagePath := range packagePaths {
		info := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
		}
		_, err := (&types.Config{
			GoVersion: "go1.22",
			Importer:  exportImporter,
		}).Check(packagePath, fset, filesByPackage[packagePath], info)
		if err != nil {
			t.Fatalf("type-check production package %s: %v", packagePath, err)
		}
		typed = append(typed, typedProductionPackage{
			path:   packagePath,
			fset:   fset,
			syntax: filesByPackage[packagePath],
			info:   info,
		})
	}
	return typed
}

func goListExportFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	command := exec.Command("go", "list", "-export", "-deps", "-f", "{{if .Export}}{{.ImportPath}}\t{{.Export}}{{end}}", "./...")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("load production export data: %v\n%s", err, output)
	}
	exportFiles := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" {
			continue
		}
		packagePath, exportPath, found := strings.Cut(line, "\t")
		if !found {
			t.Fatalf("parse go list export line %q", line)
		}
		exportFiles[packagePath] = exportPath
	}
	return exportFiles
}

func analyzeTypedDiscoveryPackages(typedPackages []typedProductionPackage) discoverySourceAnalysis {
	var analysis discoverySourceAnalysis
	for _, typedPackage := range typedPackages {
		for _, file := range typedPackage.syntax {
			if strings.HasSuffix(typedPackage.fset.Position(file.Pos()).Filename, "_test.go") {
				continue
			}
			parents := parentMap(file)
			ast.Inspect(file, func(node ast.Node) bool {
				switch item := node.(type) {
				case *ast.CompositeLit:
					if isCanonicalMdnsEntry(typedPackage.info.TypeOf(item)) {
						recordMdnsAllocation(&analysis, typedPackage, parents, item)
					}
				case *ast.CallExpr:
					if isBuiltinNew(item, typedPackage.info) && len(item.Args) == 1 &&
						isCanonicalMdnsEntry(typedPackage.info.TypeOf(item.Args[0])) {
						recordMdnsAllocation(&analysis, typedPackage, parents, item)
					}
					if isReportMdnsEntriesCall(item, typedPackage.info) {
						site := typedSite(typedPackage, parents, item)
						analysis.reportCalls = append(analysis.reportCalls, site)
						if !isReviewedMdnsReportMethod(typedPackage, enclosingFunctionDeclaration(parents, item)) {
							analysis.unauthorizedReportCalls = append(analysis.unauthorizedReportCalls, site)
						}
					}
				case *ast.SelectorExpr:
					if !isReportMdnsEntriesSelector(item, typedPackage.info) {
						return true
					}
					call, directlyCalled := parents[item].(*ast.CallExpr)
					if directlyCalled && call.Fun == item {
						return true
					}
					site := typedSite(typedPackage, parents, item) + " (method value)"
					analysis.unauthorizedReportCalls = append(analysis.unauthorizedReportCalls, site)
				case *ast.TypeSpec:
					if !isHubType(item, typedPackage) {
						return true
					}
					structure, ok := item.Type.(*ast.StructType)
					if !ok {
						return true
					}
					for _, field := range structure.Fields.List {
						if storesCanonicalMdnsEntry(typedPackage.info.TypeOf(field.Type), make(map[types.Type]bool)) {
							analysis.hubEndpointCollections = append(analysis.hubEndpointCollections,
								typedPackage.fset.Position(field.Pos()).String())
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(analysis.reportCalls)
	sort.Strings(analysis.unauthorizedReportCalls)
	sort.Strings(analysis.unauthorizedAllocations)
	sort.Strings(analysis.hubEndpointCollections)
	return analysis
}

func recordMdnsAllocation(
	analysis *discoverySourceAnalysis,
	typedPackage typedProductionPackage,
	parents map[ast.Node]ast.Node,
	node ast.Node,
) {
	owner := enclosingFunctionDeclaration(parents, node)
	if !isMdnsProviderMethod(typedPackage, owner) {
		analysis.unauthorizedAllocations = append(analysis.unauthorizedAllocations,
			typedSite(typedPackage, parents, node))
	}
}

func isBuiltinNew(call *ast.CallExpr, info *types.Info) bool {
	identifier, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	builtin, ok := info.Uses[identifier].(*types.Builtin)
	return ok && builtin.Name() == "new"
}

func isReportMdnsEntriesCall(call *ast.CallExpr, info *types.Info) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && isReportMdnsEntriesSelector(selector, info)
}

func isReportMdnsEntriesSelector(selector *ast.SelectorExpr, info *types.Info) bool {
	var object types.Object
	if selection := info.Selections[selector]; selection != nil {
		object = selection.Obj()
	} else {
		object = info.Uses[selector.Sel]
	}
	function, ok := object.(*types.Func)
	if !ok || (function.Name() != "ReportMdnsEntries" && function.Name() != "ReportMdnsEntriesWithCandidates") {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || (signature.Params().Len() != 2 && signature.Params().Len() != 4) {
		return false
	}
	entries, ok := types.Unalias(signature.Params().At(0).Type()).(*types.Map)
	if !ok || !isStringType(entries.Key()) || !isCanonicalMdnsEntry(entries.Elem()) ||
		!isBoolType(signature.Params().At(1).Type()) {
		return false
	}
	return signature.Params().Len() == 2 || isUint64Type(signature.Params().At(3).Type())
}

func isCanonicalMdnsEntry(value types.Type) bool {
	if value == nil {
		return false
	}
	value = types.Unalias(value)
	if pointer, ok := value.(*types.Pointer); ok {
		return isCanonicalMdnsEntry(pointer.Elem())
	}
	named, ok := value.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == canonicalAPIPath &&
		named.Obj().Name() == "MdnsEntry"
}

func storesCanonicalMdnsEntry(value types.Type, seen map[types.Type]bool) bool {
	if value == nil {
		return false
	}
	value = types.Unalias(value)
	if isCanonicalMdnsEntry(value) {
		return true
	}
	if seen[value] {
		return false
	}
	seen[value] = true

	switch concrete := value.(type) {
	case *types.Pointer:
		return storesCanonicalMdnsEntry(concrete.Elem(), seen)
	case *types.Array:
		return storesCanonicalMdnsEntry(concrete.Elem(), seen)
	case *types.Slice:
		return storesCanonicalMdnsEntry(concrete.Elem(), seen)
	case *types.Map:
		return storesCanonicalMdnsEntry(concrete.Key(), seen) || storesCanonicalMdnsEntry(concrete.Elem(), seen)
	case *types.Named:
		return storesCanonicalMdnsEntry(concrete.Underlying(), seen)
	case *types.Struct:
		for index := 0; index < concrete.NumFields(); index++ {
			if storesCanonicalMdnsEntry(concrete.Field(index).Type(), seen) {
				return true
			}
		}
	}
	return false
}

func isHubType(specification *ast.TypeSpec, typedPackage typedProductionPackage) bool {
	object, ok := typedPackage.info.Defs[specification.Name].(*types.TypeName)
	return ok && object.Pkg() != nil && object.Pkg().Path() == canonicalModulePath+"/hub" && object.Name() == "Hub"
}

func isMdnsProviderMethod(typedPackage typedProductionPackage, declaration *ast.FuncDecl) bool {
	if declaration == nil || typedPackage.path != canonicalModulePath+"/mdns" {
		return false
	}
	function, ok := typedPackage.info.Defs[declaration.Name].(*types.Func)
	if !ok {
		return false
	}
	signature, ok := function.Type().(*types.Signature)
	if !ok || signature.Recv() == nil {
		return false
	}
	receiver := types.Unalias(signature.Recv().Type())
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = types.Unalias(pointer.Elem())
	}
	named, ok := receiver.(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == canonicalModulePath+"/mdns" &&
		named.Obj().Name() == "MdnsManager"
}

func isReviewedMdnsReportMethod(typedPackage typedProductionPackage, declaration *ast.FuncDecl) bool {
	if isMdnsProviderMethod(typedPackage, declaration) {
		return true
	}
	return declaration != nil && typedPackage.path == canonicalModulePath+"/hub" &&
		declaration.Name.Name == "ReportMdnsEntries" && receiverName(declaration) == "Hub"
}

func isStringType(value types.Type) bool {
	basic, ok := types.Unalias(value).(*types.Basic)
	return ok && basic.Kind() == types.String
}

func isBoolType(value types.Type) bool {
	basic, ok := types.Unalias(value).(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

func isUint64Type(value types.Type) bool {
	basic, ok := types.Unalias(value).(*types.Basic)
	return ok && basic.Kind() == types.Uint64
}

func typedSite(typedPackage typedProductionPackage, parents map[ast.Node]ast.Node, node ast.Node) string {
	return typedPackage.fset.Position(node.Pos()).String() + " in " + enclosingFunction(parents, node)
}

type fixtureImporter struct {
	api *types.Package
}

func (importer fixtureImporter) Import(path string) (*types.Package, error) {
	if path == canonicalAPIPath {
		return importer.api, nil
	}
	return nil, fmt.Errorf("fixture import %q is not supported", path)
}

func loadTypedFixture(t *testing.T, name, source string) typedProductionPackage {
	t.Helper()
	fset := token.NewFileSet()
	filename := strings.ReplaceAll(name, " ", "_") + ".go"
	file, err := parser.ParseFile(fset, filename, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	info := &types.Info{
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Defs:       make(map[*ast.Ident]types.Object),
		Uses:       make(map[*ast.Ident]types.Object),
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
	}
	packagePath := "example.invalid/" + strings.ReplaceAll(name, " ", "-")
	checked, err := (&types.Config{
		GoVersion: "go1.22",
		Importer:  fixtureImporter{api: newFixtureAPIPackage()},
	}).Check(packagePath, fset, []*ast.File{file}, info)
	if err != nil {
		t.Fatalf("type-check fixture: %v", err)
	}
	return typedProductionPackage{path: checked.Path(), fset: fset, syntax: []*ast.File{file}, info: info}
}

func newFixtureAPIPackage() *types.Package {
	apiPackage := types.NewPackage(canonicalAPIPath, "api")
	ski := types.NewVar(token.NoPos, apiPackage, "Ski", types.Typ[types.String])
	entryName := types.NewTypeName(token.NoPos, apiPackage, "MdnsEntry", nil)
	types.NewNamed(entryName, types.NewStruct([]*types.Var{ski}, []string{""}), nil)
	apiPackage.Scope().Insert(entryName)
	apiPackage.MarkComplete()
	return apiPackage
}

func enclosingFunctionDeclaration(parents map[ast.Node]ast.Node, node ast.Node) *ast.FuncDecl {
	for current := node; current != nil; current = parents[current] {
		if declaration, ok := current.(*ast.FuncDecl); ok {
			return declaration
		}
	}
	return nil
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
