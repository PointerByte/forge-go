// Command api-inventory emits a deterministic inventory of GoForge declarations.
//
// It deliberately uses only the Go standard library so the Phase 0 audit can run
// before dependency updates and on every module in the workspace.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type inventory struct {
	SchemaVersion string        `json:"schemaVersion"`
	GeneratedAt   string        `json:"generatedAt"`
	Repository    string        `json:"repository"`
	Summary       summary       `json:"summary"`
	Packages      []packageItem `json:"packages"`
	APIs          []apiItem     `json:"apis"`
}

type summary struct {
	Modules        int `json:"modules"`
	Packages       int `json:"packages"`
	PublicAPIs     int `json:"publicApis"`
	PrivateAPIs    int `json:"privateApis"`
	Interfaces     int `json:"interfaces"`
	Structs        int `json:"structs"`
	Constants      int `json:"constants"`
	Globals        int `json:"globals"`
	Tests          int `json:"tests"`
	Benchmarks     int `json:"benchmarks"`
	Examples       int `json:"examples"`
	CLICommands    int `json:"cliCommands"`
	MiddlewareAPIs int `json:"middlewareApis"`
}

type packageItem struct {
	Module       string   `json:"module"`
	ImportPath   string   `json:"importPath"`
	Directory    string   `json:"directory"`
	Name         string   `json:"name"`
	Files        int      `json:"files"`
	TestFiles    int      `json:"testFiles"`
	Dependencies []string `json:"dependencies"`
	Portability  string   `json:"portability"`
	Reason       string   `json:"portabilityReason"`
}

type apiItem struct {
	ID             string   `json:"id"`
	Module         string   `json:"module"`
	Package        string   `json:"package"`
	Directory      string   `json:"directory"`
	File           string   `json:"file"`
	Line           int      `json:"line"`
	Name           string   `json:"name"`
	Receiver       string   `json:"receiver,omitempty"`
	Kind           string   `json:"kind"`
	Visibility     string   `json:"visibility"`
	Classification string   `json:"classification"`
	Documented     bool     `json:"documented"`
	Tested         bool     `json:"tested"`
	Benchmarked    bool     `json:"benchmarked"`
	Consumers      []string `json:"consumers"`
	Portability    string   `json:"portability"`
	Recommendation string   `json:"recommendation"`
}

type moduleInfo struct {
	dir  string
	path string
}

type parsedFile struct {
	path       string
	rel        string
	module     moduleInfo
	file       *ast.File
	fset       *token.FileSet
	isTest     bool
	identNames map[string]bool
}

type pkgAccum struct {
	item    packageItem
	imports map[string]bool
}

func main() {
	rootFlag := flag.String("root", ".", "GoForge repository root")
	jsonFlag := flag.String("json", "", "JSON output path (stdout when empty)")
	mdFlag := flag.String("markdown", "", "optional Markdown summary path")
	checkFlag := flag.Bool("check", false, "compare generated content with output paths instead of writing")
	stampFlag := flag.String("generated-at", "", "RFC3339 timestamp; SOURCE_DATE_EPOCH or current UTC when empty")
	flag.Parse()

	root, err := filepath.Abs(*rootFlag)
	must(err)
	modules, err := findModules(root)
	must(err)
	files, err := parseFiles(root, modules)
	must(err)
	inv := buildInventory(root, modules, files, generatedAt(*stampFlag))

	b, err := json.MarshalIndent(inv, "", "  ")
	must(err)
	b = append(b, '\n')
	markdownContent := []byte(markdown(inv))
	if *checkFlag {
		if *jsonFlag == "" {
			panic("-check requires -json")
		}
		mustMatches(*jsonFlag, b)
		if *mdFlag != "" {
			mustMatches(*mdFlag, markdownContent)
		}
		fmt.Println("GoForge API inventory is current.")
		return
	}
	if *jsonFlag == "" {
		_, err = os.Stdout.Write(b)
	} else {
		err = os.WriteFile(*jsonFlag, b, 0o644)
	}
	must(err)
	if *mdFlag != "" {
		must(os.WriteFile(*mdFlag, markdownContent, 0o644))
	}
}

func generatedAt(explicit string) string {
	if explicit != "" {
		if _, err := time.Parse(time.RFC3339, explicit); err != nil {
			panic(fmt.Errorf("invalid -generated-at: %w", err))
		}
		return explicit
	}
	if epoch := os.Getenv("SOURCE_DATE_EPOCH"); epoch != "" {
		var seconds int64
		if _, err := fmt.Sscan(epoch, &seconds); err != nil {
			panic(fmt.Errorf("invalid SOURCE_DATE_EPOCH: %w", err))
		}
		return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}

func findModules(root string) ([]moduleInfo, error) {
	var modules []moduleInfo
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && path != root && skipDir(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() || entry.Name() != "go.mod" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		modulePath := ""
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "module" {
				modulePath = fields[1]
				break
			}
		}
		if modulePath == "" {
			return fmt.Errorf("module directive missing in %s", path)
		}
		modules = append(modules, moduleInfo{dir: filepath.Dir(path), path: modulePath})
		return nil
	})
	sort.Slice(modules, func(i, j int) bool {
		if len(modules[i].dir) != len(modules[j].dir) {
			return len(modules[i].dir) > len(modules[j].dir)
		}
		return modules[i].dir < modules[j].dir
	})
	return modules, err
}

func parseFiles(root string, modules []moduleInfo) ([]parsedFile, error) {
	fset := token.NewFileSet()
	var files []parsedFile
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && path != root && skipDir(entry.Name()) {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		pf := parsedFile{path: path, rel: filepath.ToSlash(rel), module: moduleFor(path, modules), file: file, fset: fset, isTest: strings.HasSuffix(path, "_test.go"), identNames: map[string]bool{}}
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				pf.identNames[ident.Name] = true
			}
			return true
		})
		files = append(files, pf)
		return nil
	})
	return files, err
}

func buildInventory(root string, modules []moduleInfo, files []parsedFile, stamp string) inventory {
	pkgs := map[string]*pkgAccum{}
	testNames := map[string]bool{}
	benchNames := map[string]bool{}
	for _, pf := range files {
		dir := filepath.Dir(pf.path)
		key := dir + "\x00" + pf.file.Name.Name
		acc := pkgs[key]
		if acc == nil {
			relDir, _ := filepath.Rel(root, dir)
			importPath := pf.module.path
			if suffix, _ := filepath.Rel(pf.module.dir, dir); suffix != "." {
				importPath += "/" + filepath.ToSlash(suffix)
			}
			acc = &pkgAccum{item: packageItem{Module: pf.module.path, ImportPath: importPath, Directory: filepath.ToSlash(relDir), Name: pf.file.Name.Name}, imports: map[string]bool{}}
			pkgs[key] = acc
		}
		acc.item.Files++
		if pf.isTest {
			acc.item.TestFiles++
		}
		for _, imp := range pf.file.Imports {
			acc.imports[strings.Trim(imp.Path.Value, "\"")] = true
		}
		if pf.isTest {
			for _, decl := range pf.file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					if strings.HasPrefix(fn.Name.Name, "Test") || strings.HasPrefix(fn.Name.Name, "Example") {
						testNames[fn.Name.Name] = true
					}
					if strings.HasPrefix(fn.Name.Name, "Benchmark") {
						benchNames[fn.Name.Name] = true
					}
				}
			}
		}
	}

	inv := inventory{SchemaVersion: "1.0.0", GeneratedAt: stamp, Repository: "forge-go-private"}
	for _, acc := range pkgs {
		for imp := range acc.imports {
			acc.item.Dependencies = append(acc.item.Dependencies, imp)
		}
		sort.Strings(acc.item.Dependencies)
		acc.item.Portability, acc.item.Reason = classifyImports(acc.item.Dependencies)
		inv.Packages = append(inv.Packages, acc.item)
	}
	sort.Slice(inv.Packages, func(i, j int) bool { return inv.Packages[i].ImportPath < inv.Packages[j].ImportPath })

	packageByDir := map[string]packageItem{}
	for _, pkg := range inv.Packages {
		packageByDir[pkg.Directory] = pkg
	}
	for _, pf := range files {
		if pf.isTest {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(pf.rel))
		pkg := packageByDir[dir]
		for _, decl := range pf.file.Decls {
			switch node := decl.(type) {
			case *ast.FuncDecl:
				receiver := receiverName(node.Recv)
				kind := "function"
				if receiver != "" {
					kind = "method"
				}
				inv.APIs = append(inv.APIs, makeAPI(root, pf, pkg, node.Name.Name, receiver, kind, docText(node.Doc), node.Pos(), files, testNames, benchNames))
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					switch item := spec.(type) {
					case *ast.TypeSpec:
						kind := "type"
						switch item.Type.(type) {
						case *ast.StructType:
							kind = "struct"
						case *ast.InterfaceType:
							kind = "interface"
						}
						doc := docText(node.Doc)
						if item.Doc != nil {
							doc = docText(item.Doc)
						}
						inv.APIs = append(inv.APIs, makeAPI(root, pf, pkg, item.Name.Name, "", kind, doc, item.Pos(), files, testNames, benchNames))
						switch typed := item.Type.(type) {
						case *ast.StructType:
							for _, field := range typed.Fields.List {
								for _, member := range fieldNames(field) {
									inv.APIs = append(inv.APIs, makeAPI(root, pf, pkg, member, item.Name.Name, "field", docText(field.Doc), field.Pos(), files, testNames, benchNames))
								}
							}
						case *ast.InterfaceType:
							for _, field := range typed.Methods.List {
								for _, member := range fieldNames(field) {
									inv.APIs = append(inv.APIs, makeAPI(root, pf, pkg, member, item.Name.Name, "interface-method", docText(field.Doc), field.Pos(), files, testNames, benchNames))
								}
							}
						}
					case *ast.ValueSpec:
						kind := "global"
						if node.Tok == token.CONST {
							kind = "constant"
						}
						for _, name := range item.Names {
							doc := docText(node.Doc)
							if item.Doc != nil {
								doc = docText(item.Doc)
							}
							inv.APIs = append(inv.APIs, makeAPI(root, pf, pkg, name.Name, "", kind, doc, name.Pos(), files, testNames, benchNames))
						}
					}
				}
			}
		}
	}
	sort.Slice(inv.APIs, func(i, j int) bool { return inv.APIs[i].ID < inv.APIs[j].ID })
	inv.Summary.Modules = len(modules)
	inv.Summary.Packages = len(inv.Packages)
	for _, api := range inv.APIs {
		if api.Visibility == "public" {
			inv.Summary.PublicAPIs++
		} else if api.Visibility == "private" {
			inv.Summary.PrivateAPIs++
		}
		switch api.Kind {
		case "interface":
			inv.Summary.Interfaces++
		case "struct":
			inv.Summary.Structs++
		case "constant":
			inv.Summary.Constants++
		case "global":
			inv.Summary.Globals++
		}
		if strings.Contains(strings.ToLower(api.Package+"/"+api.Name), "middleware") {
			inv.Summary.MiddlewareAPIs++
		}
	}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			switch {
			case strings.HasPrefix(fn.Name.Name, "Test"):
				inv.Summary.Tests++
			case strings.HasPrefix(fn.Name.Name, "Benchmark"):
				inv.Summary.Benchmarks++
			case strings.HasPrefix(fn.Name.Name, "Example"):
				inv.Summary.Examples++
			}
		}
		if strings.Contains("/"+pf.rel, "/cmd/") && !pf.isTest && pf.file.Name.Name == "main" {
			inv.Summary.CLICommands++
		}
	}
	return inv
}

func makeAPI(root string, pf parsedFile, pkg packageItem, name, receiver, kind, doc string, pos token.Pos, files []parsedFile, tests, benches map[string]bool) apiItem {
	visibility := "private"
	classification := "Internal"
	publicReceiver := receiver == "" || ast.IsExported(receiver)
	if ast.IsExported(name) && publicReceiver && pkg.Name != "main" {
		visibility = "public"
		classification = "Stable"
	} else if pkg.Name == "main" && ast.IsExported(name) {
		visibility = "cli"
		classification = "Internal"
	}
	lowerDoc := strings.ToLower(doc)
	switch {
	case strings.Contains(lowerDoc, "deprecated:"):
		classification = "Deprecated"
	case strings.Contains(lowerDoc, "experimental"):
		classification = "Experimental"
	case strings.Contains("/"+pf.rel, "/internal/") || strings.HasPrefix(pf.file.Name.Name, "internal"):
		classification = "Internal"
		visibility = "private"
	}
	portability, _ := classifyImports(pkg.Dependencies)
	idName := name
	if receiver != "" {
		idName = receiver + "." + name
	}
	item := apiItem{
		ID:             pkg.ImportPath + "." + idName,
		Module:         pf.module.path,
		Package:        pkg.ImportPath,
		Directory:      pkg.Directory,
		File:           pf.rel,
		Line:           pf.fset.Position(pos).Line,
		Name:           name,
		Receiver:       receiver,
		Kind:           kind,
		Visibility:     visibility,
		Classification: classification,
		Documented:     strings.TrimSpace(doc) != "",
		Portability:    portability,
		Recommendation: recommendation(visibility, classification, portability),
	}
	for _, file := range files {
		if !file.identNames[name] || file.path == pf.path {
			continue
		}
		if file.isTest {
			item.Tested = true
			if containsBenchmark(file.file, name) {
				item.Benchmarked = true
			}
		} else {
			consumerDir := filepath.ToSlash(filepath.Dir(file.rel))
			if consumerDir != pkg.Directory {
				item.Consumers = append(item.Consumers, consumerDir)
			}
		}
	}
	item.Tested = item.Tested || tests["Test"+name] || tests["Example"+name]
	item.Benchmarked = item.Benchmarked || benches["Benchmark"+name]
	item.Consumers = uniqueSorted(item.Consumers)
	return item
}

func classifyImports(imports []string) (string, string) {
	host := []string{"github.com/gin-gonic", "google.golang.org/grpc", "go.opentelemetry.io", "github.com/spf13/viper", "github.com/aws/", "github.com/Azure/", "cloud.google.com/", "os/exec", "net/http", "crypto/tls", "os", "syscall"}
	for _, imp := range imports {
		for _, marker := range host {
			if imp == marker || strings.HasPrefix(imp, marker) {
				return "host-dependent", "imports " + imp
			}
		}
	}
	return "portable-candidate", "no known host-only import"
}

func recommendation(visibility, classification, portability string) string {
	if classification == "Deprecated" {
		return "preserve compatibility; publish replacement and removal window"
	}
	if visibility != "public" {
		return "retain internally unless reference analysis proves dead code"
	}
	if portability == "portable-candidate" {
		return "evaluate for portable core/component parity"
	}
	return "retain Go facade; model as host capability or Deno native adapter"
}

func receiverName(fields *ast.FieldList) string {
	if fields == nil || len(fields.List) == 0 {
		return ""
	}
	expr := fields.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return "receiver"
}

func fieldNames(field *ast.Field) []string {
	if len(field.Names) > 0 {
		names := make([]string, 0, len(field.Names))
		for _, name := range field.Names {
			names = append(names, name.Name)
		}
		return names
	}
	expr := field.Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	switch typed := expr.(type) {
	case *ast.Ident:
		return []string{typed.Name}
	case *ast.SelectorExpr:
		return []string{typed.Sel.Name}
	default:
		return []string{"embedded"}
	}
}

func containsBenchmark(file *ast.File, name string) bool {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fn.Name.Name, "Benchmark") || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok && ident.Name == name {
				found = true
				return false
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func docText(group *ast.CommentGroup) string {
	if group == nil {
		return ""
	}
	return strings.TrimSpace(group.Text())
}

func moduleFor(path string, modules []moduleInfo) moduleInfo {
	for _, module := range modules {
		rel, err := filepath.Rel(module.dir, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return module
		}
	}
	panic("no Go module for " + path)
}

func skipDir(name string) bool {
	switch name {
	case ".git", "vendor", "coverage", "openspec", "research", "testdata", "node_modules", "api-inventory":
		return true
	default:
		return false
	}
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func markdown(inv inventory) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# GoForge Phase 0 API Inventory\n\nGenerated: `%s`\n\n", inv.GeneratedAt)
	fmt.Fprintf(&b, "Modules: **%d** · Packages: **%d** · Public APIs: **%d** · Private APIs: **%d** · Tests: **%d** · Benchmarks: **%d**\n\n", inv.Summary.Modules, inv.Summary.Packages, inv.Summary.PublicAPIs, inv.Summary.PrivateAPIs, inv.Summary.Tests, inv.Summary.Benchmarks)
	b.WriteString("| API | Kind | Class | Docs | Tests | Benchmark | Portability | Recommendation |\n")
	b.WriteString("|---|---|---|---:|---:|---:|---|---|\n")
	for _, api := range inv.APIs {
		if api.Visibility != "public" {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %t | %t | %t | %s | %s |\n", api.ID, api.Kind, api.Classification, api.Documented, api.Tested, api.Benchmarked, api.Portability, api.Recommendation)
	}
	return b.String()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustMatches(path string, generated []byte) {
	expected, err := os.ReadFile(path)
	must(err)
	if string(expected) != string(generated) {
		panic(fmt.Sprintf("API inventory drifted: regenerate and review %s", path))
	}
}
