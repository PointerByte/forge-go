package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestClassifyImports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		imports []string
		want    string
	}{
		{name: "portable", imports: []string{"encoding/json"}, want: "portable-candidate"},
		{name: "operating system", imports: []string{"os"}, want: "host-dependent"},
		{name: "grpc", imports: []string{"google.golang.org/grpc"}, want: "host-dependent"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, _ := classifyImports(test.imports)
			if got != test.want {
				t.Fatalf("classifyImports() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestFieldNames(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "model.go", `package model
type Item struct {
	Name string
	*Embedded
}
`, 0)
	if err != nil {
		t.Fatal(err)
	}
	typeSpec := file.Decls[0].(*ast.GenDecl).Specs[0].(*ast.TypeSpec)
	fields := typeSpec.Type.(*ast.StructType).Fields.List
	got := append(fieldNames(fields[0]), fieldNames(fields[1])...)
	want := []string{"Name", "Embedded"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fieldNames() = %#v, want %#v", got, want)
	}
}

func TestGeneratedAtFromEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "0")
	if got := generatedAt(""); got != "1970-01-01T00:00:00Z" {
		t.Fatalf("generatedAt() = %q", got)
	}
}
