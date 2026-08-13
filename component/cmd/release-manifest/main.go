package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/PointerByte/forge-go/component/internal/bundle"
)

func main() {
	artifacts := flag.String("artifacts", "artifacts", "release bundle output directory")
	portable := flag.String("portable", "../portable", "canonical portable module directory")
	compiler := flag.String(
		"compiler",
		"tinygo",
		"component compiler that produced the build: tinygo (production per ADR 0012) "+
			"or componentize-go (regression only)",
	)
	flag.Parse()

	var chain bundle.Toolchain
	switch *compiler {
	case "tinygo":
		chain = bundle.TinyGoToolchain()
	case "componentize-go":
		chain = bundle.ComponentizeGoToolchain()
	default:
		fmt.Fprintf(os.Stderr, "unknown component compiler %q\n", *compiler)
		os.Exit(2)
	}

	if err := bundle.Generate(*artifacts, *portable, chain); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
