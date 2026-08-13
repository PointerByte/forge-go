//go:build tinygo

package main

import (
	"github.com/PointerByte/forge-go/share/tinygo-wasip2/generated/pointerbyte/goforge-poc/host"
	"github.com/PointerByte/forge-go/share/tinygo-wasip2/generated/pointerbyte/goforge-poc/operations"
)

func init() {
	operations.Exports.Add = add
	operations.Exports.Greet = greet
	operations.Exports.ReverseBytes = reverseBytes
	operations.Exports.Summarize = summarize
	operations.Exports.Annotate = host.Annotate
}

func main() {}
