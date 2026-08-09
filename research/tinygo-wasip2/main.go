//go:generate ./scripts/generate.sh

package main

import (
	"math"

	"github.com/PointerByte/forge-go/research/tinygo-wasip2/generated/pointerbyte/goforge-poc/operations"
	"go.bytecodealliance.org/cm"
)

func add(left, right uint32) uint32 {
	return left + right
}

func greet(name string) string {
	return "hello, " + name
}

func reverseBytes(value cm.List[uint8]) cm.List[uint8] {
	in := value.Slice()
	out := make([]byte, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return cm.ToList(out)
}

func summarize(value operations.Pair) cm.Result[operations.SummaryShape, operations.Summary, operations.OperationError] {
	if value.Left == 0 && value.Right == 0 {
		return cm.Err[cm.Result[operations.SummaryShape, operations.Summary, operations.OperationError]](
			operations.OperationErrorInvalidInput("both values must not be zero"),
		)
	}
	if value.Right > math.MaxUint32-value.Left {
		return cm.Err[cm.Result[operations.SummaryShape, operations.Summary, operations.OperationError]](
			operations.OperationErrorOverflow(),
		)
	}

	total := value.Left + value.Right
	return cm.OK[cm.Result[operations.SummaryShape, operations.Summary, operations.OperationError]](
		operations.Summary{Total: total, Label: "sum:" + uint32String(total)},
	)
}

// uint32String avoids fmt and strconv in the guest so the PoC remains focused
// on the canonical ABI rather than extra TinyGo standard-library coverage.
func uint32String(value uint32) string {
	if value == 0 {
		return "0"
	}

	var buffer [10]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
