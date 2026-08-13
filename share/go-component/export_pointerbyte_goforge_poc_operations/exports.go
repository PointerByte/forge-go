package export_pointerbyte_goforge_poc_operations

import (
	"math"

	types "go.bytecodealliance.org/pkg/wit/types"
	"wit_component/pointerbyte_goforge_poc_host"
	"wit_component/pointerbyte_goforge_poc_operations"
)

func Add(left, right uint32) uint32 {
	return left + right
}

func Greet(name string) string {
	return "hello, " + name
}

func ReverseBytes(value []uint8) []uint8 {
	result := make([]byte, len(value))
	for index := range value {
		result[len(value)-1-index] = value[index]
	}
	return result
}

func Summarize(
	value pointerbyte_goforge_poc_operations.Pair,
) types.Result[pointerbyte_goforge_poc_operations.Summary, pointerbyte_goforge_poc_operations.OperationError] {
	if value.Left == 0 && value.Right == 0 {
		return types.Err[pointerbyte_goforge_poc_operations.Summary](
			pointerbyte_goforge_poc_operations.MakeOperationErrorInvalidInput("both values must not be zero"),
		)
	}
	if value.Right > math.MaxUint32-value.Left {
		return types.Err[pointerbyte_goforge_poc_operations.Summary](
			pointerbyte_goforge_poc_operations.MakeOperationErrorOverflow(),
		)
	}

	total := value.Left + value.Right
	return types.Ok[pointerbyte_goforge_poc_operations.Summary, pointerbyte_goforge_poc_operations.OperationError](
		pointerbyte_goforge_poc_operations.Summary{
			Total: total,
			Label: "sum:" + uint32String(total),
		},
	)
}

func Annotate(value string) string {
	return pointerbyte_goforge_poc_host.Annotate(value)
}

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
