// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import "runtime"

var runtimeCaller = runtime.Caller
var runtimeFuncForPC = runtime.FuncForPC

func TraceCaller(skip int) (funcName string, line int) {
	pc, _, line, ok := runtimeCaller(skip)
	if !ok {
		return "unknown", 0
	}
	fn := runtimeFuncForPC(pc)
	if fn == nil {
		return "unknown", line
	}
	return fn.Name(), line
}
