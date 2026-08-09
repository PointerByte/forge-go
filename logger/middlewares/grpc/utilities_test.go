// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"net/http"
	"testing"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/spf13/viper"
)

func TestEnableBody(t *testing.T) {
	resetGRPCUtilitiesTestState(t)

	tests := []struct {
		name               string
		enableRequestBody  bool
		enableResponseBody bool
	}{
		{
			name:               "enables only request body",
			enableRequestBody:  true,
			enableResponseBody: false,
		},
		{
			name:               "enables only response body",
			enableRequestBody:  false,
			enableResponseBody: true,
		},
		{
			name:               "enables both bodies",
			enableRequestBody:  true,
			enableResponseBody: true,
		},
		{
			name:               "disables both bodies",
			enableRequestBody:  false,
			enableResponseBody: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctxLogger := builder.New(context.Background())

			if flag, ok := ctxLogger.Get(common.DisableRequestBodyKey); !ok || flag != true {
				t.Fatalf("%q before EnableBody = %#v, want true", common.DisableRequestBodyKey, flag)
			}
			if flag, ok := ctxLogger.Get(common.DisableResponseBodyKey); !ok || flag != true {
				t.Fatalf("%q before EnableBody = %#v, want true", common.DisableResponseBodyKey, flag)
			}

			EnableBody(ctxLogger, tt.enableRequestBody, tt.enableResponseBody)

			requestFlag, ok := ctxLogger.Get(common.DisableRequestBodyKey)
			wantRequestFlag := !tt.enableRequestBody
			if !ok || requestFlag != wantRequestFlag {
				t.Fatalf("%q = %#v, want %#v", common.DisableRequestBodyKey, requestFlag, wantRequestFlag)
			}
			responseFlag, ok := ctxLogger.Get(common.DisableResponseBodyKey)
			wantResponseFlag := !tt.enableResponseBody
			if !ok || responseFlag != wantResponseFlag {
				t.Fatalf("%q = %#v, want %#v", common.DisableResponseBodyKey, responseFlag, wantResponseFlag)
			}
		})
	}
}

func TestEnableTraceBody(t *testing.T) {
	resetGRPCUtilitiesTestState(t)

	tests := []struct {
		name               string
		enableRequestBody  bool
		enableResponseBody bool
		wantRequest        any
		wantResponse       any
	}{
		{
			name:               "enables only trace request body",
			enableRequestBody:  true,
			enableResponseBody: false,
			wantRequest:        "trace-request",
			wantResponse:       nil,
		},
		{
			name:               "enables only trace response body",
			enableRequestBody:  false,
			enableResponseBody: true,
			wantRequest:        nil,
			wantResponse:       "trace-response",
		},
		{
			name:               "enables both trace bodies",
			enableRequestBody:  true,
			enableResponseBody: true,
			wantRequest:        "trace-request",
			wantResponse:       "trace-response",
		},
		{
			name:               "disables both trace bodies",
			enableRequestBody:  false,
			enableResponseBody: false,
			wantRequest:        nil,
			wantResponse:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctxLogger := builder.New(context.Background())

			if flag, ok := ctxLogger.Get(common.DisableTraceRequestBodyKey); !ok || flag != true {
				t.Fatalf("%q before EnableTraceBody = %#v, want true", common.DisableTraceRequestBodyKey, flag)
			}
			if flag, ok := ctxLogger.Get(common.DisableTraceResponseBodyKey); !ok || flag != true {
				t.Fatalf("%q before EnableTraceBody = %#v, want true", common.DisableTraceResponseBodyKey, flag)
			}

			EnableTraceBody(ctxLogger, tt.enableRequestBody, tt.enableResponseBody)

			requestFlag, ok := ctxLogger.Get(common.DisableTraceRequestBodyKey)
			wantRequestFlag := !tt.enableRequestBody
			if !ok || requestFlag != wantRequestFlag {
				t.Fatalf("%q = %#v, want %#v", common.DisableTraceRequestBodyKey, requestFlag, wantRequestFlag)
			}
			responseFlag, ok := ctxLogger.Get(common.DisableTraceResponseBodyKey)
			wantResponseFlag := !tt.enableResponseBody
			if !ok || responseFlag != wantResponseFlag {
				t.Fatalf("%q = %#v, want %#v", common.DisableTraceResponseBodyKey, responseFlag, wantResponseFlag)
			}

			process := &formatter.Process{
				System:   "test-service",
				Process:  "trace-process",
				Code:     http.StatusOK,
				Request:  "trace-request",
				Response: "trace-response",
			}
			ctxLogger.TraceInit(process)
			ctxLogger.TraceEnd(process)

			if process.Request != tt.wantRequest {
				t.Fatalf("process.Request = %#v, want %#v", process.Request, tt.wantRequest)
			}
			if process.Response != tt.wantResponse {
				t.Fatalf("process.Response = %#v, want %#v", process.Response, tt.wantResponse)
			}
		})
	}
}

func resetGRPCUtilitiesTestState(t *testing.T) {
	t.Helper()
	viper.Reset()
	viperdata.ResetViperDataSingleton()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	viper.Set(string(viperdata.AppAtribute), "test-service")
	viper.Set(string(viperdata.LoggerIgnoredHeadersAtribute), []string{})
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)
}
