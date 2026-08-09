// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func TestEnableBody(t *testing.T) {
	gin.SetMode(gin.TestMode)

	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	if _, ok := c.Get(common.DisableRequestBodyKey); ok {
		t.Fatalf("did not expect %q before calling EnableBody", common.DisableRequestBodyKey)
	}
	if _, ok := c.Get(common.DisableResponseBodyKey); ok {
		t.Fatalf("did not expect %q before calling EnableBody", common.DisableResponseBodyKey)
	}

	EnableBody(c, true, false)

	gotRequest, ok := c.Get(common.DisableRequestBodyKey)
	if !ok {
		t.Fatalf("expected %q to be set", common.DisableRequestBodyKey)
	}
	disabledRequest, ok := gotRequest.(bool)
	if !ok {
		t.Fatalf("%q type = %T, want bool", common.DisableRequestBodyKey, gotRequest)
	}
	if disabledRequest {
		t.Fatalf("%q = %v, want false", common.DisableRequestBodyKey, disabledRequest)
	}

	gotResponse, ok := c.Get(common.DisableResponseBodyKey)
	if !ok {
		t.Fatalf("expected %q to be set", common.DisableResponseBodyKey)
	}
	disabledResponse, ok := gotResponse.(bool)
	if !ok {
		t.Fatalf("%q type = %T, want bool", common.DisableResponseBodyKey, gotResponse)
	}
	if !disabledResponse {
		t.Fatalf("%q = %v, want true", common.DisableResponseBodyKey, disabledResponse)
	}
}

func TestEnableTraceBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	viper.Reset()
	viperdata.ResetViperDataSingleton()
	t.Cleanup(func() {
		viper.Reset()
		viperdata.ResetViperDataSingleton()
	})

	viper.Set(string(viperdata.AppAtribute), "test-service")
	viper.Set(string(viperdata.LoggerModeTestAtribute), false)
	viper.Set(string(viperdata.LoggerIgnoredHeadersAtribute), []string{})

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
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

			ctxLogger := builder.New(c.Request.Context())
			c.Request = c.Request.WithContext(ctxLogger)

			if flag, ok := ctxLogger.Get(common.DisableTraceRequestBodyKey); !ok || flag != true {
				t.Fatalf("%q before EnableTraceBody = %#v, want true", common.DisableTraceRequestBodyKey, flag)
			}
			if flag, ok := ctxLogger.Get(common.DisableTraceResponseBodyKey); !ok || flag != true {
				t.Fatalf("%q before EnableTraceBody = %#v, want true", common.DisableTraceResponseBodyKey, flag)
			}

			EnableTraceBody(c, tt.enableRequestBody, tt.enableResponseBody)

			gotRequestFlag, ok := ctxLogger.Get(common.DisableTraceRequestBodyKey)
			wantRequestFlag := !tt.enableRequestBody
			if !ok || gotRequestFlag != wantRequestFlag {
				t.Fatalf("%q = %#v, want %#v", common.DisableTraceRequestBodyKey, gotRequestFlag, wantRequestFlag)
			}
			gotResponseFlag, ok := ctxLogger.Get(common.DisableTraceResponseBodyKey)
			wantResponseFlag := !tt.enableResponseBody
			if !ok || gotResponseFlag != wantResponseFlag {
				t.Fatalf("%q = %#v, want %#v", common.DisableTraceResponseBodyKey, gotResponseFlag, wantResponseFlag)
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
