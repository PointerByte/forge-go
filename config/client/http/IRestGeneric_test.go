// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/golang/mock/gomock"
	"github.com/spf13/viper"
)

func getDefaultTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:          100,
		MaxConnsPerHost:       200,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
}

type closeErrorReadCloser struct {
	io.Reader
	err error
}

func (b closeErrorReadCloser) Close() error {
	return b.err
}

func TestNewGenericRest(t *testing.T) {
	NewGenericRest(time.Second, getDefaultTransport())
}

func TestRestGeneric_PostGeneric(t *testing.T) {
	type response struct {
		Message string `json:"message"`
		Method  string `json:"method"`
	}

	tests := []struct {
		name    string
		input   RequestGeneric
		wantErr bool
	}{
		{name: "success"},
		{name: "marshal_error", input: RequestGeneric{Request: func() {}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "success":
				var receivedMethod string
				var receivedBody string
				var receivedHeader string
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedMethod = r.Method
					receivedHeader = r.Header.Get("X-Post")
					body, _ := io.ReadAll(r.Body)
					receivedBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response{Message: "ok", Method: r.Method})
				}))
				defer ts.Close()

				respObj := &response{}
				input := RequestGeneric{
					Url:      ts.URL + "/create",
					Header:   http.Header{"X-Post": []string{"1"}},
					Request:  map[string]any{"name": "Manuel"},
					Response: respObj,
				}
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.PostGeneric(context.Background(), input)
				if gotErr != nil {
					t.Fatalf("PostGeneric() failed: %v", gotErr)
				}
				if receivedMethod != http.MethodPost {
					t.Fatalf("method = %s", receivedMethod)
				}
				if receivedHeader != "1" {
					t.Fatalf("x-post = %s", receivedHeader)
				}
				if !strings.Contains(receivedBody, "Manuel") {
					t.Fatalf("body = %s", receivedBody)
				}
				if respObj.Message != "ok" || respObj.Method != http.MethodPost {
					t.Fatalf("response = %+v", respObj)
				}
			case "marshal_error":
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.PostGeneric(context.Background(), tt.input)
				if gotErr == nil {
					t.Fatal("PostGeneric() succeeded unexpectedly")
				}
			}
		})
	}
}

func TestGenericRest_GetGeneric(t *testing.T) {
	type response struct {
		Message string `json:"message"`
		Query   string `json:"query"`
	}

	tests := []struct {
		name    string
		input   RequestGeneric
		wantErr bool
	}{
		{name: "success_with_url"},
		{name: "success_with_params"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "success_with_url", "success_with_params":
				var receivedMethod string
				var receivedQuery string
				var receivedHeader string
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedMethod = r.Method
					receivedQuery = r.URL.RawQuery
					receivedHeader = r.Header.Get("X-Token")
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response{Message: "ok", Query: r.URL.RawQuery})
				}))
				defer ts.Close()

				respObj := &response{}
				input := RequestGeneric{
					System:   "sys",
					Process:  "get",
					Header:   http.Header{"X-Token": []string{"abc"}},
					Response: respObj,
				}
				if tt.name == "success_with_url" {
					input.Url = ts.URL + "/items"
				} else {
					input.Host = ts.URL
					input.Path = "items"
					input.Params = url.Values{"page": []string{"1"}, "filter": []string{"hello world"}}
				}

				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.GetGeneric(context.Background(), input)
				if gotErr != nil {
					t.Fatalf("GetGeneric() failed: %v", gotErr)
				}
				if receivedMethod != http.MethodGet {
					t.Fatalf("method = %s", receivedMethod)
				}
				if receivedHeader != "abc" {
					t.Fatalf("x-token = %s", receivedHeader)
				}
				if tt.name == "success_with_params" {
					vals, err := url.ParseQuery(receivedQuery)
					if err != nil {
						t.Fatalf("ParseQuery() failed: %v", err)
					}
					if vals.Get("page") != "1" || vals.Get("filter") != "hello world" {
						t.Fatalf("query = %s", receivedQuery)
					}
				}
				if respObj.Message != "ok" {
					t.Fatalf("response = %+v", respObj)
				}
			}
		})
	}
}

func TestGenericRestAddsTraceIDHeader(t *testing.T) {
	type response struct {
		Message string `json:"message"`
	}

	var receivedTraceID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceID = r.Header.Get(common.TraceIDHeader)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{Message: "ok"})
	}))
	defer ts.Close()

	ctxLogger := builder.New(context.Background())
	ctxLogger.SetTraceID("trace-http-out")

	respObj := &response{}
	gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
	if err := gr.GetGeneric(ctxLogger, RequestGeneric{
		Url:      ts.URL + "/items",
		Response: respObj,
	}); err != nil {
		t.Fatalf("GetGeneric() failed: %v", err)
	}
	if receivedTraceID != "trace-http-out" {
		t.Fatalf("%s = %q, want %q", common.TraceIDHeader, receivedTraceID, "trace-http-out")
	}
}

func TestGenericRestPreservesExistingTraceIDHeader(t *testing.T) {
	type response struct {
		Message string `json:"message"`
	}

	var receivedTraceID string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedTraceID = r.Header.Get(common.TraceIDHeader)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{Message: "ok"})
	}))
	defer ts.Close()

	ctxLogger := builder.New(context.Background())
	ctxLogger.SetTraceID("trace-http-out")

	respObj := &response{}
	gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
	if err := gr.GetGeneric(ctxLogger, RequestGeneric{
		Url:      ts.URL + "/items",
		Header:   http.Header{common.TraceIDHeader: []string{"trace-existing"}},
		Response: respObj,
	}); err != nil {
		t.Fatalf("GetGeneric() failed: %v", err)
	}
	if receivedTraceID != "trace-existing" {
		t.Fatalf("%s = %q, want %q", common.TraceIDHeader, receivedTraceID, "trace-existing")
	}
}

func TestGenericRestDisableTracePreservesHeadersAndClosesNon2xxBody(t *testing.T) {
	type response struct {
		Message string `json:"message"`
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctxLogger := builder.New(context.Background())
	ctxLogger.SetTraceID("trace-must-not-be-injected")
	output := &response{Message: "unchanged"}
	body := newTrackingReadCloser(`{"message":"rejected"}`)
	resp := &http.Response{
		StatusCode: http.StatusUnprocessableEntity,
		Body:       body,
	}
	input := RequestGeneric{
		Url:      "http://example.test/rejected",
		Header:   http.Header{"X-Caller": []string{"present"}},
		Response: output,
	}

	var gotHeaders http.Header
	mock := NewMockIRest(ctrl)
	mock.EXPECT().SetRequest(nil)
	mock.EXPECT().SetContext(ctxLogger)
	mock.EXPECT().SetHeaders(gomock.Any()).Do(func(headers http.Header) {
		gotHeaders = headers.Clone()
	})
	mock.EXPECT().Get(input.Url, "application/json", output).Return(resp, nil)

	gr := &RestGeneric{newIRest: mock}
	gr.DisableTrace()
	if !gr.disableTrace.Load() {
		t.Fatal("DisableTrace() did not disable tracing")
	}
	if err := gr.GetGeneric(ctxLogger, input); err != nil {
		t.Fatalf("GetGeneric() error = %v, want nil for HTTP status", err)
	}
	if gotHeaders.Get("X-Caller") != "present" {
		t.Fatalf("X-Caller = %q, want %q", gotHeaders.Get("X-Caller"), "present")
	}
	if gotHeaders.Get(common.TraceIDHeader) != "" {
		t.Fatalf("%s = %q, want no automatic trace header", common.TraceIDHeader, gotHeaders.Get(common.TraceIDHeader))
	}
	if output.Message != "unchanged" {
		t.Fatalf("output was decoded on non-2xx response: %+v", output)
	}
	if !body.closed {
		t.Fatal("disabled-trace response body was not closed")
	}
	if body.reader.Len() != 0 {
		t.Fatalf("disabled-trace response body has %d unread bytes", body.reader.Len())
	}
	if resp.Body != http.NoBody {
		t.Fatalf("response body = %T, want http.NoBody", resp.Body)
	}
}

type genericRequestContextKey struct{}

func TestRestGenericConcurrentSetterSequenceIsIsolated(t *testing.T) {
	const requests = 32
	rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
		marker := strings.TrimPrefix(req.URL.Path, "/")
		if got := req.Header.Get("X-Request-ID"); got != marker {
			return nil, fmt.Errorf("header request id = %q, want %q", got, marker)
		}
		if got, _ := req.Context().Value(genericRequestContextKey{}).(string); got != marker {
			return nil, fmt.Errorf("context request id = %q, want %q", got, marker)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       io.NopCloser(strings.NewReader("discarded")),
			Request:    req,
		}, nil
	})
	generic := &RestGeneric{newIRest: rest}
	generic.DisableTrace()

	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for i := range requests {
		marker := fmt.Sprintf("generic-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.WithValue(context.Background(), genericRequestContextKey{}, marker)
			headers := make(http.Header)
			headers.Set("X-Request-ID", marker)
			errs <- generic.GetGeneric(ctx, RequestGeneric{
				Url:    "http://example.test/" + marker,
				Header: headers,
			})
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRestGenericBuildService(t *testing.T) {
	type response struct {
		Message string `json:"message"`
	}

	t.Run("fills trace fields from response and request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "http://api.example.test/v1/items", nil)
		req.Header.Set("X-Test", "ok")
		respObj := &response{Message: "created"}
		body := newTrackingReadCloser(`{"message":"created"}`)
		service := &formatter.Process{}
		gr := &RestGeneric{}

		err := gr.buildService(service, map[string]any{"name": "Manuel"}, respObj, &http.Response{
			StatusCode: http.StatusCreated,
			Proto:      "HTTP/1.1",
			Request:    req,
			Body:       body,
		})
		if err != nil {
			t.Fatalf("buildService() failed: %v", err)
		}

		if service.Code != http.StatusCreated {
			t.Fatalf("Code = %d, want %d", service.Code, http.StatusCreated)
		}
		if service.Protocol != "HTTP/1.1" {
			t.Fatalf("Protocol = %q, want %q", service.Protocol, "HTTP/1.1")
		}
		if service.Server != "api.example.test" {
			t.Fatalf("Server = %q, want %q", service.Server, "api.example.test")
		}
		if service.Method != http.MethodPost {
			t.Fatalf("Method = %q, want %q", service.Method, http.MethodPost)
		}
		if service.Path != "/v1/items" {
			t.Fatalf("Path = %q, want %q", service.Path, "/v1/items")
		}
		if service.Headers == nil || service.Headers.Get("X-Test") != "ok" {
			t.Fatalf("Headers = %#v, want X-Test=ok", service.Headers)
		}
		if respObj.Message != "created" {
			t.Fatalf("decoded response = %+v, want message created", respObj)
		}
		if service.Response != respObj {
			t.Fatalf("Response = %#v, want response object pointer", service.Response)
		}
		if !body.closed || body.reader.Len() != 0 {
			t.Fatalf("response body lifecycle: closed=%v unread=%d", body.closed, body.reader.Len())
		}
	})

	t.Run("keeps response metadata without request or body", func(t *testing.T) {
		service := &formatter.Process{}
		gr := &RestGeneric{}

		err := gr.buildService(service, nil, nil, &http.Response{
			StatusCode: http.StatusNoContent,
			Proto:      "HTTP/2.0",
		})
		if err != nil {
			t.Fatalf("buildService() failed: %v", err)
		}

		if service.Code != http.StatusNoContent {
			t.Fatalf("Code = %d, want %d", service.Code, http.StatusNoContent)
		}
		if service.Protocol != "HTTP/2.0" {
			t.Fatalf("Protocol = %q, want %q", service.Protocol, "HTTP/2.0")
		}
		if service.Headers != nil {
			t.Fatalf("Headers = %#v, want nil", service.Headers)
		}
		if service.Response != nil {
			t.Fatalf("Response = %#v, want nil", service.Response)
		}
	})

	t.Run("caps traced non-success response and records truncation", func(t *testing.T) {
		key := string(viperdata.LoggerBodyCaptureMaxBytesAtribute)
		previous := viper.Get(key)
		viper.Set(key, 8)
		viperdata.ResetViperDataSingleton()
		t.Cleanup(func() {
			viper.Set(key, previous)
			viperdata.ResetViperDataSingleton()
		})

		body := newTrackingReadCloser("0123456789abcdef")
		service := &formatter.Process{}
		gr := &RestGeneric{}
		err := gr.buildService(service, nil, nil, &http.Response{
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			Body:       body,
		})
		if err != nil {
			t.Fatalf("buildService() failed: %v", err)
		}
		if got := service.Response; got != "01234567" {
			t.Fatalf("Response = %#v, want capped prefix", got)
		}
		metadata := service.ResponseCapture
		if metadata == nil || !metadata.Truncated ||
			metadata.CapturedBytes != 8 || metadata.LimitBytes != 8 {
			t.Fatalf("ResponseCapture = %#v, want truncated 8-byte capture", metadata)
		}
		if !body.closed || body.reader.Len() != 0 {
			t.Fatalf("response body lifecycle: closed=%v unread=%d", body.closed, body.reader.Len())
		}
	})

	t.Run("ignores nil inputs", func(t *testing.T) {
		gr := &RestGeneric{}
		if err := gr.buildService(&formatter.Process{}, nil, nil, nil); err != nil {
			t.Fatalf("buildService(nil response) error = %v", err)
		}
		if err := gr.buildService(nil, nil, nil, &http.Response{}); err != nil {
			t.Fatalf("buildService(nil service) error = %v", err)
		}
	})

	t.Run("returns body close error", func(t *testing.T) {
		wantErr := errors.New("close body")
		service := &formatter.Process{}
		respObj := &response{}
		gr := &RestGeneric{}

		err := gr.buildService(service, nil, respObj, &http.Response{
			StatusCode: http.StatusOK,
			Proto:      "HTTP/1.1",
			Body: closeErrorReadCloser{
				Reader: strings.NewReader(`{"message":"ok"}`),
				err:    wantErr,
			},
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("buildService() error = %v, want %v", err, wantErr)
		}
	})
}

func TestGenericRest_PutGeneric(t *testing.T) {
	type response struct {
		Message string `json:"message"`
		Method  string `json:"method"`
	}

	tests := []struct {
		name    string
		input   RequestGeneric
		wantErr bool
	}{
		{name: "success"},
		{name: "marshal_error", input: RequestGeneric{Request: func() {}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "success":
				var receivedMethod string
				var receivedBody string
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedMethod = r.Method
					body, _ := io.ReadAll(r.Body)
					receivedBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response{Message: "ok", Method: r.Method})
				}))
				defer ts.Close()

				respObj := &response{}
				input := RequestGeneric{
					Host:     ts.URL,
					Path:     "update",
					Header:   http.Header{"X-Put": []string{"1"}},
					Request:  map[string]any{"id": 10},
					Response: respObj,
				}
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.PutGeneric(context.Background(), input)
				if gotErr != nil {
					t.Fatalf("PutGeneric() failed: %v", gotErr)
				}
				if receivedMethod != http.MethodPut {
					t.Fatalf("method = %s", receivedMethod)
				}
				if !strings.Contains(receivedBody, "10") {
					t.Fatalf("body = %s", receivedBody)
				}
				if respObj.Message != "ok" || respObj.Method != http.MethodPut {
					t.Fatalf("response = %+v", respObj)
				}
			case "marshal_error":
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.PutGeneric(context.Background(), tt.input)
				if gotErr == nil {
					t.Fatal("PutGeneric() succeeded unexpectedly")
				}
			}
		})
	}
}

func TestGenericRest_PatchGeneric(t *testing.T) {
	type response struct {
		Message string `json:"message"`
		Method  string `json:"method"`
	}

	tests := []struct {
		name    string
		input   RequestGeneric
		wantErr bool
	}{
		{name: "success"},
		{name: "marshal_error", input: RequestGeneric{Request: func() {}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "success":
				var receivedMethod string
				var receivedBody string
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedMethod = r.Method
					body, _ := io.ReadAll(r.Body)
					receivedBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response{Message: "ok", Method: r.Method})
				}))
				defer ts.Close()

				respObj := &response{}
				input := RequestGeneric{
					Url:      ts.URL + "/patch",
					Request:  map[string]any{"active": true},
					Response: respObj,
				}
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.PatchGeneric(context.Background(), input)
				if gotErr != nil {
					t.Fatalf("PatchGeneric() failed: %v", gotErr)
				}
				if receivedMethod != http.MethodPatch {
					t.Fatalf("method = %s", receivedMethod)
				}
				if !strings.Contains(receivedBody, "true") {
					t.Fatalf("body = %s", receivedBody)
				}
				if respObj.Message != "ok" || respObj.Method != http.MethodPatch {
					t.Fatalf("response = %+v", respObj)
				}
			case "marshal_error":
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.PatchGeneric(context.Background(), tt.input)
				if gotErr == nil {
					t.Fatal("PatchGeneric() succeeded unexpectedly")
				}
			}
		})
	}
}

func TestGenericRest_OptionGeneric(t *testing.T) {
	type response struct {
		Message string `json:"message"`
		Method  string `json:"method"`
	}

	tests := []struct {
		name    string
		input   RequestGeneric
		wantErr bool
	}{
		{name: "success"},
		{name: "marshal_error", input: RequestGeneric{Request: func() {}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "success":
				var receivedMethod string
				var receivedBody string
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					receivedMethod = r.Method
					body, _ := io.ReadAll(r.Body)
					receivedBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(response{Message: "ok", Method: r.Method})
				}))
				defer ts.Close()

				respObj := &response{}
				input := RequestGeneric{
					Host:     ts.URL,
					Path:     "options",
					Request:  map[string]any{"check": "yes"},
					Response: respObj,
				}
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.OptionGeneric(context.Background(), input)
				if gotErr != nil {
					t.Fatalf("OptionGeneric() failed: %v", gotErr)
				}
				if receivedMethod != http.MethodOptions {
					t.Fatalf("method = %s", receivedMethod)
				}
				if !strings.Contains(receivedBody, "yes") {
					t.Fatalf("body = %s", receivedBody)
				}
				if respObj.Message != "ok" || respObj.Method != http.MethodOptions {
					t.Fatalf("response = %+v", respObj)
				}
			case "marshal_error":
				gr := NewGenericRest(time.Second, getDefaultTransport()).(*RestGeneric)
				gr.DisableTrace()
				gotErr := gr.OptionGeneric(context.Background(), tt.input)
				if gotErr == nil {
					t.Fatal("OptionGeneric() succeeded unexpectedly")
				}
			}
		})
	}
}

func TestMockIRestGenericMethods(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	input := RequestGeneric{System: "sys", Process: "proc"}
	expectedErr := errors.New("mock generic")

	mock := NewMockIRestGeneric(ctrl)
	mock.EXPECT().DisableTrace()
	mock.EXPECT().PostGeneric(ctx, input).Return(expectedErr)
	mock.EXPECT().GetGeneric(ctx, input).Return(expectedErr)
	mock.EXPECT().PutGeneric(ctx, input).Return(expectedErr)
	mock.EXPECT().PatchGeneric(ctx, input).Return(expectedErr)
	mock.EXPECT().OptionGeneric(ctx, input).Return(expectedErr)

	mock.DisableTrace()
	if err := mock.PostGeneric(ctx, input); !errors.Is(err, expectedErr) {
		t.Fatalf("PostGeneric() error = %v", err)
	}
	if err := mock.GetGeneric(ctx, input); !errors.Is(err, expectedErr) {
		t.Fatalf("GetGeneric() error = %v", err)
	}
	if err := mock.PutGeneric(ctx, input); !errors.Is(err, expectedErr) {
		t.Fatalf("PutGeneric() error = %v", err)
	}
	if err := mock.PatchGeneric(ctx, input); !errors.Is(err, expectedErr) {
		t.Fatalf("PatchGeneric() error = %v", err)
	}
	if err := mock.OptionGeneric(ctx, input); !errors.Is(err, expectedErr) {
		t.Fatalf("OptionGeneric() error = %v", err)
	}
}
