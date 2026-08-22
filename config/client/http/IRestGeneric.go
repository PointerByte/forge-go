// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate mockgen -source=IRestGeneric.go -destination=./mocksIRestGeneric_test.go -package=http

package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	viperdata "github.com/PointerByte/forge-go/logger/viperData"
	"github.com/gin-gonic/gin/binding"
)

// IRestGeneric defines the contract for executing generic REST requests.
//
// Each method receives a context to support cancellation and timeouts,
// along with a RequestGeneric instance that contains all required data
// to build and execute the HTTP request.
//
// The implementation is responsible for serializing the request body,
// setting headers, propagating context, and deserializing the response
// into the provided Response object. Every response body is drained and closed,
// including when tracing is disabled. A non-2xx status does not synthesize an
// error and is not decoded into Response.
type IRestGeneric interface {
	// DisableTrace disables automatic tracing for subsequent requests.
	DisableTrace()

	// PostGeneric executes an HTTP POST request.
	//
	// The input parameter contains the URL or Host/Path combination,
	// request body, headers, and the object where the response will
	// be deserialized.
	PostGeneric(context.Context, RequestGeneric) error

	// GetGeneric executes an HTTP GET request.
	//
	// Query parameters are taken from input.Params, and the response
	// is deserialized into input.Response.
	GetGeneric(ctx context.Context, input RequestGeneric) error

	// PutGeneric executes an HTTP PUT request.
	//
	// Typically used to replace or update existing resources.
	PutGeneric(ctx context.Context, input RequestGeneric) error

	// PatchGeneric executes an HTTP PATCH request.
	//
	// Used for partial updates of a resource.
	PatchGeneric(ctx context.Context, input RequestGeneric) error

	// OptionGeneric executes an HTTP OPTIONS request.
	//
	// Useful for retrieving the supported capabilities or methods
	// of a remote resource.
	OptionGeneric(ctx context.Context, input RequestGeneric) error
}

// RestGeneric implements the IRestGeneric interface using an internal
// IRest instance to execute HTTP requests and process responses.
type RestGeneric struct {
	newIRest     IRest
	disableTrace atomic.Bool
	requestMu    sync.Mutex
}

// NewGenericRest creates a new instance of IRestGeneric.
//
// The timeOut parameter defines the maximum duration for each request.
// The tr parameter allows injecting a custom HTTP transport.
func NewGenericRest(timeout time.Duration, tr *http.Transport) IRestGeneric {
	return &RestGeneric{
		newIRest: NewIRest(timeout, tr),
	}
}

// NewConfiguredGenericRest creates a generic REST client and returns TLS/mTLS
// configuration errors while resolving client.http settings.
func NewConfiguredGenericRest(timeout time.Duration, tr *http.Transport) (IRestGeneric, error) {
	rest, err := NewConfiguredIRest(timeout, tr)
	if err != nil {
		return nil, err
	}
	return &RestGeneric{
		newIRest: rest,
	}, nil
}

// NewGenericRestFromConfig creates a generic REST client using
// client.http.timeout and TLS/mTLS settings from Viper.
func NewGenericRestFromConfig() (IRestGeneric, error) {
	return NewConfiguredGenericRest(clientHTTPTimeout(), nil)
}

type handlerTrace func(process *formatter.Process)

func traceClient(ctx context.Context, system, process string, disableTraceBody bool) (*formatter.Process, handlerTrace) {
	ctxLogger := builder.New(ctx)
	service := &formatter.Process{
		System:      system,
		Process:     process,
		Status:      formatter.SUCCESS,
		DisableBody: disableTraceBody,
	}
	ctxLogger.TraceInit(service)
	return service, ctxLogger.TraceEnd
}

func headersWithTraceID(ctx context.Context, header http.Header) http.Header {
	headers := header.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	if headers.Get(common.TraceIDHeader) != "" {
		return headers
	}
	if traceID := builder.New(ctx).TraceID(); traceID != "" {
		headers.Set(common.TraceIDHeader, traceID)
	}
	return headers
}

func (gr *RestGeneric) requestHeaders(ctx context.Context, header http.Header) http.Header {
	if gr.disableTrace.Load() {
		headers := header.Clone()
		if headers == nil {
			headers = http.Header{}
		}
		return headers
	}
	return headersWithTraceID(ctx, header)
}

// buildService enriches the trace service entry with data extracted from the
// HTTP response and request objects used by the REST client.
//
// When tracing is enabled, it copies transport metadata such as host, headers,
// method, path, HTTP status code, and protocol into service. It also stores the
// outbound request body and the response value already decoded by IRest.
//
// The response body is always drained and closed before the function returns.
func (gr *RestGeneric) buildService(service *formatter.Process, reqBody, object any, resp *http.Response) (err error) {
	if resp == nil {
		return nil
	}
	if gr.disableTrace.Load() || service == nil {
		return drainAndCloseResponseBody(resp)
	}

	service.Code = int64(resp.StatusCode)
	service.Protocol = resp.Proto

	if resp.Request != nil {
		req := resp.Request
		if req.URL != nil {
			service.Server = req.URL.Host
			service.Path = req.URL.Path
		}
		service.Headers = &req.Header
		service.Method = req.Method
		service.SetRequest(reqBody)
	}

	if isSuccessfulHTTPStatus(resp.StatusCode) && !isNilOutput(object) {
		service.SetResponse(object)
		return drainAndCloseResponseBody(resp)
	}

	responseBody, truncated, err := readAndCloseResponseBodyLimited(resp)
	if err != nil {
		return err
	}
	if truncated {
		limit := viperdata.BodyCaptureMaxBytes()
		service.ResponseCapture = &formatter.BodyCaptureMetadata{
			Truncated:     true,
			CapturedBytes: len(responseBody),
			LimitBytes:    limit,
		}
	}
	if len(responseBody) > 0 {
		var decoded any
		if jsonErr := json.Unmarshal(responseBody, &decoded); jsonErr == nil {
			service.SetResponse(decoded)
		} else {
			service.SetResponse(string(responseBody))
		}
	}
	return nil
}

// DisableTrace disables request tracing for the current instance.
func (gr *RestGeneric) DisableTrace() {
	gr.disableTrace.Store(true)
}

// PostGeneric executes an HTTP POST request with JSON content.
//
// If input.Url is provided, it is used directly; otherwise, the URL
// is constructed using input.Host and input.Path.
//
// The input.Request is serialized into JSON and the response is
// deserialized into input.Response.
func (gr *RestGeneric) PostGeneric(ctx context.Context, input RequestGeneric) error {
	gr.requestMu.Lock()
	defer gr.requestMu.Unlock()

	var process *formatter.Process
	var traceEnd handlerTrace
	if !gr.disableTrace.Load() {
		process, traceEnd = traceClient(ctx, input.System, input.Process, input.DisableTraceBody)
		defer traceEnd(process)
	}

	var pathEncode string
	if input.Url != "" {
		pathEncode = input.Url
	} else {
		pathEncode = fmt.Sprintf("%s/%s", input.Host, input.Path)
	}

	req, err := json.Marshal(input.Request)
	if err != nil {
		if !gr.disableTrace.Load() {
			process.SetStatus(formatter.ERROR)
		}
		return err
	}
	gr.newIRest.SetRequest(input.HttpRequest)
	gr.newIRest.SetContext(ctx)
	gr.newIRest.SetHeaders(gr.requestHeaders(ctx, input.Header))

	resp, err := gr.newIRest.Post(pathEncode, binding.MIMEJSON, bytes.NewReader(req), input.Response)
	if err != nil {
		_ = drainAndCloseResponseBody(resp)
		return formatHTTPClientError(resp, err)
	}
	return gr.buildService(process, input.Request, input.Response, resp)
}

func formatHTTPClientError(resp *http.Response, err error) error {
	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
	}
	return fmt.Errorf("error consuming the service status[%d] error[%s]", statusCode, err.Error())
}

func buildURL(input RequestGeneric) (string, error) {
	var raw string
	if input.Url != "" {
		raw = input.Url
	} else {
		raw = strings.TrimRight(input.Host, "/") + "/" + strings.TrimLeft(input.Path, "/")
	}
	if len(input.Params) == 0 {
		return raw, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for key, vals := range input.Params {
		for _, val := range vals {
			q.Add(key, val)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// GetGeneric executes an HTTP GET request.
//
// If input.Params contains values, they are encoded as a query string
// and appended to the final URL. The response is deserialized into
// input.Response.
func (gr *RestGeneric) GetGeneric(ctx context.Context, input RequestGeneric) error {
	gr.requestMu.Lock()
	defer gr.requestMu.Unlock()

	var process *formatter.Process
	var traceEnd handlerTrace
	if !gr.disableTrace.Load() {
		process, traceEnd = traceClient(ctx, input.System, input.Process, input.DisableTraceBody)
		defer traceEnd(process)
	}

	pathEncode, err := buildURL(input)
	if err != nil {
		return err
	}
	gr.newIRest.SetRequest(input.HttpRequest)
	gr.newIRest.SetContext(ctx)
	gr.newIRest.SetHeaders(gr.requestHeaders(ctx, input.Header))

	resp, err := gr.newIRest.Get(pathEncode, binding.MIMEJSON, input.Response)
	if err != nil {
		_ = drainAndCloseResponseBody(resp)
		return formatHTTPClientError(resp, err)
	}
	return gr.buildService(process, input.Request, input.Response, resp)
}

// PutGeneric executes an HTTP PUT request with JSON content.
//
// The input.Request is serialized into JSON and the response is
// deserialized into input.Response.
func (gr *RestGeneric) PutGeneric(ctx context.Context, input RequestGeneric) error {
	gr.requestMu.Lock()
	defer gr.requestMu.Unlock()

	var process *formatter.Process
	var traceEnd handlerTrace
	if !gr.disableTrace.Load() {
		process, traceEnd = traceClient(ctx, input.System, input.Process, input.DisableTraceBody)
		defer traceEnd(process)
	}

	var pathEncode string
	if input.Url != "" {
		pathEncode = input.Url
	} else {
		pathEncode = fmt.Sprintf("%s/%s", input.Host, input.Path)
	}

	req, err := json.Marshal(input.Request)
	if err != nil {
		if !gr.disableTrace.Load() {
			process.SetStatus(formatter.ERROR)
		}
		return err
	}
	gr.newIRest.SetRequest(input.HttpRequest)
	gr.newIRest.SetContext(ctx)
	gr.newIRest.SetHeaders(gr.requestHeaders(ctx, input.Header))

	resp, err := gr.newIRest.Put(pathEncode, binding.MIMEJSON, bytes.NewReader(req), input.Response)
	if err != nil {
		_ = drainAndCloseResponseBody(resp)
		return formatHTTPClientError(resp, err)
	}
	return gr.buildService(process, input.Request, input.Response, resp)
}

// PatchGeneric executes an HTTP PATCH request with JSON content.
//
// The input.Request is serialized into JSON and the response is
// deserialized into input.Response.
func (gr *RestGeneric) PatchGeneric(ctx context.Context, input RequestGeneric) error {
	gr.requestMu.Lock()
	defer gr.requestMu.Unlock()

	var process *formatter.Process
	var traceEnd handlerTrace
	if !gr.disableTrace.Load() {
		process, traceEnd = traceClient(ctx, input.System, input.Process, input.DisableTraceBody)
		defer traceEnd(process)
	}

	var pathEncode string
	if input.Url != "" {
		pathEncode = input.Url
	} else {
		pathEncode = fmt.Sprintf("%s/%s", input.Host, input.Path)
	}

	req, err := json.Marshal(input.Request)
	if err != nil {
		if !gr.disableTrace.Load() {
			process.SetStatus(formatter.ERROR)
		}
		return err
	}
	gr.newIRest.SetRequest(input.HttpRequest)
	gr.newIRest.SetContext(ctx)
	gr.newIRest.SetHeaders(gr.requestHeaders(ctx, input.Header))

	resp, err := gr.newIRest.Patch(pathEncode, binding.MIMEJSON, bytes.NewReader(req), input.Response)
	if err != nil {
		_ = drainAndCloseResponseBody(resp)
		return formatHTTPClientError(resp, err)
	}
	return gr.buildService(process, input.Request, input.Response, resp)
}

// OptionGeneric executes an HTTP OPTIONS request.
//
// This method can be used to retrieve the capabilities supported by
// a remote resource. If the response contains a body, it will be
// deserialized into input.Response.
func (gr *RestGeneric) OptionGeneric(ctx context.Context, input RequestGeneric) error {
	gr.requestMu.Lock()
	defer gr.requestMu.Unlock()

	var process *formatter.Process
	var traceEnd handlerTrace
	if !gr.disableTrace.Load() {
		process, traceEnd = traceClient(ctx, input.System, input.Process, input.DisableTraceBody)
		defer traceEnd(process)
	}

	var pathEncode string
	if input.Url != "" {
		pathEncode = input.Url
	} else {
		pathEncode = fmt.Sprintf("%s/%s", input.Host, input.Path)
	}

	req, err := json.Marshal(input.Request)
	if err != nil {
		if !gr.disableTrace.Load() {
			process.SetStatus(formatter.ERROR)
		}
		return err
	}
	gr.newIRest.SetRequest(input.HttpRequest)
	gr.newIRest.SetContext(ctx)
	gr.newIRest.SetHeaders(gr.requestHeaders(ctx, input.Header))

	resp, err := gr.newIRest.Option(pathEncode, binding.MIMEJSON, bytes.NewReader(req), input.Response)
	if err != nil {
		_ = drainAndCloseResponseBody(resp)
		return formatHTTPClientError(resp, err)
	}
	return gr.buildService(process, input.Request, input.Response, resp)
}
