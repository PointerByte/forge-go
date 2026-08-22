// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate mockgen -source=IRest.go -destination=./mocksIRest_test.go -package=http

package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// IRest defines an interface for making HTTP requests in a generic manner.
//
// Implementations of this interface allow
// you to execute HTTP methods (`GET`, `POST`, `PUT`, `PATCH`) and handle headers,
// context, and response decoding in a target object.
//
// A successful 2xx response is decoded only when the output is non-nil; its
// consumed body is then drained and closed. With a nil output, or with a
// non-2xx status, the raw body remains available and the caller must close it.
//
// An HTTP status code does not by itself produce an error. Request methods
// return the *http.Response for status inspection and report only request
// construction, transport, decoding, draining, or closing failures as errors.
// Verb calls may execute concurrently; each call uses a local request and
// snapshots the configured context and headers. Callers must still avoid
// mutating a supplied request or body reader while it is in use.
type IRest interface {
	// SetContext sets a context (`context.Context`) that will be used
	// by HTTP requests. It allows you to control cancellations and timeouts.
	SetContext(ctx context.Context)

	// SetRequest defines a custom request (*http.Request).
	SetRequest(req *http.Request)

	// SetHeaders defines the base HTTP headers that will be included in every
	// request. If called again, the previous values are overwritten.
	SetHeaders(header http.Header)

	// Executes a pre-built HTTP request and decodes the response
	// into the provided object, if applicable.
	Do(object any) (*http.Response, error)

	// Get sends an HTTP GET request to the specified `url`, with the specified
	// content type, and decodes the response into an `object`.
	Get(url, contentType string, object any) (*http.Response, error)

	// Post sends an HTTP POST request to the specified `url`, using `body`
	// as the request body, and decodes the response into `object`.
	Post(url, contentType string, body io.Reader, object any) (*http.Response, error)

	// Put sends a PUT HTTP request to the specified `url`, using `body`
	// as the request body, and decodes the response into `object`.
	Put(url, contentType string, body io.Reader, object any) (*http.Response, error)

	// Patch sends an HTTP PATCH request to the specified `url`, using `body`
	// as the request body, and decodes the response into `object`.
	Patch(url, contentType string, body io.Reader, object any) (*http.Response, error)

	// Option sends an HTTP OPTIONS request to the specified `url`, using `body`
	// as the request body, and decodes the response into `object`.
	Option(url, contentType string, body io.Reader, object any) (*http.Response, error)
}

type Rest struct {
	restClient  *http.Client
	initErr     error
	hdr         atomic.Value // stores http.Header (immutable after a Store operation)
	mux         sync.RWMutex
	ctx         context.Context
	withContext bool
	req         *http.Request
	customReq   *http.Request
}

// NewIRest creates a new instance of IRest.
//
// The timeOut parameter defines the maximum duration for each request.
// The tr parameter allows injecting a custom HTTP transport.
func NewIRest(timeout time.Duration, tr *http.Transport) IRest {
	restClient, err := newRestClient(timeout, tr)
	s := &Rest{
		restClient: restClient,
		initErr:    err,
	}
	s.hdr.Store(http.Header{}) // Init value imutable
	return s
}

// NewConfiguredIRest creates a REST wrapper and returns TLS/mTLS configuration
// errors while resolving client.http settings.
func NewConfiguredIRest(timeout time.Duration, tr *http.Transport) (IRest, error) {
	restClient, err := newRestClient(timeout, tr)
	if err != nil {
		return nil, err
	}
	s := &Rest{
		restClient: restClient,
	}
	s.hdr.Store(http.Header{})
	return s, nil
}

// NewIRestFromConfig creates a REST wrapper using client.http.timeout and
// TLS/mTLS settings from Viper.
func NewIRestFromConfig() (IRest, error) {
	return NewConfiguredIRest(clientHTTPTimeout(), nil)
}

func (sr *Rest) SetRequest(req *http.Request) {
	sr.mux.Lock()
	defer sr.mux.Unlock()
	sr.req = req
	sr.customReq = req
}

func (sr *Rest) configuredContext() (context.Context, bool) {
	sr.mux.RLock()
	defer sr.mux.RUnlock()
	if sr.customReq != nil {
		return sr.customReq.Context(), true
	}
	return sr.ctx, sr.withContext && sr.ctx != nil
}

func (sr *Rest) configuredRequest() *http.Request {
	sr.mux.RLock()
	defer sr.mux.RUnlock()
	if sr.customReq == nil {
		return nil
	}
	return sr.customReq.Clone(sr.customReq.Context())
}

func (sr *Rest) storeLastRequest(req *http.Request) {
	sr.mux.Lock()
	defer sr.mux.Unlock()
	sr.req = req
}

func (sr *Rest) newRequest(method, url string, body io.Reader) (*http.Request, error) {
	if ctx, ok := sr.configuredContext(); ok {
		return http.NewRequestWithContext(ctx, method, url, body)
	}
	return http.NewRequest(method, url, body)
}

func (sr *Rest) doRequest(req *http.Request, output any) (*http.Response, error) {
	if sr.initErr != nil {
		return nil, sr.initErr
	}
	if req == nil {
		return nil, fmt.Errorf("problem executing the request: request is nil")
	}

	sr.storeLastRequest(req)
	resp, err := sr.restClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("problema al ejecutar la solicitud: %w", err)
	}
	if isNilOutput(output) || resp.Body == nil || !isSuccessfulHTTPStatus(resp.StatusCode) {
		return resp, nil
	}
	if err := decodeResponse(resp, output); err != nil {
		return resp, err
	}
	return resp, nil
}

func (sr *Rest) Do(output any) (*http.Response, error) {
	req := sr.configuredRequest()
	if req != nil {
		mergeRequestHeaders(req, sr.hdr.Load().(http.Header))
	}
	return sr.doRequest(req, output)
}

func mergeRequestHeaders(req *http.Request, base http.Header) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for key, values := range base {
		if _, exists := req.Header[key]; exists {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
}

func (sr *Rest) SetHeaders(header http.Header) {
	if header == nil {
		return
	}
	sr.hdr.Store(header.Clone())
}

func (sr *Rest) SetContext(ctx context.Context) {
	sr.mux.Lock()
	defer sr.mux.Unlock()
	sr.ctx = ctx
	sr.withContext = ctx != nil
}

func (sr *Rest) Get(url, contentType string, output any) (*http.Response, error) {
	req, err := sr.newRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("problem creating the request get: %w", err)
	}

	// Take a snapshot of the header and include the Content-Type field ONLY in this request
	h := sr.hdr.Load().(http.Header)
	req.Header = h.Clone()
	req.Header.Set("Content-Type", contentType)
	return sr.doRequest(req, output)
}

func (sr *Rest) Post(url, contentType string, body io.Reader, output any) (*http.Response, error) {
	req, err := sr.newRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("problem creating the request post: %w", err)
	}

	// Take a snapshot of the header and include the Content-Type field ONLY in this request
	h := sr.hdr.Load().(http.Header)
	req.Header = h.Clone()
	req.Header.Set("Content-Type", contentType)
	return sr.doRequest(req, output)
}

func (sr *Rest) Put(url, contentType string, body io.Reader, output any) (*http.Response, error) {
	req, err := sr.newRequest(http.MethodPut, url, body)
	if err != nil {
		return nil, fmt.Errorf("problem creating the request put: %w", err)
	}

	// Take a snapshot of the header and include the Content-Type field ONLY in this request
	h := sr.hdr.Load().(http.Header)
	req.Header = h.Clone()
	req.Header.Set("Content-Type", contentType)
	return sr.doRequest(req, output)
}

func (sr *Rest) Patch(url, contentType string, body io.Reader, output any) (*http.Response, error) {
	req, err := sr.newRequest(http.MethodPatch, url, body)
	if err != nil {
		return nil, fmt.Errorf("problem creating the request patch: %w", err)
	}

	// Take a snapshot of the header and include the Content-Type field ONLY in this request
	h := sr.hdr.Load().(http.Header)
	req.Header = h.Clone()
	req.Header.Set("Content-Type", contentType)
	return sr.doRequest(req, output)
}

func (sr *Rest) Option(url, contentType string, body io.Reader, output any) (*http.Response, error) {
	req, err := sr.newRequest(http.MethodOptions, url, body)
	if err != nil {
		return nil, fmt.Errorf("problem creating the request option: %w", err)
	}

	// Take a snapshot of the header and include the Content-Type field ONLY in this request
	h := sr.hdr.Load().(http.Header)
	req.Header = h.Clone()
	req.Header.Set("Content-Type", contentType)
	return sr.doRequest(req, output)
}
