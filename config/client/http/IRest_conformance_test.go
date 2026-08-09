// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

type trackingReadCloser struct {
	reader *strings.Reader
	closed bool
}

func newTrackingReadCloser(body string) *trackingReadCloser {
	return &trackingReadCloser{reader: strings.NewReader(body)}
}

func (body *trackingReadCloser) Read(p []byte) (int, error) {
	return body.reader.Read(p)
}

func (body *trackingReadCloser) Close() error {
	body.closed = true
	return nil
}

func newRoundTripRest(fn roundTripFunc) *Rest {
	rest := &Rest{
		restClient: &http.Client{Transport: fn},
	}
	rest.hdr.Store(http.Header{})
	return rest
}

func TestIRestMethodsDecodeSuccessfulJSONAndCloseBody(t *testing.T) {
	type output struct {
		Method string `json:"method"`
	}
	tests := []struct {
		name   string
		method string
		invoke func(*Rest, any) (*http.Response, error)
	}{
		{
			name:   "Do",
			method: http.MethodGet,
			invoke: func(rest *Rest, output any) (*http.Response, error) {
				req, err := http.NewRequest(http.MethodGet, "http://example.test/do", nil)
				if err != nil {
					return nil, err
				}
				rest.SetRequest(req)
				return rest.Do(output)
			},
		},
		{
			name:   "Get",
			method: http.MethodGet,
			invoke: func(rest *Rest, output any) (*http.Response, error) {
				return rest.Get("http://example.test/get", "application/json", output)
			},
		},
		{
			name:   "Post",
			method: http.MethodPost,
			invoke: func(rest *Rest, output any) (*http.Response, error) {
				return rest.Post("http://example.test/post", "application/json", strings.NewReader("{}"), output)
			},
		},
		{
			name:   "Put",
			method: http.MethodPut,
			invoke: func(rest *Rest, output any) (*http.Response, error) {
				return rest.Put("http://example.test/put", "application/json", strings.NewReader("{}"), output)
			},
		},
		{
			name:   "Patch",
			method: http.MethodPatch,
			invoke: func(rest *Rest, output any) (*http.Response, error) {
				return rest.Patch("http://example.test/patch", "application/json", strings.NewReader("{}"), output)
			},
		},
		{
			name:   "Option",
			method: http.MethodOptions,
			invoke: func(rest *Rest, output any) (*http.Response, error) {
				return rest.Option("http://example.test/options", "application/json", strings.NewReader("{}"), output)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := newTrackingReadCloser(`{"method":"` + tt.method + `"}`)
			rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
				if req.Method != tt.method {
					t.Fatalf("request method = %q, want %q", req.Method, tt.method)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       body,
					Request:    req,
				}, nil
			})
			got := &output{}

			resp, err := tt.invoke(rest, got)
			if err != nil {
				t.Fatalf("%s() failed: %v", tt.name, err)
			}
			if got.Method != tt.method {
				t.Fatalf("decoded method = %q, want %q", got.Method, tt.method)
			}
			if !body.closed {
				t.Fatal("response body was not closed")
			}
			if body.reader.Len() != 0 {
				t.Fatalf("response body has %d unread bytes", body.reader.Len())
			}
			if resp.Body != http.NoBody {
				t.Fatalf("response body = %T, want http.NoBody", resp.Body)
			}
		})
	}
}

func TestIRestNilOutputPreservesRawResponseBody(t *testing.T) {
	body := newTrackingReadCloser("raw response")
	rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Request:    req,
		}, nil
	})

	resp, err := rest.Get("http://example.test/raw", "text/plain", nil)
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}
	if body.closed {
		t.Fatal("nil output closed the response body before the caller could read it")
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(response.Body) failed: %v", err)
	}
	if string(raw) != "raw response" {
		t.Fatalf("response body = %q, want %q", raw, "raw response")
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("response.Body.Close() failed: %v", err)
	}
	if !body.closed {
		t.Fatal("caller close did not close the response body")
	}
}

func TestIRestNon2xxReturnsResponseWithoutDecoding(t *testing.T) {
	type output struct {
		Message string `json:"message"`
	}
	body := newTrackingReadCloser(`{"message":"rejected"}`)
	rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnprocessableEntity,
			Body:       body,
			Request:    req,
		}, nil
	})
	got := &output{Message: "unchanged"}

	resp, err := rest.Get("http://example.test/rejected", "application/json", got)
	if err != nil {
		t.Fatalf("Get() error = %v, want nil for HTTP status", err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnprocessableEntity)
	}
	if got.Message != "unchanged" {
		t.Fatalf("output was decoded on non-2xx response: %+v", got)
	}
	if body.closed {
		t.Fatal("non-2xx response body closed before caller inspection")
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll(response.Body) failed: %v", err)
	}
	if string(raw) != `{"message":"rejected"}` {
		t.Fatalf("response body = %q", raw)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("response.Body.Close() failed: %v", err)
	}
}

func TestIRestDecodeErrorStillClosesBody(t *testing.T) {
	body := newTrackingReadCloser("not-json")
	rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       body,
			Request:    req,
		}, nil
	})
	output := &struct {
		Message string `json:"message"`
	}{}

	resp, err := rest.Get("http://example.test/invalid", "application/json", output)
	if err == nil || !strings.Contains(err.Error(), "problem decoding the response") {
		t.Fatalf("Get() error = %v, want JSON decoding error", err)
	}
	if !body.closed {
		t.Fatal("response body was not closed after decoding failed")
	}
	if body.reader.Len() != 0 {
		t.Fatalf("response body has %d unread bytes", body.reader.Len())
	}
	if resp == nil || resp.Body != http.NoBody {
		t.Fatalf("response body = %#v, want http.NoBody", resp)
	}
}

func TestIRestConcurrentRequestsRemainIsolated(t *testing.T) {
	const requests = 64
	rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
		marker := strings.TrimPrefix(req.URL.Path, "/")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if req.Method != http.MethodPost {
			return nil, fmt.Errorf("method = %q, want POST", req.Method)
		}
		if string(body) != marker {
			return nil, fmt.Errorf("body = %q, want marker %q", body, marker)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})

	errs := make(chan error, requests)
	var wg sync.WaitGroup
	for i := range requests {
		marker := fmt.Sprintf("request-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := rest.Post(
				"http://example.test/"+marker,
				"text/plain",
				strings.NewReader(marker),
				nil,
			)
			if err == nil && resp != nil && resp.StatusCode != http.StatusNoContent {
				err = fmt.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
			}
			errs <- err
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

func TestDoRequestUsesOneHeaderSnapshot(t *testing.T) {
	rest := newRoundTripRest(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("X-Snapshot"); got != "A" {
			return nil, fmt.Errorf("X-Snapshot = %q, want A", got)
		}
		if got := req.Header.Get("X-Later"); got != "" {
			return nil, fmt.Errorf("X-Later = %q, want absent", got)
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	req, err := http.NewRequest(http.MethodGet, "http://example.test/snapshot", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Snapshot", "A")

	rest.SetHeaders(http.Header{"X-Later": []string{"B"}})
	if _, err := rest.doRequest(req, nil); err != nil {
		t.Fatal(err)
	}
}
