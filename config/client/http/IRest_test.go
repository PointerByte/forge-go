// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func newHTTPTestServer(t *testing.T, status int, assert func(*testing.T, *http.Request), body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if assert != nil {
			assert(t, r)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func newBaseSubRest(timeout time.Duration) *Rest {
	sr := &Rest{restClient: NewRestClient(timeout, &http.Transport{})}
	sr.hdr.Store(http.Header{})
	return sr
}

func TestNewIRest(t *testing.T) {
	tr := &http.Transport{
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
	NewIRest(time.Second, tr)
}

func TestSubRest_SetRequest(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	tests := []struct {
		name string
		req  *http.Request
	}{
		{name: "sets nil request", req: nil},
		{name: "sets concrete request", req: req},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sr Rest
			sr.SetRequest(tt.req)
			if sr.req != tt.req {
				t.Fatalf("SetRequest() stored %v, want %v", sr.req, tt.req)
			}
		})
	}
}

func TestSubRest_Do(t *testing.T) {
	server := newHTTPTestServer(t, http.StatusOK, func(t *testing.T, r *http.Request) {
		if r.Header.Get("X-Test") != "value" {
			t.Fatalf("header X-Test = %q", r.Header.Get("X-Test"))
		}
	}, "ok")
	defer server.Close()
	reqOK, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	reqErr, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
	reqMerge, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	reqMerge.Header = http.Header{"Content-Type": {"existing/type"}}
	tests := []struct {
		name      string
		setup     func() *Rest
		object    any
		want      *http.Response
		wantErr   bool
		errText   string
		assertion func(*testing.T, *Rest, *http.Response)
	}{
		{
			name: "executes request successfully",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				sr.SetHeaders(http.Header{"X-Test": {"value"}})
				sr.SetRequest(reqOK.Clone(context.Background()))
				return sr
			},
			object:  any(nil),
			wantErr: false,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if got.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", got.StatusCode)
				}
			},
		},
		{
			name: "returns wrapped error on transport failure",
			setup: func() *Rest {
				sr := newBaseSubRest(50 * time.Millisecond)
				sr.SetRequest(reqErr.Clone(context.Background()))
				return sr
			},
			object:  nil,
			wantErr: true,
			errText: "problema al ejecutar la solicitud",
		},
		{
			name: "merges base header without overwriting request header",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				sr.SetHeaders(http.Header{"Content-Type": {"base/type"}, "X-Test": {"value"}})
				sr.SetRequest(reqMerge.Clone(context.Background()))
				return sr
			},
			object:  nil,
			wantErr: false,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if sr.req.Header.Get("Content-Type") != "existing/type" {
					t.Fatalf("content-type overwritten = %q", sr.req.Header.Get("Content-Type"))
				}
				if sr.req.Header.Get("X-Test") != "value" {
					t.Fatalf("header not merged = %q", sr.req.Header.Get("X-Test"))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := tt.setup()
			got, gotErr := sr.Do(tt.object)
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("Do() succeeded unexpectedly")
				}
				if tt.errText != "" && !strings.Contains(gotErr.Error(), tt.errText) {
					t.Fatalf("Do() error = %v", gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("Do() failed: %v", gotErr)
			}
			if tt.want != nil && got != tt.want {
				t.Fatalf("Do() = %v, want %v", got, tt.want)
			}
			if tt.assertion != nil {
				tt.assertion(t, sr, got)
			}
		})
	}
}

func TestSubRest_SetHeaders(t *testing.T) {
	tests := []struct {
		name      string
		header    http.Header
		assertion func(*testing.T, *Rest)
	}{
		{
			name:   "ignores nil header",
			header: nil,
			assertion: func(t *testing.T, sr *Rest) {
				if sr.hdr.Load() != nil {
					t.Fatalf("expected nil stored header, got %v", sr.hdr.Load())
				}
			},
		},
		{
			name:   "stores cloned header",
			header: http.Header{"X-Test": {"value"}},
			assertion: func(t *testing.T, sr *Rest) {
				stored, ok := sr.hdr.Load().(http.Header)
				if !ok {
					t.Fatalf("stored header type = %T", sr.hdr.Load())
				}
				if !reflect.DeepEqual(stored, http.Header{"X-Test": {"value"}}) {
					t.Fatalf("stored header = %v", stored)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sr Rest
			sr.SetHeaders(tt.header)
			if tt.header != nil {
				tt.header.Set("X-Test", "mutated")
			}
			tt.assertion(t, &sr)
		})
	}
}

type testContextKey struct{}

func TestSubRest_Get(t *testing.T) {
	ctxKey := testContextKey{}
	server := newHTTPTestServer(t, http.StatusOK, func(t *testing.T, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-Test") != "value" {
			t.Fatalf("X-Test = %q", r.Header.Get("X-Test"))
		}
	}, "get")
	defer server.Close()
	tests := []struct {
		name      string
		setup     func() *Rest
		url       string
		content   string
		object    any
		want      *http.Response
		wantErr   bool
		errText   string
		assertion func(*testing.T, *Rest, *http.Response)
	}{
		{
			name: "success with context and headers",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				sr.SetHeaders(http.Header{"X-Test": {"value"}})
				sr.SetContext(context.WithValue(context.Background(), ctxKey, "ctx-value"))
				baseReq, _ := http.NewRequest(http.MethodGet, server.URL, nil)
				sr.SetRequest(baseReq)
				return sr
			},
			url:     server.URL,
			content: "application/json",
			object:  nil,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if got.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", got.StatusCode)
				}
				if sr.req == nil || sr.req.Method != http.MethodGet {
					t.Fatalf("stored request = %#v", sr.req)
				}
				if !sr.withContext {
					t.Fatalf("withContext = %v", sr.withContext)
				}
				ctx := sr.ctx
				if ctx == nil || ctx.Value(ctxKey) != "ctx-value" {
					t.Fatalf("stored context value = %v", ctx.Value(ctxKey))
				}
			},
		},
		{
			name: "invalid url returns wrapped error",
			setup: func() *Rest {
				return newBaseSubRest(time.Second)
			},
			url:     "://bad-url",
			content: "application/json",
			wantErr: true,
			errText: "problem creating the request get",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := tt.setup()
			got, gotErr := sr.Get(tt.url, tt.content, tt.object)
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("Get() succeeded unexpectedly")
				}
				if tt.errText != "" && !strings.Contains(gotErr.Error(), tt.errText) {
					t.Fatalf("Get() error = %v", gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("Get() failed: %v", gotErr)
			}
			if tt.want != nil && got != tt.want {
				t.Fatalf("Get() = %v, want %v", got, tt.want)
			}
			if tt.assertion != nil {
				tt.assertion(t, sr, got)
			}
		})
	}
}

func TestSubRest_Post(t *testing.T) {
	server := newHTTPTestServer(t, http.StatusCreated, func(t *testing.T, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"name":"test"}` {
			t.Fatalf("body = %q", string(b))
		}
	}, "post")
	defer server.Close()
	tests := []struct {
		name      string
		setup     func() *Rest
		url       string
		content   string
		body      io.Reader
		object    any
		want      *http.Response
		wantErr   bool
		errText   string
		assertion func(*testing.T, *Rest, *http.Response)
	}{
		{
			name: "success request",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				baseReq, _ := http.NewRequest(http.MethodPost, server.URL, nil)
				sr.SetRequest(baseReq)
				return sr
			},
			url:     server.URL,
			content: "application/json",
			body:    strings.NewReader(`{"name":"test"}`),
			object:  nil,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if got.StatusCode != http.StatusCreated {
					t.Fatalf("status = %d", got.StatusCode)
				}
				if sr.req.Method != http.MethodPost {
					t.Fatalf("stored method = %s", sr.req.Method)
				}
			},
		},
		{
			name: "invalid url returns wrapped error",
			setup: func() *Rest {
				return newBaseSubRest(time.Second)
			},
			url:     "://bad-url",
			content: "application/json",
			body:    strings.NewReader("x"),
			wantErr: true,
			errText: "problem creating the request post",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := tt.setup()
			got, gotErr := sr.Post(tt.url, tt.content, tt.body, tt.object)
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("Post() succeeded unexpectedly")
				}
				if tt.errText != "" && !strings.Contains(gotErr.Error(), tt.errText) {
					t.Fatalf("Post() error = %v", gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("Post() failed: %v", gotErr)
			}
			if tt.want != nil && got != tt.want {
				t.Fatalf("Post() = %v, want %v", got, tt.want)
			}
			if tt.assertion != nil {
				tt.assertion(t, sr, got)
			}
		})
	}
}

func TestSubRest_Put(t *testing.T) {
	server := newHTTPTestServer(t, http.StatusAccepted, func(t *testing.T, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"id":1}` {
			t.Fatalf("body = %q", string(b))
		}
	}, "put")
	defer server.Close()
	tests := []struct {
		name      string
		setup     func() *Rest
		url       string
		content   string
		body      io.Reader
		object    any
		want      *http.Response
		wantErr   bool
		errText   string
		assertion func(*testing.T, *Rest, *http.Response)
	}{
		{
			name: "success request",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				baseReq, _ := http.NewRequest(http.MethodPut, server.URL, nil)
				sr.SetRequest(baseReq)
				return sr
			},
			url:     server.URL,
			content: "application/json",
			body:    strings.NewReader(`{"id":1}`),
			object:  nil,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if got.StatusCode != http.StatusAccepted {
					t.Fatalf("status = %d", got.StatusCode)
				}
				if sr.req.Method != http.MethodPut {
					t.Fatalf("stored method = %s", sr.req.Method)
				}
			},
		},
		{
			name: "invalid url returns wrapped error",
			setup: func() *Rest {
				return newBaseSubRest(time.Second)
			},
			url:     "://bad-url",
			content: "application/json",
			body:    strings.NewReader("x"),
			wantErr: true,
			errText: "problem creating the request put",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := tt.setup()
			got, gotErr := sr.Put(tt.url, tt.content, tt.body, tt.object)
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("Put() succeeded unexpectedly")
				}
				if tt.errText != "" && !strings.Contains(gotErr.Error(), tt.errText) {
					t.Fatalf("Put() error = %v", gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("Put() failed: %v", gotErr)
			}
			if tt.want != nil && got != tt.want {
				t.Fatalf("Put() = %v, want %v", got, tt.want)
			}
			if tt.assertion != nil {
				tt.assertion(t, sr, got)
			}
		})
	}
}

func TestSubRest_Patch(t *testing.T) {
	server := newHTTPTestServer(t, http.StatusOK, func(t *testing.T, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/merge-patch+json" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"active":true}` {
			t.Fatalf("body = %q", string(b))
		}
	}, "patch")
	defer server.Close()
	tests := []struct {
		name      string
		setup     func() *Rest
		url       string
		content   string
		body      io.Reader
		object    any
		want      *http.Response
		wantErr   bool
		errText   string
		assertion func(*testing.T, *Rest, *http.Response)
	}{
		{
			name: "success request",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				baseReq, _ := http.NewRequest(http.MethodPatch, server.URL, nil)
				sr.SetRequest(baseReq)
				return sr
			},
			url:     server.URL,
			content: "application/merge-patch+json",
			body:    strings.NewReader(`{"active":true}`),
			object:  nil,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if got.StatusCode != http.StatusOK {
					t.Fatalf("status = %d", got.StatusCode)
				}
				if sr.req.Method != http.MethodPatch {
					t.Fatalf("stored method = %s", sr.req.Method)
				}
			},
		},
		{
			name: "invalid url returns wrapped error",
			setup: func() *Rest {
				return newBaseSubRest(time.Second)
			},
			url:     "://bad-url",
			content: "application/json",
			body:    strings.NewReader("x"),
			wantErr: true,
			errText: "problem creating the request patch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := tt.setup()
			got, gotErr := sr.Patch(tt.url, tt.content, tt.body, tt.object)
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("Patch() succeeded unexpectedly")
				}
				if tt.errText != "" && !strings.Contains(gotErr.Error(), tt.errText) {
					t.Fatalf("Patch() error = %v", gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("Patch() failed: %v", gotErr)
			}
			if tt.want != nil && got != tt.want {
				t.Fatalf("Patch() = %v, want %v", got, tt.want)
			}
			if tt.assertion != nil {
				tt.assertion(t, sr, got)
			}
		})
	}
}

func TestSubRest_Option(t *testing.T) {
	server := newHTTPTestServer(t, http.StatusNoContent, func(t *testing.T, r *http.Request) {
		if r.Method != http.MethodOptions {
			t.Fatalf("method = %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content-type = %q", r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != `{"q":1}` {
			t.Fatalf("body = %q", string(b))
		}
	}, "")
	defer server.Close()
	tests := []struct {
		name      string
		setup     func() *Rest
		url       string
		content   string
		body      io.Reader
		object    any
		want      *http.Response
		wantErr   bool
		errText   string
		assertion func(*testing.T, *Rest, *http.Response)
	}{
		{
			name: "success request",
			setup: func() *Rest {
				sr := newBaseSubRest(time.Second)
				baseReq, _ := http.NewRequest(http.MethodOptions, server.URL, nil)
				sr.SetRequest(baseReq)
				return sr
			},
			url:     server.URL,
			content: "application/json",
			body:    bytes.NewBufferString(`{"q":1}`),
			object:  nil,
			assertion: func(t *testing.T, sr *Rest, got *http.Response) {
				if got.StatusCode != http.StatusNoContent {
					t.Fatalf("status = %d", got.StatusCode)
				}
				if sr.req.Method != http.MethodOptions {
					t.Fatalf("stored method = %s", sr.req.Method)
				}
			},
		},
		{
			name: "invalid url returns wrapped error",
			setup: func() *Rest {
				return newBaseSubRest(time.Second)
			},
			url:     "://bad-url",
			content: "application/json",
			body:    strings.NewReader("x"),
			wantErr: true,
			errText: "problem creating the request option",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := tt.setup()
			got, gotErr := sr.Option(tt.url, tt.content, tt.body, tt.object)
			if tt.wantErr {
				if gotErr == nil {
					t.Fatal("Option() succeeded unexpectedly")
				}
				if tt.errText != "" && !strings.Contains(gotErr.Error(), tt.errText) {
					t.Fatalf("Option() error = %v", gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("Option() failed: %v", gotErr)
			}
			if tt.want != nil && got != tt.want {
				t.Fatalf("Option() = %v, want %v", got, tt.want)
			}
			if tt.assertion != nil {
				tt.assertion(t, sr, got)
			}
		})
	}
}

func TestMockIRestMethods(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockResp := &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader("mock"))}
	mockErr := errors.New("mock do error")

	ctxKey := testContextKey{}
	ctx := context.WithValue(context.Background(), ctxKey, "v")
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	h := http.Header{"X-Test": {"value"}}

	mock := NewMockIRest(ctrl)
	mock.EXPECT().SetContext(ctx)
	mock.EXPECT().SetHeaders(h)
	mock.EXPECT().SetRequest(req)
	mock.EXPECT().Do("boom").Return(nil, mockErr)
	mock.EXPECT().Get("http://get", "json", "obj").Return(mockResp, nil)
	mock.EXPECT().Post("http://post", "json", gomock.Any(), "obj").Return(mockResp, nil)
	mock.EXPECT().Put("http://put", "json", gomock.Any(), "obj").Return(mockResp, nil)
	mock.EXPECT().Patch("http://patch", "json", gomock.Any(), "obj").Return(mockResp, nil)
	mock.EXPECT().Option("http://option", "json", gomock.Any(), "obj").Return(mockResp, nil)

	mock.SetContext(ctx)
	mock.SetHeaders(h)
	mock.SetRequest(req)
	if _, err := mock.Do("boom"); !errors.Is(err, mockErr) {
		t.Fatalf("Do() error = %v", err)
	}
	if resp, err := mock.Get("http://get", "json", "obj"); err != nil || resp != mockResp {
		t.Fatalf("Get() = %v, %v", resp, err)
	}
	if resp, err := mock.Post("http://post", "json", strings.NewReader("{}"), "obj"); err != nil || resp != mockResp {
		t.Fatalf("Post() = %v, %v", resp, err)
	}
	if resp, err := mock.Put("http://put", "json", strings.NewReader("{}"), "obj"); err != nil || resp != mockResp {
		t.Fatalf("Put() = %v, %v", resp, err)
	}
	if resp, err := mock.Patch("http://patch", "json", strings.NewReader("{}"), "obj"); err != nil || resp != mockResp {
		t.Fatalf("Patch() = %v, %v", resp, err)
	}
	if resp, err := mock.Option("http://option", "json", strings.NewReader("{}"), "obj"); err != nil || resp != mockResp {
		t.Fatalf("Option() = %v, %v", resp, err)
	}
}
