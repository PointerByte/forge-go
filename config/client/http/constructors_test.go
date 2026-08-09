// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

// failTLSConfig makes resolveTLSConfig fail so the error-returning constructors
// can be exercised without a real TLS handshake.
func failTLSConfig(t *testing.T) error {
	t.Helper()
	wantErr := errors.New("ca file unavailable")
	readFileFn = func(string) ([]byte, error) { return nil, wantErr }
	viper.Set("client.http.tls.enable", true)
	viper.Set("client.http.tls.caFile", "missing.pem")
	return wantErr
}

// --- REST constructors ---

func TestNewConfiguredIRest(t *testing.T) {
	t.Run("returns a usable client", func(t *testing.T) {
		resetHTTPClientTestState(t)

		client, err := NewConfiguredIRest(5*time.Second, nil)
		if err != nil {
			t.Fatalf("NewConfiguredIRest() error = %v", err)
		}
		if client == nil {
			t.Fatal("NewConfiguredIRest() = nil, want a client")
		}
		rest, ok := client.(*Rest)
		if !ok {
			t.Fatalf("NewConfiguredIRest() = %T, want *Rest", client)
		}
		if rest.restClient.Timeout != 5*time.Second {
			t.Fatalf("timeout = %v, want 5s", rest.restClient.Timeout)
		}
		// Headers must be initialized so concurrent readers never see a nil map.
		if headers, ok := rest.hdr.Load().(http.Header); !ok || headers == nil {
			t.Fatalf("hdr = %#v, want an initialized http.Header", rest.hdr.Load())
		}
	})

	t.Run("propagates TLS configuration errors", func(t *testing.T) {
		resetHTTPClientTestState(t)
		wantErr := failTLSConfig(t)

		client, err := NewConfiguredIRest(time.Second, nil)
		if !errors.Is(err, wantErr) {
			t.Fatalf("NewConfiguredIRest() error = %v, want %v", err, wantErr)
		}
		if client != nil {
			t.Fatalf("NewConfiguredIRest() = %#v, want nil on error", client)
		}
	})

	t.Run("clones a supplied transport", func(t *testing.T) {
		resetHTTPClientTestState(t)

		transport := &http.Transport{MaxIdleConns: 7}
		client, err := NewConfiguredIRest(time.Second, transport)
		if err != nil {
			t.Fatalf("NewConfiguredIRest() error = %v", err)
		}
		resolved, ok := client.(*Rest).restClient.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport = %T, want *http.Transport", client.(*Rest).restClient.Transport)
		}
		if resolved == transport {
			t.Fatal("transport was not cloned")
		}
		if resolved.MaxIdleConns != 7 {
			t.Fatalf("MaxIdleConns = %d, want 7", resolved.MaxIdleConns)
		}
	})
}

func TestNewIRestFromConfig(t *testing.T) {
	t.Run("uses the configured timeout", func(t *testing.T) {
		resetHTTPClientTestState(t)
		viper.Set("client.http.timeout", "12s")

		client, err := NewIRestFromConfig()
		if err != nil {
			t.Fatalf("NewIRestFromConfig() error = %v", err)
		}
		if got := client.(*Rest).restClient.Timeout; got != 12*time.Second {
			t.Fatalf("timeout = %v, want 12s", got)
		}
	})

	t.Run("falls back to the default timeout", func(t *testing.T) {
		resetHTTPClientTestState(t)

		client, err := NewIRestFromConfig()
		if err != nil {
			t.Fatalf("NewIRestFromConfig() error = %v", err)
		}
		if got := client.(*Rest).restClient.Timeout; got != 30*time.Second {
			t.Fatalf("timeout = %v, want the 30s default", got)
		}
	})

	t.Run("propagates TLS configuration errors", func(t *testing.T) {
		resetHTTPClientTestState(t)
		wantErr := failTLSConfig(t)

		client, err := NewIRestFromConfig()
		if !errors.Is(err, wantErr) || client != nil {
			t.Fatalf("NewIRestFromConfig() = (%#v, %v), want (nil, %v)", client, err, wantErr)
		}
	})
}

// --- generic REST constructors ---

func TestNewConfiguredGenericRest(t *testing.T) {
	t.Run("returns a usable client", func(t *testing.T) {
		resetHTTPClientTestState(t)

		client, err := NewConfiguredGenericRest(3*time.Second, nil)
		if err != nil {
			t.Fatalf("NewConfiguredGenericRest() error = %v", err)
		}
		generic, ok := client.(*RestGeneric)
		if !ok {
			t.Fatalf("NewConfiguredGenericRest() = %T, want *RestGeneric", client)
		}
		if generic.newIRest == nil {
			t.Fatal("newIRest = nil, want the wrapped REST client")
		}
	})

	t.Run("propagates TLS configuration errors", func(t *testing.T) {
		resetHTTPClientTestState(t)
		wantErr := failTLSConfig(t)

		client, err := NewConfiguredGenericRest(time.Second, nil)
		if !errors.Is(err, wantErr) || client != nil {
			t.Fatalf("NewConfiguredGenericRest() = (%#v, %v), want (nil, %v)", client, err, wantErr)
		}
	})
}

func TestNewGenericRestFromConfig(t *testing.T) {
	t.Run("uses the configured timeout", func(t *testing.T) {
		resetHTTPClientTestState(t)
		viper.Set("client.http.timeout", "8s")

		client, err := NewGenericRestFromConfig()
		if err != nil {
			t.Fatalf("NewGenericRestFromConfig() error = %v", err)
		}
		rest, ok := client.(*RestGeneric).newIRest.(*Rest)
		if !ok {
			t.Fatalf("newIRest = %T, want *Rest", client.(*RestGeneric).newIRest)
		}
		if rest.restClient.Timeout != 8*time.Second {
			t.Fatalf("timeout = %v, want 8s", rest.restClient.Timeout)
		}
	})

	t.Run("propagates TLS configuration errors", func(t *testing.T) {
		resetHTTPClientTestState(t)
		wantErr := failTLSConfig(t)

		client, err := NewGenericRestFromConfig()
		if !errors.Is(err, wantErr) || client != nil {
			t.Fatalf("NewGenericRestFromConfig() = (%#v, %v), want (nil, %v)", client, err, wantErr)
		}
	})
}

// --- error formatting ---

func TestFormatHTTPClientError(t *testing.T) {
	tests := []struct {
		name     string
		response *http.Response
		wantHas  string
	}{
		{name: "without a response reports status zero", wantHas: "status[0]"},
		{
			name:     "with a response reports its status",
			response: &http.Response{StatusCode: http.StatusBadGateway},
			wantHas:  "status[502]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := formatHTTPClientError(tt.response, errors.New("dial failed"))
			if err == nil {
				t.Fatal("formatHTTPClientError() = nil, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantHas) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tt.wantHas)
			}
			if !strings.Contains(err.Error(), "dial failed") {
				t.Fatalf("error = %q, want it to contain the cause", err.Error())
			}
		})
	}
}
