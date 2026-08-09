// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func resetHTTPClientTestState(t *testing.T) {
	t.Helper()

	originalLoadX509KeyPairFn := loadX509KeyPairFn
	originalReadFileFn := readFileFn
	originalNewCertPoolFn := newCertPoolFn
	originalClientTLSConfig := clientTLSConfig

	viper.Reset()
	clientTLSConfig = nil
	loadX509KeyPairFn = tls.LoadX509KeyPair
	readFileFn = os.ReadFile
	newCertPoolFn = x509.NewCertPool

	t.Cleanup(func() {
		loadX509KeyPairFn = originalLoadX509KeyPairFn
		readFileFn = originalReadFileFn
		newCertPoolFn = originalNewCertPoolFn
		clientTLSConfig = originalClientTLSConfig
		viper.Reset()
	})
}

func TestRestClient(t *testing.T) {
	resetHTTPClientTestState(t)
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

	got := NewRestClient(time.Second, tr)
	if got == nil {
		t.Fatalf("RestClient() returned nil client")
	}

	// Transport debe ser *http.Transport
	tr, ok := got.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("client.Transport = %#v, want *http.Transport", got.Transport)
	}
}

func TestHTTPClientTLSConfiguration(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		resetHTTPClientTestState(t)

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config != nil {
			t.Fatalf("resolveTLSConfig() = %#v, want nil", config)
		}
	})

	t.Run("manual config", func(t *testing.T) {
		resetHTTPClientTestState(t)

		want := &tls.Config{MinVersion: tls.VersionTLS13}
		SetTLSConfig(want)
		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config != want {
			t.Fatalf("resolveTLSConfig() = %p, want %p", config, want)
		}
	})

	t.Run("tls from client http config", func(t *testing.T) {
		resetHTTPClientTestState(t)
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer ts.Close()
		caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
		readFileFn = func(path string) ([]byte, error) {
			if path != "ca.pem" {
				t.Fatalf("readFileFn(%q)", path)
			}
			return caPEM, nil
		}
		viper.Set("client.http.tls.enable", true)
		viper.Set("client.http.tls.caFile", "ca.pem")
		viper.Set("client.http.tls.serverName", "localhost")
		viper.Set("client.http.tls.version", "tlsv13")
		viper.Set("client.http.tls.insecureSkipVerify", true)

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if config.MinVersion != tls.VersionTLS13 {
			t.Fatalf("MinVersion = %v, want %v", config.MinVersion, tls.VersionTLS13)
		}
		if config.RootCAs == nil {
			t.Fatal("RootCAs = nil, want populated pool")
		}
		if config.ServerName != "localhost" {
			t.Fatalf("ServerName = %q, want localhost", config.ServerName)
		}
		if !config.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify = false, want true")
		}
	})

	t.Run("mtls from client http config", func(t *testing.T) {
		resetHTTPClientTestState(t)
		loadX509KeyPairFn = func(certFile, keyFile string) (tls.Certificate, error) {
			if certFile != "client-cert.pem" || keyFile != "client-key.pem" {
				t.Fatalf("loadX509KeyPairFn(%q, %q)", certFile, keyFile)
			}
			return tls.Certificate{Certificate: [][]byte{{1}}}, nil
		}
		viper.Set("client.http.mtls.enable", true)
		viper.Set("client.http.mtls.certFile", "client-cert.pem")
		viper.Set("client.http.mtls.keyFile", "client-key.pem")

		config, err := resolveTLSConfig()
		if err != nil {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
		if len(config.Certificates) != 1 {
			t.Fatalf("Certificates len = %d, want 1", len(config.Certificates))
		}
	})

	t.Run("mtls requires cert and key", func(t *testing.T) {
		resetHTTPClientTestState(t)
		viper.Set("client.http.mtls.enable", true)

		_, err := resolveTLSConfig()
		if err == nil || err.Error() != "client.http.mtls.certFile and client.http.mtls.keyFile are required" {
			t.Fatalf("resolveTLSConfig() error = %v", err)
		}
	})

	t.Run("configured constructor returns errors", func(t *testing.T) {
		resetHTTPClientTestState(t)
		wantErr := errors.New("read ca")
		readFileFn = func(string) ([]byte, error) {
			return nil, wantErr
		}
		viper.Set("client.http.tls.enable", true)
		viper.Set("client.http.tls.caFile", "missing-ca.pem")

		client, err := NewConfiguredRestClient(time.Second, nil)
		if err == nil || !errors.Is(err, wantErr) {
			t.Fatalf("NewConfiguredRestClient() error = %v", err)
		}
		if client == nil {
			t.Fatal("NewConfiguredRestClient() returned nil client")
		}
	})

	t.Run("timeout from config", func(t *testing.T) {
		resetHTTPClientTestState(t)
		viper.Set("client.http.timeout", "5s")

		client, err := NewRestClientFromConfig()
		if err != nil {
			t.Fatalf("NewRestClientFromConfig() error = %v", err)
		}
		if client.Timeout != 5*time.Second {
			t.Fatalf("Timeout = %v, want 5s", client.Timeout)
		}
	})

	if got := parseTLSVersion("tlsv10"); got != tls.VersionTLS10 {
		t.Fatalf("parseTLSVersion(tlsv10) = %v, want %v", got, tls.VersionTLS10)
	}
	if got := parseTLSVersion("unknown"); got != tls.VersionTLS12 {
		t.Fatalf("parseTLSVersion(unknown) = %v, want %v", got, tls.VersionTLS12)
	}
}
