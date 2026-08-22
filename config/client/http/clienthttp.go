// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var (
	loadX509KeyPairFn = tls.LoadX509KeyPair
	readFileFn        = os.ReadFile
	newCertPoolFn     = x509.NewCertPool
	clientTLSConfig   *tls.Config
)

// SetTLSConfig sets the TLS configuration used by HTTP clients created by this
// package when no explicit transport TLS configuration should be resolved from
// Viper.
func SetTLSConfig(config *tls.Config) {
	clientTLSConfig = config
}

// NewRestClient creates an http client.
//
// If client.http.tls.enable or client.http.mtls.enable is set in Viper, the
// returned client uses those settings when TLS resolution succeeds. Use
// NewConfiguredRestClient when configuration errors must be returned directly.
func NewRestClient(timeout time.Duration, tr *http.Transport) *http.Client {
	client, _ := newRestClient(timeout, tr)
	return client
}

// NewConfiguredRestClient creates an http client and returns configuration
// errors while resolving client.http TLS and mTLS settings.
func NewConfiguredRestClient(timeout time.Duration, tr *http.Transport) (*http.Client, error) {
	return newRestClient(timeout, tr)
}

// NewRestClientFromConfig creates an http client using client.http.timeout and
// TLS/mTLS settings from Viper.
func NewRestClientFromConfig() (*http.Client, error) {
	return newRestClient(clientHTTPTimeout(), nil)
}

func newRestClient(timeout time.Duration, tr *http.Transport) (*http.Client, error) {
	resolvedTransport, err := resolveTransport(tr)
	return &http.Client{
		Transport: resolvedTransport,
		Timeout:   timeout,
	}, err
}

func resolveTransport(tr *http.Transport) (*http.Transport, error) {
	if tr == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		tr = tr.Clone()
	}

	config, err := resolveTLSConfig()
	if err != nil {
		return tr, err
	}
	if config != nil {
		tr.TLSClientConfig = config
	}
	return tr, nil
}

func resolveTLSConfig() (*tls.Config, error) {
	if clientTLSConfig != nil {
		return clientTLSConfig, nil
	}

	tlsEnabled := viper.GetBool("client.http.tls.enable")
	mtlsEnabled := viper.GetBool("client.http.mtls.enable")
	if !tlsEnabled && !mtlsEnabled {
		return nil, nil
	}

	config := &tls.Config{
		MinVersion:         parseTLSVersion(viper.GetString("client.http.tls.version")),
		ServerName:         strings.TrimSpace(viper.GetString("client.http.tls.serverName")),
		InsecureSkipVerify: viper.GetBool("client.http.tls.insecureSkipVerify"), // #nosec G402 -- explicitly configured legacy test escape hatch.
	}

	if caFile := strings.TrimSpace(viper.GetString("client.http.tls.caFile")); caFile != "" {
		caPEM, err := readFileFn(caFile)
		if err != nil {
			return nil, fmt.Errorf("problem reading http tls ca file: %w", err)
		}
		pool := newCertPoolFn()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("problem parsing http tls ca file")
		}
		config.RootCAs = pool
	}

	if mtlsEnabled {
		certFile := strings.TrimSpace(viper.GetString("client.http.mtls.certFile"))
		keyFile := strings.TrimSpace(viper.GetString("client.http.mtls.keyFile"))
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("client.http.mtls.certFile and client.http.mtls.keyFile are required")
		}
		certificate, err := loadX509KeyPairFn(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("problem loading http client mtls certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}

	return config, nil
}

func clientHTTPTimeout() time.Duration {
	if timeout := viper.GetDuration("client.http.timeout"); timeout > 0 {
		return timeout
	}
	return 30 * time.Second
}

func parseTLSVersion(raw string) uint16 {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tlsv10":
		return tls.VersionTLS10
	case "tlsv11":
		return tls.VersionTLS11
	case "tlsv13":
		return tls.VersionTLS13
	default:
		return tls.VersionTLS12
	}
}
