// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"encoding/json"
	"fmt"
)

const (
	generatedMainPath  = "cmd/main.go"
	resourcesConfigDir = "resources"
)

// buildProjectFiles returns the generated file set for the requested service type and config format.
func buildProjectFiles(serviceType string, options scaffoldOptions) (map[string]string, error) {
	files := map[string]string{
		generatedMainPath: buildMainTemplate(serviceType, options.appName),
		//"go.mod":  buildGoModTemplate(options.modulePath, serviceType),
	}

	switch options.configFormat {
	case configYAML:
		files[resourcesConfigDir+"/application.yaml"] = buildApplicationYAML(serviceType, options.appName)
	case configJSON:
		content, err := buildApplicationJSON(serviceType, options.appName)
		if err != nil {
			return nil, err
		}
		files[resourcesConfigDir+"/application.json"] = content
	default:
		return nil, fmt.Errorf("unsupported config format %q", options.configFormat)
	}

	return files, nil
}

// buildMainTemplate renders the starter main.go for the selected transport.
func buildMainTemplate(serviceType string, appName string) string {
	switch serviceType {
	case serviceTypeGin:
		return fmt.Sprintf(`package main

import (
	"log"

	serverGin "github.com/PointerByte/forge-go/config/server/gin"
	"github.com/gin-gonic/gin"
)

func main() {
	srv, err := serverGin.CreateApp()
	if err != nil {
		log.Fatal(err)
	}

	api := serverGin.GetRoute("/api/v1")
	api.GET("/hello", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"app":     "%s",
			"message": "hello from GoForge Gin",
		})
	})

	serverGin.Start(srv)
}
`, appName)
	case serviceTypeGRPC:
		return `package main

import (
	"log"

	serverGRPC "github.com/PointerByte/forge-go/config/server/grpc"
)

func main() {
	srv := serverGRPC.NewIConfig(nil, nil)
	if err := srv.Serve(); err != nil {
		log.Fatal(err)
	}
}
`
	default:
		return ""
	}
}

// buildApplicationYAML renders the default YAML configuration for the generated service.
func buildApplicationYAML(serviceType string, appName string) string {
	if serviceType == serviceTypeGRPC {
		return fmt.Sprintf(`app:
  name: %s
  version: 0.0.1

env:
  files:
    - .env
    - .env.local

server:
  grpc:
    port: ":50051"
    rate:
      limit: 1000
      burst: 2000
    LoggerWithConfig:
      enabled: true
      SkipFunction: []
    tls:
      enable: false
      certFile: ./certs/server/cert.pem
      keyFile: ./certs/server/key.pem
      version: tlsv12
    mtls:
      enable: false
      clientCAFile: ./certs/ca.pem
      clientAuth: require_and_verify_client_cert

client:
  grpc:
    tls:
      enable: false
      caFile: ./certs/client/ca.pem
      version: tlsv12
      insecureSkipVerify: false
    mtls:
      enable: false
      certFile: ./certs/client/cert.pem
      keyFile: ./certs/client/key.pem

logger:
  dir: logs
  level: info
  ignoredHeaders:
    - Authorization
    - Cookie
  formatter: json
  formatDate: "2006-01-02T15:04:05.000"
  rotate:
    enable: true
    maxSize: 10
    maxBackups: 5
    maxAge: 30
    compress: true
  sensibleKeys:
    - password
    - pwd
    - email
    - phone

traces:
  SkipPaths:
    - /health

jwt:
  enable: false
  transport: header
  algorithm: EDDSA
  keys:
    private_key: ./certs/jwt/ed25519-key.pem
    public_key: ./certs/jwt/ed25519-public.pem
`, appName)
	}

	return fmt.Sprintf(`app:
  name: %s
  version: 0.0.1

env:
  files:
    - .env
    - .env.local

server:
  gin:
    groups:
      - /api/v1
    port: ":8080"
    mode: release
    readHeaderTimeout: 5s
    UseH2C: true
    rate:
      limit: 1000
      burst: 2000
    LoggerWithConfig:
      enabled: true
      SkipPaths:
        - /health
      SkipQueryString: false
    autotls:
      enable: false
      domain: api.example.com
      dirCache: ./certs
      version: tlsv12
    tls:
      enable: false
      certFile: ./certs/server/cert.pem
      keyFile: ./certs/server/key.pem
      version: tlsv12
    mtls:
      enable: false
      clientCAFile: ./certs/server/ca.pem
      clientAuth: require_and_verify_client_cert

client:
  http:
    timeout: 5s
    tls:
      enable: false
      caFile: ./certs/client/ca.pem
      version: tlsv12
      insecureSkipVerify: false
    mtls:
      enable: false
      certFile: ./certs/client/cert.pem
      keyFile: ./certs/client/key.pem
  grpc:
    tls:
      enable: false
      caFile: ./certs/client/ca.pem
      version: tlsv12
      insecureSkipVerify: false
    mtls:
      enable: false
      certFile: ./certs/client/cert.pem
      keyFile: ./certs/client/key.pem

logger:
  dir: logs
  level: info
  ignoredHeaders:
    - Authorization
    - Cookie
  formatter: json
  formatDate: "2006-01-02T15:04:05.000"
  rotate:
    enable: true
    maxSize: 10
    maxBackups: 5
    maxAge: 30
    compress: true
  sensibleKeys:
    - password
    - pwd
    - email
    - phone

traces:
  SkipPaths:
    - /health

jwt:
  enable: false
  transport: header
  algorithm: EDDSA
  keys:
    private_key: ./certs/jwt/ed25519-key.pem
    public_key: ./certs/jwt/ed25519-public.pem
`, appName)
}

// buildApplicationJSON renders the default JSON configuration for the generated service.
func buildApplicationJSON(serviceType string, appName string) (string, error) {
	data := map[string]any{
		"app": map[string]any{
			"name":    appName,
			"version": "0.0.1",
		},
		"env": map[string]any{
			"files": []string{
				".env",
				".env.local",
			},
		},
		"logger": map[string]any{
			"dir":   "logs",
			"level": "info",
			"ignoredHeaders": []string{
				"Authorization",
				"Cookie",
			},
			"formatter":  "json",
			"formatDate": "2006-01-02T15:04:05.000",
			"rotate": map[string]any{
				"enable":     true,
				"maxSize":    10,
				"maxBackups": 5,
				"maxAge":     30,
				"compress":   true,
			},
			"sensibleKeys": []string{
				"password",
				"pwd",
				"email",
				"phone",
			},
		},
	}

	if serviceType == serviceTypeGRPC {
		data["server"] = map[string]any{
			"grpc": map[string]any{
				"port": ":50051",
				"rate": map[string]any{
					"limit": 1000,
					"burst": 2000,
				},
				"LoggerWithConfig": map[string]any{
					"enabled":      true,
					"SkipFunction": []string{},
				},
				"tls": map[string]any{
					"enable":   false,
					"certFile": "./certs/server/cert.pem",
					"keyFile":  "./certs/server/key.pem",
					"version":  "tlsv12",
				},
				"mtls": map[string]any{
					"enable":       false,
					"clientCAFile": "./certs/ca.pem",
					"clientAuth":   "require_and_verify_client_cert",
				},
			},
		}
		data["client"] = map[string]any{
			"grpc": map[string]any{
				"tls": map[string]any{
					"enable":             false,
					"caFile":             "./certs/client/ca.pem",
					"version":            "tlsv12",
					"insecureSkipVerify": false,
				},
				"mtls": map[string]any{
					"enable":   false,
					"certFile": "./certs/client/cert.pem",
					"keyFile":  "./certs/client/key.pem",
				},
			},
		}
		data["traces"] = map[string]any{
			"enable": false,
			"SkipPaths": []string{
				"/health",
			},
		}
		data["jwt"] = map[string]any{
			"enable":    false,
			"transport": "header",
			"algorithm": "EDDSA",
			"keys": map[string]any{
				"private_key": "./certs/jwt/ed25519-key.pem",
				"public_key":  "./certs/jwt/ed25519-public.pem",
			},
		}
	} else {
		data["server"] = map[string]any{
			"gin": map[string]any{
				"groups":            []string{"/api/v1"},
				"port":              ":8080",
				"mode":              "release",
				"readHeaderTimeout": "5s",
				"UseH2C":            true,
				"rate": map[string]any{
					"limit": 1000,
					"burst": 2000,
				},
				"LoggerWithConfig": map[string]any{
					"enabled": true,
					"SkipPaths": []string{
						"/health",
					},
					"SkipQueryString": false,
				},
				"autotls": map[string]any{
					"enable":   false,
					"domain":   "api.example.com",
					"dirCache": "./certs",
					"version":  "tlsv12",
				},
				"tls": map[string]any{
					"enable":   false,
					"certFile": "./certs/server/cert.pem",
					"keyFile":  "./certs/server/key.pem",
					"version":  "tlsv12",
				},
				"mtls": map[string]any{
					"enable":       false,
					"clientCAFile": "./certs/server/ca.pem",
					"clientAuth":   "require_and_verify_client_cert",
				},
			},
		}
		data["client"] = map[string]any{
			"http": map[string]any{
				"timeout": "5s",
				"tls": map[string]any{
					"enable":             false,
					"caFile":             "./certs/client/ca.pem",
					"version":            "tlsv12",
					"insecureSkipVerify": false,
				},
				"mtls": map[string]any{
					"enable":   false,
					"certFile": "./certs/client/cert.pem",
					"keyFile":  "./certs/client/key.pem",
				},
			},
			"grpc": map[string]any{
				"tls": map[string]any{
					"enable":             false,
					"caFile":             "./certs/client/ca.pem",
					"version":            "tlsv12",
					"insecureSkipVerify": false,
				},
				"mtls": map[string]any{
					"enable":   false,
					"certFile": "./certs/client/cert.pem",
					"keyFile":  "./certs/client/key.pem",
				},
			},
		}
		data["traces"] = map[string]any{
			"enable": false,
			"SkipPaths": []string{
				"/health",
			},
		}
		data["jwt"] = map[string]any{
			"enable":    false,
			"transport": "header",
			"algorithm": "EDDSA",
			"keys": map[string]any{
				"private_key": "./certs/jwt/ed25519-key.pem",
				"public_key":  "./certs/jwt/ed25519-public.pem",
			},
		}
	}

	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal application json: %w", err)
	}
	return string(payload) + "\n", nil
}
