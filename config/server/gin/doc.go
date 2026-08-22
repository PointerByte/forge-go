// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package gin provides the HTTP bootstrap layer used by GoForge services.
//
// It is responsible for turning the framework configuration into a runnable Gin
// server with shared middleware, route groups, observability setup, health
// handlers, and graceful shutdown coordination.
//
// In a typical application flow this package:
//   - loads configuration through tools/utilities
//   - initializes logger and OpenTelemetry
//   - creates the shared gin.Engine
//   - registers the common middleware stack
//   - creates the route groups declared in server.gin.groups
//   - builds the final *http.Server returned by CreateApp
//
// Main entry points:
//   - CreateApp to initialize configuration and build the HTTP server
//   - GetEngine to access the shared gin.Engine after CreateApp
//   - GetRoute to obtain one of the configured route groups
//   - Start to run the HTTP server and coordinate shutdown
//
// Complete example from a main package:
//
//	package main
//
//	import (
//		"log"
//
//		servergin "github.com/PointerByte/forge-go/config/server/gin"
//		"github.com/gin-gonic/gin"
//	)
//
//	func main() {
//		srv, err := servergin.CreateApp()
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		api := servergin.GetRoute("/api/v1")
//		if api == nil {
//			log.Fatal("route group /api/v1 is not configured in server.gin.groups")
//		}
//
//		api.GET("/hello", func(c *gin.Context) {
//			c.JSON(200, gin.H{
//				"message": "ok",
//			})
//		})
//
//		servergin.Start(srv)
//	}
//
// In that example, `/api/v1` must exist in the `server.gin.groups` configuration.
// Once CreateApp succeeds, the package will also register `/health` under each
// configured route group.
package gin
