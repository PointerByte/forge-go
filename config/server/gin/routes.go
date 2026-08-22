// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gin

import (
	"github.com/gin-gonic/gin"
)

var globalRoute map[string]*gin.RouterGroup

func setRoute(route map[string]*gin.RouterGroup) {
	globalRoute = route
}

// GetRoute returns the Gin route group registered for the provided key.
//
// The key must match one of the configured values from `server.gin.groups`.
func GetRoute(key string /*args ...any*/) *gin.RouterGroup {
	return globalRoute[key]
}
