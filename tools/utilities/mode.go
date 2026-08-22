// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package utilities

import (
	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

// SetModeTest configures shared packages for test execution.
//
// It enables logger test mode, switches Gin to test mode, and sets Viper
// defaults that disable behaviors not needed during tests.
func SetModeTest() {
	builder.EnableModeTest()
	gin.SetMode(gin.TestMode)
	viper.SetDefault("server.modeTest", true)
}
