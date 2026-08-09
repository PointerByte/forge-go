// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
)

func healthGin() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"aplicacion": viper.GetString("app.name"),
			"appVersion": viper.GetString("app.version"),
		})
	}

}

func notFound() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"message": "Path not found",
		})
	}
}

func noMethod() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{
			"message": "Method not allowed",
		})
	}
}
