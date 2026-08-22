// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/formatter"
	httpmiddlewares "github.com/PointerByte/forge-go/logger/middlewares/http"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

var readInConfig = viper.ReadInConfig

func loadEnv() error {
	// Load application.json
	viper.SetConfigName("application")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")
	if err := readInConfig(); err != nil {
		return err
	}
	return nil
}

var initLogger = builder.InitLogger

func loadConfig(ctx context.Context) (*sdklog.LoggerProvider, error) {
	if err := loadEnv(); err != nil {
		return nil, err
	}
	viper.SetDefault("server.gin.readHeaderTimeout", "5s")
	return initLogger(ctx, filepath.Join(".", "logs"))
}

var quit chan os.Signal

func init() {
	quit = make(chan os.Signal, 1)
	gin.SetMode(gin.ReleaseMode)
}

func subprocces(wg *sync.WaitGroup, ctxLogger *builder.Context) {
	defer wg.Done()
	process := formatter.Process{
		System:  "subprocess",
		Process: "execute subprocess",
	}
	ctxLogger.TraceInit(&process)
	defer ctxLogger.TraceEnd(&process)
	time.Sleep(time.Second)
}

func endpointExample() func(c *gin.Context) {
	return func(c *gin.Context) {
		ctxLogger := builder.New(c.Request.Context())

		var wg sync.WaitGroup
		wg.Add(2)
		go subprocces(&wg, ctxLogger)
		go subprocces(&wg, ctxLogger)
		wg.Wait()

		httpmiddlewares.PrintInfo(c, "example execute")
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	}
}

func main() {
	ctx := context.Background()
	lp, err := loadConfig(ctx)
	if err != nil {
		panic(err)
	}
	ctxLogger := builder.New(ctx)

	engine := gin.New()
	engine.Use(
		gin.Recovery(),
		httpmiddlewares.InitLogger(),
		httpmiddlewares.LoggerWithConfig(),
		httpmiddlewares.CaptureBody(),
	)

	groups := viper.GetStringSlice("server.groups")
	for _, g := range groups {
		route := engine.Group(g)
		route.GET("/example", endpointExample())
	}

	srv := &http.Server{
		Addr:              viper.GetString("server.gin.port"),
		Handler:           engine,
		ReadHeaderTimeout: viper.GetDuration("server.gin.readHeaderTimeout"),
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	ctxLogger.Info("Server started successfully")
	shutdown(srv, lp.Shutdown)
}

type handlerShutdown func(ctx context.Context) error

func shutdown(srv *http.Server, shutdownOtel handlerShutdown) {
	// Graceful shutdown
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	ctx := context.Background()
	ctxLogger := builder.New(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := shutdownOtel(ctx); err != nil {
		ctxLogger.Error(fmt.Errorf("failed to shutdown logger provider: %v", err))
		return
	}

	ctxLogger.Info("Signal received, turning off...")
	if err := srv.Shutdown(ctx); err != nil {
		ctxLogger.Error(fmt.Errorf("shutdown force: %v", err))
		return
	}
	ctxLogger.Info("Server stopped successfully")
}
