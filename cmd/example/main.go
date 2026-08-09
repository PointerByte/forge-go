// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package main provides practical runnable examples for bootstrapping GoForge
// servers from the config module.
//
// Gin example:
//
//	srv, err := serverGin.CreateApp()
//	if err != nil {
//		panic(err)
//	}
//
//	api := serverGin.GetRoute("/api/v1")
//	api.GET("/hello", func(c *gin.Context) {
//		c.JSON(200, gin.H{"message": "ok"})
//	})
//
//	serverGin.Start(srv)
//
// gRPC example:
//
//	srv := serverGRPC.NewIConfig(nil, nil)
//
//	if err := srv.Register(func(r grpc.ServiceRegistrar) {
//		pb.RegisterGreeterServer(r, greeterServer{})
//	}); err != nil {
//		panic(err)
//	}
//
//	if err := srv.Serve(); err != nil {
//		panic(err)
//	}
//
// To run the executable examples in this file:
//
//	GoForge_EXAMPLE_SERVER=gin go run ./cmd/example
//
// or:
//
//	GoForge_EXAMPLE_SERVER=grpc go run ./cmd/example
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	pb "github.com/PointerByte/forge-go/config/proto"
	serverGin "github.com/PointerByte/forge-go/config/server/gin"
	serverGRPC "github.com/PointerByte/forge-go/config/server/grpc"
	serverLogger "github.com/PointerByte/forge-go/logger/builder"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"
)

const (
	exampleModeEnv  = "GoForge_EXAMPLE_SERVER"
	exampleModeGin  = "gin"
	exampleModeGRPC = "grpc"
)

type exampleGreeterServer struct {
	pb.UnimplementedGreeterServer
}

var (
	runGinExampleFn  = runGinExample
	runGRPCExampleFn = runGRPCExample
	logFatalFn       = func(args ...any) { log.Fatal(args...) }
	logPrintfFn      = func(format string, args ...any) { log.Printf(format, args...) }
	createGinAppFn   = func() (*http.Server, error) { return serverGin.CreateApp() }
	getGinRouteFn    = serverGin.GetRoute
	startGinServerFn = serverGin.Start
	newGRPCServerFn  = func() serverGRPC.IConfig { return serverGRPC.NewIConfig(nil, nil) }
)

func main() {
	switch os.Getenv(exampleModeEnv) {
	case exampleModeGin:
		if err := runGinExampleFn(); err != nil {
			logFatalFn(err)
		}
	case exampleModeGRPC:
		if err := runGRPCExampleFn(); err != nil {
			logFatalFn(err)
		}
	default:
		logPrintfFn("Set %s=%s or %s=%s to run a practical example server.", exampleModeEnv, exampleModeGin, exampleModeEnv, exampleModeGRPC)
	}
}

func runGinExample() error {
	srv, err := createGinAppFn()
	if err != nil {
		return fmt.Errorf("problem creating gin example: %w", err)
	}

	api := getGinRouteFn("/api/v1")
	if api == nil {
		return fmt.Errorf("route group /api/v1 is not configured in resources/application.yml")
	}

	api.GET("/hello", func(c *gin.Context) {
		ctxLogger := serverLogger.New(c.Request.Context())
		ctxLogger.Info("gin example route hit")
		c.JSON(200, gin.H{
			"framework": "gin",
			"message":   "hello from GoForge HTTP server",
			"path":      c.FullPath(),
		})
	})

	startGinServerFn(srv)
	return nil
}

func runGRPCExample() error {
	srv := newGRPCServerFn()

	if err := srv.Register(func(r grpc.ServiceRegistrar) {
		pb.RegisterGreeterServer(r, exampleGreeterServer{})
	}); err != nil {
		return fmt.Errorf("problem registering grpc example service: %w", err)
	}
	return srv.Serve()
}

func (exampleGreeterServer) SayHello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
	serverLogger.New(ctx).Info("grpc example unary method hit")
	return &pb.HelloReply{
		Message: fmt.Sprintf("hello %s from GoForge gRPC", req.GetName()),
	}, nil
}

func (exampleGreeterServer) CreateChat(stream grpc.ClientStreamingServer[pb.ChatMessage, pb.ChatSummary]) error {
	var (
		total       int32
		lastMessage string
	)

	for {
		msg, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return stream.SendAndClose(&pb.ChatSummary{
				ChatId:        "example-chat",
				TotalMessages: total,
				LastMessage:   lastMessage,
			})
		case err != nil:
			return err
		default:
			total++
			lastMessage = msg.GetMessage()
		}
	}
}

func (exampleGreeterServer) StreamAlerts(stream grpc.BidiStreamingServer[pb.AlertMessage, pb.AlertMessage]) error {
	for {
		msg, err := stream.Recv()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return err
		default:
			if err := stream.Send(&pb.AlertMessage{
				AlertId:       msg.GetAlertId(),
				Source:        "GoForge-example",
				Level:         msg.GetLevel(),
				Message:       fmt.Sprintf("echo: %s", msg.GetMessage()),
				CreatedAtUnix: msg.GetCreatedAtUnix(),
			}); err != nil {
				return err
			}
		}
	}
}
