// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package grpc provides server-side gRPC bootstrap helpers for the config
// module.
//
// It wraps grpc.Server creation so services can be started with shared
// configuration loading, tracing, TLS, mTLS, and graceful lifecycle handling.
//
// The package is transport-oriented: it does not depend on a concrete
// generated service. Any service generated in the proto package can be
// registered through Register.
//
// NewIConfig loads configuration through utilities.LoadEnv using the current
// working directory, then initializes the logger and OpenTelemetry providers.
// The loader resolves resources/application.yml, resources/application.yaml, or
// resources/application.json, so values such as server.grpc.port, rate limits,
// TLS, and mTLS settings can be sourced from the resources directory plus
// environment overrides.
//
// Basic usage:
//
//	package main
//
//	import (
//		"context"
//		"log"
//
//		pb "github.com/PointerByte/forge-go/config/proto"
//		servergrpc "github.com/PointerByte/forge-go/config/server/grpc"
//		grpcstd "google.golang.org/grpc"
//	)
//
//	type greeterServer struct {
//		pb.UnimplementedGreeterServer
//	}
//
//	func (s greeterServer) SayHello(_ context.Context, req *pb.HelloRequest) (*pb.HelloReply, error) {
//		return &pb.HelloReply{Message: "hello " + req.GetName()}, nil
//	}
//
//	func (s greeterServer) CreateChat(stream pb.Greeter_CreateChatServer) error {
//		return nil
//	}
//
//	func (s greeterServer) StreamAlerts(stream pb.Greeter_StreamAlertsServer) error {
//		return nil
//	}
//
//	func main() {
//		srv := servergrpc.NewIConfig(nil, nil)
//		srv.SetAddress(":50051")
//
//		err := srv.Register(func(r grpcstd.ServiceRegistrar) {
//			pb.RegisterGreeterServer(r, greeterServer{})
//		})
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		log.Fatal(srv.Serve())
//	}
//
// If you already have your own listener, inject it with SetListener instead of
// SetAddress.
//
// JWT can be attached explicitly with the security gRPC interceptors:
//
//	import (
//		servergrpc "github.com/PointerByte/forge-go/config/server/grpc"
//		"github.com/PointerByte/forge-go/security/middlewares"
//	)
//
//	srv := servergrpc.NewIConfig(nil, nil,
//		servergrpc.WithUnaryInterceptors(middlewares.RequireJWTUnaryServerInterceptor()),
//		servergrpc.WithStreamInterceptors(middlewares.RequireJWTStreamServerInterceptor()),
//	)
package grpc
