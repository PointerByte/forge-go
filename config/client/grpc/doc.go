// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package grpc provides client-side gRPC bootstrap helpers for the config
// module.
//
// It wraps grpc.ClientConn setup so application code can create generated proto
// clients with consistent transport configuration, TLS or mTLS resolution, and
// outbound tracing.
//
// The package is transport-oriented: it does not depend on a concrete
// generated client. Any generated gRPC client can be created through
// BuildClient.
//
// When Connect creates the connection itself, it also attaches:
//   - TLS or mTLS transport credentials resolved from viper under client.grpc.*
//   - unary and stream interceptors that trace outbound requests through the logger package
//
// Supported configuration keys:
//   - client.grpc.tls.enable
//   - client.grpc.tls.caFile
//   - client.grpc.tls.serverName
//   - client.grpc.tls.version
//   - client.grpc.tls.insecureSkipVerify
//   - client.grpc.mtls.enable
//   - client.grpc.mtls.certFile
//   - client.grpc.mtls.keyFile
//
// You can also bypass viper-based transport resolution by calling SetTLSConfig
// with a prebuilt *tls.Config before Connect.
//
// Tracing stores metadata, target, method name, status code, request payload,
// and response payload in formatter.Service entries, mirroring the HTTP client
// instrumentation used elsewhere in the module.
//
// Basic usage:
//
//	package main
//
//	import (
//		"context"
//		"log"
//
//		clientgrpc "github.com/PointerByte/forge-go/config/client/grpc"
//		pb "github.com/PointerByte/forge-go/config/proto"
//		"google.golang.org/grpc/metadata"
//	)
//
//	func main() {
//		cli := clientgrpc.NewIClient(nil)
//		cli.SetAddress("localhost:50051")
//
//		greeter, err := clientgrpc.BuildClient(cli, pb.NewGreeterClient)
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		ctx := metadata.AppendToOutgoingContext(
//			context.Background(),
//			"authorization", "Bearer <JWT>",
//		)
//
//		resp, err := greeter.SayHello(ctx, &pb.HelloRequest{Name: "Manuel"})
//		if err != nil {
//			log.Fatal(err)
//		}
//
//		log.Println(resp.GetMessage())
//	}
//
// The same metadata pattern applies to streams: pass the outgoing metadata
// context when creating the generated client stream.
package grpc
