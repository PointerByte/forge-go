// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

//go:generate mockgen -source=IClient.go -destination=./mocksIClient_test.go -package=grpc

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/PointerByte/forge-go/logger/builder"
	"github.com/PointerByte/forge-go/logger/common"
	"github.com/PointerByte/forge-go/logger/formatter"
	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

var (
	newGRPCClient     = grpc.NewClient
	loadX509KeyPairFn = tls.LoadX509KeyPair
	readFileFn        = os.ReadFile
	newCertPoolFn     = x509.NewCertPool
	clientTLSConfig   *tls.Config
)

// BuildClientFunc creates a generated proto client from a grpc connection.
// Example:
//
//	greeter, err := client_gRPC.BuildClient(cli, proto.NewGreeterClient)
type BuildClientFunc[T any] func(grpc.ClientConnInterface) T

// IClient defines the transport operations required to configure and manage a gRPC client connection.
//
// It is protocol-agnostic: any client generated in the proto package can be created from the stored connection.
type IClient interface {
	SetAddress(address string)
	SetConn(conn *grpc.ClientConn)
	SetContext(ctx context.Context)
	SetDialOptions(opts ...grpc.DialOption)
	Connect() error
	Close() error
	GetConn() *grpc.ClientConn
}

type Client struct {
	conn        *grpc.ClientConn
	address     string
	ctx         context.Context
	dialOptions []grpc.DialOption
	mux         sync.RWMutex
}

type handlerTrace func(process *formatter.Process)

type tracedClientStream struct {
	grpc.ClientStream
	service   *formatter.Process
	traceEnd  handlerTrace
	desc      *grpc.StreamDesc
	target    string
	method    string
	ctx       context.Context
	requests  []any
	responses []any
	once      sync.Once
}

// SetTLSConfig sets the TLS configuration that Connect should use when it has
// to create a new grpc.ClientConn and no explicit transport credentials were
// provided through SetDialOptions.
func SetTLSConfig(config *tls.Config) {
	clientTLSConfig = config
}

// NewIClient creates a new gRPC client wrapper.
//
// If conn is nil, Connect will create one from the configured address.
// If no dial options are set, the package resolves TLS/mTLS from configuration
// and falls back to insecure transport credentials when TLS is disabled.
func NewIClient(conn *grpc.ClientConn) IClient {
	return &Client{
		conn: conn,
	}
}

func (c *Client) SetAddress(address string) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.address = address
}

func (c *Client) SetConn(conn *grpc.ClientConn) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.conn = conn
}

func (c *Client) SetContext(ctx context.Context) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.ctx = ctx
}

func (c *Client) SetDialOptions(opts ...grpc.DialOption) {
	c.mux.Lock()
	defer c.mux.Unlock()
	c.dialOptions = append([]grpc.DialOption(nil), opts...)
}

func (c *Client) Connect() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.conn != nil {
		return nil
	}
	if c.address == "" {
		return fmt.Errorf("address is required")
	}

	opts := append([]grpc.DialOption(nil), c.dialOptions...)
	opts = append(opts, defaultTraceDialOptions()...)
	transportOptions, err := transportDialOptionsFor(c.dialOptions)
	if err != nil {
		return err
	}
	opts = append(opts, transportOptions...)

	conn, err := newGRPCClient(c.address, opts...)
	if err != nil {
		return fmt.Errorf("problem creating grpc client: %w", err)
	}
	c.conn = conn
	return nil
}

func (c *Client) Close() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) GetConn() *grpc.ClientConn {
	c.mux.RLock()
	defer c.mux.RUnlock()
	return c.conn
}

// BuildClient creates any generated proto client from the current connection.
func BuildClient[T any](client IClient, build BuildClientFunc[T]) (T, error) {
	var zero T

	if client == nil {
		return zero, fmt.Errorf("client is required")
	}
	if build == nil {
		return zero, fmt.Errorf("build function is required")
	}
	if err := client.Connect(); err != nil {
		return zero, err
	}

	conn := client.GetConn()
	if conn == nil {
		return zero, fmt.Errorf("grpc connection is required")
	}

	return build(conn), nil
}

func (s *tracedClientStream) SendMsg(m any) error {
	err := s.ClientStream.SendMsg(m)
	if err == nil && !s.service.DisableBody {
		s.requests = append(s.requests, m)
	}
	if hasError(err) {
		s.finish(err)
	}
	return err
}

func (s *tracedClientStream) RecvMsg(m any) error {
	err := s.ClientStream.RecvMsg(m)
	if err == nil && !s.service.DisableBody {
		s.responses = append(s.responses, m)
	}
	switch {
	case errorsIsEOF(err):
		s.finish(nil)
	case hasError(err):
		s.finish(err)
	case !s.desc.ServerStreams:
		s.finish(nil)
	}
	return err
}

func (s *tracedClientStream) CloseSend() error {
	err := s.ClientStream.CloseSend()
	if hasError(err) {
		s.finish(err)
	}
	return err
}

func (s *tracedClientStream) finish(err error) {
	s.once.Do(func() {
		_ = buildService(s.service, collapseBodies(s.requests), collapseBodies(s.responses), s.method, s.target, s.ctx, err)
		s.traceEnd(s.service)
	})
}

func traceClient(ctx context.Context, system, process string, disableTraceBody bool) (*formatter.Process, handlerTrace) {
	ctxLogger := builder.New(ctx)
	service := &formatter.Process{
		System:      system,
		Process:     process,
		Status:      formatter.SUCCESS,
		DisableBody: disableTraceBody,
	}
	ctxLogger.TraceInit(service)
	return service, ctxLogger.TraceEnd
}

func contextWithTraceIDMetadata(ctx context.Context) context.Context {
	traceID := builder.New(ctx).TraceID()
	if traceID == "" {
		return ctx
	}

	key := strings.ToLower(common.TraceIDHeader)
	if md, ok := metadata.FromOutgoingContext(ctx); ok && len(md.Get(key)) > 0 {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, key, traceID)
}

func buildService(service *formatter.Process, reqBody, object any, method, target string, ctx context.Context, err error) error {
	if service == nil {
		return nil
	}

	service.Server = target
	service.Protocol = "gRPC"
	service.Method = grpcMethodName(method)
	service.Path = method

	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		headers := metadataToHTTPHeader(md)
		service.Headers = &headers
	}

	if hasError(err) {
		service.SetStatus(formatter.ERROR)
		service.Code = int64(status.Code(err))
		if !service.DisableBody {
			service.SetRequest(reqBody)
			service.SetResponse(err.Error())
		}
		return nil
	}

	service.SetStatus(formatter.SUCCESS)
	service.Code = int64(codes.OK)
	if !service.DisableBody {
		service.SetRequest(reqBody)
		service.SetResponse(object)
	}
	return nil
}

func defaultTraceDialOptions() []grpc.DialOption {
	return []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(traceUnaryClientInterceptor()),
		grpc.WithChainStreamInterceptor(traceStreamClientInterceptor()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
}

func transportDialOptionsFor(existing []grpc.DialOption) ([]grpc.DialOption, error) {
	config, err := resolveTLSConfig()
	if err != nil {
		return nil, err
	}
	if config != nil {
		return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(config))}, nil
	}
	if len(existing) == 0 {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	return nil, nil
}

func resolveTLSConfig() (*tls.Config, error) {
	if clientTLSConfig != nil {
		return clientTLSConfig, nil
	}

	tlsEnabled := viper.GetBool("client.grpc.tls.enable")
	mtlsEnabled := viper.GetBool("client.grpc.mtls.enable")
	if !tlsEnabled && !mtlsEnabled {
		return nil, nil
	}

	config := &tls.Config{
		MinVersion:         parseTLSVersion(viper.GetString("client.grpc.tls.version")),
		ServerName:         strings.TrimSpace(viper.GetString("client.grpc.tls.serverName")),
		InsecureSkipVerify: viper.GetBool("client.grpc.tls.insecureSkipVerify"), // #nosec G402 -- explicitly configured legacy test escape hatch.
	}

	if caFile := strings.TrimSpace(viper.GetString("client.grpc.tls.caFile")); caFile != "" {
		caPEM, err := readFileFn(caFile)
		if err != nil {
			return nil, fmt.Errorf("problem reading tls ca file: %w", err)
		}
		pool := newCertPoolFn()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("problem parsing tls ca file")
		}
		config.RootCAs = pool
	}

	if mtlsEnabled {
		certFile := strings.TrimSpace(viper.GetString("client.grpc.mtls.certFile"))
		keyFile := strings.TrimSpace(viper.GetString("client.grpc.mtls.keyFile"))
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("client.grpc.mtls.certFile and client.grpc.mtls.keyFile are required")
		}
		certificate, err := loadX509KeyPairFn(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("problem loading client mtls certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}

	return config, nil
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

func traceUnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = contextWithTraceIDMetadata(ctx)
		system, process := grpcServiceMethod(method)
		service, traceEnd := traceClient(ctx, system, process, false)
		defer traceEnd(service)

		err := invoker(ctx, method, req, reply, cc, opts...)
		_ = buildService(service, req, reply, method, cc.Target(), ctx, err)
		return err
	}
}

func traceStreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = contextWithTraceIDMetadata(ctx)
		system, process := grpcServiceMethod(method)
		service, traceEnd := traceClient(ctx, system, process, false)

		stream, err := streamer(ctx, desc, cc, method, opts...)
		if hasError(err) {
			_ = buildService(service, nil, nil, method, cc.Target(), ctx, err)
			traceEnd(service)
			return nil, err
		}

		return &tracedClientStream{
			ClientStream: stream,
			service:      service,
			traceEnd:     traceEnd,
			desc:         desc,
			target:       cc.Target(),
			method:       method,
			ctx:          ctx,
		}, nil
	}
}

func collapseBodies(items []any) any {
	switch len(items) {
	case 0:
		return nil
	case 1:
		return items[0]
	default:
		return items
	}
}

func metadataToHTTPHeader(md metadata.MD) http.Header {
	headers := make(http.Header, len(md))
	for key, values := range md {
		copyValues := make([]string, len(values))
		copy(copyValues, values)
		headers[textproto.CanonicalMIMEHeaderKey(key)] = copyValues
	}
	return headers
}

func grpcServiceMethod(fullMethod string) (string, string) {
	trimmed := strings.TrimPrefix(fullMethod, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) == 0 {
		return "", ""
	}
	if len(parts) == 1 {
		return parts[0], parts[0]
	}
	return parts[0], parts[1]
}

func grpcMethodName(fullMethod string) string {
	_, method := grpcServiceMethod(fullMethod)
	return method
}

func hasError(err error) bool {
	if err == nil {
		return false
	}
	value := reflect.ValueOf(err)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}

func errorsIsEOF(err error) bool {
	return err != nil && err == io.EOF
}
