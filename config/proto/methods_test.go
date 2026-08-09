// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package proto

import (
	"context"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	gproto "google.golang.org/protobuf/proto"
)

type mockClientConn struct {
	method string
	req    any
	opts   []grpc.CallOption
	err    error
	reply  *HelloReply
	stream grpc.ClientStream
}

func (m *mockClientConn) Invoke(_ context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	m.method = method
	m.req = args
	m.opts = opts
	if m.err != nil {
		return m.err
	}
	if out, ok := reply.(*HelloReply); ok && m.reply != nil {
		gproto.Reset(out)
		gproto.Merge(out, m.reply)
	}
	return nil
}

func (m *mockClientConn) NewStream(_ context.Context, _ *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	m.method = method
	m.opts = opts
	if m.err != nil {
		return nil, m.err
	}
	return m.stream, nil
}

type mockRegistrar struct {
	desc *grpc.ServiceDesc
	srv  any
}

func (m *mockRegistrar) RegisterService(desc *grpc.ServiceDesc, srv any) {
	m.desc = desc
	m.srv = srv
}

type testGreeterServer struct {
	UnimplementedGreeterServer
}

func (s testGreeterServer) SayHello(_ context.Context, req *HelloRequest) (*HelloReply, error) {
	return &HelloReply{Message: "hello " + req.GetName()}, nil
}

func (s testGreeterServer) CreateChat(stream grpc.ClientStreamingServer[ChatMessage, ChatSummary]) error {
	count := int32(0)
	last := ""
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&ChatSummary{
				ChatId:        "chat-1",
				TotalMessages: count,
				LastMessage:   last,
			})
		}
		if err != nil {
			return err
		}
		count++
		last = msg.GetMessage()
	}
}

func (s testGreeterServer) StreamAlerts(stream grpc.BidiStreamingServer[AlertMessage, AlertMessage]) error {
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := stream.Send(&AlertMessage{
			AlertId: msg.GetAlertId(),
			Source:  "server",
			Level:   msg.GetLevel(),
			Message: "ack: " + msg.GetMessage(),
		}); err != nil {
			return err
		}
	}
}

type mockClientStream struct {
	ctx          context.Context
	sent         []any
	recv         []any
	recvErr      error
	closeSendErr error
}

func (m *mockClientStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (m *mockClientStream) Trailer() metadata.MD         { return metadata.MD{} }
func (m *mockClientStream) CloseSend() error             { return m.closeSendErr }
func (m *mockClientStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}
func (m *mockClientStream) SendMsg(msg any) error {
	m.sent = append(m.sent, msg)
	return nil
}
func (m *mockClientStream) RecvMsg(msg any) error {
	if len(m.recv) == 0 {
		if m.recvErr != nil {
			return m.recvErr
		}
		return io.EOF
	}
	next := m.recv[0]
	m.recv = m.recv[1:]
	switch dst := msg.(type) {
	case *ChatSummary:
		gproto.Reset(dst)
		gproto.Merge(dst, next.(*ChatSummary))
	case *AlertMessage:
		gproto.Reset(dst)
		gproto.Merge(dst, next.(*AlertMessage))
	default:
		return errors.New("unexpected recv message type")
	}
	return nil
}

type mockServerStream struct {
	ctx        context.Context
	recv       []any
	recvErr    error
	sent       []any
	sendErr    error
	header     metadata.MD
	trailer    metadata.MD
	sendHeader metadata.MD
}

func (m *mockServerStream) SetHeader(md metadata.MD) error {
	m.header = md
	return nil
}
func (m *mockServerStream) SendHeader(md metadata.MD) error {
	m.sendHeader = md
	return nil
}
func (m *mockServerStream) SetTrailer(md metadata.MD) { m.trailer = md }
func (m *mockServerStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}
func (m *mockServerStream) SendMsg(msg any) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, msg)
	return nil
}
func (m *mockServerStream) RecvMsg(msg any) error {
	if len(m.recv) == 0 {
		if m.recvErr != nil {
			return m.recvErr
		}
		return io.EOF
	}
	next := m.recv[0]
	m.recv = m.recv[1:]
	switch dst := msg.(type) {
	case *ChatMessage:
		gproto.Reset(dst)
		gproto.Merge(dst, next.(*ChatMessage))
	case *AlertMessage:
		gproto.Reset(dst)
		gproto.Merge(dst, next.(*AlertMessage))
	default:
		return errors.New("unexpected recv message type")
	}
	return nil
}

func TestMessageMethods(t *testing.T) {
	req := &HelloRequest{Name: "Manuel"}
	if req.GetName() != "Manuel" || req.String() == "" {
		t.Fatalf("HelloRequest = %#v", req)
	}
	if got := req.ProtoReflect().Descriptor().Name(); string(got) != "HelloRequest" {
		t.Fatalf("HelloRequest descriptor = %q", got)
	}
	if desc, idx := req.Descriptor(); len(desc) == 0 || len(idx) != 1 || idx[0] != 0 {
		t.Fatalf("HelloRequest Descriptor() = len:%d idx:%v", len(desc), idx)
	}
	req.Reset()
	if req.GetName() != "" {
		t.Fatalf("HelloRequest after Reset() = %#v", req)
	}

	reply := &HelloReply{Message: "ok"}
	if reply.GetMessage() != "ok" || reply.String() == "" {
		t.Fatalf("HelloReply = %#v", reply)
	}
	if got := reply.ProtoReflect().Descriptor().Name(); string(got) != "HelloReply" {
		t.Fatalf("HelloReply descriptor = %q", got)
	}
	if desc, idx := reply.Descriptor(); len(desc) == 0 || len(idx) != 1 || idx[0] != 1 {
		t.Fatalf("HelloReply Descriptor() = len:%d idx:%v", len(desc), idx)
	}
	reply.Reset()
	if reply.GetMessage() != "" {
		t.Fatalf("HelloReply after Reset() = %#v", reply)
	}

	chat := &ChatMessage{User: "manuel", Message: "hola", SentAtUnix: 123}
	if chat.GetUser() != "manuel" || chat.GetMessage() != "hola" || chat.GetSentAtUnix() != 123 || chat.String() == "" {
		t.Fatalf("ChatMessage = %#v", chat)
	}
	if got := chat.ProtoReflect().Descriptor().Name(); string(got) != "ChatMessage" {
		t.Fatalf("ChatMessage descriptor = %q", got)
	}
	if desc, idx := chat.Descriptor(); len(desc) == 0 || len(idx) != 1 || idx[0] != 2 {
		t.Fatalf("ChatMessage Descriptor() = len:%d idx:%v", len(desc), idx)
	}
	chat.Reset()
	if chat.GetUser() != "" || chat.GetMessage() != "" || chat.GetSentAtUnix() != 0 {
		t.Fatalf("ChatMessage after Reset() = %#v", chat)
	}

	summary := &ChatSummary{ChatId: "chat-1", TotalMessages: 2, LastMessage: "adios"}
	if summary.GetChatId() != "chat-1" || summary.GetTotalMessages() != 2 || summary.GetLastMessage() != "adios" || summary.String() == "" {
		t.Fatalf("ChatSummary = %#v", summary)
	}
	if got := summary.ProtoReflect().Descriptor().Name(); string(got) != "ChatSummary" {
		t.Fatalf("ChatSummary descriptor = %q", got)
	}
	if desc, idx := summary.Descriptor(); len(desc) == 0 || len(idx) != 1 || idx[0] != 3 {
		t.Fatalf("ChatSummary Descriptor() = len:%d idx:%v", len(desc), idx)
	}
	summary.Reset()
	if summary.GetChatId() != "" || summary.GetTotalMessages() != 0 || summary.GetLastMessage() != "" {
		t.Fatalf("ChatSummary after Reset() = %#v", summary)
	}

	alert := &AlertMessage{AlertId: "a1", Source: "sensor", Level: "high", Message: "heat", CreatedAtUnix: 456}
	if alert.GetAlertId() != "a1" || alert.GetSource() != "sensor" || alert.GetLevel() != "high" || alert.GetMessage() != "heat" || alert.GetCreatedAtUnix() != 456 || alert.String() == "" {
		t.Fatalf("AlertMessage = %#v", alert)
	}
	if got := alert.ProtoReflect().Descriptor().Name(); string(got) != "AlertMessage" {
		t.Fatalf("AlertMessage descriptor = %q", got)
	}
	if desc, idx := alert.Descriptor(); len(desc) == 0 || len(idx) != 1 || idx[0] != 4 {
		t.Fatalf("AlertMessage Descriptor() = len:%d idx:%v", len(desc), idx)
	}
	alert.Reset()
	if alert.GetAlertId() != "" || alert.GetSource() != "" || alert.GetLevel() != "" || alert.GetMessage() != "" || alert.GetCreatedAtUnix() != 0 {
		t.Fatalf("AlertMessage after Reset() = %#v", alert)
	}
}

func TestNilMessageBranchesAndFileInit(t *testing.T) {
	var req *HelloRequest
	if req.GetName() != "" || string(req.ProtoReflect().Descriptor().Name()) != "HelloRequest" {
		t.Fatalf("nil HelloRequest = %#v", req)
	}

	var reply *HelloReply
	if reply.GetMessage() != "" || string(reply.ProtoReflect().Descriptor().Name()) != "HelloReply" {
		t.Fatalf("nil HelloReply = %#v", reply)
	}

	var chat *ChatMessage
	if chat.GetUser() != "" || chat.GetMessage() != "" || chat.GetSentAtUnix() != 0 || string(chat.ProtoReflect().Descriptor().Name()) != "ChatMessage" {
		t.Fatalf("nil ChatMessage = %#v", chat)
	}

	var summary *ChatSummary
	if summary.GetChatId() != "" || summary.GetTotalMessages() != 0 || summary.GetLastMessage() != "" || string(summary.ProtoReflect().Descriptor().Name()) != "ChatSummary" {
		t.Fatalf("nil ChatSummary = %#v", summary)
	}

	var alert *AlertMessage
	if alert.GetAlertId() != "" || alert.GetSource() != "" || alert.GetLevel() != "" || alert.GetMessage() != "" || alert.GetCreatedAtUnix() != 0 || string(alert.ProtoReflect().Descriptor().Name()) != "AlertMessage" {
		t.Fatalf("nil AlertMessage = %#v", alert)
	}

	first := file_proto_methods_proto_rawDescGZIP()
	second := file_proto_methods_proto_rawDescGZIP()
	if len(first) == 0 || len(second) == 0 || string(first) != string(second) {
		t.Fatal("raw descriptor gzip should be stable and non-empty")
	}

	file_proto_methods_proto_init()
	if File_proto_methods_proto == nil {
		t.Fatal("File_proto_methods_proto should be initialized")
	}
}

func TestGreeterClientSayHello(t *testing.T) {
	cc := &mockClientConn{reply: &HelloReply{Message: "hello Manuel"}}
	client := NewGreeterClient(cc)

	resp, err := client.SayHello(context.Background(), &HelloRequest{Name: "Manuel"})
	if err != nil {
		t.Fatalf("SayHello() error = %v", err)
	}
	if cc.method != Greeter_SayHello_FullMethodName || len(cc.opts) != 1 || resp.GetMessage() != "hello Manuel" {
		t.Fatalf("SayHello() method=%q opts=%d resp=%#v", cc.method, len(cc.opts), resp)
	}
}

func TestGreeterClientSayHelloError(t *testing.T) {
	expectedErr := errors.New("invoke failed")
	cc := &mockClientConn{err: expectedErr}
	client := NewGreeterClient(cc)

	resp, err := client.SayHello(context.Background(), &HelloRequest{Name: "Manuel"})
	if !errors.Is(err, expectedErr) || resp != nil {
		t.Fatalf("SayHello() err=%v resp=%#v", err, resp)
	}
}

func TestGreeterClientCreateChat(t *testing.T) {
	stream := &mockClientStream{recv: []any{&ChatSummary{ChatId: "chat-1", TotalMessages: 1, LastMessage: "hola"}}}
	cc := &mockClientConn{stream: stream}
	client := NewGreeterClient(cc)

	chat, err := client.CreateChat(context.Background())
	if err != nil {
		t.Fatalf("CreateChat() error = %v", err)
	}
	if cc.method != Greeter_CreateChat_FullMethodName || len(cc.opts) != 1 {
		t.Fatalf("CreateChat() method=%q opts=%d", cc.method, len(cc.opts))
	}
	if err := chat.Send(&ChatMessage{User: "manuel", Message: "hola"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	resp, err := chat.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv() error = %v", err)
	}
	if len(stream.sent) != 1 || resp.GetChatId() != "chat-1" || resp.GetLastMessage() != "hola" {
		t.Fatalf("CreateChat() sent=%d resp=%#v", len(stream.sent), resp)
	}
}

func TestGreeterClientCreateChatError(t *testing.T) {
	expectedErr := errors.New("new stream failed")
	cc := &mockClientConn{err: expectedErr}
	client := NewGreeterClient(cc)

	stream, err := client.CreateChat(context.Background())
	if !errors.Is(err, expectedErr) || stream != nil {
		t.Fatalf("CreateChat() err=%v stream=%#v", err, stream)
	}
}

func TestGreeterClientStreamAlerts(t *testing.T) {
	stream := &mockClientStream{recv: []any{&AlertMessage{AlertId: "a1", Source: "server", Level: "high", Message: "ack: heat"}}}
	cc := &mockClientConn{stream: stream}
	client := NewGreeterClient(cc)

	alerts, err := client.StreamAlerts(context.Background())
	if err != nil {
		t.Fatalf("StreamAlerts() error = %v", err)
	}
	if cc.method != Greeter_StreamAlerts_FullMethodName || len(cc.opts) != 1 {
		t.Fatalf("StreamAlerts() method=%q opts=%d", cc.method, len(cc.opts))
	}
	if err := alerts.Send(&AlertMessage{AlertId: "a1", Source: "sensor", Level: "high", Message: "heat"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	resp, err := alerts.Recv()
	if err != nil {
		t.Fatalf("Recv() error = %v", err)
	}
	if resp.GetMessage() != "ack: heat" {
		t.Fatalf("Recv() response = %#v", resp)
	}
}

func TestGreeterClientStreamAlertsError(t *testing.T) {
	expectedErr := errors.New("new stream failed")
	cc := &mockClientConn{err: expectedErr}
	client := NewGreeterClient(cc)

	stream, err := client.StreamAlerts(context.Background())
	if !errors.Is(err, expectedErr) || stream != nil {
		t.Fatalf("StreamAlerts() err=%v stream=%#v", err, stream)
	}
}

func TestUnimplementedGreeterServer(t *testing.T) {
	srv := UnimplementedGreeterServer{}

	resp, err := srv.SayHello(context.Background(), &HelloRequest{Name: "Manuel"})
	if resp != nil || status.Code(err) != codes.Unimplemented {
		t.Fatalf("SayHello() resp=%#v err=%v", resp, err)
	}
	if err := srv.CreateChat(nil); status.Code(err) != codes.Unimplemented {
		t.Fatalf("CreateChat() err=%v", err)
	}
	if err := srv.StreamAlerts(nil); status.Code(err) != codes.Unimplemented {
		t.Fatalf("StreamAlerts() err=%v", err)
	}

	srv.mustEmbedUnimplementedGreeterServer()
	srv.testEmbeddedByValue()
}

func TestRegisterGreeterServer(t *testing.T) {
	registrar := &mockRegistrar{}
	srv := testGreeterServer{}

	RegisterGreeterServer(registrar, srv)

	if registrar.desc == nil || registrar.desc.ServiceName != "helloworld.Greeter" || registrar.desc.Metadata != "proto/methods.proto" {
		t.Fatalf("RegisterService() desc=%#v", registrar.desc)
	}
	if len(registrar.desc.Methods) != 1 || registrar.desc.Methods[0].MethodName != "SayHello" {
		t.Fatalf("Methods = %#v", registrar.desc.Methods)
	}
	if len(registrar.desc.Streams) != 2 {
		t.Fatalf("Streams = %#v", registrar.desc.Streams)
	}
	if registrar.desc.Streams[0].StreamName != "CreateChat" || !registrar.desc.Streams[0].ClientStreams || registrar.desc.Streams[0].ServerStreams {
		t.Fatalf("CreateChat stream = %#v", registrar.desc.Streams[0])
	}
	if registrar.desc.Streams[1].StreamName != "StreamAlerts" || !registrar.desc.Streams[1].ClientStreams || !registrar.desc.Streams[1].ServerStreams {
		t.Fatalf("StreamAlerts stream = %#v", registrar.desc.Streams[1])
	}
	if registrar.srv != srv {
		t.Fatalf("registered server = %#v", registrar.srv)
	}
}

func TestGreeterSayHelloHandler(t *testing.T) {
	resp, err := _Greeter_SayHello_Handler(
		testGreeterServer{},
		context.Background(),
		func(v interface{}) error {
			req, ok := v.(*HelloRequest)
			if !ok {
				t.Fatalf("decoder received %T", v)
			}
			req.Name = "Manuel"
			return nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("_Greeter_SayHello_Handler() error = %v", err)
	}
	got, ok := resp.(*HelloReply)
	if !ok || got.GetMessage() != "hello Manuel" {
		t.Fatalf("_Greeter_SayHello_Handler() response = %#v", resp)
	}
}

func TestGreeterSayHelloHandlerWithInterceptor(t *testing.T) {
	srv := testGreeterServer{}
	intercepted := false

	resp, err := _Greeter_SayHello_Handler(
		srv,
		context.Background(),
		func(v interface{}) error {
			v.(*HelloRequest).Name = "Ana"
			return nil
		},
		func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			intercepted = true
			if info.FullMethod != Greeter_SayHello_FullMethodName || info.Server != srv {
				t.Fatalf("info = %#v", info)
			}
			return handler(ctx, req)
		},
	)
	if err != nil || !intercepted {
		t.Fatalf("_Greeter_SayHello_Handler() err=%v intercepted=%v", err, intercepted)
	}
	if got := resp.(*HelloReply); got.GetMessage() != "hello Ana" {
		t.Fatalf("response = %#v", got)
	}
}

func TestGreeterSayHelloHandlerDecodeError(t *testing.T) {
	expectedErr := errors.New("decode failed")

	resp, err := _Greeter_SayHello_Handler(
		testGreeterServer{},
		context.Background(),
		func(interface{}) error { return expectedErr },
		nil,
	)
	if !errors.Is(err, expectedErr) || resp != nil {
		t.Fatalf("_Greeter_SayHello_Handler() err=%v resp=%#v", err, resp)
	}
}

func TestGreeterCreateChatHandler(t *testing.T) {
	serverStream := &mockServerStream{
		recv: []any{
			&ChatMessage{User: "manuel", Message: "hola"},
			&ChatMessage{User: "manuel", Message: "adios"},
		},
	}

	err := _Greeter_CreateChat_Handler(testGreeterServer{}, serverStream)
	if err != nil {
		t.Fatalf("_Greeter_CreateChat_Handler() error = %v", err)
	}
	if len(serverStream.sent) != 1 {
		t.Fatalf("sent responses = %d", len(serverStream.sent))
	}
	resp := serverStream.sent[0].(*ChatSummary)
	if resp.GetChatId() != "chat-1" || resp.GetTotalMessages() != 2 || resp.GetLastMessage() != "adios" {
		t.Fatalf("_Greeter_CreateChat_Handler() response = %#v", resp)
	}
}

func TestGreeterCreateChatHandlerError(t *testing.T) {
	expectedErr := errors.New("recv failed")
	err := _Greeter_CreateChat_Handler(testGreeterServer{}, &mockServerStream{recvErr: expectedErr})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("_Greeter_CreateChat_Handler() err=%v", err)
	}
}

func TestGreeterStreamAlertsHandler(t *testing.T) {
	serverStream := &mockServerStream{
		recv: []any{
			&AlertMessage{AlertId: "a1", Source: "sensor", Level: "high", Message: "heat"},
		},
	}

	err := _Greeter_StreamAlerts_Handler(testGreeterServer{}, serverStream)
	if err != nil {
		t.Fatalf("_Greeter_StreamAlerts_Handler() error = %v", err)
	}
	if len(serverStream.sent) != 1 {
		t.Fatalf("sent responses = %d", len(serverStream.sent))
	}
	resp := serverStream.sent[0].(*AlertMessage)
	if resp.GetAlertId() != "a1" || resp.GetSource() != "server" || resp.GetMessage() != "ack: heat" {
		t.Fatalf("_Greeter_StreamAlerts_Handler() response = %#v", resp)
	}
}

func TestGreeterStreamAlertsHandlerError(t *testing.T) {
	expectedErr := errors.New("recv failed")
	err := _Greeter_StreamAlerts_Handler(testGreeterServer{}, &mockServerStream{recvErr: expectedErr})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("_Greeter_StreamAlerts_Handler() err=%v", err)
	}
}
