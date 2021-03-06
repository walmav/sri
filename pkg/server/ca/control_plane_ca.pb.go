// Code generated by protoc-gen-go. DO NOT EDIT.
// source: control_plane_ca.proto

/*
Package ca is a generated protocol buffer package.

It is generated from these files:
	control_plane_ca.proto

It has these top-level messages:
	SignCsrRequest
	SignCsrResponse
	GenerateCsrRequest
	GenerateCsrResponse
	FetchCertificateRequest
	FetchCertificateResponse
	LoadCertificateRequest
	LoadCertificateResponse
*/
package ca

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import sriplugin "github.com/spiffe/sri/pkg/common/plugin"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// ConfigureRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type ConfigureRequest sriplugin.ConfigureRequest

func (m *ConfigureRequest) Reset()         { (*sriplugin.ConfigureRequest)(m).Reset() }
func (m *ConfigureRequest) String() string { return (*sriplugin.ConfigureRequest)(m).String() }
func (*ConfigureRequest) ProtoMessage()    {}
func (m *ConfigureRequest) GetConfiguration() string {
	return (*sriplugin.ConfigureRequest)(m).GetConfiguration()
}

// ConfigureResponse from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type ConfigureResponse sriplugin.ConfigureResponse

func (m *ConfigureResponse) Reset()         { (*sriplugin.ConfigureResponse)(m).Reset() }
func (m *ConfigureResponse) String() string { return (*sriplugin.ConfigureResponse)(m).String() }
func (*ConfigureResponse) ProtoMessage()    {}
func (m *ConfigureResponse) GetErrorList() []string {
	return (*sriplugin.ConfigureResponse)(m).GetErrorList()
}

// GetPluginInfoRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type GetPluginInfoRequest sriplugin.GetPluginInfoRequest

func (m *GetPluginInfoRequest) Reset()         { (*sriplugin.GetPluginInfoRequest)(m).Reset() }
func (m *GetPluginInfoRequest) String() string { return (*sriplugin.GetPluginInfoRequest)(m).String() }
func (*GetPluginInfoRequest) ProtoMessage()    {}

// GetPluginInfoResponse from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type GetPluginInfoResponse sriplugin.GetPluginInfoResponse

func (m *GetPluginInfoResponse) Reset()         { (*sriplugin.GetPluginInfoResponse)(m).Reset() }
func (m *GetPluginInfoResponse) String() string { return (*sriplugin.GetPluginInfoResponse)(m).String() }
func (*GetPluginInfoResponse) ProtoMessage()    {}
func (m *GetPluginInfoResponse) GetName() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetName()
}
func (m *GetPluginInfoResponse) GetCategory() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetCategory()
}
func (m *GetPluginInfoResponse) GetType() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetType()
}
func (m *GetPluginInfoResponse) GetDescription() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetDescription()
}
func (m *GetPluginInfoResponse) GetDateCreated() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetDateCreated()
}
func (m *GetPluginInfoResponse) GetLocation() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetLocation()
}
func (m *GetPluginInfoResponse) GetVersion() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetVersion()
}
func (m *GetPluginInfoResponse) GetAuthor() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetAuthor()
}
func (m *GetPluginInfoResponse) GetCompany() string {
	return (*sriplugin.GetPluginInfoResponse)(m).GetCompany()
}

// PluginInfoRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type PluginInfoRequest sriplugin.PluginInfoRequest

func (m *PluginInfoRequest) Reset()         { (*sriplugin.PluginInfoRequest)(m).Reset() }
func (m *PluginInfoRequest) String() string { return (*sriplugin.PluginInfoRequest)(m).String() }
func (*PluginInfoRequest) ProtoMessage()    {}

// PluginInfoReply from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type PluginInfoReply sriplugin.PluginInfoReply

func (m *PluginInfoReply) Reset()         { (*sriplugin.PluginInfoReply)(m).Reset() }
func (m *PluginInfoReply) String() string { return (*sriplugin.PluginInfoReply)(m).String() }
func (*PluginInfoReply) ProtoMessage()    {}
func (m *PluginInfoReply) GetPluginInfo() []*GetPluginInfoResponse {
	o := (*sriplugin.PluginInfoReply)(m).GetPluginInfo()
	if o == nil {
		return nil
	}
	s := make([]*GetPluginInfoResponse, len(o))
	for i, x := range o {
		s[i] = (*GetPluginInfoResponse)(x)
	}
	return s
}

// StopRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type StopRequest sriplugin.StopRequest

func (m *StopRequest) Reset()         { (*sriplugin.StopRequest)(m).Reset() }
func (m *StopRequest) String() string { return (*sriplugin.StopRequest)(m).String() }
func (*StopRequest) ProtoMessage()    {}

// StopReply from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type StopReply sriplugin.StopReply

func (m *StopReply) Reset()         { (*sriplugin.StopReply)(m).Reset() }
func (m *StopReply) String() string { return (*sriplugin.StopReply)(m).String() }
func (*StopReply) ProtoMessage()    {}

// *Represents a request with a certificate signing request.
type SignCsrRequest struct {
	Csr []byte `protobuf:"bytes,1,opt,name=csr,proto3" json:"csr,omitempty"`
}

func (m *SignCsrRequest) Reset()                    { *m = SignCsrRequest{} }
func (m *SignCsrRequest) String() string            { return proto.CompactTextString(m) }
func (*SignCsrRequest) ProtoMessage()               {}
func (*SignCsrRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *SignCsrRequest) GetCsr() []byte {
	if m != nil {
		return m.Csr
	}
	return nil
}

// *Represents a response with a signed certificate.
type SignCsrResponse struct {
	SignedCertificate []byte `protobuf:"bytes,1,opt,name=signedCertificate,proto3" json:"signedCertificate,omitempty"`
}

func (m *SignCsrResponse) Reset()                    { *m = SignCsrResponse{} }
func (m *SignCsrResponse) String() string            { return proto.CompactTextString(m) }
func (*SignCsrResponse) ProtoMessage()               {}
func (*SignCsrResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *SignCsrResponse) GetSignedCertificate() []byte {
	if m != nil {
		return m.SignedCertificate
	}
	return nil
}

// *Represents an empty request.
type GenerateCsrRequest struct {
}

func (m *GenerateCsrRequest) Reset()                    { *m = GenerateCsrRequest{} }
func (m *GenerateCsrRequest) String() string            { return proto.CompactTextString(m) }
func (*GenerateCsrRequest) ProtoMessage()               {}
func (*GenerateCsrRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

// *Represents a response with a certificate signing request.
type GenerateCsrResponse struct {
	Csr []byte `protobuf:"bytes,1,opt,name=csr,proto3" json:"csr,omitempty"`
}

func (m *GenerateCsrResponse) Reset()                    { *m = GenerateCsrResponse{} }
func (m *GenerateCsrResponse) String() string            { return proto.CompactTextString(m) }
func (*GenerateCsrResponse) ProtoMessage()               {}
func (*GenerateCsrResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *GenerateCsrResponse) GetCsr() []byte {
	if m != nil {
		return m.Csr
	}
	return nil
}

// *Represents an empty request.
type FetchCertificateRequest struct {
}

func (m *FetchCertificateRequest) Reset()                    { *m = FetchCertificateRequest{} }
func (m *FetchCertificateRequest) String() string            { return proto.CompactTextString(m) }
func (*FetchCertificateRequest) ProtoMessage()               {}
func (*FetchCertificateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

// *Represents a response with a stored intermediate certificate.
type FetchCertificateResponse struct {
	StoredIntermediateCert []byte `protobuf:"bytes,1,opt,name=storedIntermediateCert,proto3" json:"storedIntermediateCert,omitempty"`
}

func (m *FetchCertificateResponse) Reset()                    { *m = FetchCertificateResponse{} }
func (m *FetchCertificateResponse) String() string            { return proto.CompactTextString(m) }
func (*FetchCertificateResponse) ProtoMessage()               {}
func (*FetchCertificateResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *FetchCertificateResponse) GetStoredIntermediateCert() []byte {
	if m != nil {
		return m.StoredIntermediateCert
	}
	return nil
}

// *Represents a request with a signed intermediate certificate.
type LoadCertificateRequest struct {
	SignedIntermediateCert []byte `protobuf:"bytes,1,opt,name=signedIntermediateCert,proto3" json:"signedIntermediateCert,omitempty"`
}

func (m *LoadCertificateRequest) Reset()                    { *m = LoadCertificateRequest{} }
func (m *LoadCertificateRequest) String() string            { return proto.CompactTextString(m) }
func (*LoadCertificateRequest) ProtoMessage()               {}
func (*LoadCertificateRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *LoadCertificateRequest) GetSignedIntermediateCert() []byte {
	if m != nil {
		return m.SignedIntermediateCert
	}
	return nil
}

// *Represents an empty response.
type LoadCertificateResponse struct {
}

func (m *LoadCertificateResponse) Reset()                    { *m = LoadCertificateResponse{} }
func (m *LoadCertificateResponse) String() string            { return proto.CompactTextString(m) }
func (*LoadCertificateResponse) ProtoMessage()               {}
func (*LoadCertificateResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func init() {
	proto.RegisterType((*SignCsrRequest)(nil), "ca.SignCsrRequest")
	proto.RegisterType((*SignCsrResponse)(nil), "ca.SignCsrResponse")
	proto.RegisterType((*GenerateCsrRequest)(nil), "ca.GenerateCsrRequest")
	proto.RegisterType((*GenerateCsrResponse)(nil), "ca.GenerateCsrResponse")
	proto.RegisterType((*FetchCertificateRequest)(nil), "ca.FetchCertificateRequest")
	proto.RegisterType((*FetchCertificateResponse)(nil), "ca.FetchCertificateResponse")
	proto.RegisterType((*LoadCertificateRequest)(nil), "ca.LoadCertificateRequest")
	proto.RegisterType((*LoadCertificateResponse)(nil), "ca.LoadCertificateResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for ControlPlaneCA service

type ControlPlaneCAClient interface {
	// * Responsible for configuration of the plugin.
	Configure(ctx context.Context, in *sriplugin.ConfigureRequest, opts ...grpc.CallOption) (*sriplugin.ConfigureResponse, error)
	// * Returns the  version and related metadata of the installed plugin.
	GetPluginInfo(ctx context.Context, in *sriplugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*sriplugin.GetPluginInfoResponse, error)
	// * Interface will take in a CSR and sign it with the stored intermediate certificate.
	SignCsr(ctx context.Context, in *SignCsrRequest, opts ...grpc.CallOption) (*SignCsrResponse, error)
	// * Used for generating a CSR for the intermediate signing certificate. The CSR will then be submitted to the CA plugin for signing.
	GenerateCsr(ctx context.Context, in *GenerateCsrRequest, opts ...grpc.CallOption) (*GenerateCsrResponse, error)
	// * Used to read the stored Intermediate CP cert.
	FetchCertificate(ctx context.Context, in *FetchCertificateRequest, opts ...grpc.CallOption) (*FetchCertificateResponse, error)
	// * Used for setting/storing the signed intermediate certificate.
	LoadCertificate(ctx context.Context, in *LoadCertificateRequest, opts ...grpc.CallOption) (*LoadCertificateResponse, error)
}

type controlPlaneCAClient struct {
	cc *grpc.ClientConn
}

func NewControlPlaneCAClient(cc *grpc.ClientConn) ControlPlaneCAClient {
	return &controlPlaneCAClient{cc}
}

func (c *controlPlaneCAClient) Configure(ctx context.Context, in *sriplugin.ConfigureRequest, opts ...grpc.CallOption) (*sriplugin.ConfigureResponse, error) {
	out := new(sriplugin.ConfigureResponse)
	err := grpc.Invoke(ctx, "/ca.ControlPlaneCA/Configure", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlPlaneCAClient) GetPluginInfo(ctx context.Context, in *sriplugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*sriplugin.GetPluginInfoResponse, error) {
	out := new(sriplugin.GetPluginInfoResponse)
	err := grpc.Invoke(ctx, "/ca.ControlPlaneCA/GetPluginInfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlPlaneCAClient) SignCsr(ctx context.Context, in *SignCsrRequest, opts ...grpc.CallOption) (*SignCsrResponse, error) {
	out := new(SignCsrResponse)
	err := grpc.Invoke(ctx, "/ca.ControlPlaneCA/SignCsr", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlPlaneCAClient) GenerateCsr(ctx context.Context, in *GenerateCsrRequest, opts ...grpc.CallOption) (*GenerateCsrResponse, error) {
	out := new(GenerateCsrResponse)
	err := grpc.Invoke(ctx, "/ca.ControlPlaneCA/GenerateCsr", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlPlaneCAClient) FetchCertificate(ctx context.Context, in *FetchCertificateRequest, opts ...grpc.CallOption) (*FetchCertificateResponse, error) {
	out := new(FetchCertificateResponse)
	err := grpc.Invoke(ctx, "/ca.ControlPlaneCA/FetchCertificate", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *controlPlaneCAClient) LoadCertificate(ctx context.Context, in *LoadCertificateRequest, opts ...grpc.CallOption) (*LoadCertificateResponse, error) {
	out := new(LoadCertificateResponse)
	err := grpc.Invoke(ctx, "/ca.ControlPlaneCA/LoadCertificate", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for ControlPlaneCA service

type ControlPlaneCAServer interface {
	// * Responsible for configuration of the plugin.
	Configure(context.Context, *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	// * Returns the  version and related metadata of the installed plugin.
	GetPluginInfo(context.Context, *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
	// * Interface will take in a CSR and sign it with the stored intermediate certificate.
	SignCsr(context.Context, *SignCsrRequest) (*SignCsrResponse, error)
	// * Used for generating a CSR for the intermediate signing certificate. The CSR will then be submitted to the CA plugin for signing.
	GenerateCsr(context.Context, *GenerateCsrRequest) (*GenerateCsrResponse, error)
	// * Used to read the stored Intermediate CP cert.
	FetchCertificate(context.Context, *FetchCertificateRequest) (*FetchCertificateResponse, error)
	// * Used for setting/storing the signed intermediate certificate.
	LoadCertificate(context.Context, *LoadCertificateRequest) (*LoadCertificateResponse, error)
}

func RegisterControlPlaneCAServer(s *grpc.Server, srv ControlPlaneCAServer) {
	s.RegisterService(&_ControlPlaneCA_serviceDesc, srv)
}

func _ControlPlaneCA_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(sriplugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneCAServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ca.ControlPlaneCA/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneCAServer).Configure(ctx, req.(*sriplugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ControlPlaneCA_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(sriplugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneCAServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ca.ControlPlaneCA/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneCAServer).GetPluginInfo(ctx, req.(*sriplugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ControlPlaneCA_SignCsr_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignCsrRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneCAServer).SignCsr(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ca.ControlPlaneCA/SignCsr",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneCAServer).SignCsr(ctx, req.(*SignCsrRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ControlPlaneCA_GenerateCsr_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateCsrRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneCAServer).GenerateCsr(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ca.ControlPlaneCA/GenerateCsr",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneCAServer).GenerateCsr(ctx, req.(*GenerateCsrRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ControlPlaneCA_FetchCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneCAServer).FetchCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ca.ControlPlaneCA/FetchCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneCAServer).FetchCertificate(ctx, req.(*FetchCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ControlPlaneCA_LoadCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoadCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ControlPlaneCAServer).LoadCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ca.ControlPlaneCA/LoadCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ControlPlaneCAServer).LoadCertificate(ctx, req.(*LoadCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ControlPlaneCA_serviceDesc = grpc.ServiceDesc{
	ServiceName: "ca.ControlPlaneCA",
	HandlerType: (*ControlPlaneCAServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Configure",
			Handler:    _ControlPlaneCA_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _ControlPlaneCA_GetPluginInfo_Handler,
		},
		{
			MethodName: "SignCsr",
			Handler:    _ControlPlaneCA_SignCsr_Handler,
		},
		{
			MethodName: "GenerateCsr",
			Handler:    _ControlPlaneCA_GenerateCsr_Handler,
		},
		{
			MethodName: "FetchCertificate",
			Handler:    _ControlPlaneCA_FetchCertificate_Handler,
		},
		{
			MethodName: "LoadCertificate",
			Handler:    _ControlPlaneCA_LoadCertificate_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "control_plane_ca.proto",
}

func init() { proto.RegisterFile("control_plane_ca.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 389 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x93, 0xd1, 0xaa, 0xda, 0x40,
	0x10, 0x86, 0x6b, 0x85, 0x96, 0x4e, 0x5b, 0xb5, 0x6b, 0x89, 0x36, 0x0a, 0x95, 0xdc, 0xb4, 0x17,
	0x25, 0x01, 0x5b, 0x7a, 0xd9, 0x52, 0x02, 0x8a, 0xa5, 0x85, 0x90, 0xf3, 0x00, 0x12, 0x37, 0x93,
	0xb8, 0x1c, 0xb3, 0x9b, 0xb3, 0xbb, 0x79, 0xba, 0xf3, 0x72, 0x87, 0x24, 0xab, 0xc7, 0x98, 0xe4,
	0x4a, 0x99, 0x7f, 0xfe, 0x6f, 0x76, 0xf8, 0x27, 0x60, 0x51, 0xc1, 0xb5, 0x14, 0xa7, 0x7d, 0x7e,
	0x8a, 0x38, 0xee, 0x69, 0xe4, 0xe6, 0x52, 0x68, 0x41, 0x5e, 0xd2, 0xc8, 0xfe, 0x91, 0x32, 0x7d,
	0x2c, 0x0e, 0x2e, 0x15, 0x99, 0xa7, 0x72, 0x96, 0x24, 0xe8, 0x29, 0xc9, 0xbc, 0xfc, 0x3e, 0xf5,
	0xa8, 0xc8, 0x32, 0xc1, 0xbd, 0xfc, 0x54, 0xa4, 0xec, 0xfc, 0x53, 0x3b, 0x1d, 0x07, 0x46, 0x77,
	0x2c, 0xe5, 0xbe, 0x92, 0x21, 0x3e, 0x14, 0xa8, 0x34, 0x99, 0xc0, 0x90, 0x2a, 0x39, 0x1f, 0xac,
	0x06, 0x5f, 0xdf, 0x85, 0xe5, 0x5f, 0xe7, 0x37, 0x8c, 0x2f, 0x3d, 0x2a, 0x17, 0x5c, 0x21, 0xf9,
	0x06, 0x1f, 0x14, 0x4b, 0x39, 0xc6, 0x3e, 0x4a, 0xcd, 0x12, 0x46, 0x23, 0x8d, 0xc6, 0xd2, 0x16,
	0x9c, 0x8f, 0x40, 0xb6, 0xc8, 0x51, 0x46, 0x1a, 0x9f, 0x07, 0x39, 0x5f, 0x60, 0xda, 0xa8, 0x1a,
	0x74, 0x7b, 0xfe, 0x27, 0x98, 0x6d, 0x50, 0xd3, 0xe3, 0x15, 0xf2, 0xcc, 0x08, 0x61, 0xde, 0x96,
	0x0c, 0xe8, 0x27, 0x58, 0x4a, 0x0b, 0x89, 0xf1, 0x8e, 0x6b, 0x94, 0x19, 0xc6, 0xac, 0x9c, 0x84,
	0x52, 0x1b, 0x76, 0x8f, 0xea, 0x04, 0x60, 0xfd, 0x13, 0x51, 0xdc, 0x9e, 0x56, 0x11, 0xab, 0xe5,
	0x7a, 0x89, 0x9d, 0x6a, 0xb9, 0x40, 0x8b, 0x58, 0x3f, 0x72, 0xfd, 0x38, 0x84, 0x91, 0x5f, 0x87,
	0x1a, 0x94, 0x99, 0xfa, 0x7f, 0xc8, 0x06, 0xde, 0xf8, 0x82, 0x27, 0x2c, 0x2d, 0x24, 0x92, 0x85,
	0xab, 0x24, 0x33, 0x89, 0x5d, 0xaa, 0xe6, 0x3d, 0xf6, 0xb2, 0x5b, 0x34, 0xfb, 0x87, 0xf0, 0x7e,
	0x8b, 0x3a, 0xa8, 0xe4, 0x1d, 0x4f, 0x04, 0xf9, 0x7c, 0xd5, 0xde, 0x50, 0xce, 0xbc, 0x55, 0x7f,
	0x83, 0x61, 0xae, 0xe1, 0xb5, 0x39, 0x05, 0x42, 0x5c, 0x1a, 0xb9, 0xcd, 0xdb, 0xb1, 0xa7, 0x8d,
	0x9a, 0xf1, 0xfc, 0x82, 0xb7, 0x57, 0x39, 0x13, 0xab, 0xec, 0x69, 0x9f, 0x83, 0x3d, 0x6b, 0xd5,
	0x8d, 0xff, 0x3f, 0x4c, 0x6e, 0x33, 0x26, 0x8b, 0xb2, 0xb9, 0xe7, 0x28, 0xec, 0x65, 0xb7, 0x68,
	0x70, 0x7f, 0x61, 0x7c, 0x13, 0x06, 0xb1, 0x4b, 0x43, 0x77, 0xe6, 0xf6, 0xa2, 0x53, 0xab, 0x59,
	0xc1, 0x8b, 0xc3, 0xab, 0xea, 0x33, 0xfa, 0xfe, 0x14, 0x00, 0x00, 0xff, 0xff, 0xeb, 0x97, 0xc4,
	0x3c, 0x9a, 0x03, 0x00, 0x00,
}
