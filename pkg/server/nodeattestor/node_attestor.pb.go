// Code generated by protoc-gen-go. DO NOT EDIT.
// source: node_attestor.proto

/*
Package nodeattestor is a generated protocol buffer package.

It is generated from these files:
	node_attestor.proto

It has these top-level messages:
	AttestRequest
	AttestResponse
*/
package nodeattestor

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import sriplugin "github.com/spiffe/sri/pkg/common/plugin"
import common "github.com/spiffe/sri/pkg/common"

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

// Empty from public import github.com/spiffe/sri/pkg/common/common.proto
type Empty common.Empty

func (m *Empty) Reset()         { (*common.Empty)(m).Reset() }
func (m *Empty) String() string { return (*common.Empty)(m).String() }
func (*Empty) ProtoMessage()    {}

// AttestedData from public import github.com/spiffe/sri/pkg/common/common.proto
type AttestedData common.AttestedData

func (m *AttestedData) Reset()          { (*common.AttestedData)(m).Reset() }
func (m *AttestedData) String() string  { return (*common.AttestedData)(m).String() }
func (*AttestedData) ProtoMessage()     {}
func (m *AttestedData) GetType() string { return (*common.AttestedData)(m).GetType() }
func (m *AttestedData) GetData() []byte { return (*common.AttestedData)(m).GetData() }

// Selector from public import github.com/spiffe/sri/pkg/common/common.proto
type Selector common.Selector

func (m *Selector) Reset()           { (*common.Selector)(m).Reset() }
func (m *Selector) String() string   { return (*common.Selector)(m).String() }
func (*Selector) ProtoMessage()      {}
func (m *Selector) GetType() string  { return (*common.Selector)(m).GetType() }
func (m *Selector) GetValue() string { return (*common.Selector)(m).GetValue() }

// Selectors from public import github.com/spiffe/sri/pkg/common/common.proto
type Selectors common.Selectors

func (m *Selectors) Reset()         { (*common.Selectors)(m).Reset() }
func (m *Selectors) String() string { return (*common.Selectors)(m).String() }
func (*Selectors) ProtoMessage()    {}
func (m *Selectors) GetEntries() []*Selector {
	o := (*common.Selectors)(m).GetEntries()
	if o == nil {
		return nil
	}
	s := make([]*Selector, len(o))
	for i, x := range o {
		s[i] = (*Selector)(x)
	}
	return s
}

// RegistrationEntry from public import github.com/spiffe/sri/pkg/common/common.proto
type RegistrationEntry common.RegistrationEntry

func (m *RegistrationEntry) Reset()         { (*common.RegistrationEntry)(m).Reset() }
func (m *RegistrationEntry) String() string { return (*common.RegistrationEntry)(m).String() }
func (*RegistrationEntry) ProtoMessage()    {}
func (m *RegistrationEntry) GetSelectors() []*Selector {
	o := (*common.RegistrationEntry)(m).GetSelectors()
	if o == nil {
		return nil
	}
	s := make([]*Selector, len(o))
	for i, x := range o {
		s[i] = (*Selector)(x)
	}
	return s
}
func (m *RegistrationEntry) GetParentId() string { return (*common.RegistrationEntry)(m).GetParentId() }
func (m *RegistrationEntry) GetSpiffeId() string { return (*common.RegistrationEntry)(m).GetSpiffeId() }
func (m *RegistrationEntry) GetTtl() int32       { return (*common.RegistrationEntry)(m).GetTtl() }
func (m *RegistrationEntry) GetFbSpiffeIds() []string {
	return (*common.RegistrationEntry)(m).GetFbSpiffeIds()
}

// RegistrationEntries from public import github.com/spiffe/sri/pkg/common/common.proto
type RegistrationEntries common.RegistrationEntries

func (m *RegistrationEntries) Reset()         { (*common.RegistrationEntries)(m).Reset() }
func (m *RegistrationEntries) String() string { return (*common.RegistrationEntries)(m).String() }
func (*RegistrationEntries) ProtoMessage()    {}
func (m *RegistrationEntries) GetEntries() []*RegistrationEntry {
	o := (*common.RegistrationEntries)(m).GetEntries()
	if o == nil {
		return nil
	}
	s := make([]*RegistrationEntry, len(o))
	for i, x := range o {
		s[i] = (*RegistrationEntry)(x)
	}
	return s
}

// *Represents a request to attest a node.
type AttestRequest struct {
	AttestedData   *common.AttestedData `protobuf:"bytes,1,opt,name=attestedData" json:"attestedData,omitempty"`
	AttestedBefore bool                 `protobuf:"varint,2,opt,name=attestedBefore" json:"attestedBefore,omitempty"`
}

func (m *AttestRequest) Reset()                    { *m = AttestRequest{} }
func (m *AttestRequest) String() string            { return proto.CompactTextString(m) }
func (*AttestRequest) ProtoMessage()               {}
func (*AttestRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *AttestRequest) GetAttestedData() *common.AttestedData {
	if m != nil {
		return m.AttestedData
	}
	return nil
}

func (m *AttestRequest) GetAttestedBefore() bool {
	if m != nil {
		return m.AttestedBefore
	}
	return false
}

// *Represents a response when attesting a node.
type AttestResponse struct {
	Valid        bool   `protobuf:"varint,1,opt,name=valid" json:"valid,omitempty"`
	BaseSPIFFEID string `protobuf:"bytes,2,opt,name=baseSPIFFEID" json:"baseSPIFFEID,omitempty"`
}

func (m *AttestResponse) Reset()                    { *m = AttestResponse{} }
func (m *AttestResponse) String() string            { return proto.CompactTextString(m) }
func (*AttestResponse) ProtoMessage()               {}
func (*AttestResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *AttestResponse) GetValid() bool {
	if m != nil {
		return m.Valid
	}
	return false
}

func (m *AttestResponse) GetBaseSPIFFEID() string {
	if m != nil {
		return m.BaseSPIFFEID
	}
	return ""
}

func init() {
	proto.RegisterType((*AttestRequest)(nil), "nodeattestor.AttestRequest")
	proto.RegisterType((*AttestResponse)(nil), "nodeattestor.AttestResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for NodeAttestor service

type NodeAttestorClient interface {
	// *Responsible for configuration of the plugin.
	Configure(ctx context.Context, in *sriplugin.ConfigureRequest, opts ...grpc.CallOption) (*sriplugin.ConfigureResponse, error)
	// *Returns the  version and related metadata of the installed plugin.
	GetPluginInfo(ctx context.Context, in *sriplugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*sriplugin.GetPluginInfoResponse, error)
	// *Attesta a node.
	Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error)
}

type nodeAttestorClient struct {
	cc *grpc.ClientConn
}

func NewNodeAttestorClient(cc *grpc.ClientConn) NodeAttestorClient {
	return &nodeAttestorClient{cc}
}

func (c *nodeAttestorClient) Configure(ctx context.Context, in *sriplugin.ConfigureRequest, opts ...grpc.CallOption) (*sriplugin.ConfigureResponse, error) {
	out := new(sriplugin.ConfigureResponse)
	err := grpc.Invoke(ctx, "/nodeattestor.NodeAttestor/Configure", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nodeAttestorClient) GetPluginInfo(ctx context.Context, in *sriplugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*sriplugin.GetPluginInfoResponse, error) {
	out := new(sriplugin.GetPluginInfoResponse)
	err := grpc.Invoke(ctx, "/nodeattestor.NodeAttestor/GetPluginInfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *nodeAttestorClient) Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error) {
	out := new(AttestResponse)
	err := grpc.Invoke(ctx, "/nodeattestor.NodeAttestor/Attest", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for NodeAttestor service

type NodeAttestorServer interface {
	// *Responsible for configuration of the plugin.
	Configure(context.Context, *sriplugin.ConfigureRequest) (*sriplugin.ConfigureResponse, error)
	// *Returns the  version and related metadata of the installed plugin.
	GetPluginInfo(context.Context, *sriplugin.GetPluginInfoRequest) (*sriplugin.GetPluginInfoResponse, error)
	// *Attesta a node.
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
}

func RegisterNodeAttestorServer(s *grpc.Server, srv NodeAttestorServer) {
	s.RegisterService(&_NodeAttestor_serviceDesc, srv)
}

func _NodeAttestor_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(sriplugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAttestorServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/nodeattestor.NodeAttestor/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAttestorServer).Configure(ctx, req.(*sriplugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NodeAttestor_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(sriplugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAttestorServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/nodeattestor.NodeAttestor/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAttestorServer).GetPluginInfo(ctx, req.(*sriplugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _NodeAttestor_Attest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeAttestorServer).Attest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/nodeattestor.NodeAttestor/Attest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeAttestorServer).Attest(ctx, req.(*AttestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _NodeAttestor_serviceDesc = grpc.ServiceDesc{
	ServiceName: "nodeattestor.NodeAttestor",
	HandlerType: (*NodeAttestorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Configure",
			Handler:    _NodeAttestor_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _NodeAttestor_GetPluginInfo_Handler,
		},
		{
			MethodName: "Attest",
			Handler:    _NodeAttestor_Attest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "node_attestor.proto",
}

func init() { proto.RegisterFile("node_attestor.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 306 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x51, 0xc1, 0x4e, 0xc2, 0x40,
	0x10, 0xb5, 0x26, 0x12, 0x58, 0x0b, 0x87, 0x95, 0x03, 0x29, 0x24, 0x12, 0x0e, 0x86, 0x8b, 0xdb,
	0x04, 0x3d, 0x78, 0x45, 0x10, 0x83, 0x07, 0xd3, 0xac, 0x1f, 0x60, 0x5a, 0x3a, 0xad, 0x1b, 0x69,
	0xa7, 0xec, 0x6e, 0xfd, 0x6d, 0x7f, 0xc1, 0xd8, 0xdd, 0x9a, 0xd6, 0x60, 0x3c, 0x6d, 0xe6, 0xbd,
	0x37, 0x6f, 0x66, 0xe7, 0x91, 0x8b, 0x1c, 0x63, 0x78, 0x0d, 0xb5, 0x06, 0xa5, 0x51, 0xb2, 0x42,
	0xa2, 0x46, 0xea, 0x7e, 0x83, 0x35, 0xe6, 0xdd, 0xa6, 0x42, 0xbf, 0x95, 0x11, 0xdb, 0x61, 0xe6,
	0xab, 0x42, 0x24, 0x09, 0xf8, 0x4a, 0x0a, 0xbf, 0x78, 0x4f, 0xfd, 0x1d, 0x66, 0x19, 0xe6, 0x7e,
	0xb1, 0x2f, 0x53, 0x51, 0x3f, 0xc6, 0xc3, 0xbb, 0xfe, 0xb7, 0xcb, 0x3c, 0x46, 0x3e, 0x3b, 0x90,
	0xfe, 0xb2, 0x1a, 0xc8, 0xe1, 0x50, 0x82, 0xd2, 0xf4, 0x8e, 0xb8, 0x66, 0x03, 0x88, 0xd7, 0xa1,
	0x0e, 0x47, 0xce, 0xd4, 0x99, 0x9f, 0x2f, 0x86, 0xcc, 0x76, 0x2d, 0x1b, 0x1c, 0x6f, 0x29, 0xe9,
	0x15, 0x19, 0xd4, 0xf5, 0x3d, 0x24, 0x28, 0x61, 0x74, 0x3a, 0x75, 0xe6, 0x5d, 0xfe, 0x0b, 0x9d,
	0x3d, 0x91, 0x41, 0x3d, 0x52, 0x15, 0x98, 0x2b, 0xa0, 0x43, 0x72, 0xf6, 0x11, 0xee, 0x45, 0x5c,
	0x0d, 0xeb, 0x72, 0x53, 0xd0, 0x19, 0x71, 0xa3, 0x50, 0xc1, 0x4b, 0xb0, 0xdd, 0x6c, 0x1e, 0xb6,
	0xeb, 0xca, 0xad, 0xc7, 0x5b, 0xd8, 0xe2, 0xd3, 0x21, 0xee, 0x33, 0xc6, 0xb0, 0xb4, 0x47, 0xa3,
	0x1b, 0xd2, 0x5b, 0x61, 0x9e, 0x88, 0xb4, 0x94, 0x40, 0xc7, 0x4c, 0x49, 0x61, 0xaf, 0xf3, 0x83,
	0xda, 0x8f, 0x7a, 0x93, 0xe3, 0xa4, 0x5d, 0x89, 0x93, 0xfe, 0x23, 0xe8, 0xa0, 0xa2, 0xb7, 0x79,
	0x82, 0xf4, 0xb2, 0x21, 0x6f, 0x31, 0xb5, 0xdf, 0xf4, 0x6f, 0x81, 0xf5, 0x5c, 0x91, 0x8e, 0xd9,
	0x93, 0x8e, 0x59, 0x33, 0x69, 0xd6, 0x4a, 0xc0, 0x9b, 0x1c, 0x27, 0x8d, 0x49, 0x70, 0x12, 0x38,
	0x51, 0xa7, 0xca, 0xee, 0xe6, 0x2b, 0x00, 0x00, 0xff, 0xff, 0x2c, 0x69, 0x27, 0xe6, 0x45, 0x02,
	0x00, 0x00,
}
