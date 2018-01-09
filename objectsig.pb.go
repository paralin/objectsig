// Code generated by protoc-gen-go. DO NOT EDIT.
// source: github.com/aperturerobotics/objectsig/objectsig.proto

/*
Package objectsig is a generated protocol buffer package.

It is generated from these files:
	github.com/aperturerobotics/objectsig/objectsig.proto

It has these top-level messages:
	Signature
*/
package objectsig

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Signature is a signature of a object hash.
type Signature struct {
	// KeyMultihash is the multihash of the signer's public key.
	KeyMultihash []byte `protobuf:"bytes,1,opt,name=key_multihash,json=keyMultihash,proto3" json:"key_multihash,omitempty"`
	// Signature is the signature of the data.
	Signature []byte `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (m *Signature) Reset()                    { *m = Signature{} }
func (m *Signature) String() string            { return proto.CompactTextString(m) }
func (*Signature) ProtoMessage()               {}
func (*Signature) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Signature) GetKeyMultihash() []byte {
	if m != nil {
		return m.KeyMultihash
	}
	return nil
}

func (m *Signature) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

func init() {
	proto.RegisterType((*Signature)(nil), "objectsig.Signature")
}

func init() {
	proto.RegisterFile("github.com/aperturerobotics/objectsig/objectsig.proto", fileDescriptor0)
}

var fileDescriptor0 = []byte{
	// 135 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x32, 0x4d, 0xcf, 0x2c, 0xc9,
	0x28, 0x4d, 0xd2, 0x4b, 0xce, 0xcf, 0xd5, 0x4f, 0x2c, 0x48, 0x2d, 0x2a, 0x29, 0x2d, 0x4a, 0x2d,
	0xca, 0x4f, 0xca, 0x2f, 0xc9, 0x4c, 0x2e, 0xd6, 0xcf, 0x4f, 0xca, 0x4a, 0x4d, 0x2e, 0x29, 0xce,
	0x4c, 0x47, 0xb0, 0xf4, 0x0a, 0x8a, 0xf2, 0x4b, 0xf2, 0x85, 0x38, 0xe1, 0x02, 0x4a, 0x7e, 0x5c,
	0x9c, 0xc1, 0x99, 0xe9, 0x79, 0x89, 0x20, 0x9d, 0x42, 0xca, 0x5c, 0xbc, 0xd9, 0xa9, 0x95, 0xf1,
	0xb9, 0xa5, 0x39, 0x25, 0x99, 0x19, 0x89, 0xc5, 0x19, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x3c, 0x41,
	0x3c, 0xd9, 0xa9, 0x95, 0xbe, 0x30, 0x31, 0x21, 0x19, 0x2e, 0xce, 0x62, 0x98, 0x0e, 0x09, 0x66,
	0xb0, 0x02, 0x84, 0x40, 0x12, 0x1b, 0xd8, 0x06, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0xd5,
	0xf6, 0x6a, 0xe4, 0x9a, 0x00, 0x00, 0x00,
}