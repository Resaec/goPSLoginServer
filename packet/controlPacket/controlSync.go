package controlPacket

import (
	"goPSLoginServer/packet"

	"goPSLoginServer/utils/bitstream"
)

type ControlSync struct {
	packet.DefaultPacket
	TimeDiff uint16
	Unk      uint32
	Field1   uint32
	Field2   uint32
	Field3   uint32
	Field4   uint32
	Field64A uint64
	Field64B uint64
}

func (p *ControlSync) GetOpcode() []uint8 {
	return []uint8{
		packet.CPOpcode_ControlSync,
	}
}

func (p *ControlSync) Decode(stream *bitstream.BitStream) (err error) {

	stream.ReadUint16(&p.TimeDiff, false)
	stream.ReadUint32(&p.Unk, false)
	stream.ReadUint32(&p.Field1, false)
	stream.ReadUint32(&p.Field2, false)
	stream.ReadUint32(&p.Field3, false)
	stream.ReadUint32(&p.Field4, false)
	stream.ReadUint64(&p.Field64A, false)
	stream.ReadUint64(&p.Field64B, false)

	return stream.GetLastError()
}
