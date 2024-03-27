package controlPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type SlottedMetaAck struct {
	packet.Base
	Slot    uint8
	Subslot uint16
}

func (p *SlottedMetaAck) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_RelatedB0,
	}
}

func (p *SlottedMetaAck) Encode(stream *bitstream.BitStream) (err error) {

	var (
		opcode []uint8
	)

	opcode = p.GetOpcode()
	opcode[1] += p.Slot % 4

	stream.WriteBytes(opcode)

	stream.WriteUint16(p.Subslot)

	return stream.GetLastError()
}
