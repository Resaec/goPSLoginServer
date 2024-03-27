package controlPacket

import (
	"goPSLoginServer/packet"

	"goPSLoginServer/utils/bitstream"
)

type SlottedMetaPacket struct {
	packet.Base
	Slot    uint8
	Subslot uint16
	Rest    []uint8
}

func (p *SlottedMetaPacket) GetOpcode() []uint8 {
	return []uint8{
		packet.CPOpcode_ControlSync,
	}
}

func (p *SlottedMetaPacket) Decode(stream *bitstream.BitStream) (err error) {

	// read opcode as slot
	stream.DeltaPosBytes(-1)
	stream.ReadUint8(&p.Slot, false)

	// substract first SlottedMetaPacket opcode to get the actual slot
	p.Slot = p.Slot - packet.CPOpcode_SlottedMetaPacket0

	stream.ReadUint16(&p.Subslot, false)
	stream.ReadBytes(&p.Rest, stream.GetRemainingBytes(), false)

	return stream.GetLastError()
}
