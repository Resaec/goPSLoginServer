package controlPacket

import (
	"errors"

	"goPSLoginServer/packet"

	"goPSLoginServer/utils/bitstream"
)

type ClientStart struct {
	packet.DefaultPacket
	Opcode      uint8
	Unk0        uint32
	ClientNonce uint32
	Unk1        uint32
}

func (p *ClientStart) GetOpcode() []uint8 {
	return []uint8{
		packet.CPOpcode_ClientStart,
	}
}

func (p *ClientStart) Decode(stream *bitstream.BitStream) (err error) {

	// 00 01 00000002 00261e27 000001f0

	stream.DeltaPosBytes(1)
	stream.ReadUint8(&p.Opcode, false)

	if p.Opcode != p.GetOpcode()[0] {
		return errors.New(packet.PACKET_DECODE_ERR_OPCODE_MISMATCH)
	}

	stream.ReadUint32(&p.Unk0, false)
	stream.ReadUint32(&p.ClientNonce, false)
	stream.ReadUint32(&p.Unk1, false)

	return stream.GetLastError()
}
