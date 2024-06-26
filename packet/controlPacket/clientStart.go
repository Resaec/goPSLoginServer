package controlPacket

import (
	"bytes"
	"errors"

	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ClientStart struct {
	packet.Base
	Unk0        uint32
	ClientNonce uint32
	Unk1        uint32
}

func (p *ClientStart) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_ClientStart,
	}
}

func (p *ClientStart) Decode(stream *bitstream.BitStream) (err error) {

	// 00 01 00000002 00261e27 000001f0

	var (
		opcode = p.GetOpcode()
	)

	stream.ReadBytes(&p.Opcode, uint64(len(opcode)), false)

	if !bytes.Equal(p.Opcode, p.GetOpcode()) {
		return errors.New(packet.PACKET_DECODE_ERR_OPCODE_MISMATCH)
	}

	stream.ReadUint32(&p.Unk0, false)
	stream.ReadUint32(&p.ClientNonce, false)
	stream.ReadUint32(&p.Unk1, false)

	return stream.GetLastError()
}
