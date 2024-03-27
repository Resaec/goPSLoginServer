package controlPacket

import (
	"bytes"
	"errors"

	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type TeardownConnection struct {
	packet.Base
	ClientNonce uint32
	Unk0        uint8
	Unk1        uint8
}

func (p *TeardownConnection) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_TeardownConnection,
	}
}

func (p *TeardownConnection) Decode(stream *bitstream.BitStream) (err error) {

	var (
		opcode = p.GetOpcode()
	)

	stream.ReadBytes(&p.Opcode, uint64(len(opcode)), false)

	if bytes.Compare(p.Opcode, p.GetOpcode()) != 0 {
		return errors.New(packet.PACKET_DECODE_ERR_OPCODE_MISMATCH)
	}

	stream.ReadUint32(&p.ClientNonce, false)
	stream.ReadUint8(&p.Unk0, false)
	stream.ReadUint8(&p.Unk1, false)

	return stream.GetLastError()
}

func (p *TeardownConnection) Encode(stream *bitstream.BitStream) (err error) {

	// 00 05 024F5717 0006

	stream.WriteBytes(p.GetOpcode())

	stream.WriteUint32(p.ClientNonce)
	stream.WriteUint8(p.Unk0)
	stream.WriteUint8(p.Unk1)

	return stream.GetLastError()
}
