package controlPacket

import (
	"bytes"
	"errors"

	"goPSLoginServer/packet"

	"goPSLoginServer/utils/bitstream"
)

type ConnectionClose struct {
	packet.Base
}

func (p *ConnectionClose) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_ConnectionClose,
	}
}

func (p *ConnectionClose) Decode(stream *bitstream.BitStream) (err error) {

	// 00 1D

	var (
		opcode = p.GetOpcode()
	)

	stream.ReadBytes(&p.Opcode, uint64(len(opcode)), false)

	if !bytes.Equal(p.Opcode, p.GetOpcode()) {
		return errors.New(packet.PACKET_DECODE_ERR_OPCODE_MISMATCH)
	}

	return stream.GetLastError()
}

func (p *ConnectionClose) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteBytes(p.GetOpcode())

	return stream.GetLastError()
}
