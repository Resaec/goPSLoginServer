package controlPacket

import (
	"bytes"
	"errors"

	"goPSLoginServer/packet"

	"goPSLoginServer/utils/bitstream"
)

// C >> S
// Received after sending a ConnectionClose() to the client (while it is waiting for World Server connection data
type Unknown30 struct {
	packet.Base
	ClientNonce uint32
	ServerNonce uint32
}

func (p *Unknown30) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_Unknown30,
	}
}

func (p *Unknown30) Decode(stream *bitstream.BitStream) (err error) {

	// 00 1E

	var (
		opcode = p.GetOpcode()
	)

	stream.ReadBytes(&p.Opcode, uint64(len(opcode)), false)

	if bytes.Compare(p.Opcode, p.GetOpcode()) != 0 {
		return errors.New(packet.PACKET_DECODE_ERR_OPCODE_MISMATCH)
	}

	stream.ReadUint32(&p.ClientNonce, false)
	stream.ReadUint32(&p.ServerNonce, false)

	return stream.GetLastError()
}

func (p *Unknown30) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteBytes(p.GetOpcode())

	return stream.GetLastError()
}
