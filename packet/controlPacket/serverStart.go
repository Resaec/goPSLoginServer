package controlPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ServerStart struct {
	packet.Base
	ClientNonce uint32  //
	ServerNonce uint32  //
	Unk         []uint8 // 11 byte
}

func (p *ServerStart) GetOpcode() []uint8 {
	return []uint8{
		0x00,
		packet.CPOpcode_ServerStart,
	}
}

func (p *ServerStart) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteBytes(p.GetOpcode())

	stream.WriteUint32(p.ClientNonce)
	stream.WriteUint32(p.ServerNonce)
	stream.WriteBytes(p.Unk)

	return stream.GetLastError()
}
