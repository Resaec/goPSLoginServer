package cryptoPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ClientFinished struct {
	packet.Base
	UnkObjectType   uint8
	PubKeyLen       uint16
	PubKey          []uint8 // 16
	Unk0            uint16
	ChallengeResult []uint8 // 12
}

func (p *ClientFinished) Decode(stream *bitstream.BitStream) (err error) {

	stream.ReadUint8(&p.UnkObjectType, false)
	stream.ReadUint16(&p.PubKeyLen, false)
	stream.ReadBytes(&p.PubKey, 16, false)
	stream.ReadUint16(&p.Unk0, false)
	stream.ReadBytes(&p.ChallengeResult, 12, false)

	return stream.GetLastError()
}
