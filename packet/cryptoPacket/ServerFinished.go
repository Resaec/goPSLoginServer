package cryptoPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ServerFinished struct {
	packet.Base
	Unk0            uint16
	ChallengeResult []uint8 // 12
}

func (p *ServerFinished) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteUint16(p.Unk0)
	stream.WriteBytes(p.ChallengeResult)

	return stream.GetLastError()
}
