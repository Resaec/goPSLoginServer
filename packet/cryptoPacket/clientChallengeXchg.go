package cryptoPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ClientChallengeXchg struct {
	packet.Base
	Unk0            uint8
	Unk1            uint8
	ClientTime      uint32
	Challenge       []uint8 // 12
	UnkEndChallenge uint8
	UnkObjects0     uint8
	UnkObjectType   uint16
	Unk2            uint32
	PLen            uint16
	P               []uint8 // 16
	GLen            uint16
	G               []uint8 // 16
	UnkEnd0         uint8
	UnkEnd1         uint8
	UnkObjects1     uint8
	Unk3            uint32
	UnkEnd2         uint8
}

func (p *ClientChallengeXchg) Decode(stream *bitstream.BitStream) (err error) {

	stream.ReadUint8(&p.Unk0, false)
	stream.ReadUint8(&p.Unk1, false)
	stream.ReadUint32(&p.ClientTime, false)
	stream.ReadBytes(&p.Challenge, 12, false)
	stream.ReadUint8(&p.UnkEndChallenge, false)
	stream.ReadUint8(&p.UnkObjects0, false)
	stream.ReadUint16(&p.UnkObjectType, false)
	stream.ReadUint32(&p.Unk2, false)
	stream.ReadUint16(&p.PLen, false)
	stream.ReadBytes(&p.P, 16, false)
	stream.ReadUint16(&p.GLen, false)
	stream.ReadBytes(&p.G, 16, false)
	stream.ReadUint8(&p.UnkEnd0, false)
	stream.ReadUint8(&p.UnkEnd1, false)
	stream.ReadUint8(&p.UnkObjects1, false)
	stream.ReadUint32(&p.Unk3, false)
	stream.ReadUint8(&p.UnkEnd2, false)

	return stream.GetLastError()
}
