package cryptoPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ServerChallengeXchg struct {
	packet.Base
	Unk0            uint8
	Unk1            uint8
	ServerTime      uint32
	Challenge       []uint8 // 12
	UnkChallengeEnd uint8
	UnkObjects      uint8
	Unk2            []uint8 // 7
	PubKeyLen       uint16
	PubKey          []uint8 // 16
	Unk3            uint8
}

func (p *ServerChallengeXchg) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteUint8(p.Unk0)
	stream.WriteUint8(p.Unk1)
	stream.WriteUint32(p.ServerTime)
	stream.WriteBytes(p.Challenge)
	stream.WriteUint8(p.UnkChallengeEnd)
	stream.WriteUint8(p.UnkObjects)
	stream.WriteBytes(p.Unk2)
	stream.WriteUint16(p.PubKeyLen)
	stream.WriteBytes(p.PubKey)
	stream.WriteUint8(p.Unk3)

	return stream.GetLastError()
}

func (p *ServerChallengeXchg) Decode(stream *bitstream.BitStream) (err error) {

	stream.ReadUint8(&p.Unk0, false)
	stream.ReadUint8(&p.Unk1, false)
	stream.ReadUint32(&p.ServerTime, false)
	stream.ReadBytes(&p.Challenge, 12, false)
	stream.ReadUint8(&p.UnkChallengeEnd, false)
	stream.ReadUint8(&p.UnkObjects, false)
	stream.ReadBytes(&p.Unk2, 7, false)
	stream.ReadUint16(&p.PubKeyLen, false)
	stream.ReadBytes(&p.PubKey, 16, false)
	stream.ReadUint8(&p.Unk3, false)

	return stream.GetLastError()
}
