package loginPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type LoginRespMessage struct {
	packet.DefaultPacket
	Token              []uint8 // 16
	Unk0               []uint8 // 16
	Error              uint32
	StationError       uint32
	SubscriptionStatus uint32
	Unk1               uint32
	Username           []uint8 // string
	Privilege          uint32
}

func (p *LoginRespMessage) GetOpcode() []uint8 {
	return []uint8{
		packet.GamePacketOpcode_LoginRespMessage,
	}
}

func (p *LoginRespMessage) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteBytes(p.GetOpcode())

	stream.WriteBytes(p.Token)
	stream.WriteBytes(p.Unk0)
	stream.WriteUint32(p.Error)
	stream.WriteUint32(p.StationError)
	stream.WriteUint32(p.SubscriptionStatus)
	stream.WriteUint32(p.Unk1)
	stream.WriteString(p.Username)
	stream.WriteUint32(p.Privilege)
	stream.WriteBool(p.Privilege != 0)

	return nil
}
