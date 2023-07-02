package loginPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ConnectToWorldMessage struct {
	packet.DefaultPacket
	ServerName    []uint8 // string
	ServerAddress []uint8 // string
	ServerPort    uint16
}

func (p *ConnectToWorldMessage) GetOpcode() []uint8 {
	return []uint8{
		packet.GamePacketOpcode_ConnectToWorldMessage,
	}
}

func (p *ConnectToWorldMessage) Encode(stream *bitstream.BitStream) (err error) {

	stream.WriteBytes(p.GetOpcode())

	stream.WriteString(p.ServerName)
	stream.WriteString(p.ServerAddress)
	stream.WriteUint16(p.ServerPort)

	return nil
}
