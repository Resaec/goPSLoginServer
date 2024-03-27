package loginPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

type ConnectToWorldRequestMessage struct {
	packet.Base
	ServerName   []uint8 // string
	Token        []uint8 // 32
	MajorVersion uint32
	MinorVersion uint32
	Revision     uint32
	BuildDate    []uint8 // string
	Unk0         uint16
}

func (p *ConnectToWorldRequestMessage) Decode(stream *bitstream.BitStream) (err error) {

	stream.ReadString(&p.ServerName, false)
	stream.ReadBytes(&p.Token, 32, false)
	stream.ReadUint32(&p.MajorVersion, false)
	stream.ReadUint32(&p.MinorVersion, false)
	stream.ReadUint32(&p.Revision, false)
	stream.ReadString(&p.BuildDate, false)
	stream.ReadUint16(&p.Unk0, false)

	return stream.GetLastError()
}
