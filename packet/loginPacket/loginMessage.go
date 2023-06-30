package loginPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

const (
	LOGIN_MESSAGE_CREDENTIAL_PASSWORD = false
	LOGIN_MESSAGE_CREDENTIAL_TOKEN    = true
)

type LoginMessage struct {
	packet.DefaultPacket
	MajorVersion    uint32
	MinorVersion    uint32
	BuildDate       []uint8 // string
	CredentialsType bool
	Username        []uint8 // string
	Password        []uint8 // string
	Token           []uint8 // 32
	Revision        uint32
}

func (p *LoginMessage) Decode(stream *bitstream.BitStream) (err error) {

	stream.ReadUint32(&p.MajorVersion, false)
	stream.ReadUint32(&p.MinorVersion, false)
	stream.ReadString(&p.BuildDate, false)

	stream.ReadBit(&p.CredentialsType, false)
	if p.CredentialsType == LOGIN_MESSAGE_CREDENTIAL_PASSWORD {

		stream.ReadString(&p.Username, false)
		stream.ReadString(&p.Password, false)

	} else {

		stream.ReadBytes(&p.Token, 32, false)
		stream.ReadString(&p.Username, false)
	}

	stream.ReadUint32(&p.Revision, false)

	return stream.GetLastError()
}
