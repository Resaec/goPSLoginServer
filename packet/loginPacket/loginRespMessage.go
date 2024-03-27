package loginPacket

import (
	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
)

// LoginError
const (
	LoginError_Success               = iota //
	LoginError_unk1                         //
	LoginError_unk2                         //
	LoginError_unk3                         //
	LoginError_unk4                         //
	LoginError_BadUsernameOrPassword        // "Invalid Username or Password"

	BadVersion = 15 //
)

// StationError
const (
	StationError_Unk0          = iota //
	StationError_AccountActive        //
	StationError_AccountClosed        // "Your Station account is currently closed"
)

// StationSubscriptionStatus
const (
	StationSubscriptionStatus_unk0         = iota //
	StationSubscriptionStatus_None                // "You do not have a PlanetSide subscription"
	StationSubscriptionStatus_Active              // / Not sure about this one (guessing) (no ingame error message)
	StationSubscriptionStatus_unk3                //
	StationSubscriptionStatus_Closed              // "Your PlanetSide subscription is currently closed"
	StationSubscriptionStatus_Trial               // / Not sure about this one either (no ingame error message)
	StationSubscriptionStatus_TrialExpired        // "Your trial PlanetSide subscription has expired"
)

type LoginRespMessage struct {
	packet.Base
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

	return stream.GetLastError()
}
