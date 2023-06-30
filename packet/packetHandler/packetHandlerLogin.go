package packetHandler

import (
	"fmt"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/loginPacket"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/crypto"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

// handle login packets that only arrive via encrypted packets
func handleLoginPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.ReadUint8(&opcode, false)

	switch opcode {

	// case packet.GamePacketOpcode_Unknown0:
	// 	{
	//
	// 	}

	case packet.GamePacketOpcode_LoginMessage:
		{
			return handleLoginMessage(stream, sess)
		}

	// case packet.GamePacketOpcode_LoginRespMessage:
	// 	{
	//
	// 	}
	// case packet.GamePacketOpcode_ConnectToWorldRequestMessage:
	// 	{
	//
	// 	}
	// case packet.GamePacketOpcode_ConnectToWorldMessage:
	// 	{
	//
	// 	}
	// case packet.GamePacketOpcode_VNLWorldStatusMessage:
	// 	{
	//
	// 	}
	// case packet.GamePacketOpcode_UnknownMessage6:
	// 	{
	//
	// 	}
	// case packet.GamePacketOpcode_UnknownMessage7:
	// 	{
	//
	// 	}

	default:
		{
			return nil, fmt.Errorf(packet.PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL_LOGIN, opcode)
		}

	}
}

func handleLoginMessage(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		loginMessage loginPacket.LoginMessage

		loginRespMessage *loginPacket.LoginRespMessage
	)

	logging.Infoln("Handling LoginMessage")

	err = loginMessage.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Error decoding LoginMessage packet: %v", err)
		return
	}

	logging.Infof(
		"Login from user with v%d.%d build on %s revision %d",
		loginMessage.MajorVersion,
		loginMessage.MinorVersion,
		loginMessage.BuildDate,
		loginMessage.Revision,
	)

	if loginMessage.CredentialsType == loginPacket.LOGIN_MESSAGE_CREDENTIAL_PASSWORD {
		logging.Infof("Username: %s Password: %s", loginMessage.Username, loginMessage.Password)
	} else {
		logging.Infof("Username: %s Token: %s", loginMessage.Username, loginMessage.Token)
	}

	loginRespMessage = &loginPacket.LoginRespMessage{}
	loginRespMessage.Token = crypto.GenerateToken()
	loginRespMessage.Unk0 = []uint8{
		0x00,
		0x00,
		0x00,
		0x00,
		0x18,
		0xFA,
		0xBE,
		0x0C,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
	}
	loginRespMessage.Error = 0
	loginRespMessage.StationError = 1
	loginRespMessage.SubscriptionStatus = 2
	loginRespMessage.Unk1 = 685276011
	loginRespMessage.Username = loginMessage.Username
	loginRespMessage.Privilege = 10001

	response = &bitstream.BitStream{}

	err = loginRespMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode LoginRespMessage packet: %v", err)
		return
	}

	return
}
