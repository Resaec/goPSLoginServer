package packetHandler

import (
	"fmt"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/loginPacket"
	"goPSLoginServer/utils"
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

	case packet.GamePacketOpcode_ConnectToWorldRequestMessage:
		{
			return handleConnectToWorldRequestMessage(stream, sess)
		}

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

	return
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
	loginRespMessage.Error = loginPacket.LoginError_Success
	loginRespMessage.StationError = loginPacket.StationError_AccountActive
	loginRespMessage.SubscriptionStatus = loginPacket.StationSubscriptionStatus_Active
	loginRespMessage.Unk1 = 0
	loginRespMessage.Username = loginMessage.Username
	loginRespMessage.Privilege = 10001

	response = &bitstream.BitStream{}

	err = loginRespMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode LoginRespMessage packet: %v", err)
		return
	}

	logging.Debugf("Login: %X", response.GetBuffer())

	PreparePacketForSending(response, sess)
	err = SendPacket(response, sess)
	if err != nil {
		err = fmt.Errorf("Error sending LoginRespMessage: %v", err)
		return
	}

	response.Clear()

	// worldConnectionInfo := make([]loginPacket.WorldConnectionInfo, 1)
	//
	// worldConnectionInfo[0] = loginPacket.WorldConnectionInfo{
	// 	Ip:   []uint8{127, 0, 0, 1},
	// 	Port: uint16(99),
	// }

	worldInfo := make([]loginPacket.WorldInfo, 1)

	worldInfo[0] = loginPacket.WorldInfo{
		Name:        []uint8("Bluber Server"),
		Status2:     loginPacket.WorldStatus_Up,
		ServerType:  loginPacket.ServerType_Released,
		Status1:     loginPacket.WorldStatus_Up,
		Connections: nil,
		EmpireNeed:  utils.Empire_NC,
	}

	worldMessage := loginPacket.VNLWorldStatusMessage{
		DefaultPacket:  packet.DefaultPacket{},
		WelcomeMessage: []uint8("ASDF"),
		Worlds:         worldInfo,
	}

	err = worldMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Error encoding VNLWorldStatusMessage: %v", err)
		return
	}

	logging.Debugf("WorldInfo: %X", response.GetBuffer())

	PreparePacketForSending(response, sess)
	err = SendPacket(response, sess)
	if err != nil {
		logging.Errf("BLUBBB")
	}

	response.Clear()

	return
}

func handleConnectToWorldRequestMessage(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		connectToWorldRequestMessage loginPacket.ConnectToWorldRequestMessage
		connectToWorldMessage        *loginPacket.ConnectToWorldMessage
	)

	logging.Infoln("Handling ConnectToWorldRequestMessage")

	err = connectToWorldRequestMessage.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Error decoding ConnectToWorldRequestMessage packet: %v", err)
		return
	}

	connectToWorldMessage = &loginPacket.ConnectToWorldMessage{
		ServerName:    []uint8("PSForever"),
		ServerAddress: []uint8("127.0.0.1"),
		ServerPort:    uint16(51001),
	}

	response = &bitstream.BitStream{}

	err = connectToWorldMessage.Encode(response)
	if err != nil {
		err = fmt.Errorf("Error encoding VNLWorldStatusMessage: %v", err)
		return
	}

	return
}
