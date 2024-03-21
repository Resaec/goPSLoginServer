package packetHandler

import (
	"fmt"

	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func HandlePacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.ReadUint8(&opcode, true)

	// handle control packets, decrypted or not
	if opcode == 0x00 {
		response, err = handleControlPacket(stream, sess)
	} else {
		response, err = handleNonControlPacket(stream, sess)
	}

	return
}

func SendPacket(stream *bitstream.BitStream, sess *session.Session) (err error) {

	var (
		writeCount int

		responseBuffer []uint8

		targetEndpoint = sess.ClientEndpoint
	)

	writeCount, err = utils.LoginUDPSocket.WriteToSocket(stream.GetBuffer(), targetEndpoint)
	if err != nil {
		err = fmt.Errorf(
			"Error answering packet for client %s:%d: %v\n",
			targetEndpoint.IP,
			targetEndpoint.Port,
			err,
		)

		return
	}

	if uint32(writeCount) != stream.GetSize() {
		err = fmt.Errorf(
			"WriteCount of response is not equal to response size %d / %d for client %s:%d\n",
			writeCount,
			stream.GetSize(),
			targetEndpoint.IP,
			targetEndpoint.Port,
		)

		return
	}

	responseBuffer = stream.GetBuffer()

	logging.LogPacket(
		"UDP",
		"Login",
		utils.LoginUDPSocket.GetLocalAddress(),
		sess.ClientEndpoint,
		responseBuffer,
		false,
	)

	return
}

func PreparePacketForSending(stream *bitstream.BitStream, sess *session.Session) {

	var (
		packet = stream.GetBuffer()
	)

	// crypto is finished, all packets need to be encrypted and have the encrypted header
	if sess.CryptoState == session.CryptoState_Finished {

		logging.Verboseln("Encrypted packet")

		sess.EncryptPacket(&packet)

		stream.Clear()
		EncodeHeaderEncrypted(stream)

		stream.WriteBytes(packet)

	}

	// crypto is in challenge, all packets need to have the challenge header
	if sess.CryptoState == session.CryptoState_Challenge {

		logging.Verboseln("Crypto packet")

		stream.Clear()
		encodeHeaderCrypto(stream)

		stream.WriteBytes(packet)
	}

	if sess.CryptoState == session.CryptoState_Init {
		logging.Verboseln("Init packet")
	}

	// nothing to do for CryptoState_Init

	// update CryptoState for next packet
	if sess.CryptoStateSwitch != session.CryptoState_Init {
		sess.CryptoState = sess.CryptoStateSwitch
		sess.CryptoStateSwitch = session.CryptoState_Init
	}
}
