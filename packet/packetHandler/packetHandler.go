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

func SendEncryptedPacket(stream *bitstream.BitStream, sess *session.Session) (err error) {

	var (
		packet []uint8

		encryptedStream *bitstream.BitStream
	)

	// get unencrypted packet from stream
	packet = stream.GetBuffer()

	logging.Infof("Pre Encrypt: %X", packet)

	// encrypt packet
	sess.EncryptPacket(&packet)

	encryptedStream = &bitstream.BitStream{}

	// prepend the encryption packet header
	EncodeHeaderEncrypted(encryptedStream)

	// write encrypted packet to stream
	encryptedStream.WriteBytes(packet)

	err = SendPacket(encryptedStream, sess)
	if err != nil {
		err = fmt.Errorf("Error sending encrypted packet: %v", err)
		return
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

	fmt.Println()

	return
}
