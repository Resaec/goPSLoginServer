package packetHandler

import (
	"goPSLoginServer/utils/bitstream"
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
