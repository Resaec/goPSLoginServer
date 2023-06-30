package packetHandler

import (
	"errors"
	"fmt"

	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func handleNonControlPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		seqNumber uint16

		packetHeader packet.PacketHeader
	)

	err = packetHeader.Decode(stream)
	if err != nil {
		return nil, errors.New(packet.PACKET_HEADER_DECODE_FAILED)
	}

	if packetHeader.Secured {
		logging.Infof("Received secured packet from %v", sess.ClientEndpoint)
		stream.DeltaPosBytes(1)
	}

	err = stream.GetLastError()
	if err != nil {
		err = fmt.Errorf("Error aligning stream after packet header read: %v", err)
		return
	}

	seqNumber = packetHeader.SeqNum
	_ = seqNumber

	switch packetHeader.PacketType {

	case packet.PacketType_ResetSequence:
		{
			response, err = handleControlPacket(stream, sess)
		}

	case packet.PacketType_Crypto:
		{
			response, err = handleCryptoPacket(stream, sess)
		}

	case packet.PacketType_Normal:
		{
			response, err = handleEncryptedPacket(stream, sess)
		}

	default:
		{
			return nil, fmt.Errorf(packet.PACKET_TYPE_UNKNOWN, packetHeader.PacketType)
		}
	}

	if err != nil {
		err = fmt.Errorf("Error handling non control packet: %v", err)
		return
	}

	return
}
