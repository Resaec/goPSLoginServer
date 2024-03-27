package packetHandler

import (
	"fmt"

	"golang.org/x/exp/rand"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/controlPacket"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func handleControlPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.DeltaPosBytes(1)
	stream.ReadUint8(&opcode, false)
	stream.DeltaPosBytes(-2)

	switch opcode {

	case packet.CPOpcode_ClientStart:
		{
			response, err = handleClientStart(stream, sess)
		}

	case packet.CPOpcode_TeardownConnection:
		{
			logging.Noticef("Received TeardownConnection from %s", sess.ClientEndpoint)

			session.GetSessionHandler().RemoveSession(sess)
		}

	case packet.CPOpcode_ConnectionClose:
		{
			logging.Noticef("Received ConnectionClose from %s", sess.ClientEndpoint)

			session.GetSessionHandler().RemoveSession(sess)
		}

	default:
		logging.Errf("Unknown Control Packet: %d -> %X\n", opcode, stream.GetBuffer())
	}

	if err != nil {
		logging.Errf("Error in handleControlPacket: %v\n", err)
	}

	return
}

func handleClientStart(stream *bitstream.BitStream, sess *session.Session) (response *bitstream.BitStream, err error) {

	var (
		clientStart controlPacket.ClientStart
	)

	logging.Debugln("Handling ClientStart")

	err = clientStart.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Failed to decode ClientStart packet: %v", err)
		return
	}

	sess.StoredClientNonce = clientStart.ClientNonce
	sess.StoredServerNonce = rand.Uint32()

	serverStart := controlPacket.ServerStart{
		ClientNonce: sess.StoredClientNonce,
		ServerNonce: sess.StoredServerNonce,
		Unk:         []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD3, 0x00, 0x00, 0x00, 0x02},
	}

	logging.Verbosef("ClientNonce: %X", sess.StoredClientNonce)
	logging.Verbosef("ServerNonce: %X", sess.StoredServerNonce)

	response = &bitstream.BitStream{}

	err = serverStart.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode ServerStart packet: %v", err)
		return
	}

	return
}
