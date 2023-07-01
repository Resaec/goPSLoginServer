package packetHandler

import (
	"fmt"
	"math/big"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/cryptoPacket"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func handleCryptoPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	switch sess.CryptoState {

	case session.CryptoState_Init:
		{
			return handleCryptoInit(stream, sess)
		}

	case session.CryptoState_Challenge:
		{
			return handleCryptoChallenge(stream, sess)
		}

	case session.CryptoState_Finished:
		{
			return nil, fmt.Errorf(packet.PACKET_CRYPTO_STATE_NOT_IMPLEMENTED, sess.CryptoState)
		}

	default:
		return nil, fmt.Errorf(packet.PACKET_CRYPTO_STATE_UNKNOWN, sess.CryptoState)
	}
}

func encodeHeaderCrypto(stream *bitstream.BitStream) {

	packetHeader := packet.PacketHeader{
		PacketType:   packet.PacketType_Crypto,
		Unused:       false,
		Secured:      false,
		Advanced:     true,
		LenSpecified: false,
		SeqNum:       0,
	}

	err := packetHeader.Encode(stream)
	if err != nil {
		err = fmt.Errorf("Failed to encode Crypto Header packet: %v", err)
		return
	}

}

func handleCryptoInit(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		p big.Int
		g big.Int

		clientChallengeXchg cryptoPacket.ClientChallengeXchg
	)

	logging.Infoln("Handling CryptoState_Init")

	sess.MacBuffer = append(sess.MacBuffer, stream.GetBufferFromHead()...)

	err = clientChallengeXchg.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Failed to decode ClientChallengeXchg packet: %v", err)
		return
	}

	p.SetBytes(clientChallengeXchg.P)
	g.SetBytes(clientChallengeXchg.G)

	sess.GenerateCrypto1(clientChallengeXchg.ClientTime, clientChallengeXchg.Challenge, &p, &g)

	serverChallengeXchg := cryptoPacket.ServerChallengeXchg{
		Unk0:            2,
		Unk1:            1,
		ServerTime:      sess.StoredServerTime,
		Challenge:       sess.StoredServerChallenge,
		UnkChallengeEnd: 0,
		UnkObjects:      1,
		Unk2:            []uint8{0x03, 0x07, 0x00, 0x00, 0x00, 0x0C, 0x00},
		PubKeyLen:       16,
		PubKey:          sess.ServerPubKey,
		Unk3:            14,
	}

	response = &bitstream.BitStream{}

	// write packet
	err = serverChallengeXchg.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode ServerChallengeXchg packet: %v", err)
		return
	}

	sess.MacBuffer = append(sess.MacBuffer, response.GetBuffer()...)

	return
}

func handleCryptoChallenge(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		clientFinished cryptoPacket.ClientFinished
	)

	logging.Infoln("Handling CryptoState_Challenge")

	sess.MacBuffer = append(sess.MacBuffer, stream.GetBufferFromHead()...)

	err = clientFinished.Decode(stream)
	if err != nil {
		err = fmt.Errorf("Failed to decode ClientFinished packet: %v", err)
		return
	}

	sess.GenerateCrypto2(clientFinished.PubKey, clientFinished.ChallengeResult)

	serverFinished := cryptoPacket.ServerFinished{
		Unk0:            0x1401,
		ChallengeResult: sess.ServerChallengeResult,
	}

	response = &bitstream.BitStream{}

	err = serverFinished.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode ServerFinished packet: %v", err)
		return
	}

	return
}
