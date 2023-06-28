package login

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"

	"golang.org/x/exp/rand"

	"goPSLoginServer/packet"
	"goPSLoginServer/packet/controlPacket"
	"goPSLoginServer/packet/cryptoPacket"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/connection"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func handleClientStart(stream *bitstream.BitStream) (response *bitstream.BitStream, err error) {

	var (
		clientStart controlPacket.ClientStart
	)

	err = clientStart.Decode(stream)
	err = stream.GetLastError()
	if err != nil {
		return
	}

	serverStart := controlPacket.ServerStart{
		ClientNonce: clientStart.ClientNonce,
		ServerNonce: rand.Uint32(),
		Unk:         []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD3, 0x00, 0x00, 0x00, 0x02},
	}

	response = &bitstream.BitStream{}

	err = serverStart.Encode(response)
	if err != nil {
		return
	}

	return
}

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
			response, err = handleClientStart(stream)
		}

	// case packet.CPOpcode_ControlSync:
	// 	{
	//
	// 	}
	//
	// case
	// 	packet.CPOpcode_SlottedMetaPacket0,
	// 	packet.CPOpcode_SlottedMetaPacket1,
	// 	packet.CPOpcode_SlottedMetaPacket2,
	// 	packet.CPOpcode_SlottedMetaPacket3,
	// 	packet.CPOpcode_SlottedMetaPacket4,
	// 	packet.CPOpcode_SlottedMetaPacket5,
	// 	packet.CPOpcode_SlottedMetaPacket6,
	// 	packet.CPOpcode_SlottedMetaPacket7:
	// 	{
	//
	// 	}
	//
	// case packet.CPOpcode_MultiPacket:
	// 	{
	//
	// 	}

	case packet.CPOpcode_ConnectionClose:
		{
			logging.Infoln("Received ConnectionClose")
		}

	default:
		logging.Errf("Unknown Control Packet: %d\n", opcode)
	}

	if err != nil {
		logging.Errf("Error in handleControlPacket: %v\n", err)
	}

	return
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

	logging.Infoln("Starting CryptoState_Init")

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

	// write crypto header
	encodeHeaderCrypto(response)

	// write packet
	err = serverChallengeXchg.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode ServerChallengeXchg packet: %v", err)
		return
	}

	// +3 to skip crypto header
	sess.MacBuffer = append(sess.MacBuffer, response.GetBufferFromByte(3)...)

	return
}

func handleCryptoChallenge(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		clientFinished cryptoPacket.ClientFinished
	)

	logging.Infoln("Starting CryptoState_Challenge")

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

	encodeHeaderCrypto(response)

	err = serverFinished.Encode(response)
	if err != nil {
		err = fmt.Errorf("Failed to encode ServerFinished packet: %v", err)
		return
	}

	return
}

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

	return
}

func handleEncryptedPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	logging.Warnln("Encrypted packets not supported!")

	stream.ReadUint8(&opcode, false)

	return nil, fmt.Errorf(packet.PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL, opcode)
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
		logging.Errf("Error encoding crypto header: %v", err)
	}

}

func encodeHeaderEncrypted(stream *bitstream.BitStream) {

	packetHeader := packet.PacketHeader{
		PacketType:   packet.PacketType_Normal,
		Unused:       false,
		Secured:      true,
		Advanced:     true,
		LenSpecified: false,
		SeqNum:       0,
	}

	err := packetHeader.Encode(stream)
	if err != nil {
		logging.Errf("Error encoding encrypted header: %v", err)
	}

	// pad for encrypt align
	stream.WriteUint8(0x00)

}

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

func HandlePacket(stream *bitstream.BitStream, sess *session.Session) (response *bitstream.BitStream, err error) {

	var (
		opcode uint8
	)

	stream.ReadUint8(&opcode, true)

	if opcode == 0x00 {
		response, err = handleControlPacket(stream, sess)
	} else {
		response, err = handleNonControlPacket(stream, sess)
	}

	return
}

func HandleLogin(port int32) {

	var (
		err error

		responseBuffer []uint8

		readCount   int
		readAddress *net.UDPAddr

		writeCount int

		socket   *net.UDPConn
		response *bitstream.BitStream

		sess *session.Session

		buffer = make([]uint8, 1024*2)
	)

	socket, err = connection.CreateSocketUDP(port)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer socket.Close()

	for {

		var (
			isClientStartup bool

			header uint8

			stream *bitstream.BitStream
		)

		readCount, readAddress, err = socket.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println(err)
			continue
		}

		stream = bitstream.NewBitStream(buffer[:readCount])

		// get packet header for session generation checks
		stream.DeltaPosBytes(1)
		stream.ReadUint8(&header, false)

		stream.ResetStream()

		// check if this should be a new session
		if header == 0x01 {
			isClientStartup = true
		}

		// get clientEndpoint hash from connecting IP
		hash := binary.LittleEndian.Uint32(readAddress.IP)

		// get session by endpoint hash
		sess = session.GetSessionHandler().GetOrCreateSession(hash, isClientStartup)

		// check for invalid packet
		if sess == nil {
			logging.Errf("Dropping packet for client %v because it arrived out of session!", readAddress.IP)
			continue
		}

		logging.LogPacket("UDP", "Login", socket.LocalAddr(), readAddress, buffer[:readCount], true)

		response, err = HandlePacket(stream, sess)
		if err != nil {
			logging.Errf(
				"Error in Login - dropping connection to %s:%d: %v\n",
				readAddress.IP.String(),
				readAddress.Port,
				err,
			)
			continue
		}

		if response == nil {
			logging.Warnf(
				"No response for packet from client %s:%d\n",
				readAddress.IP,
				readAddress.Port,
			)
		}

		responseBuffer = response.GetBuffer()

		logging.LogPacket("UDP", "Login", socket.LocalAddr(), readAddress, responseBuffer, false)

		writeCount, err = socket.WriteToUDP(responseBuffer, readAddress)
		if err != nil {
			logging.Errf(
				"Error answering packet for client %s:%d: %v\n",
				readAddress.IP,
				readAddress.Port,
				err,
			)
			continue
		}

		if uint32(writeCount) != response.GetSize() {
			logging.Warnf(
				"WriteCount of response is not equal to response size %d / %d for client %s:%d\n",
				writeCount,
				response.GetSize(),
				readAddress.IP,
				readAddress.Port,
			)
		}
	}

	utils.GlobalWaitGroup.Done()
}
