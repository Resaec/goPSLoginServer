package packetHandler

import (
	"fmt"

	"goPSLoginServer/packet"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/session"
)

func handleEncryptedPacket(
	stream *bitstream.BitStream,
	sess *session.Session,
) (response *bitstream.BitStream, err error) {

	var (
		decodedMessage []uint8
		decodedStream  *bitstream.BitStream

		packet            []uint8
		encryptedResponse *bitstream.BitStream
	)

	err = sess.DecryptPacket(stream, &decodedMessage)
	if err != nil {
		err = fmt.Errorf("Failed to decode Packet for Client %v: %v", sess.ClientEndpoint, err)
		return
	}

	// create new message stream from decrypted packet
	decodedStream = bitstream.NewBitStream(decodedMessage)

	// call HandlePacket again to process decrypted message
	response, err = handleDecryptedPacket(decodedStream, sess)
	if err != nil {
		err = fmt.Errorf("Error handling decrypted packet: %v", err)
		return
	}

	// if there is no response we are done
	if response == nil {
		return
	}

	// response needs to be encrypted

	// get unencrypted packet from stream
	packet = response.GetBuffer()

	// encrypt packet
	sess.EncryptPacket(&packet)

	encryptedResponse = &bitstream.BitStream{}

	// prepend the encryption packet header
	EncodeHeaderEncrypted(encryptedResponse)

	// write encrypted packet to stream
	encryptedResponse.WriteBytes(packet)

	response = encryptedResponse

	return
}

func EncodeHeaderEncrypted(stream *bitstream.BitStream) {

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
		err = fmt.Errorf("Failed to encode Encrypted Header packet: %v", err)
		return
	}

	// pad for encrypt align
	stream.WriteUint8(0x00)

}
