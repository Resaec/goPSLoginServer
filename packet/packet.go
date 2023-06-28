package packet

import (
	"errors"

	"goPSLoginServer/utils/bitstream"
)

const (
	PACKET_OPCODE_NOT_IMPLEMENTED = "Packet Opcode [%X] not implemented"

	PACKET_CRYPTO_STATE_NOT_IMPLEMENTED = "Crypto packet state [%X] not implemented"
	PACKET_CRYPTO_STATE_UNKNOWN         = "Crypto packet for unknown state [%X]"

	PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL = "Encrypted packet Opcode [%X] not implemented"

	PACKET_TYPE_UNKNOWN = "Unknown packet type [%X]"

	PACKET_ENCODE_NOT_SUPPORTED = "Packet Encode() not supported"
	PACKET_DECODE_NOT_SUPPORTED = "Packet Decode() not supported"

	PACKET_DECODE_ERR_OPCODE_MISMATCH = "Packet Decode Opcode Mismatch"

	PACKET_HEADER_DECODE_FAILED = "Packet Header Decode failed"
)

type Packet interface {
	GetOpcode() []uint8
	Encode(stream *bitstream.BitStream) (err error)
	Decode(bitstream *bitstream.BitStream) (err error)
}

type DefaultPacket struct{}

func (packet *DefaultPacket) GetOpcode() []uint8 {
	return nil
}

func (packet *DefaultPacket) Encode(stream *bitstream.BitStream) (err error) {
	return errors.New(PACKET_ENCODE_NOT_SUPPORTED)
}

func (packet *DefaultPacket) Decode(bitstream *bitstream.BitStream) (err error) {
	return errors.New(PACKET_DECODE_NOT_SUPPORTED)
}
