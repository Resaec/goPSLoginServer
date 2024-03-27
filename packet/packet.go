package packet

import (
	"errors"

	"goPSLoginServer/utils/bitstream"
)

const (
	PACKET_OPCODE_NOT_IMPLEMENTED = "Packet Opcode [%d] not implemented"

	PACKET_CRYPTO_STATE_NOT_IMPLEMENTED = "Crypto packet state [%d] not implemented"
	PACKET_CRYPTO_STATE_UNKNOWN         = "Crypto packet for unknown state [%d]"

	PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL_CONTROL = "Encrypted control packet Opcode [%d] not implemented"
	PACKET_OPCODE_NOT_IMPLEMENTED_NORMAL_LOGIN   = "Encrypted login packet Opcode [%d] not implemented"

	PACKET_TYPE_UNKNOWN = "Unknown packet type [%d]"

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

type Functions struct{}
type Base struct {
	Functions
	Opcode []uint8
}

func (packet *Base) GetOpcode() []uint8 {
	return nil
}

func (packet *Functions) Encode(stream *bitstream.BitStream) (err error) {
	return errors.New(PACKET_ENCODE_NOT_SUPPORTED)
}

func (packet *Functions) Decode(stream *bitstream.BitStream) (err error) {
	return errors.New(PACKET_DECODE_NOT_SUPPORTED)
}
