package packet

import (
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
)

type PacketHeader struct {
	PacketType   uint8
	Unused       bool
	Secured      bool
	Advanced     bool
	LenSpecified bool
	SeqNum       uint16
}

func (ph *PacketHeader) Encode(stream *bitstream.BitStream) (err error) {

	var (
		flags uint8
	)

	flags |= (ph.PacketType & 0b1111) << 4
	flags |= utils.BoolToUnt8(ph.Unused) << 3
	flags |= utils.BoolToUnt8(ph.Secured) << 2
	flags |= utils.BoolToUnt8(ph.Advanced) << 1
	flags |= utils.BoolToUnt8(ph.LenSpecified)

	stream.WriteUint8(flags)
	stream.WriteUint16(ph.SeqNum)

	return stream.GetLastError()
}

func (ph *PacketHeader) Decode(stream *bitstream.BitStream) (err error) {

	// XX 00 0001 ... 0125F990643F66BCF24CA388CF3A41112600010002FF2400001000FDACB88303F0EEAECE900F98CE873F8F1000000000000000000000000000000000020000010307000000

	var (
		flags uint8
	)

	stream.ReadUint8(&flags, false)

	ph.PacketType = (flags & 0b11110000) >> 4
	ph.Unused = utils.Uint8ToBool((flags & 0b1000) >> 3)
	ph.Secured = utils.Uint8ToBool((flags & 0b100) >> 2)
	ph.Advanced = utils.Uint8ToBool((flags & 0b10) >> 1)
	ph.LenSpecified = utils.Uint8ToBool(flags & 0b1)

	stream.ReadUint16(&ph.SeqNum, false)

	return stream.GetLastError()
}
