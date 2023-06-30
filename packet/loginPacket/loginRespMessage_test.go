package loginPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestLoginRespMessage_Encode(t *testing.T) {

	const (
		encoded = "02 5448495349534D59544F4B454E594553 0000000018FABE0C0000000000000000 0000000001000000020000006B7BD828 84617364661127000080"
	)

	lrm := LoginRespMessage{
		Token: []uint8{'T', 'H', 'I', 'S', 'I', 'S', 'M', 'Y', 'T', 'O', 'K', 'E', 'N', 'Y', 'E', 'S'},
		Unk0: []uint8{
			0x00,
			0x00,
			0x00,
			0x00,
			0x18,
			0xFA,
			0xBE,
			0x0C,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
		},
		Error:              0,
		StationError:       1,
		SubscriptionStatus: 2,
		Unk1:               685276011,
		Username:           []uint8("asdf"),
		Privilege:          10001,
	}

	targetStream := &bitstream.BitStream{}
	err := lrm.Encode(targetStream)
	if err != nil {
		t.Errorf("Error encoding LoginRespMessage: %v", err)
		return
	}

	buffer := targetStream.GetBuffer()
	data, _ := hex.DecodeString(strings.ReplaceAll(encoded, " ", ""))

	if !bytes.Equal(buffer, data) {
		t.Errorf("Encoded LoginRespMessage not as expected:\n%X\n%X", buffer, data)
		return
	}
}
