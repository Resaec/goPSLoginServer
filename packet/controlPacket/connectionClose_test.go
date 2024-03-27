package controlPacket

import (
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestConnectionClose_Decode(t *testing.T) {

	type inputType struct {
		hexText string
	}

	type testcase struct {
		name     string
		input    inputType
		expected *ConnectionClose
	}

	var (
		cases = []testcase{
			{
				name: "decode",
				input: inputType{
					hexText: "001D",
				},
				expected: &ConnectionClose{},
			},
		}
	)

	for _, c := range cases {

		t.Run(
			c.name, func(t *testing.T) {

				var (
					err error

					data   []uint8
					stream *bitstream.BitStream

					trim = strings.ReplaceAll(c.input.hexText, " ", "")

					connectionClose ConnectionClose
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = bitstream.NewBitStream(data)

				err = connectionClose.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding ConnectionClose: %v", err)
					return
				}

				return
			},
		)
	}
}
