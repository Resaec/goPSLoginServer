package controlPacket

import (
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestClientStart_Decode(t *testing.T) {

	type inputType struct {
		hexText string
	}

	type testcase struct {
		name     string
		input    inputType
		expected *ClientStart
	}

	var (
		cases = []testcase{
			{
				name: "decode",
				input: inputType{
					hexText: "0001 0000000200261E27000001F0",
				},
				expected: &ClientStart{
					Unk0:        0x02000000,
					ClientNonce: 0x271E2600,
					Unk1:        0xF0010000,
				},
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

					clientStart ClientStart
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = bitstream.NewBitStream(data)

				err = clientStart.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding ClientStart: %v", err)
					return
				}

				if clientStart.Unk0 != c.expected.Unk0 {
					t.Errorf(
						"Error unk0 not as expected: %v - %v",
						clientStart.Unk0,
						c.expected.Unk0,
					)
				}

				if clientStart.ClientNonce != c.expected.ClientNonce {
					t.Errorf(
						"Error clientNonce not as expected: %v - %v",
						clientStart.ClientNonce,
						c.expected.ClientNonce,
					)
				}

				if clientStart.Unk1 != c.expected.Unk1 {
					t.Errorf(
						"Error unk1 not as expected: %v - %v",
						clientStart.Unk1,
						c.expected.Unk1,
					)
				}

				return
			},
		)
	}
}
