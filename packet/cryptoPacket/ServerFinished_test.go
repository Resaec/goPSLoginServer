package cryptoPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestServerFinished_Encode(t *testing.T) {

	type inputType struct {
		obj *ServerFinished
	}

	type testcase struct {
		name     string
		input    inputType
		expected string
	}

	var (
		cases = []testcase{
			{
				name: "encode",
				input: inputType{
					&ServerFinished{
						Unk0: 0x1401,
						ChallengeResult: []uint8{
							0xD6,
							0x4F,
							0xFB,
							0x8E,
							0x52,
							0x63,
							0x11,
							0xB4,
							0xAF,
							0x46,
							0xBE,
							0xCE,
						},
					},
				},

				expected: "0114D64FFB8E526311B4AF46BECE",
			},
		}
	)

	for _, c := range cases {

		t.Run(
			c.name, func(t *testing.T) {

				var (
					err error

					data   []uint8
					result []uint8

					stream *bitstream.BitStream

					trim = strings.ReplaceAll(c.expected, " ", "")
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = &bitstream.BitStream{}

				err = c.input.obj.Encode(stream)
				if err != nil {
					t.Errorf("Error encoding ServerFinished: %v", err)
					return
				}

				result = stream.GetBuffer()
				if !bytes.Equal(result, data) {
					t.Errorf(
						"Error encoded bytes not as expexted:\n%v\n%v",
						result,
						data,
					)
				}

				return
			},
		)
	}
}
