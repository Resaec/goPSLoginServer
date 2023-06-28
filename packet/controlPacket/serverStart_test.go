package controlPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestServerStart_Encode(t *testing.T) {

	type inputType struct {
		obj *ServerStart
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
					&ServerStart{
						ClientNonce: 0x271E2600,
						ServerNonce: 0xCEC1BD51,
						Unk:         []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xD3, 0x00, 0x00, 0x00, 0x02},
					},
				},

				expected: "0002 00261E2751BDC1CE000000000001D300 000002",
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
