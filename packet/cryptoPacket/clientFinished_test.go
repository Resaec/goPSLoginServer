package cryptoPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestClientFinished_Decode(t *testing.T) {

	type inputType struct {
		hexText string
	}

	type testcase struct {
		name     string
		input    inputType
		expected *ClientFinished
	}

	var (
		cases = []testcase{
			{
				name: "decode",
				input: inputType{
					hexText: "101000EDDC35F252B02D0E496BA27354 578E730114EA3CF05DA5CB42568BB91A A7",
				},
				expected: &ClientFinished{
					UnkObjectType: 0,
					PubKeyLen:     0x0010,
					PubKey: []uint8{
						0xED,
						0xDC,
						0x35,
						0xF2,
						0x52,
						0xB0,
						0x2D,
						0x0E,
						0x49,
						0x6B,
						0xA2,
						0x73,
						0x54,
						0x57,
						0x8E,
						0x73,
					},
					Unk0:            0,
					ChallengeResult: []uint8{0xEA, 0x3C, 0xF0, 0x5D, 0xA5, 0xCB, 0x42, 0x56, 0x8B, 0xB9, 0x1A, 0xA7},
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

					clientFinished ClientFinished
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = bitstream.NewBitStream(data)

				err = clientFinished.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding ClientFinished: %v", err)
					return
				}

				if clientFinished.PubKeyLen != c.expected.PubKeyLen {
					t.Errorf(
						"Error PubKeyLen not as expected: %v - %v",
						clientFinished.PubKeyLen,
						c.expected.PubKeyLen,
					)
				}

				if !bytes.Equal(clientFinished.PubKey, c.expected.PubKey) {
					t.Errorf(
						"Error PubKey not as expected: %v - %v",
						clientFinished.PubKey,
						c.expected.PubKey,
					)
				}

				if !bytes.Equal(clientFinished.ChallengeResult, c.expected.ChallengeResult) {
					t.Errorf(
						"Error ChallengeResult not as expected: %v - %v",
						clientFinished.ChallengeResult,
						c.expected.ChallengeResult,
					)
				}

				return
			},
		)
	}
}
