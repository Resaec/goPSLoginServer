package cryptoPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestClientChallengeXchg_Decode(t *testing.T) {

	type inputType struct {
		hexText string
	}

	type testcase struct {
		name     string
		input    inputType
		expected *ClientChallengeXchg
	}

	var (
		cases = []testcase{
			{
				name: "decode",
				input: inputType{
					hexText: "0101962D845324F5997CC7D16031D1F5 67E900010002FF2400001000F57511EB 8E5D1EFB8B7F3287D5A18B1710000000 00000000000000000000000000020000 010307000000",
				},
				expected: &ClientChallengeXchg{
					Unk0:            0,
					Unk1:            0,
					ClientTime:      0x53842D96,
					Challenge:       []uint8{0x24, 0xF5, 0x99, 0x7C, 0xC7, 0xD1, 0x60, 0x31, 0xD1, 0xF5, 0x67, 0xE9},
					UnkEndChallenge: 0,
					UnkObjects0:     0,
					UnkObjectType:   0,
					Unk2:            0,
					PLen:            0x0010,
					P: []uint8{
						0xF5,
						0x75,
						0x11,
						0xEB,
						0x8E,
						0x5D,
						0x1E,
						0xFB,
						0x8B,
						0x7F,
						0x32,
						0x87,
						0xD5,
						0xA1,
						0x8B,
						0x17,
					},
					GLen: 0x0010,
					G: []uint8{
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x00,
						0x02,
					},
					UnkEnd0:     0,
					UnkEnd1:     0,
					UnkObjects1: 0,
					Unk3:        0,
					UnkEnd2:     0,
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

					clientChallengeXchg ClientChallengeXchg
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = bitstream.NewBitStream(data)

				err = clientChallengeXchg.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding ClientChallengeXchg: %v", err)
					return
				}

				if clientChallengeXchg.ClientTime != c.expected.ClientTime {
					t.Errorf(
						"Error clientTime not as expected: %v - %v",
						clientChallengeXchg.ClientTime,
						c.expected.ClientTime,
					)
				}

				if !bytes.Equal(clientChallengeXchg.Challenge, c.expected.Challenge) {
					t.Errorf(
						"Error challenge not as expected: %v - %v",
						clientChallengeXchg.ClientTime,
						c.expected.ClientTime,
					)
				}

				if !bytes.Equal(clientChallengeXchg.P, c.expected.P) {
					t.Errorf(
						"Error P not as expected: %v - %v",
						clientChallengeXchg.ClientTime,
						c.expected.ClientTime,
					)
				}

				if clientChallengeXchg.PLen != c.expected.PLen {
					t.Errorf(
						"Error PLen not as expected: %v - %v",
						clientChallengeXchg.ClientTime,
						c.expected.ClientTime,
					)
				}

				if !bytes.Equal(clientChallengeXchg.G, c.expected.G) {
					t.Errorf(
						"Error G not as expected: %v - %v",
						clientChallengeXchg.ClientTime,
						c.expected.ClientTime,
					)
				}

				if clientChallengeXchg.GLen != c.expected.GLen {
					t.Errorf(
						"Error GLen not as expected: %v - %v",
						clientChallengeXchg.ClientTime,
						c.expected.ClientTime,
					)
				}

				return
			},
		)
	}
}
