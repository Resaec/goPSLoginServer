package cryptoPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestServerChallengeXchg_Encode(t *testing.T) {

	type inputType struct {
		obj *ServerChallengeXchg
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
					&ServerChallengeXchg{
						Unk0:       2,
						Unk1:       1,
						ServerTime: 0x53842D96,
						Challenge: []uint8{
							0x1B,
							0x0E,
							0x64,
							0x08,
							0xCD,
							0x93,
							0x5E,
							0xC2,
							0x42,
							0x9A,
							0xEB,
							0x58,
						},
						UnkChallengeEnd: 0,
						UnkObjects:      1,
						Unk2:            []uint8{0x03, 0x07, 0x00, 0x00, 0x00, 0x0C, 0x00},
						PubKeyLen:       16,
						PubKey: []uint8{
							0x51,
							0xF8,
							0x3C,
							0xE6,
							0x45,
							0xE8,
							0x6C,
							0x3E,
							0x79,
							0xC8,
							0xFC,
							0x70,
							0xF6,
							0xDD,
							0xF1,
							0x4B,
						},
						Unk3: 14,
					},
				},

				expected: "0201962D84531B0E6408CD935EC2429A EB58000103070000000C00100051F83C E645E86C3E79C8FC70F6DDF14B0E",
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
					t.Errorf("Error encoding ServerChallengeXchg: %v", err)
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

// this test is mainly for making sure that encode and decode on bitstream works in both directions and has no byte order problems
func TestServerChallengeXchg_Decode(t *testing.T) {

	type inputType struct {
		obj *ServerChallengeXchg
	}

	type testcase struct {
		name     string
		input    inputType
		expected string
	}

	var (
		cases = []testcase{
			{
				name: "encode decode",
				input: inputType{
					&ServerChallengeXchg{
						Unk0:       2,
						Unk1:       1,
						ServerTime: 0x53842D96,
						Challenge: []uint8{
							0x1B,
							0x0E,
							0x64,
							0x08,
							0xCD,
							0x93,
							0x5E,
							0xC2,
							0x42,
							0x9A,
							0xEB,
							0x58,
						},
						UnkChallengeEnd: 0,
						UnkObjects:      1,
						Unk2:            []uint8{0x03, 0x07, 0x00, 0x00, 0x00, 0x0C, 0x00},
						PubKeyLen:       16,
						PubKey: []uint8{
							0x51,
							0xF8,
							0x3C,
							0xE6,
							0x45,
							0xE8,
							0x6C,
							0x3E,
							0x79,
							0xC8,
							0xFC,
							0x70,
							0xF6,
							0xDD,
							0xF1,
							0x4B,
						},
						Unk3: 14,
					},
				},

				expected: "0201962D84531B0E6408CD935EC2429A EB58000103070000000C00100051F83C E645E86C3E79C8FC70F6DDF14B0E",
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

					stream              *bitstream.BitStream
					serverChallengeXchg ServerChallengeXchg

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
					t.Errorf("Error encoding ServerChallengeXchg: %v", err)
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

				stream.ResetStream()
				err = serverChallengeXchg.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding ServerChallengeXchg: %v", err)
					return
				}

				// check if all values are the same
				if c.input.obj.Unk0 != serverChallengeXchg.Unk0 {
					t.Errorf("Unk0 not as expected:\n%v\n%v", c.input.obj.Unk0, serverChallengeXchg.Unk0)
				}
				if c.input.obj.Unk1 != serverChallengeXchg.Unk1 {
					t.Errorf("Unk1 not as expected:\n%v\n%v", c.input.obj.Unk1, serverChallengeXchg.Unk1)
				}
				if c.input.obj.ServerTime != serverChallengeXchg.ServerTime {
					t.Errorf(
						"ServerTime not as expected:\n%v\n%v",
						c.input.obj.ServerTime,
						serverChallengeXchg.ServerTime,
					)
				}
				if !bytes.Equal(c.input.obj.Challenge, serverChallengeXchg.Challenge) {
					t.Errorf("Challenge not as expected:\n%v\n%v", c.input.obj.Challenge, serverChallengeXchg.Challenge)
				}
				if c.input.obj.UnkChallengeEnd != serverChallengeXchg.UnkChallengeEnd {
					t.Errorf(
						"UnkChallengeEnd not as expected:\n%v\n%v",
						c.input.obj.UnkChallengeEnd,
						serverChallengeXchg.UnkChallengeEnd,
					)
				}
				if c.input.obj.UnkObjects != serverChallengeXchg.UnkObjects {
					t.Errorf(
						"UnkObjects not as expected:\n%v\n%v",
						c.input.obj.UnkObjects,
						serverChallengeXchg.UnkObjects,
					)
				}
				if !bytes.Equal(c.input.obj.Unk2, serverChallengeXchg.Unk2) {
					t.Errorf("Unk2 not as expected:\n%v\n%v", c.input.obj.Unk2, serverChallengeXchg.Unk2)
				}
				if c.input.obj.PubKeyLen != serverChallengeXchg.PubKeyLen {
					t.Errorf("PubKeyLen not as expected:\n%v\n%v", c.input.obj.PubKeyLen, serverChallengeXchg.PubKeyLen)
				}
				if !bytes.Equal(c.input.obj.PubKey, serverChallengeXchg.PubKey) {
					t.Errorf("PubKey not as expected:\n%v\n%v", c.input.obj.PubKey, serverChallengeXchg.PubKey)
				}
				if c.input.obj.Unk3 != serverChallengeXchg.Unk3 {
					t.Errorf("Unk3 not as expected:\n%v\n%v", c.input.obj.Unk3, serverChallengeXchg.Unk3)
				}

				return
			},
		)
	}
}
