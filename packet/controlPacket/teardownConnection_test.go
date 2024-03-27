package controlPacket

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestTeardownConnection_Encode(t *testing.T) {

	type inputType struct {
		obj *TeardownConnection
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
					&TeardownConnection{
						ClientNonce: 391597826,
						Unk0:        0,
						Unk1:        6,
					},
				},

				expected: "0005 024F5717 0006",
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
					t.Errorf("Error encoding TeardownConnection: %v", err)
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
func TestTeardownConnection_Decode(t *testing.T) {

	type inputType struct {
		obj *TeardownConnection
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
					&TeardownConnection{
						ClientNonce: 391597826,
						Unk0:        0,
						Unk1:        6,
					},
				},

				expected: "0005 024F5717 0006",
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

					stream             *bitstream.BitStream
					teardownConnection TeardownConnection

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

				err = teardownConnection.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding ServerChallengeXchg: %v", err)
					return
				}

				// check if all values are the same
				if c.input.obj.ClientNonce != teardownConnection.ClientNonce {
					t.Errorf(
						"ClientNonce not as expected:\n%v\n%v",
						c.input.obj.ClientNonce,
						teardownConnection.ClientNonce,
					)
				}

				if c.input.obj.Unk0 != teardownConnection.Unk0 {
					t.Errorf("Unk0 not as expected:\n%v\n%v", c.input.obj.Unk0, teardownConnection.Unk0)
				}

				if c.input.obj.Unk1 != teardownConnection.Unk1 {
					t.Errorf("Unk1 not as expected:\n%v\n%v", c.input.obj.Unk1, teardownConnection.Unk1)
				}

				return
			},
		)
	}
}
