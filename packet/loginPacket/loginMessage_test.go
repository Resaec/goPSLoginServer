package loginPacket

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"goPSLoginServer/utils/bitstream"
)

func TestLoginMessage_Decode(t *testing.T) {

	type inputType struct {
		hexText string
	}

	type testcase struct {
		name     string
		input    inputType
		expected *LoginMessage
	}

	var (
		cases = []testcase{
			{
				name: "decode",
				input: inputType{
					hexText: "030000000F0000008B44656320203220 32303039420061736466843132333454 000000",
				},
				expected: &LoginMessage{
					MajorVersion:    3,
					MinorVersion:    15,
					BuildDate:       []uint8("Dec  2 2009"),
					CredentialsType: LOGIN_MESSAGE_CREDENTIAL_PASSWORD,
					Username:        []uint8("asdf"),
					Password:        []uint8("1234"),
					Revision:        84,
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

					loginMessage LoginMessage
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = bitstream.NewBitStream(data)

				err = loginMessage.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding LoginMessage: %v", err)
					return
				}

				if reflect.DeepEqual(loginMessage, c.expected) {
					t.Errorf("Error LoginMessage not decoded as expected")
				}

				return
			},
		)
	}
}
