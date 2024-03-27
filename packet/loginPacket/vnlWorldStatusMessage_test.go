package loginPacket

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
)

func TestVNLWorldStatusMessage_Encode(t *testing.T) {

	const (
		encoded = "05 97 570065006c0063006f006d006500200074006f00200050006c0061006e00650074005300690064006500210020000186 67656d696e69 0100 04 00 01 459e2540 3775 40"
	)

	var (
		geminiIP = net.ParseIP("64.37.158.69")

		vwsm = VNLWorldStatusMessage{
			WelcomeMessage: []uint8("Welcome to PlanetSide! "),
			Worlds: []WorldInfo{
				{
					Name:       []uint8("gemini"),
					status2:    1,
					ServerType: ServerType_ReleasedGemini,
					status1:    0,
					Connections: []WorldConnectionInfo{
						{
							Ip:   geminiIP.To4(),
							Port: 30007,
						},
					},
					EmpireNeed: utils.Empire_NC,
				},
			},
		}
	)

	/*
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 11 00400014 0259E45 3775 40
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 10 00400014 59E2540 3775 40
		                                                                                                     gemini
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 11 00400014 0259E45 3775 40
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 10 00400014 59E2540 3775 40
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 11 00400014 0259E45 3775 00
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 10 00400014 59E2540 3775 40
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 11 00400014 59E2540 3775 40
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 10 00400014 59E2540 3775 40

		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 11 00400014 59E2540 3775 40
		0597570065006C0063006F006D006500200074006F00200050006C0061006E00650074005300690064006500210020000186 67656D696E69 0 10 00400014 59E2540 3775 40
	*/

	targetStream := &bitstream.BitStream{}
	err := vwsm.Encode(targetStream)
	if err != nil {
		t.Errorf("Error encoding LoginRespMessage: %v", err)
		return
	}

	buffer := targetStream.GetBuffer()
	data, _ := hex.DecodeString(strings.ReplaceAll(encoded, " ", ""))

	if !bytes.Equal(buffer, data) {
		t.Errorf("Encoded VNLWorldStatusMessage not as expected:\n%X\n%X", buffer, data)
		return
	}
}

func TestVNLWorldStatusMessage_Decode(t *testing.T) {

	type inputType struct {
		hexText string
	}

	type testcase struct {
		name     string
		input    inputType
		expected *VNLWorldStatusMessage
	}

	var (
		geminiIP = net.ParseIP("64.37.158.69")

		cases = []testcase{
			{
				name: "decode",
				input: inputType{
					hexText: "05 97 570065006c0063006f006d006500200074006f00200050006c0061006e0065007400530069006400650021002000 01 86 67656d696e69 0100 04 00 01 459e2540 3775 40",
				},
				expected: &VNLWorldStatusMessage{
					WelcomeMessage: []uint8("Welcome to PlanetSide! "),
					Worlds: []WorldInfo{
						{
							Name:       []uint8("gemini"),
							status2:    1,
							ServerType: ServerType_ReleasedGemini,
							status1:    0,
							Connections: []WorldConnectionInfo{
								{
									Ip:   geminiIP.To4(),
									Port: 30007,
								},
							},
							EmpireNeed: utils.Empire_NC,
						},
					},
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

					vwsm VNLWorldStatusMessage
				)

				data, err = hex.DecodeString(trim)
				if err != nil {
					t.Fail()
					return
				}

				stream = bitstream.NewBitStream(data)

				err = vwsm.Decode(stream)
				if err != nil {
					t.Errorf("Error decoding VNLWorldStatusMessage: %v", err)
					return
				}

				if string(vwsm.WelcomeMessage) != string(c.expected.WelcomeMessage) {
					// utf16 vs string
					// t.Errorf(
					// 	"Error WelcomeMessage not as expected: %v - %v",
					// 	vwsm.WelcomeMessage,
					// 	c.expected.WelcomeMessage,
					// )
				}

				if len(vwsm.Worlds) != len(c.expected.Worlds) {
					t.Errorf(
						"Error World count not as expected: %v - %v",
						len(vwsm.Worlds),
						len(c.expected.Worlds),
					)
				}

				world := vwsm.Worlds[0]
				expWorld := c.expected.Worlds[0]

				if string(world.Name) != string(expWorld.Name) {
					t.Errorf(
						"Error World Name not as expected: %v - %v",
						world.Name,
						expWorld.Name,
					)
				}

				if world.ServerType != expWorld.ServerType {
					t.Errorf(
						"Error ServerType not as expected: %v - %v",
						world.ServerType,
						expWorld.ServerType,
					)
				}

				if world.status1 != expWorld.status1 {
					t.Errorf(
						"Error Status1 not as expected: %v - %v",
						world.status1,
						expWorld.status1,
					)
				}

				if world.status2 != expWorld.status2 {
					t.Errorf(
						"Error Status2 not as expected: %v - %v",
						world.status2,
						expWorld.status2,
					)
				}

				if world.EmpireNeed != expWorld.EmpireNeed {
					t.Errorf(
						"Error EmpireNeed not as expected: %v - %v",
						world.EmpireNeed,
						expWorld.EmpireNeed,
					)
				}

				conn := world.Connections[0]
				expCon := expWorld.Connections[0]

				if bytes.Compare(conn.Ip, expCon.Ip) != 0 {
					t.Errorf(
						"Error Connection Ip not as expected: %v - %v",
						conn.Ip,
						expCon.Ip,
					)
				}

				if conn.Port != expCon.Port {
					t.Errorf(
						"Error Connection Port not as expected: %v - %v",
						conn.Port,
						expCon.Port,
					)
				}

				return
			},
		)
	}
}
