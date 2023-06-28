package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/monnand/dhkx"
)

func TestRC5(t *testing.T) {

	type inputType struct {
		key     []uint8
		message []uint8
	}

	type testcase struct {
		name  string
		input inputType
	}

	var (
		cases = []testcase{
			{
				name: "Encrypt Decrypt",
				input: inputType{
					key:     bytes.Repeat([]uint8{0x41}, 16),
					message: bytes.Repeat([]uint8{0x42}, 32),
				},
			},
		}
	)

	for _, c := range cases {

		t.Run(
			c.name, func(t *testing.T) {

				var (
					encrypted []uint8
					decrypted []uint8
				)

				encrypted = EncryptPacket(c.input.message, c.input.key)
				decrypted = DecryptPacket(encrypted, c.input.key)

				if bytes.Equal(encrypted, c.input.message) {
					t.Errorf("Message was not encrypted")
					return
				}

				if !bytes.Equal(decrypted, c.input.message) {
					t.Errorf("Message was not decrypted to original message:\n%X\n%X", decrypted, c.input.message)
					return
				}

				return
			},
		)
	}
}

func TestCalcMD5Mac(t *testing.T) {

	type inputType struct {
		key     string
		message string
	}

	type testcase struct {
		name     string
		input    inputType
		expected string
	}

	var (
		cases = []testcase{
			{
				name: "Calculate MC5MAC",
				input: inputType{
					key: "377b60f8790f91b35a9da82945743da9",
					message: fmt.Sprintf(
						"%x",
						[]uint8{'m', 'a', 's', 't', 'e', 'r', ' ', 's', 'e', 'c', 'r', 'e', 't'},
					) + "b4aea1559444a20b6112a2892de40eac00000000c8aea155b53d187076b79abab59001b600000000",
				},

				expected: "5aa15de41f5220cf5cca489155e1438c5aa15de4",
			},
		}
	)

	for _, c := range cases {

		t.Run(
			c.name, func(t *testing.T) {

				var (
					err error

					key, message, output, expected []uint8

					// mac *md5mac.MD5MAC

					hexKey     = c.input.key
					hexMessage = c.input.message
				)

				expected, err = hex.DecodeString(c.expected)
				if err != nil {
					t.Errorf("Failed to decode expected: %v", err)
					return
				}

				key, err = hex.DecodeString(hexKey)
				if err != nil {
					t.Errorf("Failed to decode key: %v", err)
					return
				}

				message, err = hex.DecodeString(hexMessage)
				if err != nil {
					t.Errorf("Failed to decode message: %v", err)
					return
				}

				output = make([]uint8, 20)
				err = CalcMD5Mac(key, message, &output)

				if !bytes.Equal(output, expected) {
					t.Errorf("Output not as expected:\n%X\n%X", output, c.expected)
					return
				}

				return
			},
		)
	}
}

func TestDiffieHellman(t *testing.T) {

	type inputType struct {
		p big.Int
		g big.Int
	}

	type testcase struct {
		name  string
		input inputType
	}

	var (
		maxBigInt = big.NewInt(0).Exp(big.NewInt(2), big.NewInt(130), nil)
		p, _      = rand.Int(rand.Reader, maxBigInt)
		g, _      = rand.Int(rand.Reader, maxBigInt)
	)

	var (
		cases = []testcase{
			{
				name: "Agree on secret",
				input: inputType{
					p: *p,
					g: *g,
				},
			},
		}
	)

	for _, c := range cases {

		t.Run(
			c.name, func(t *testing.T) {

				var (
					err error

					group *dhkx.DHGroup

					keyAlice   *dhkx.DHKey
					pubAlice   *dhkx.DHKey
					agreeAlice *dhkx.DHKey

					keyBob   *dhkx.DHKey
					pubBob   *dhkx.DHKey
					agreeBob *dhkx.DHKey
				)

				// generate group from provided P and G
				group = dhkx.CreateGroup(&c.input.p, &c.input.g)

				// generate Alice's private key
				keyAlice, err = group.GeneratePrivateKey(nil)
				if err != nil {
					t.Errorf("Could not generate Alice's key: %v", err)
					return
				}

				// derive the public key
				pubAlice = dhkx.NewPublicKey(keyAlice.Bytes())

				// generate Bob's private key
				keyBob, err = group.GeneratePrivateKey(nil)
				if err != nil {
					t.Errorf("Could not generate Bob's key: %v", err)
					return
				}

				// derive the public key
				pubBob = dhkx.NewPublicKey(keyBob.Bytes())

				agreeAlice, err = group.ComputeKey(pubBob, keyAlice)
				if err != nil {
					t.Errorf("Could not generate shared secret for Alice: %v", err)
					return
				}

				agreeBob, err = group.ComputeKey(pubAlice, keyBob)
				if err != nil {
					t.Errorf("Could not generate shared secret for Bob: %v", err)
					return
				}

				if !bytes.Equal(agreeAlice.Bytes(), agreeBob.Bytes()) {
					t.Errorf("Shared secret not equal: %v", err)
					return
				}

				return
			},
		)
	}
}
