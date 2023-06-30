package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/Resaec/go-md5mac"
	"github.com/Resaec/go-rc5"
	"golang.org/x/exp/rand"

	"goPSLoginServer/utils/logging"
)

const (
	RC5_BLOCK_SIZE = 8
)

func fixRC5ResultOrder(blocks []uint8) []uint8 {

	blockSize := 8
	numBlocks := len(blocks) / blockSize
	result := make([]uint8, len(blocks))

	for i := 0; i < numBlocks; i++ {
		startIndex := i * blockSize

		result[startIndex+0] = blocks[startIndex+3]
		result[startIndex+1] = blocks[startIndex+2]
		result[startIndex+2] = blocks[startIndex+1]
		result[startIndex+3] = blocks[startIndex+0]

		result[startIndex+4] = blocks[startIndex+7]
		result[startIndex+5] = blocks[startIndex+6]
		result[startIndex+6] = blocks[startIndex+5]
		result[startIndex+7] = blocks[startIndex+4]
	}

	return result
}

func fixRC5DecodePadding(data []uint8) []uint8 {

	var (
		padHint uint8

		dataLen      = len(data)
		missingBytes = dataLen % RC5_BLOCK_SIZE
	)

	if missingBytes == 0 {
		return data
	}

	// get the pad hint from the end of the data
	padHint = data[dataLen-1]

	// remove old hint
	data[dataLen-1] = 0x00

	// add missing bytes
	data = append(data, bytes.Repeat([]uint8{0x00}, missingBytes)...)

	// set the hint at the new end of the data
	data[len(data)-1] = padHint

	return data
}

func CalcMD5Mac(key, data []uint8, outBuf *[]uint8) (err error) {

	var (
		tempBuff []uint8

		md5macObj *md5mac.MD5MAC

		bufferSize = len(*outBuf)
	)

	key = key[:16]

	tempBuff = make([]uint8, bufferSize)

	md5macObj, err = md5mac.NewMD5MACWithKey(key)
	if err != nil {
		return err
	}

	md5macObj.Update(data)
	md5macObj.Finalize(data)

	for i := 0; i < bufferSize; i += md5mac.MACLENGTH {
		copy(tempBuff[i:], data[:16])
	}

	*outBuf = tempBuff

	return
}

func padPacketForEncryption(data []uint8) (result []uint8) {

	var (
		paddingEncoded uint8

		padding         []uint8
		dataWithPadding []uint8

		remainder     = len(data) % RC5_BLOCK_SIZE
		paddingNeeded = RC5_BLOCK_SIZE - remainder
	)

	// substract the byte informing about the padding size
	paddingNeeded -= 1

	// Encode paddingNeeded as byte
	paddingEncoded = uint8(paddingNeeded)

	// Create dataWithPadding
	padding = bytes.Repeat([]uint8{0x00}, paddingNeeded)
	dataWithPadding = append(data, padding...)

	// append padding size hint
	result = append(dataWithPadding, paddingEncoded)

	fmt.Printf("%s\n", hex.EncodeToString(result))

	return
}

func EncryptPacket(data []uint8, key []uint8) (result []uint8) {

	var (
		dataLen     = len(data)
		cipher, err = rc5.NewCipher32(key, 16)
	)

	if !IsValidRC5Buffer(data) {
		err = errors.New("input is not a valid RC5 buffer")
		return
	}

	if err != nil {
		logging.Errf("Error creating encryption cipher: %v", err)
		return
	}

	result = make([]uint8, dataLen)

	for i := 0; i < dataLen; i += 8 {
		cipher.Encrypt(result[i:i+8], data[i:i+8])
	}

	result = fixRC5ResultOrder(result)

	return
}

func DecryptPacket(data []uint8, key []uint8) (result []uint8) {

	var (
		dataLen     = len(data)
		cipher, err = rc5.NewCipher32(key, 16)
	)

	if !IsValidRC5Buffer(data) {
		err = errors.New("input is not a valid RC5 buffer")
		return
	}

	if err != nil {
		logging.Errf("Error creating decryption cipher: %v", err)
		return
	}

	result = make([]uint8, dataLen)

	for i := 0; i < dataLen; i += 8 {
		cipher.Decrypt(result[i:i+8], data[i:i+8])
	}

	// result = fixRC5DecodePadding(result)

	return
}

func IsValidRC5Buffer(buffer []byte) bool {

	if buffer == nil {
		return false
	}

	if len(buffer)%RC5_BLOCK_SIZE != 0 {
		return false
	}

	return true
}

func GenerateToken() (token []uint8) {

	token = make([]uint8, 32)
	_, _ = rand.Read(token)

	return
}
