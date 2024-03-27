package crypto

import (
	"errors"

	"github.com/Resaec/go-md5mac"
	"github.com/Resaec/go-rc5"
	"golang.org/x/exp/rand"

	"goPSLoginServer/utils/logging"
)

const (
	RC5_BLOCK_SIZE = 8
)

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

	token = make([]uint8, 16)
	_, _ = rand.Read(token)

	return
}
