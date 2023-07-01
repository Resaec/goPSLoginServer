package session

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"time"

	"github.com/Resaec/go-md5mac"
	"github.com/monnand/dhkx"
	"golang.org/x/exp/slices"

	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/crypto"
	"goPSLoginServer/utils/logging"
)

const (
	CryptoState_Init      = iota //
	CryptoState_Challenge        //
	CryptoState_Finished
)

type Session struct {
	ClientEndpoint *net.UDPAddr

	CryptoState       int
	CryptoStateSwitch int

	MacBuffer []uint8

	ServerChallengeResult []uint8 // 12

	StoredClientTime      uint32
	StoredClientChallenge []uint8 // 12

	StoredServerTime      uint32
	StoredServerChallenge []uint8 // 12

	dhGroup       *dhkx.DHGroup
	ServerPrivKey *dhkx.DHKey
	ServerPubKey  []uint8

	DecMACKey []uint8
	EncMACKey []uint8

	DecRC5Key []uint8
	EncRC5Key []uint8

	LastPokeMS uint
}

const (
	strMasterSecret    = "master secret"
	strClientExpansion = "client expansion"
	strServerExpansion = "server expansion"
	strClientFinished  = "client finished"
	strServerFinished  = "server finished"
)

func NewSession(clientEndpoint *net.UDPAddr) *Session {
	return &Session{
		ClientEndpoint: clientEndpoint,
		CryptoState:    CryptoState_Init,
	}
}

// This function generates server keys and stores some client info in the session
func (s *Session) GenerateCrypto1(clientTime uint32, clientChallenge []uint8, p, g *big.Int) {

	var (
		err error
	)

	// prepare dhGroup with given (p)rime and (g)enerator
	s.dhGroup = dhkx.CreateGroup(p, g)

	// generate a private key
	s.ServerPrivKey, err = s.dhGroup.GeneratePrivateKey(nil)
	if err != nil {
		logging.Errf("Error generating private key... continuing: %v\n", err)
	}

	// derive public key
	s.ServerPubKey = s.ServerPrivKey.Bytes()

	// store client info
	s.StoredClientTime = clientTime
	s.StoredClientChallenge = clientChallenge

	// store server info
	s.StoredServerTime = uint32(time.Now().Unix())

	s.StoredServerChallenge = make([]uint8, 12)
	_, _ = rand.Read(s.StoredServerChallenge)

	s.CryptoState = CryptoState_Challenge
}

func (s *Session) GenerateCrypto2(clientPubKey []uint8, clientChallengeResult []uint8) {

	var (
		err error

		clientKey   *dhkx.DHKey
		agreedValue *dhkx.DHKey

		masterSecret   []uint8
		expandedDecKey []uint8
		expandedEncKey []uint8
	)

	// make client public key
	clientKey = dhkx.NewPublicKey(clientPubKey)
	agreedValue, err = s.dhGroup.ComputeKey(clientKey, s.ServerPrivKey)

	if err != nil {
		// TODO: Need to terminate session
		logging.Errf("Did not agree on crypto keys: %v", err)
		return
	}

	logging.Debugf("Agreed with: %X", agreedValue.Bytes())

	// Generate the master secret
	agreedMessage := make([]uint8, 0)
	agreedMessage = append(agreedMessage, []uint8(strMasterSecret)...)
	agreedMessage = append(agreedMessage, utils.SliceUint32(s.StoredClientTime)...)
	agreedMessage = append(agreedMessage, s.StoredClientChallenge...)
	agreedMessage = append(agreedMessage, []uint8{0x00, 0x00, 0x00, 0x00}...)
	agreedMessage = append(agreedMessage, utils.SliceUint32(s.StoredServerTime)...)
	agreedMessage = append(agreedMessage, s.StoredServerChallenge...)
	agreedMessage = append(agreedMessage, []uint8{0x00, 0x00, 0x00, 0x00}...)

	logging.Debugf("adreedMessage: %X", agreedMessage)

	masterSecret = make([]uint8, 16)
	err = crypto.CalcMD5Mac(agreedValue.Bytes(), agreedMessage, &masterSecret)
	if err != nil {
		logging.Errf("Could not calculate MAC for masterSecret: %v", err)
		return
	}

	logging.Debugf("masterSecret: %X", masterSecret)

	// Generate RC5 and MAC encryption keys
	switchedServerClientChallenges := make([]uint8, 0)
	switchedServerClientChallenges = append(switchedServerClientChallenges, utils.SliceUint32(s.StoredServerTime)...)
	switchedServerClientChallenges = append(switchedServerClientChallenges, s.StoredServerChallenge...)
	switchedServerClientChallenges = append(switchedServerClientChallenges, []byte{0x00, 0x00, 0x00, 0x00}...)
	switchedServerClientChallenges = append(switchedServerClientChallenges, utils.SliceUint32(s.StoredClientTime)...)
	switchedServerClientChallenges = append(switchedServerClientChallenges, s.StoredClientChallenge...)
	switchedServerClientChallenges = append(switchedServerClientChallenges, []byte{0x00, 0x00, 0x00, 0x00}...)

	decExpansionBuffer := make([]byte, 0)
	decExpansionBuffer = append(decExpansionBuffer, []byte(strClientExpansion)...)
	decExpansionBuffer = append(decExpansionBuffer, []byte{0x00, 0x00}...)
	decExpansionBuffer = append(decExpansionBuffer, switchedServerClientChallenges...)

	logging.Debugf("decExpansionBuffer: %X", decExpansionBuffer)

	encExpansionBuffer := make([]byte, 0)
	encExpansionBuffer = append(encExpansionBuffer, []byte(strServerExpansion)...)
	encExpansionBuffer = append(encExpansionBuffer, []byte{0x00, 0x00}...)
	encExpansionBuffer = append(encExpansionBuffer, switchedServerClientChallenges...)

	logging.Debugf("encExpansionBuffer: %X", encExpansionBuffer)

	expandedDecKey = make([]uint8, 64)
	err = crypto.CalcMD5Mac(masterSecret, decExpansionBuffer, &expandedDecKey)
	if err != nil {
		logging.Errf("Could not calculate MAC for expandedDecKey: %v", err)
		return
	}

	logging.Debugf("expandedDecKey: %X", expandedDecKey)

	expandedEncKey = make([]uint8, 64)
	err = crypto.CalcMD5Mac(masterSecret, encExpansionBuffer, &expandedEncKey)
	if err != nil {
		logging.Errf("Could not calculate MAC for expandedDecKey: %v", err)
		return
	}

	logging.Debugf("expandedEncKey: %X", expandedEncKey)

	// decKey := make([]byte, 20)
	// copy(decKey[:], expandedDecKey[:20])
	s.DecRC5Key = expandedDecKey[:20]

	// encKey := make([]byte, 20)
	// copy(encKey[:], expandedEncKey[:20])
	s.EncRC5Key = expandedEncKey[:20]

	// DecMACKey := make([]byte, 16)
	// copy(DecMACKey[:], expandedDecKey[20:36])
	s.DecMACKey = expandedDecKey[20 : 20+16]

	// EncMACKey := make([]byte, 16)
	// copy(EncMACKey[:], expandedEncKey[20:36])
	s.EncMACKey = expandedEncKey[20 : 20+16]

	logging.Debugf("decKey:    %X", s.DecRC5Key)
	logging.Debugf("encKey:    %X", s.EncRC5Key)
	logging.Debugf("DecMACKey: %X", s.DecMACKey)
	logging.Debugf("EncMACKey: %X", s.EncMACKey)

	// Generate server challenge result
	serverChallengeResultBuffer := make([]byte, 0)
	serverChallengeResultBuffer = append(serverChallengeResultBuffer, []uint8(strServerFinished)...)
	serverChallengeResultBuffer = append(serverChallengeResultBuffer, s.MacBuffer...)
	serverChallengeResultBuffer = append(serverChallengeResultBuffer, 0x01)

	s.ServerChallengeResult = make([]uint8, 12)
	err = crypto.CalcMD5Mac(masterSecret, serverChallengeResultBuffer, &s.ServerChallengeResult)
	if err != nil {
		logging.Errf("Could not calculate MAC for ServerChallengeResult: %v", err)
		return
	}

	logging.Debugf("ServerChallengeResult: %X", s.ServerChallengeResult)

	// MAC buffer no longer needed
	s.MacBuffer = nil

	s.CryptoState = CryptoState_Finished
}

func (s *Session) DecryptPacket(stream *bitstream.BitStream, outBuf *[]uint8) (err error) {

	var (
		paddingUsed      int
		messageAndMacLen int

		data          []uint8
		messageMAC    []uint8
		calculatedMac []uint8

		mac *md5mac.MD5MAC
	)

	if s.CryptoState != CryptoState_Finished {
		err = fmt.Errorf("Tried to decrypt with unfinished crypto session! %v", s.ClientEndpoint)
		return
	}

	// get message from stream
	data = stream.GetBufferFromHead()

	if len(data) == 0 {
		err = fmt.Errorf("DecryptPacket packet is empty")
		return
	}

	logging.Debugf("%18s %X", "Pre Decode", data)

	// decrypt message
	data = crypto.DecryptPacket(data, s.DecRC5Key)

	logging.Debugf("%18s %X", "Post Decode", data)

	// get RC5 padding len
	paddingUsed = int(data[len(data)-1])

	// add padding value itself
	paddingUsed++

	// remove padding from data
	data = data[:len(data)-paddingUsed]

	logging.Debugf("%18s %X", "Message - Padding", data)

	messageAndMacLen = len(data)
	if messageAndMacLen < md5mac.MACLENGTH {
		err = fmt.Errorf("DecryptPacket message not large enough for 16-Byte MAC: %d/16+\n", messageAndMacLen)
		return
	}

	// get MAC
	messageMAC = data[messageAndMacLen-md5mac.MACLENGTH:]

	logging.Debugf("%18s %X", "MAC", messageMAC)

	// drop MAC from data
	data = data[:messageAndMacLen-md5mac.MACLENGTH]

	logging.Debugf("%18s %X", "Message - MAC", data)

	mac, err = md5mac.NewMD5MACWithKey(s.DecMACKey)
	if err != nil {
		err = fmt.Errorf("DecryptPacket: Could not make MAC object: %v\n", err)
		return
	}

	// generate MAC for received message
	calculatedMac = mac.UpdateFinalize(data)

	logging.Debugf("%18s %X", "Calculated MAC", calculatedMac)

	// check MACs match
	if slices.Compare(calculatedMac, messageMAC) != 0 {
		err = fmt.Errorf(
			"DecryptPacket: MAC missmatch\n"+
				"Got: %v\n"+
				"Exp: %s\n",
			messageMAC,
			calculatedMac,
		)

		return
	}

	*outBuf = data

	return
}

func (s *Session) EncryptPacket(data *[]uint8) bool {

	var (
		err error

		requiredPadding int

		calculatedMac []uint8
		padding       []uint8

		message = make([]uint8, 0, 100)

		mac *md5mac.MD5MAC
	)

	if s.CryptoState != CryptoState_Finished {
		logging.Errf("Tried to encrypt with unfinished crypto session! %v", s.ClientEndpoint)
		return false
	}

	message = append(message, *data...)

	logging.Debugf("%18s %X", "Message", message)

	// get mac of message
	mac, err = md5mac.NewMD5MACWithKey(s.EncMACKey)
	if err != nil {
		logging.Errf("EncryptPacket: Could not make MAC object: %v", err)
		return false
	}

	calculatedMac = mac.UpdateFinalize(message)

	logging.Debugf("%18s %X", "MAC", calculatedMac)

	// append mac to message
	message = append(message, calculatedMac...)

	logging.Debugf("%18s %X", "Message + MAC", message)

	requiredPadding = crypto.RC5_BLOCK_SIZE - (len(message) % crypto.RC5_BLOCK_SIZE) - 1

	// generate and append padding for message
	padding = bytes.Repeat([]byte{0x00}, requiredPadding)
	message = append(message, padding...)

	logging.Debugf("%18s %X", "Padded", message)

	// append padding hint to message
	message = append(message, uint8(requiredPadding))

	logging.Debugf("%18s %X", "Pre EncryptPacket", message)

	// encrypt using RC5 session key
	message = crypto.EncryptPacket(message, s.EncRC5Key)

	logging.Debugf("%18s %X", "Post EncryptPacket", message)

	*data = message

	return true
}
