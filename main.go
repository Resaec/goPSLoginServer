package main

import (
	"encoding/hex"

	"goPSLoginServer/admin"
	"goPSLoginServer/login"
	"goPSLoginServer/packet/cryptoPacket"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/world"
)

/*

Ports

UDP

51000/udp Login
51001/udp World

TCP / Admin

51002/tcp

*/

func main() {

	var (
		challengeResult = "ea3cf05da5cb42568bb91aa7"
		pubKey          = "eddc35f252b02d0e496ba27354578e73"
		input, _        = hex.DecodeString("101000" + pubKey + "0114" + challengeResult)

		stream = bitstream.NewBitStream(input)
	)

	clientFinished := cryptoPacket.ClientFinished{}
	err := clientFinished.Decode(stream)
	if err != nil {
		return
	}

	utils.GlobalWaitGroup.Add(3)

	go login.HandleLogin(51000)
	go world.HandleWorld(51001)
	go admin.HandleAdmin(51002)

	utils.GlobalWaitGroup.Wait()
}
