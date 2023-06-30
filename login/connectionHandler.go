package login

import (
	"encoding/binary"
	"fmt"
	"net"

	"goPSLoginServer/packet/packetHandler"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/connection"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func HandleLogin(port int32) {

	var (
		err error

		responseBuffer []uint8

		readCount   int
		readAddress *net.UDPAddr

		writeCount int

		socket   *net.UDPConn
		response *bitstream.BitStream

		sess *session.Session

		buffer = make([]uint8, 1024*2)
	)

	socket, err = connection.CreateSocketUDP(port)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer socket.Close()

	for {

		var (
			isClientStartup bool

			header uint8

			stream *bitstream.BitStream
		)

		readCount, readAddress, err = socket.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println(err)
			continue
		}

		stream = bitstream.NewBitStream(buffer[:readCount])

		// get packet header for session generation checks
		stream.DeltaPosBytes(1)
		stream.ReadUint8(&header, false)

		stream.ResetStream()

		// check if this should be a new session
		if header == 0x01 {
			isClientStartup = true
		}

		// get clientEndpoint hash from connecting IP
		hash := binary.LittleEndian.Uint32(readAddress.IP)

		// get session by endpoint hash
		sess = session.GetSessionHandler().GetOrCreateSession(hash, isClientStartup)

		// check for invalid packet
		if sess == nil {
			logging.Errf("Dropping packet for client %v because it arrived out of session!", readAddress.IP)
			continue
		}

		logging.LogPacket("UDP", "Login", socket.LocalAddr(), readAddress, buffer[:readCount], true)

		response, err = packetHandler.HandlePacket(stream, sess)
		if err != nil {
			logging.Errf(
				"Error in Login - dropping connection to %s:%d: %v\n",
				readAddress.IP.String(),
				readAddress.Port,
				err,
			)
			continue
		}

		if response == nil {
			logging.Warnf(
				"No response for packet from client %s:%d\n",
				readAddress.IP,
				readAddress.Port,
			)
		}

		responseBuffer = response.GetBuffer()

		logging.LogPacket("UDP", "Login", socket.LocalAddr(), readAddress, responseBuffer, false)

		writeCount, err = socket.WriteToUDP(responseBuffer, readAddress)
		if err != nil {
			logging.Errf(
				"Error answering packet for client %s:%d: %v\n",
				readAddress.IP,
				readAddress.Port,
				err,
			)
			continue
		}

		if uint32(writeCount) != response.GetSize() {
			logging.Warnf(
				"WriteCount of response is not equal to response size %d / %d for client %s:%d\n",
				writeCount,
				response.GetSize(),
				readAddress.IP,
				readAddress.Port,
			)
		}
	}

	utils.GlobalWaitGroup.Done()
}
