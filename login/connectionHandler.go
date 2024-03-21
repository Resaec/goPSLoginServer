package login

import (
	"net"

	"goPSLoginServer/packet/packetHandler"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/bitstream"
	"goPSLoginServer/utils/config"
	"goPSLoginServer/utils/connection"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
)

func HandleLogin() {

	var (
		err error

		loginServerConfig = config.GetInstance().LoginServer

		sess *session.Session
	)

	// notify the main routine once the LoginServer is gone
	defer utils.GlobalWaitGroup.Done()

	// open the UDP socket for the LoginServer
	utils.LoginUDPSocket, err = connection.NewSocket(
		loginServerConfig.IP,
		loginServerConfig.Port,
		connection.SocketType_UDP,
	)
	if err != nil {
		logging.Errf("Error creating new socket: %v", err)
		return
	}
	defer utils.LoginUDPSocket.CloseSocket()

	logging.Infof("Opened socket on %s:%d", loginServerConfig.IP, loginServerConfig.Port)

	// handle incoming connections indefinitely
	for {

		var (
			isClientStartup bool

			header uint8

			buffer []uint8

			readCount            int
			readAddress          *net.UDPAddr
			readAddressInterface interface{}

			response *bitstream.BitStream

			stream *bitstream.BitStream
		)

		// blocking until new data is received
		buffer, readCount, readAddressInterface, err = utils.LoginUDPSocket.ReadFromSocket()

		// the following part in whole might need to go into a go routine to allow parallel client interaction
		readAddress = (readAddressInterface).(*net.UDPAddr)

		stream = bitstream.NewBitStream(buffer[:readCount])

		// get packet header for session generation checks
		stream.DeltaPosBytes(1)
		stream.ReadUint8(&header, false)

		stream.ResetStream()

		// check if this should be a new session
		if header == 0x01 {
			isClientStartup = true
		}

		logging.LogPacket("UDP", "Login", utils.LoginUDPSocket.GetLocalAddress(), readAddress, buffer[:readCount], true)

		// get session by endpoint
		sess = session.GetSessionHandler().GetOrCreateSession(readAddress, isClientStartup)

		// check for invalid packet
		if sess == nil {
			logging.Errf("Dropping packet for client %s because it arrived out of session!", readAddress)
			continue
		}

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

			continue
		}

		packetHandler.PreparePacketForSending(response, sess)
		err = packetHandler.SendPacket(response, sess)
		if err != nil {
			logging.Errf("Error sending packet: %v", err)
			continue
		}
	}
}
