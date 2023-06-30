package world

import (
	"goPSLoginServer/utils"
)

func HandleWorld(port int32) {

	// var (
	// 	err error
	//
	// 	readCount   int
	// 	readAddress *net.UDPAddr
	//
	// 	socket *net.UDPConn
	//
	// 	buffer = make([]byte, 1024)
	// )
	//
	// socket, err = connection.CreateSocketUDP(port)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }
	// defer socket.Close()
	//
	// for {
	//
	// 	readCount, readAddress, err = socket.ReadFromUDP(buffer)
	// 	if err != nil {
	// 		fmt.Println(err)
	// 		return
	// 	}
	//
	// 	logging.LogPacket("UDP", "World", socket.LocalAddr(), readAddress, buffer[:readCount], true)
	// }

	utils.GlobalWaitGroup.Done()
}
