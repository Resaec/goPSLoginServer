package admin

import (
	"fmt"
	"net"
	"time"

	"goPSLoginServer/utils"
	"goPSLoginServer/utils/connection"
	"goPSLoginServer/utils/logging"
)

func HandleAdmin(port int32) {

	var (
		err error

		conn     *net.TCPConn
		listener *net.TCPListener
	)

	listener, err = connection.CreateSocketTCP(port)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	for {
		conn, err = listener.AcceptTCP()
		if err != nil {
			fmt.Println(err)
			return
		}

		utils.GlobalWaitGroup.Add(1)

		go handleRequest(conn)
	}

	utils.GlobalWaitGroup.Done()

}

func handleRequest(conn net.Conn) {

	var (
		err error

		readCount int

		buffer []byte
	)

	for {

		err = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		if err != nil {
			fmt.Println(err)
			return
		}

		buffer = make([]byte, 1024)

		readCount, err = conn.Read(buffer[:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Errorf("Admin read timeout: %v", err)
			} else {
				fmt.Errorf("Admin read error: %v", err)
			}

			break
		}

		logging.LogPacket("TCP", "Admin", conn.LocalAddr(), conn.RemoteAddr(), buffer[:readCount], true)
	}

	// readCount, err = conn.Read(buffer)
	// if err != nil {
	//	fmt.Errorf(err.Error())
	//	return
	// }

	// close conn
	conn.Close()

	utils.GlobalWaitGroup.Done()
}
