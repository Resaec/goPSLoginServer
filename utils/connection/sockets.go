package connection

import (
	"fmt"
	"net"
)

func createSocketUDP(host string, port int32) (socket *net.UDPConn, err error) {

	var (
		address *net.UDPAddr

		addressPort = fmt.Sprintf("%s:%d", host, port)
	)

	address, err = net.ResolveUDPAddr("udp4", addressPort)
	if err != nil {
		fmt.Println(err)
		return
	}

	socket, err = net.ListenUDP("udp4", address)
	if err != nil {
		fmt.Println(err)
		return
	}

	return
}

func createSocketTCP(host string, port int32) (listener *net.TCPListener, err error) {

	var (
		address *net.TCPAddr

		addressPort = fmt.Sprintf("%s:%d", host, port)
	)

	address, err = net.ResolveTCPAddr("tcp4", addressPort)
	if err != nil {
		fmt.Println(err)
		return
	}

	listener, err = net.ListenTCP("tcp4", address)
	if err != nil {
		fmt.Println(err)
		return
	}

	return
}
