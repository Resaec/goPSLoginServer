package connection

import (
	"fmt"
	"net"
)

const (
	SocketType_UDP = iota
	SocketType_TCP
)

type Socket struct {
	protocol  int
	socketUDP *net.UDPConn
	socketTCP *net.TCPListener
}

func NewSocket(host string, port int32, protocol int) (obj *Socket, err error) {

	obj = &Socket{
		protocol: protocol,
	}

	if protocol == SocketType_UDP {
		obj.socketUDP, err = createSocketUDP(host, port)
	} else {
		obj.socketTCP, err = createSocketTCP(host, port)
	}

	if err != nil {
		obj = nil
		err = fmt.Errorf("Error creating Socket: %v", err)
		return
	}

	return
}

func (s *Socket) ReadFromSocket() (buffer []uint8, readCount int, readAddress interface{}, err error) {

	if s.protocol == SocketType_UDP {

		buffer, readCount, readAddress, err = s.readFromUDPSocket()

	} else {

		err = fmt.Errorf("ReadFromSocket for TCP not implemented")

	}

	return
}

func (s *Socket) WriteToSocket(buffer []uint8, targetAddress interface{}) (bytesWritten int, err error) {

	if s.protocol == SocketType_UDP {

		var (
			target = (targetAddress).(*net.UDPAddr)
		)

		bytesWritten, err = s.socketUDP.WriteToUDP(buffer, target)

	} else {

		err = fmt.Errorf("WriteToSocket for TCP not implemented")

	}

	return
}

func (s *Socket) GetLocalAddress() (localAddress net.Addr) {

	if s.protocol == SocketType_UDP {
		return s.socketUDP.LocalAddr()
	} else {
		return s.socketTCP.Addr()
	}
}

func (s *Socket) CloseSocket() (err error) {

	if s.protocol == SocketType_UDP {
		err = s.socketUDP.Close()
	} else {
		err = s.socketTCP.Close()
	}

	return
}

func (s *Socket) readFromUDPSocket() (buffer []uint8, readCount int, readAddress *net.UDPAddr, err error) {

	buffer = make([]uint8, 1024*2)

	readCount, readAddress, err = s.socketUDP.ReadFromUDP(buffer)
	if err != nil {
		err = fmt.Errorf("Error reading from socket: %v", err)
		return
	}

	return
}
