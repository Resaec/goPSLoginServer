package logging

import (
	"fmt"
	"net"
	"sync"
)

var (
	writeLock sync.Mutex
)

func log(message string) {

	writeLock.Lock()

	fmt.Println(message)

	writeLock.Unlock()
}

func Debugln(message string) {

	// log(fmt.Sprintf("[DEBUG] %s", message))
}

func Debugf(format string, data ...interface{}) {

	// Infoln(fmt.Sprintf(format, data...))
}

func Infoln(message string) {

	log(fmt.Sprintf("[INFO] %s", message))
}

func Infof(format string, data ...interface{}) {

	Infoln(fmt.Sprintf(format, data...))
}

func Warnln(message string) {

	log(fmt.Sprintf("[WARN] %s", message))
}

func Warnf(format string, data ...interface{}) {

	Warnln(fmt.Sprintf(format, data...))
}

func Errln(message string) {

	log(fmt.Sprintf("[ERROR] %s", message))
}

func Errf(format string, data ...interface{}) {

	Errln(fmt.Sprintf(format, data...))
}

func LogPacket(proto string, source string, local net.Addr, remote net.Addr, packet []byte, isIncoming bool) {

	var (
		direction = "<-"
		message   string

		size = len(packet)
	)

	if !isIncoming {
		direction = "->"
	}

	message = fmt.Sprintf(
		"[%5s] %s %11s %11s [%4d] %s %X",
		source,
		proto,
		local.String(),
		remote.String(),
		size,
		direction,
		packet,
	)

	Debugln(message)
}
