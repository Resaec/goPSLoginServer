package logging

import (
	"fmt"
	"net"
	"sync"

	"goPSLoginServer/utils/config"
)

var (
	writeLock sync.Mutex

	/*
		0 ERROR
		1 WARNING
		2 NOTICE
		3 INFO
		4 DEBUG
		5 VERBOSE
		6 TRACE
	*/
	loglevel int8 = 2
)

func Init() {

	var (
		conf = config.GetInstance()
	)

	loglevel = conf.LoginServer.LogLevel
}

func log(message string) {

	writeLock.Lock()

	fmt.Println(message)

	writeLock.Unlock()
}

func Traceln(message string) {

	if loglevel < 6 {
		return
	}

	log(fmt.Sprintf("[TRACE] %s", message))
}

func Tracef(format string, data ...interface{}) {

	Traceln(fmt.Sprintf(format, data...))
}

func Verboseln(message string) {

	if loglevel < 5 {
		return
	}

	log(fmt.Sprintf("[VERBOSE] %s", message))
}

func Verbosef(format string, data ...interface{}) {

	Verboseln(fmt.Sprintf(format, data...))
}

func Debugln(message string) {

	if loglevel < 4 {
		return
	}

	log(fmt.Sprintf("[DEBUG] %s", message))
}

func Debugf(format string, data ...interface{}) {

	Debugln(fmt.Sprintf(format, data...))
}

func Infoln(message string) {

	if loglevel < 3 {
		return
	}

	log(fmt.Sprintf("[INFO] %s", message))
}

func Infof(format string, data ...interface{}) {

	Infoln(fmt.Sprintf(format, data...))
}

func Noticeln(message string) {

	if loglevel < 2 {
		return
	}

	log(fmt.Sprintf("[NOTICE] %s", message))
}

func Noticef(format string, data ...interface{}) {

	Noticeln(fmt.Sprintf(format, data...))
}

func Warnln(message string) {

	if loglevel < 1 {
		return
	}

	log(fmt.Sprintf("[WARN] %s", message))
}

func Warnf(format string, data ...interface{}) {

	Warnln(fmt.Sprintf(format, data...))
}

func Errln(message string) {

	if loglevel < 0 {
		return
	}

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

	Verboseln(message)
}
