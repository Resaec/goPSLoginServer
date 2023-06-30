package utils

import (
	"sync"

	"goPSLoginServer/utils/connection"
)

const (
	Empire_TR = iota
	Empire_NC
	Empire_VC
)

var (
	LoginUDPSocket *connection.Socket

	GlobalWaitGroup sync.WaitGroup
)
