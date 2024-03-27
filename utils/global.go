package utils

import (
	"sync"

	"goPSLoginServer/utils/connection"
)

const (
	Empire_TR = iota
	Empire_NC
	Empire_VS
	Empire_NONE
)

var (
	LoginUDPSocket *connection.Socket

	GlobalWaitGroup sync.WaitGroup
)
