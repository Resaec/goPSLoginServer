package main

import (
	"goPSLoginServer/login"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/config"
	"goPSLoginServer/utils/logging"
)

func main() {

	utils.GlobalWaitGroup.Add(3)
	// init
	_ = config.GetInstance()

	utils.GlobalWaitGroup.Add(1)

	go login.HandleLogin()

	utils.GlobalWaitGroup.Wait()
}
