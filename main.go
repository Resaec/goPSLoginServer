package main

import (
	"goPSLoginServer/login"
	"goPSLoginServer/utils"
)

func main() {

	utils.GlobalWaitGroup.Add(3)

	utils.GlobalWaitGroup.Add(1)

	go login.HandleLogin(51000)

	utils.GlobalWaitGroup.Wait()
}
