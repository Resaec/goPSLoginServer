package main

import (
	"goPSLoginServer/admin"
	"goPSLoginServer/login"
	"goPSLoginServer/utils"
	"goPSLoginServer/world"
)

/*

Ports

UDP

51000/udp Login
51001/udp World

TCP / Admin

51002/tcp

*/

func main() {

	utils.GlobalWaitGroup.Add(3)

	go login.HandleLogin(51000)
	go world.HandleWorld(51001)
	go admin.HandleAdmin(51002)

	utils.GlobalWaitGroup.Wait()
}
