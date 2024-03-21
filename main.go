package main

import (
	"goPSLoginServer/login"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/config"
	"goPSLoginServer/utils/logging"
)

func main() {

	// init
	_ = config.GetInstance()
	logging.Init()

	logging.Noticeln(`   ___  ________`)
	logging.Noticeln(`  / _ \/ __/ __/__  _______ _  _____ ____`)
	logging.Noticeln(` / ___/\ \/ _// _ \/ __/ -_) |/ / -_) __/`)
	logging.Noticeln(`/_/  /___/_/  \___/_/  \__/|___/\__/_/   `)
	logging.Noticeln(`   PSForever Server - PSForever Project`)
	logging.Noticeln(`        http://psforever.net`)
	logging.Noticeln(``)

	utils.GlobalWaitGroup.Add(1)

	go login.HandleLogin()

	utils.GlobalWaitGroup.Wait()
}
