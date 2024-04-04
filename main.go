package main

import (
	"time"

	"goPSLoginServer/login"
	"goPSLoginServer/utils"
	"goPSLoginServer/utils/config"
	"goPSLoginServer/utils/database"
	"goPSLoginServer/utils/logging"
	"goPSLoginServer/utils/session"
	"goPSLoginServer/utils/timed"
)

func main() {

	// init
	_ = config.GetInstance()
	logging.Init()
	database.Init()

	// start session cleanup
	timed.New(5*time.Second, session.CleanSessions).Start()

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
