package config

import (
	"encoding/json"
	"fmt"
	"strconv"
)

var Config *ConfigModel

// StringSlice is a []string that can unmarshal from both JSON strings and numbers
type StringSlice []string

func (s *StringSlice) UnmarshalJSON(data []byte) error {
	var raw []interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = make([]string, len(raw))
	for i, v := range raw {
		switch val := v.(type) {
		case string:
			(*s)[i] = val
		case float64:
			(*s)[i] = strconv.Itoa(int(val))
		default:
			return fmt.Errorf("cannot unmarshal %T into string", v)
		}
	}
	return nil
}

type ConfigModel struct {
	Server struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"server"`
	Database struct {
		URL string `json:"url"`
	} `json:"database"`
	Api struct {
		Enabled bool   `json:"enabled"`
		Key     string `json:"key"`
	} `json:"api"`
	WebServer struct {
		Enabled bool `json:"enabled"`
		Http    int  `json:"http"`
		Http2   int  `json:"http2"`
		Ftp     int  `json:"ftp"`
		Ftp2    int  `json:"ftp2"`
	} `json:"webserver"`
	Telegram struct {
		Enabled  bool     `json:"enabled"`
		BotToken string   `json:"botToken"`
		ChatId   int      `json:"ChatId"`
		Admins   []string `json:"admins"`
	} `json:"telegram"`
	Discord struct {
		Enabled             bool        `json:"enabled"`
		BotToken            string      `json:"botToken"`
		Prefix              string      `json:"prefix"`
		Admins              StringSlice `json:"admins"`
		AllowedChannels     StringSlice `json:"allowedChannels"`
		NotificationChannel string      `json:"notificationChannel"`
	} `json:"discord"`
	Queue struct {
		QueuedMessage    string `json:"queuedMessage"`
		BroadcastMessage string `json:"broadcastMessage"`
	} `json:"queue"`
	IpInfoToken string `json:"ipInfoToken"`
}