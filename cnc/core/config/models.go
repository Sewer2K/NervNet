package config

var Config *ConfigModel

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
		Enabled             bool   `json:"enabled"`
		BotToken            string `json:"botToken"`
		Prefix              string `json:"prefix"`
		AdminID             string `json:"adminId"`
		AllowedChannel      string `json:"allowedChannel"`
		NotificationChannel string `json:"notificationChannel"`
	} `json:"discord"`
	Queue struct {
		QueuedMessage    string `json:"queuedMessage"`
		BroadcastMessage string `json:"broadcastMessage"`
	} `json:"queue"`
	IpInfoToken string `json:"ipInfoToken"`
}