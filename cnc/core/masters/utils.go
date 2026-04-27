package masters

import (
	"bufio"
	"regexp"

	"cnc/core/attacks"
	"cnc/core/database"
	"cnc/core/masters/sessions"
	"cnc/core/slaves"
	"cnc/core/utils"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func (a *Admin) Print(data ...interface{}) {
	_, _ = a.conn.Write([]byte(fmt.Sprint(data...)))
}

func (a *Admin) Printf(format string, val ...any) {
	a.Print(fmt.Sprintf(format, val...))
}

func (a *Admin) Println(data ...interface{}) {
	a.Print(fmt.Sprint(data...) + "\r\n")
}

func (a *Admin) Clear() {
	a.Printf("\x1bc")
}

func (a *Admin) Close() {
	err := a.conn.Close()
	if err != nil {
		return
	}
}

func SlotsCooldown(username string) {
	GlobalSlots++
	for _ = range time.Tick(time.Second * 60) {
		GlobalSlots--
		break
	}
}

func BroadcastMessage(message string) {
	sessions.SessionMutex.Lock()
	defer sessions.SessionMutex.Unlock()
	for _, session := range sessions.Sessions {
		session.Println(fmt.Sprintf("\r\n\u001B[1;43m[ BROADCAST ]\x1b[0m %s", message))
	}
}

func getBotCount(botCount []int) string {
	if len(botCount) > 0 && botCount[0] >= 0 {
		return strconv.Itoa(botCount[0])
	}
	return strconv.Itoa(slaves.CL.Count())
}

func getThemePath(theme string, path string) string {
	if theme == "" {
		theme = "nerv"
	}
	
	

	
	parts := strings.Split(path, "/")
	filename := parts[len(parts)-1]

	
	flatThemePath := "assets/branding/" + theme + "/" + filename
	if _, err := os.Stat(flatThemePath); err == nil {
		return flatThemePath
	}

	return path
}

func getBrandingMap(this *Admin, username string, botCount ...int) map[string]string {
	if this.PrimaryColor == "" || this.SecondaryColor == "" {
		this.PrimaryColor, this.SecondaryColor = LoadThemeConfig(this.Theme)
	}
	pColor := HexToAnsi(this.PrimaryColor)
	sColor := HexToAnsi(this.SecondaryColor)
	reset := "\x1b[0m"

	var maxtime, cooldown, maxattacks, totalattacks int
	if this.Session != nil {
		maxtime = this.Session.Account.MaxTime
		cooldown = this.Session.Account.Cooldown
		maxattacks = this.Session.Account.MaxAttacks
		totalattacks = this.Session.Account.TotalAttacks
	}

	timenow := time.Now().Format("3:04 PM")
	memoryInfo, uptimeInfo := database.DatabaseConnection.GetSystemStats()
	uptimeDays := uptimeInfo / (60 * 60 * 24)
	uptimeHours := (uptimeInfo % (60 * 60 * 24)) / (60 * 60)

	m := map[string]string{
		"\\x1b":   "\x1b",
		"\\u001b": "\u001b",
		"\\033":   "\033",
		"\\r":     "\r",
		"\\n":     "\n",
		"\\a":     "\a",
		"\\b":     "\b",
		"\\t":     "\t",
		"\\v":     "\v",
		"\\f":     "\f",
		"\\007":   "\007",

		
		"<<$user.username>>":     username,
		"<<$username>>":          username,
		"<<username>>":           username,
		"<<$user.totalattacks>>": strconv.Itoa(totalattacks),
		"<<$user.maxattacks>>":   strconv.Itoa(maxattacks),
		"<<$user.maxtime>>":      strconv.Itoa(maxtime),
		"<<$user.cooldown>>":     strconv.Itoa(cooldown),

		
		"<<$primary>>":   pColor,
		"<<primary>>":    pColor,
		"<<$secondary>>": sColor,
		"<<secondary>>":  sColor,
		"<<$reset>>":     reset,
		"<<reset>>":      reset,

		
		"<<$botcount>>":  getBotCount(botCount),
		"<<$ongoing>>":   strconv.Itoa(database.DatabaseConnection.NumOngoing()),
		"<<$maxglobal>>": strconv.Itoa(attacks.MaxGlobalSlots),

		
		"<<$timestamp>>":           timenow,
		"<<$timenow>>":             timenow,
		"<<$server.memory.used>>":  strconv.FormatUint(memoryInfo.Used/(1024*1024), 10),
		"<<$server.memory.total>>": strconv.FormatUint(memoryInfo.Total/(1024*1024), 10),
		"<<$server.uptime>>":       fmt.Sprintf("%d days, %d hours", uptimeDays, uptimeHours),

		
		"<<$clear>>": "\033c",
	}

	return m
}

func Displayln(this *Admin, path string, username string, botCount ...int) error {
	path = getThemePath(this.Theme, path)
	sleepDurations := map[string]time.Duration{
		"<<100>>":        100 * time.Millisecond,
		"<<200>>":        200 * time.Millisecond,
		"<<300>>":        300 * time.Millisecond,
		"<<400>>":        400 * time.Millisecond,
		"<<500>>":        500 * time.Millisecond,
		"<<600>>":        600 * time.Millisecond,
		"<<700>>":        700 * time.Millisecond,
		"<<800>>":        800 * time.Millisecond,
		"<<900>>":        900 * time.Millisecond,
		"<<1000>>":       1000 * time.Millisecond,
		"<<sleep(120)>>": 120 * time.Millisecond,
		"<<sleep(20)>>":  20 * time.Millisecond,
		"<<sleep(40)>>":  40 * time.Millisecond,
		"<<sleep(60)>>":  60 * time.Millisecond,
		"<<sleep(80)>>":  80 * time.Millisecond,
		"<<sleep(100)>>": 100 * time.Millisecond,
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	brandingMap := getBrandingMap(this, username, botCount...)

	for scanner.Scan() {
		line := scanner.Text()
		for pattern, sleepDuration := range sleepDurations {
			if strings.Contains(line, pattern) {
				time.Sleep(sleepDuration)
				line = strings.ReplaceAll(line, pattern, "")
			}
		}

		resizeRe := regexp.MustCompile(`<<\$resize\((\d+):(\d+)\)>>`)
		if resizeRe.MatchString(line) {
			matches := resizeRe.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				width := match[1]
				height := match[2]
				
				_, _ = this.conn.Write([]byte(fmt.Sprintf("\x1b[8;%s;%st", height, width)))
				line = strings.Replace(line, match[0], "", 1)
			}
		}

		finalLine := utils.ReplaceFromMap(line, brandingMap)

		if strings.HasSuffix(finalLine, "\033c") {
			_, err = this.conn.Write([]byte(fmt.Sprintf("\u001B[0m%s", finalLine)))
		} else {
			_, err = this.conn.Write([]byte(fmt.Sprintf("\u001B[0m%s\r\n", finalLine)))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func Displayf(this *Admin, path string, username string) error {
	path = getThemePath(this.Theme, path)
	sleepDurations := map[string]time.Duration{
		"<<100>>":        100 * time.Millisecond,
		"<<200>>":        200 * time.Millisecond,
		"<<300>>":        300 * time.Millisecond,
		"<<400>>":        400 * time.Millisecond,
		"<<500>>":        500 * time.Millisecond,
		"<<600>>":        600 * time.Millisecond,
		"<<700>>":        700 * time.Millisecond,
		"<<800>>":        800 * time.Millisecond,
		"<<900>>":        900 * time.Millisecond,
		"<<1000>>":       1000 * time.Millisecond,
		"<<sleep(120)>>": 120 * time.Millisecond,
		"<<sleep(20)>>":  20 * time.Millisecond,
		"<<sleep(40)>>":  40 * time.Millisecond,
		"<<sleep(60)>>":  60 * time.Millisecond,
		"<<sleep(80)>>":  80 * time.Millisecond,
		"<<sleep(100)>>": 100 * time.Millisecond,
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	brandingMap := getBrandingMap(this, username)

	for scanner.Scan() {
		line := scanner.Text()
		for pattern, sleepDuration := range sleepDurations {
			if strings.Contains(line, pattern) {
				time.Sleep(sleepDuration)
				line = strings.ReplaceAll(line, pattern, "")
			}
		}

		resizeRe := regexp.MustCompile(`<<\$resize\((\d+):(\d+)\)>>`)
		if resizeRe.MatchString(line) {
			matches := resizeRe.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				width := match[1]
				height := match[2]
				_, _ = this.conn.Write([]byte(fmt.Sprintf("\x1b[8;%s;%st", height, width)))
				line = strings.Replace(line, match[0], "", 1)
			}
		}

		finalLine := utils.ReplaceFromMap(line, brandingMap)
		_, err = this.conn.Write([]byte(fmt.Sprintf("\u001B[0m%s", finalLine)))
		if err != nil {
			return err
		}
	}

	return nil
}

func DisplayTitle(this *Admin, username string) error {
	titlePath := getThemePath(this.Theme, "assets/branding/user/title.txt")
	data, err := os.ReadFile(titlePath)
	if err != nil {
		return err
	}

	title := strings.TrimSpace(string(data))

	brandingMap := getBrandingMap(this, username)

	title = utils.ReplaceFromMap(title, brandingMap)

	if !strings.HasPrefix(title, "\x1b]0;") {
		title = "\x1b]0;" + title
	}
	if !strings.HasSuffix(title, "\x07") {
		title = title + "\x07"
	}

	_, err = this.conn.Write([]byte(title))
	if err != nil {
		return err
	}

	return nil
}

func DisplayPrompt(this *Admin) (string, error) {
	username := this.Session.Username

	
	promptPath := getThemePath(this.Theme, "assets/branding/user/prompt.txt")
	data, err := os.ReadFile(promptPath)

	brandingMap := getBrandingMap(this, username)

	if err == nil && len(data) > 0 {
		prompt := string(data)
		prompt = utils.ReplaceFromMap(prompt, brandingMap)

		
		for {
			start := strings.Index(prompt, "<<#")
			if start == -1 {
				break
			}
			end := strings.Index(prompt[start:], ">>")
			if end == -1 {
				break
			}
			end += start
			hex := prompt[start+3 : end]
			if len(hex) == 6 {
				prompt = strings.Replace(prompt, "<<#"+hex+">>", HexToAnsi(hex), 1)
			} else {
				
				prompt = strings.Replace(prompt, "<<#", "___", 1)
			}
		}
		
		prompt = strings.ReplaceAll(prompt, "___", "<<#")

		return prompt, nil
	}

	
	
	pColor := brandingMap["<<$primary>>"]
	sColor := brandingMap["<<$secondary>>"]
	reset := brandingMap["<<$reset>>"]
	prompt := fmt.Sprintf("%s%s%s@%sbotnet %s# %s", pColor, username, sColor, pColor, sColor, reset)
	return prompt, nil
}
