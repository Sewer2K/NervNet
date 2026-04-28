package database

import "strings"

func parseCommand(command string) (method, target, dport, length string) {
	parts := strings.Split(command, " ")

	if len(parts) < 3 {
		return "N/A", "N/A", "N/A", "N/A"
	}

	method = parts[0]
	target = parts[1]

	// Standard format: method target port duration len [options...]
	// Parts: [0]=method [1]=target [2]=port [3]=duration [4]=len [5+]=options
	if len(parts) >= 3 {
		// Check for explicit flags first (dport=X or len=X)
		for _, part := range parts[2:] {
			if strings.HasPrefix(part, "dport=") {
				dport = strings.TrimPrefix(part, "dport=")
			}
			if strings.HasPrefix(part, "len=") || strings.HasPrefix(part, "size=") {
				length = strings.TrimPrefix(part, "len=")
				length = strings.TrimPrefix(length, "size=")
			}
		}
	}

	// If no explicit flags found, use positional args
	if dport == "" && len(parts) >= 3 {
		dport = parts[2]
	}
	if length == "" && len(parts) >= 5 {
		length = parts[4]
	}

	if dport == "" {
		dport = "65535 (not specified)"
	}
	if length == "" {
		length = "512 (not specified)"
	}

	return method, target, dport, length
}
