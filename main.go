///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const (
	IAC  = 255
	DONT = 254
	DO   = 253
	WONT = 252
	WILL = 251

	OPT_BINARY            = 0
	OPT_ECHO              = 1
	OPT_SUPPRESS_GO_AHEAD = 3
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	sshAddr                string
	telnetHostPort         string
	debugNegotiation       bool
	logDir                 string
	gracefulShutdownMode   atomic.Bool
	denyNewConnectionsMode atomic.Bool
	connections            = make(map[string]*Connection)
	connectionsMutex       sync.Mutex
	shutdownOnce           sync.Once
	loggingWg              sync.WaitGroup
	consoleInputActive     atomic.Bool
	originalLogOutput      io.Writer
	logBuffer              *strings.Builder
	logBufferMutex         sync.Mutex
	shutdownSignal         chan struct{}
	noCompress             bool
	noLog                  bool
	noBanner               bool
	idleMax                int
	timeMax                int
	altHosts               = make(map[string]string)
)

///////////////////////////////////////////////////////////////////////////////////////////////////

type Connection struct {
	ID               string
	sshConn          *ssh.ServerConn
	channel          ssh.Channel
	startTime        time.Time
	lastActivityTime time.Time
	logFile          *os.File
	basePath         string
	cancelCtx        context.Context
	cancelFunc       context.CancelFunc
	userName         string
	hostName         string
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type altHostFlag struct{}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) String() string {
	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) Set(value string) error {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid alt-host format: %s, expected username@host:port", value)
	}
	username := parts[0]
	hostPort := parts[1]

	if _, ok := altHosts[username]; ok {
		return fmt.Errorf("duplicate alt-host entry for username: %s", username)
	}

	_, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("invalid host:port in alt-host '%s': %v", value, err)
	}

	altHosts[username] = hostPort
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	flag.StringVar(&sshAddr,
		"ssh-addr", ":2222", "SSH listen address")

	flag.StringVar(&telnetHostPort,
		"telnet-host", "127.0.0.1:6180", "Default TELNET target (host:port)")

	flag.BoolVar(&debugNegotiation,
		"debug", false, "Debug TELNET negotiation")

	flag.StringVar(&logDir,
		"log-dir", "./log", "Base directory for session logs")

	flag.BoolVar(&noCompress,
		"no-compress", false, "Disable gzip session log compression")

	flag.BoolVar(&noLog,
		"no-log", false, "Disable all session logging")

	flag.IntVar(&idleMax,
		"idle-max", 0, "Maximum connection idle time in seconds")

	flag.IntVar(&timeMax,
		"time-max", 0, "Maximum connection link time in seconds")

	flag.Var(&altHostFlag{},
		"alt-host", "Alternate TELNET targets (username@host:port) [allowed multiple times]")

	flag.BoolVar(&noBanner,
		"no-banner", false, "Disable SSH connection banner")

	originalLogOutput = log.Writer()
	logBuffer = &strings.Builder{}
	shutdownSignal = make(chan struct{})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	flag.Parse()

	if strings.Contains(telnetHostPort, "@") {
		log.Fatalf("Error: -telnet-host cannot contain a username (e.g., 'user@'). Received: %s",
			telnetHostPort)
	}

	if idleMax > 0 && timeMax > 0 && idleMax >= timeMax {
		log.Fatalf("Error: -idle-max (%d) cannot be greater than or equal to -time-max (%d)",
			idleMax, timeMax)
	}

	edSigner, err := loadOrCreateHostKey("ssh_host_ed25519_key.pem", "ed25519")
	if err != nil {
		log.Fatalf("Ed25519 host key error: %v", err)
	}

	rsaSigner, err := loadOrCreateHostKey("ssh_host_rsa_key.pem", "rsa")
	if err != nil {
		log.Fatalf("RSA host key error: %v", err)
	}

	listener, err := net.Listen("tcp", sshAddr)
	if err != nil {
		log.Fatalf("LISTEN %s: %v", sshAddr, err)
	}
	defer listener.Close()

	log.Printf("SSH LISTEN ON %s", sshAddr)

	defaultHost, defaultPort, err := parseHostPort(telnetHostPort)
	if err != nil {
		log.Fatalf("Error parsing default telnet-host: %v", err)
	}
	log.Printf("DEFAULT TARGET: %s:%d", defaultHost, defaultPort)

	for user, hostPort := range altHosts {
		log.Printf("ALT TARGET: %s [%s]", hostPort, user)
	}

	log.Printf("Type '?' for help.")

	go handleConsoleInput()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for s := range sigChan {
			switch s {
			case syscall.SIGHUP:
				log.Println("SIGHUP received and ignored.")
			case syscall.SIGUSR1:
				log.Println("SIGUSR1 received: Initiating graceful shutdown.")
				gracefulShutdownMode.Store(true)
				connectionsMutex.Lock()
				if len(connections) == 0 {
					connectionsMutex.Unlock()
					select {
					case shutdownSignal <- struct{}{}:
					default:
					}
				} else {
					connectionsMutex.Unlock()
				}
			case syscall.SIGUSR2:
				log.Println("SIGUSR2 received: Denying new connections.")
				denyNewConnectionsMode.Store(true)
			case syscall.SIGINT, syscall.SIGTERM:
				immediateShutdown()
			}
		}
	}()

	go func() {
		<-shutdownSignal
		loggingWg.Wait()
		log.Println("All connections closed. Exiting.")
		os.Exit(0)
	}()

	go func() {
		if idleMax == 0 {
			return
		}
		checkInterval := 10 * time.Second
		for {
			select {
			case <-shutdownSignal:
				return
			case <-time.After(checkInterval):
				connectionsMutex.Lock()
				for id, conn := range connections {
					idleTime := time.Since(conn.lastActivityTime)
					connUptime := time.Since(conn.startTime)

					if idleMax > 0 && idleTime > time.Duration(idleMax)*time.Second {
						connUptime := time.Since(conn.startTime)
						log.Printf("IDLEKICK [%s] %s@%s (idle %s, link %s)",
							id, conn.userName, conn.hostName, idleTime.Round(time.Second),
							connUptime.Round(time.Second))
						conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nIDLE TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second))))
						conn.sshConn.Close()
						delete(connections, id)
					} else if timeMax > 0 && connUptime > time.Duration(timeMax)*time.Second {
						connUptime := time.Since(conn.startTime)
						log.Printf("TIMEKICK [%s] %s@%s (link time %s)",
							id, conn.userName, conn.hostName, connUptime.Round(time.Second))
						conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nCONNECTION TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second))))
						conn.sshConn.Close()
						delete(connections, id)
					}
				}
				connectionsMutex.Unlock()
			}
		}
	}()

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			if gracefulShutdownMode.Load() {
				return
			}
			log.Printf("ACCEPT ERROR: %v", err)
			continue
		}
		go handleConn(rawConn, edSigner, rsaSigner)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConsoleInput() {
	reader := bufio.NewReader(os.Stdin)
	for {
		if consoleInputActive.Load() {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Console read error: %v", err)
			return
		}
		cmd := strings.TrimSpace(input)
		switch cmd {
		case "?", "h", "H":
			showHelp()

		case "q":
			toggleGracefulShutdown()

		case "d":
			toggleDenyNewConnections()

		case "Q":
			immediateShutdown()

		case "l":
			listConnections()

		case "c":
			listConfiguration()

		case "k":
			killConnection()

		case "":

		default:
			log.Printf("Unknown command: %s", cmd)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showHelp() {
	fmt.Print("\r\n" +
		"\r+========== HELP ==========+\r\n" +
		"\r|                          |\r\n" +
		"\r|  c - Show Configuration  |\r\n" +
		"\r|  l - List Connections    |\r\n" +
		"\r|  k - Kill Connection     |\r\n" +
		"\r|  d - Deny Connections    |\r\n" +
		"\r|  q - Graceful Shutdown   |\r\n" +
		"\r|  Q - Immediate Shutdown  |\r\n" +
		"\r|                          |\r\n" +
		"\r+==========================+\r\n" +
		"\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleGracefulShutdown() {
	if gracefulShutdownMode.Load() {
		gracefulShutdownMode.Store(false)
		log.Println("Graceful shutdown cancelled.")
	} else {
		gracefulShutdownMode.Store(true)
		log.Println("No new connections will be accepted.")
		log.Println("Graceful shutdown initiated.")
		connectionsMutex.Lock()
		if len(connections) == 0 {
			connectionsMutex.Unlock()
			select {
			case shutdownSignal <- struct{}{}:
			default:
			}
		} else {
			connectionsMutex.Unlock()
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleDenyNewConnections() {
	if denyNewConnectionsMode.Load() {
		denyNewConnectionsMode.Store(false)
		log.Println("Deny connections cancelled.")
	} else {
		denyNewConnectionsMode.Store(true)
		log.Println("No new connections will be accepted.")
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func immediateShutdown() {
	shutdownOnce.Do(func() {
		log.Println("Immediate shutdown initiated.")
		connectionsMutex.Lock()
		for _, conn := range connections {
			if conn.channel != nil {
				conn.channel.Write([]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"))
				connUptime := time.Since(conn.startTime)
				log.Printf("LINKDOWN [%s] %s@%s (link time %s)",
					conn.ID, conn.userName, conn.hostName, connUptime.Round(time.Second))
			}
			if conn.cancelFunc != nil {
				conn.cancelFunc()
			}
			if conn.sshConn != nil {
				conn.sshConn.Close()
			}
		}

		connectionsMutex.Unlock()

		for {
			connectionsMutex.Lock()
			if len(connections) == 0 {
				connectionsMutex.Unlock()
				break
			}
			connectionsMutex.Unlock()
			time.Sleep(100 * time.Millisecond)
		}

		loggingWg.Wait()
		log.Println("Exiting.")
		os.Exit(0)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConnections() {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()
	fmt.Println("\r\n\rActive Connections")
	fmt.Println("\r==================")
	if len(connections) == 0 {
		fmt.Println("\r* None!")
		return
	}
	for id, conn := range connections {
		fmt.Printf("\r* ID %s: %s@%s [Link: %s, Idle: %s]\r\n",
			id, conn.sshConn.User(), conn.sshConn.RemoteAddr(),
			time.Since(conn.startTime).Round(time.Second),
			time.Since(conn.lastActivityTime).Round(time.Second))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConfiguration() {
	fmt.Println("\r\n\rConfiguration")
	fmt.Println("\r=============")
	fmt.Printf("\r* SSH LISTEN ON: %s\r\n", sshAddr)
	fmt.Printf("\r* DEFAULT TARGET: %s\r\n", telnetHostPort)

	if len(altHosts) > 0 {
		fmt.Println("\r* ALT TARGETS:")
		for user, hostPort := range altHosts {
			fmt.Printf("\r  * %s [%s]\r\n", hostPort, user)
		}
	} else {
		fmt.Println("\r* ALT TARGETS: None configured")
	}

	fmt.Printf("\r* TIME MAX: %d seconds\r\n", timeMax)
	fmt.Printf("\r* IDLE MAX: %d seconds\r\n", idleMax)
	fmt.Printf("\r* NO LOG: %t\r\n", noLog)
	fmt.Printf("\r* LOG DIR: %s\r\n", logDir)
	fmt.Printf("\r* NO LOG COMPRESS: %t\r\n", noCompress)
	fmt.Printf("\r* DEBUG: %t\r\n", debugNegotiation)
	fmt.Printf("\r* GRACEFUL SHUTDOWN: %t\r\n", gracefulShutdownMode.Load())
	fmt.Printf("\r* DENY NEW CONNECTIONS: %t\r\n", denyNewConnectionsMode.Load())
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func startBufferingLogs() {
	logBufferMutex.Lock()
	defer logBufferMutex.Unlock()
	logBuffer.Reset()
	log.SetOutput(io.MultiWriter(originalLogOutput, logBuffer))
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func stopBufferingLogs() {
	logBufferMutex.Lock()
	defer logBufferMutex.Unlock()
	log.SetOutput(originalLogOutput)
	if logBuffer.Len() > 0 {
		fmt.Print(logBuffer.String())
		logBuffer.Reset()
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killConnection() {
	consoleInputActive.Store(true)
	defer consoleInputActive.Store(false)

	fmt.Print("Enter session ID to kill: ")
	reader := bufio.NewReader(os.Stdin)

	var input string

	inputChan := make(chan string, 1)
	go func() {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			log.Printf("Error reading session ID: %v", readErr)
			close(inputChan)
			return
		}
		inputChan <- line
	}()

	select {
	case line, ok := <-inputChan:
		if !ok {
			return
		}
		input = line

	case <-time.After(10 * time.Second):
		fmt.Println("\nPrompt timed out.")
		return
	}

	id := strings.TrimSpace(input)
	if id == "" {
		fmt.Println("Aborted.")
		return
	}

	connectionsMutex.Lock()
	conn, ok := connections[id]
	connectionsMutex.Unlock()

	if !ok {
		fmt.Printf("Session ID '%s' not found.\r\n", id)
		return
	}

	fmt.Printf("Killing connection %s...\n", id)
	conn.channel.Write([]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"))
	connUptime := time.Since(conn.startTime)
	log.Printf("TERMKICK [%s] %s@%s (link time %s)",
		conn.ID, conn.userName, conn.hostName, connUptime.Round(time.Second))
	conn.sshConn.Close()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func loadOrCreateHostKey(path, keyType string) (ssh.Signer, error) {
	if data, err := ioutil.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(data)
	}

	switch keyType {
	case "rsa":
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}

		data := pem.EncodeToMemory(block)
		if err := ioutil.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}

		return ssh.ParsePrivateKey(data)

	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}

		block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
		data := pem.EncodeToMemory(block)
		if err := ioutil.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}

		return ssh.ParsePrivateKey(data)

	default:
		return nil, fmt.Errorf("UNSUPPORTED KEY TYPE %q", keyType)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConn(rawConn net.Conn, edSigner, rsaSigner ssh.Signer) {
	sid := newSessionID()
	keyLog := []string{}

	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	if !suppressLogs {
		host, _, err := net.SplitHostPort(rawConn.RemoteAddr().String())
		if err != nil {
			host = rawConn.RemoteAddr().String()
		}
		log.Printf("INITIATE [%s] %s", sid, host)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(
			conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{Extensions: map[string]string{"auth-method": "password"}}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			line := fmt.Sprintf(
				"VALIDATE [%s] %s@%s %q:%s",
				sid,
				c.User(),
				c.RemoteAddr(),
				pubKey.Type(),
				ssh.FingerprintSHA256(pubKey),
			)
			if !suppressLogs {
				log.Print(line)
			}
			keyLog = append(keyLog, line)
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "publickey"},
			}, fmt.Errorf("next key")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "keyboard-interactive"},
			}, nil
		},
	}
	config.AddHostKey(edSigner)
	config.AddHostKey(rsaSigner)

	if tcp, ok := rawConn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		log.Printf("TEARDOWN [%s] HANDSHAKE FAILED: %v", sid, err)
		return
	}

	var authMethod string
	switch sshConn.Permissions.Extensions["auth-method"] {
	case "password":
		authMethod = "password"

	case "publickey":
		authMethod = "publickey"

	case "keyboard-interactive":
		authMethod = "keyboard-interactive"

	default:
		authMethod = "unknown"
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := &Connection{
		ID:               sid,
		sshConn:          sshConn,
		startTime:        time.Now(),
		lastActivityTime: time.Now(),
		cancelCtx:        ctx,
		cancelFunc:       cancel,
		userName:         sshConn.User(),
		hostName:         sshConn.RemoteAddr().String(),
	}

	connectionsMutex.Lock()
	connections[sid] = conn
	connectionsMutex.Unlock()

	defer func() {
		connectionsMutex.Lock()
		delete(connections, sid)
		if gracefulShutdownMode.Load() && len(connections) == 0 {
			connectionsMutex.Unlock()
			select {
			case shutdownSignal <- struct{}{}:
			default:
			}
		} else {
			connectionsMutex.Unlock()
		}
		if !suppressLogs {
			host, _, err := net.SplitHostPort(conn.hostName)
			if err != nil {
				log.Printf("TEARDOWN [%s] %s@<UNKNOWN>",
					sid, func() string {
						if conn.userName == "" {
							return "<UNKNOWN>"
						}
						return conn.userName
					}())
			} else {
				log.Printf("TEARDOWN [%s] %s@%s",
					sid, func() string {
						if conn.userName == "" {
							return "<UNKNOWN>"
						}
						return conn.userName
					}(), host)
			}
		}
	}()

	addr := sshConn.RemoteAddr().String()
	handshakeLog := fmt.Sprintf("VALIDATE [%s] %s@%s \"ssh\":%s",
		sid, func() string {
			if conn.userName == "" {
				return "<UNKNOWN>"
			}
			return conn.userName
		}(), addr, authMethod)
	if !suppressLogs {
		log.Print(handshakeLog)
	}
	keyLog = append(keyLog, handshakeLog)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session allowed")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		conn.channel = ch
		go handleSession(conn, ch, requests, keyLog, conn.cancelCtx)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func parseHostPort(hostPort string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return host, port, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleSession(
	conn *Connection,
	channel ssh.Channel,
	requests <-chan *ssh.Request,
	keyLog []string,
	ctx context.Context,
) {
	if gracefulShutdownMode.Load() || denyNewConnectionsMode.Load() {
		if denyMsg, err := ioutil.ReadFile("deny.txt"); err == nil {
			txt := strings.ReplaceAll(
				strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n")
			channel.Write([]byte("\r\n"))
			channel.Write([]byte(txt))
			channel.Write([]byte("\r\n"))
		}
		channel.Close()
		return
	}

	sendBanner(conn.ID, conn.sshConn, channel)

	if raw, err := ioutil.ReadFile("motd.txt"); err == nil {
		txt := strings.ReplaceAll(
			strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
		channel.Write([]byte(txt + "\r\n"))
	}

	start := time.Now()
	var sshIn, sshOut, telnetIn, telnetOut uint64

	var logfile *os.File
	var logwriter io.Writer
	var basePath string
	var err error

	if !noLog {
		logfile, basePath, err = createDatedLog(conn.ID, conn.sshConn.RemoteAddr())
		if err != nil {
			fmt.Fprintf(channel, "%v\r\n", err)
			channel.Close()
			return
		}
		conn.logFile = logfile
		conn.basePath = basePath
		logwriter = logfile

		logwriter.Write([]byte(nowStamp() + " Session start\r\n"))

		for _, line := range keyLog {
			logwriter.Write([]byte(nowStamp() + " " + line + "\r\n"))
		}

		defer func() {
			logwriter.Write([]byte(nowStamp() + " Session end\r\n"))
			closeAndCompressLog(logfile, basePath+".log")
		}()
	} else {
		logwriter = ioutil.Discard
	}

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				req.Reply(true, nil)

			case "shell":
				req.Reply(true, nil)

			default:
				req.Reply(false, nil)
			}
		}
	}()

	var targetHost string
	var targetPort int

	if altHostPort, ok := altHosts[conn.userName]; ok {
		var err error
		targetHost, targetPort, err = parseHostPort(altHostPort)
		if err != nil {
			fmt.Fprintf(channel, "Error parsing alt-host for user %s: %v\r\n\r\n",
				conn.userName, err)
			log.Printf("Error parsing alt-host for user %s: %v", conn.userName, err)
			channel.Close()
			return
		}
		log.Printf("ALTROUTE [%s] %s -> %s:%d", conn.ID, conn.userName, targetHost, targetPort)
	} else {
		var err error
		targetHost, targetPort, err = parseHostPort(telnetHostPort)
		if err != nil {
			fmt.Fprintf(channel, "Error parsing default telnet-host: %v\r\n\r\n", err)
			log.Printf("Error parsing default telnet-host: %v", err)
			channel.Close()
			return
		}
	}

	if !noLog {
		logwriter.Write([]byte(fmt.Sprintf(nowStamp()+" Target: %s:%d\r\n",
			targetHost, targetPort)))
	}

	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		fmt.Fprintf(channel, "%v\r\n\r\n", err)
		log.Printf("%v", err)
		channel.Close()
		return
	}

	if tcp2, ok := remote.(*net.TCPConn); ok {
		tcp2.SetNoDelay(true)
	}

	defer remote.Close()

	negotiateTelnet(remote, channel, logwriter)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 1)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := channel.Read(buf)
			if n > 0 {
				atomic.AddUint64(&sshIn, uint64(n))
				if buf[0] == 0x1D { // Ctrl-]
					showMenu(channel, remote, logwriter, &sshIn,
						&sshOut, &telnetIn, &telnetOut, start)
					continue
				}
				m, err2 := remote.Write(buf[:n])
				atomic.AddUint64(&telnetOut, uint64(m))
				logwriter.Write(buf[:n])
				conn.lastActivityTime = time.Now()
				if err2 != nil {
					channel.Close()
					return
				}
			}
			if err != nil {
				remote.Close()
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, err := remote.Read(buf)
			if n > 0 {
				atomic.AddUint64(&telnetIn, uint64(n))
				fwd := buf[:0]
				for i := 0; i < n; i++ {
					if buf[i] != 0 {
						fwd = append(fwd, buf[i])
					}
				}
				atomic.AddUint64(&sshOut, uint64(len(fwd)))
				channel.Write(fwd)
				logwriter.Write(buf[:n])
				conn.lastActivityTime = time.Now()
			}
			if err != nil {
				dur := time.Since(start)
				log.Printf("DETACHED [%s] %s@%s (link time %s)",
					conn.ID, conn.userName, conn.hostName, dur.Round(time.Second))
				channel.Write([]byte(fmt.Sprintf("\r\nCONNECTION CLOSED (link time %s)\r\n\r\n",
					dur.Round(time.Second))))
				channel.Write([]byte(fmt.Sprintf(
					">> SSH - in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n",
					sshIn, sshOut, float64(sshIn)/dur.Seconds(), float64(sshOut)/dur.Seconds(),
				)))
				channel.Write([]byte(fmt.Sprintf(
					">> NVT - in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n\r\n",
					telnetIn, telnetOut, float64(telnetIn)/dur.Seconds(), float64(telnetOut)/dur.Seconds(),
				)))
				channel.Close()
				return
			}
		}
	}()
	wg.Wait()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendBanner(sid string, sshConn *ssh.ServerConn, ch ssh.Channel) {
	if noBanner {
		return
	}
	user := sshConn.User()
	host, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(ctx, host)
	var origin string
	if len(names) > 0 {
		origin = fmt.Sprintf("%s [%s]", strings.TrimSuffix(names[0], "."), host)
	} else if user != "" {
		origin = fmt.Sprintf("%s", host)
	} else {
		origin = host
	}
	now := nowStamp()
	fmt.Fprintf(ch, "CONNECTION from %s started at %s.\r\n", origin, now)
	fmt.Fprint(ch, "\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func negotiateTelnet(remote net.Conn, ch ssh.Channel, logw io.Writer) {
	remote.SetReadDeadline(time.Now().Add(time.Second / 3)) // 333ms
	defer remote.SetReadDeadline(time.Time{})

	buf := make([]byte, 512)
	for {
		n, err := remote.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return
		}
		i := 0
		for i < n {
			if buf[i] == IAC && i+2 < n {
				cmd, opt := buf[i+1], buf[i+2]
				writeNegotiation(ch, logw, "[RCVD "+cmdName(cmd)+" "+optName(opt)+"]")
				var reply byte
				switch cmd {
				case WILL:
					reply = DO

				case WONT:
					reply = DONT

				case DO:
					reply = WILL

				case DONT:
					reply = WONT

				default:
					i += 3
					continue
				}
				sendIAC(remote, reply, opt)
				writeNegotiation(ch, logw, "[SENT "+cmdName(reply)+" "+optName(opt)+"]")
				i += 3
			} else {
				ch.Write(buf[i : i+1])
				logw.Write(buf[i : i+1])
				i++
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func writeNegotiation(ch io.Writer, logw io.Writer, line string) {
	msg := line + "\r\n"
	logw.Write([]byte(msg))
	if debugNegotiation {
		ch.Write([]byte(msg))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendIAC(w io.Writer, cmd, opt byte) {
	w.Write([]byte{IAC, cmd, opt})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func cmdName(b byte) string {
	switch b {
	case DO:
		return "DO"

	case DONT:
		return "DONT"

	case WILL:
		return "WILL"

	case WONT:
		return "WONT"
	}

	return fmt.Sprintf("CMD_%d", b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func optName(b byte) string {
	switch b {
	case OPT_BINARY:
		return "BINARY"

	case OPT_ECHO:
		return "ECHO"

	case OPT_SUPPRESS_GO_AHEAD:
		return "SUPPRESS GO AHEAD"
	}

	return fmt.Sprintf("OPT_%d", b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showMenu(ch ssh.Channel, remote net.Conn, logw io.Writer,
	sshIn, sshOut, telnetIn, telnetOut *uint64, start time.Time) {
	menu := "\r\n" +
		"\r+====== MENU ======+\r\n" +
		"\r|                  |\r\n" +
		"\r|  B - Send Break  |\r\n" +
		"\r|  S - Show Stats  |\r\n" +
		"\r|  X - Disconnect  |\r\n" +
		"\r|                  |\r\n" +
		"\r+==================+\r\n"
	ch.Write([]byte(menu))
	sel := make([]byte, 1)

	if _, err := ch.Read(sel); err == nil {
		switch sel[0] {
		case 'b', 'B':
			remote.Write([]byte{IAC, 243}) // BREAK
			logw.Write([]byte{IAC, 243})
			ch.Write([]byte("\r\n>> Sent BREAK\r\n"))
			ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

		case 's', 'S':
			dur := time.Since(start)
			ch.Write([]byte("\r\n"))
			ch.Write([]byte(fmt.Sprintf(
				">> LNK - link time: %s\r\n", dur.Round(time.Second).String())))
			ch.Write([]byte(fmt.Sprintf(
				">> SSH - in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n",
				atomic.LoadUint64(sshIn),
				atomic.LoadUint64(sshOut),
				float64(atomic.LoadUint64(sshIn))/dur.Seconds(),
				float64(atomic.LoadUint64(sshOut))/dur.Seconds(),
			)))
			ch.Write([]byte(fmt.Sprintf(
				">> NVT - in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n",
				atomic.LoadUint64(telnetIn),
				atomic.LoadUint64(telnetOut),
				float64(atomic.LoadUint64(telnetIn))/dur.Seconds(),
				float64(atomic.LoadUint64(telnetOut))/dur.Seconds(),
			)))
			ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

		case 'x', 'X':
			ch.Write([]byte("\r\n>> DISCONNECTING...\r\n"))
			ch.Close()

		default:
			ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func createDatedLog(sid string, addr net.Addr) (*os.File, string, error) {
	host, _, _ := net.SplitHostPort(addr.String())
	ipDir := sanitizeIP(host)
	now := time.Now()
	dir := filepath.Join(
		logDir,
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
		fmt.Sprintf("%02d", now.Day()),
		ipDir,
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", err
	}

	ts := now.Format("150405")
	files, _ := ioutil.ReadDir(dir)
	maxSeq := 0
	prefix := ts + "_" + sid + "_"
	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			parts := strings.SplitN(f.Name()[len(prefix):], ".", 2)
			if n, err := strconv.Atoi(parts[0]); err == nil && n > maxSeq {
				maxSeq = n
			}
		}
	}

	loggingWg.Add(1)

	seq := maxSeq + 1
	base := fmt.Sprintf("%s_%s_%d", ts, sid, seq)
	pathBase := filepath.Join(dir, base)
	f, err := os.OpenFile(pathBase+".log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)

	return f, pathBase, err
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func closeAndCompressLog(logfile *os.File, logFilePath string) {
	defer loggingWg.Done()
	err := logfile.Close()
	if err != nil {
		return
	}

	if noCompress {
		return
	}

	compressedFilePath := logFilePath + ".gz"

	data, err := ioutil.ReadFile(logFilePath)
	if err != nil {
		log.Printf("Error reading log '%s' for compression: %v", logFilePath, err)
		return
	}

	gzFile, err := os.Create(compressedFilePath)
	if err != nil {
		log.Printf("Error creating compressed file '%s': %v", compressedFilePath, err)
		return
	}
	defer gzFile.Close()

	gzipWriter := gzip.NewWriter(gzFile)
	_, err = gzipWriter.Write(data)
	if err != nil {
		log.Printf("Error writing to compressed file '%s': %v", compressedFilePath, err)
		return
	}

	err = gzipWriter.Close()
	if err != nil {
		log.Printf("Error closing gzip writer for '%s': %v", compressedFilePath, err)
		return
	}

	err = os.Remove(logFilePath)
	if err != nil {
		log.Printf("Error removing original log '%s' after compression: %v", logFilePath, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sanitizeIP(s string) string {
	return strings.NewReplacer(":", "_", ".", "_").Replace(s)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func newSessionID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return hex.EncodeToString(b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func nowStamp() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
