///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bufio"
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
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/ssh"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const (
	NOP  = 241
	AYT  = 246
	IAC  = 255
	DONT = 254
	DO   = 253
	WONT = 252
	WILL = 251

	OPT_BINARY            = 0
	OPT_ECHO              = 1
	OPT_SUPPRESS_GO_AHEAD = 3

	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	allowRoot              bool
	logPerm                uint = 0o600
	altHosts                    = make(map[string]string)
	blacklistedNetworks    []*net.IPNet
	blacklistFile          string
	connections            = make(map[string]*Connection)
	connectionsMutex       sync.Mutex
	consoleInputActive     atomic.Bool
	consoleLogFile         *os.File
	consoleLogMutex        sync.Mutex
	consoleLog             string
	debugNegotiation       bool
	denyNewConnectionsMode atomic.Bool
	gracefulShutdownMode   atomic.Bool
	idleMax                int
	logBufferMutex         sync.Mutex
	logBuffer              *strings.Builder
	logDir                 string
	loggingWg              sync.WaitGroup
	noBanner               bool
	noCompress             bool
	noLog                  bool
	originalLogOutput      io.Writer
	showVersion            bool
	shutdownOnce           sync.Once
	shutdownSignal         chan struct{}
	sshAddr                stringSliceFlag
	telnetHostPort         string
	timeMax                int
	whitelistedNetworks    []*net.IPNet
	whitelistFile          string
	issueFile              = "issue.txt"
	denyFile               = "deny.txt"
	blockFile              = "block.txt"
	compressAlgo           string
	emacsKeymap            = map[string]string{
		"\x1b[1;5A": "\x1b\x5b", //    C-Arrow_Up -> Escape, [
		"\x1b[1;5B": "\x1b\x5d", // C-Arrrow_Down -> Escape, ]
		"\x1b[1;5C": "\x1b\x66", // C-Arrow_Right -> Escape, f
		"\x1b[1;5D": "\x1b\x62", //  C-Arrow_Left -> Escape, b
		"\x1b[1~":   "\x01",     //          Home -> Control-A
		"\x1b[3~":   "\x04",     //        Delete -> Control-D
		"\x1b[4~":   "\x05",     //           End -> Control-E
		"\x1b[5~":   "\x1b\x76", //       Page_Up -> Escape, v
		"\x1b[6~":   "\x16",     //     Page_Down -> Control-V
		"\x1b[A":    "\x10",     //      Arrow_Up -> Control-P
		"\x1b[B":    "\x0e",     //    Arrow_Down -> Control-N
		"\x1b[C":    "\x06",     //   Arrow_Right -> Control-F
		"\x1b[D":    "\x02",     //    Arrow_Left -> Control-B
	}
	emacsKeymapPrefixes = make(map[string]bool)
)

///////////////////////////////////////////////////////////////////////////////////////////////////

type Connection struct {
	basePath            string
	cancelCtx           context.Context
	cancelFunc          context.CancelFunc
	channel             ssh.Channel
	hostName            string
	ID                  string
	invalidShare        bool
	lastActivityTime    time.Time
	logFile             *os.File
	monitoredConnection *Connection
	monitoring          bool
	shareableUsername   string
	sshConn             *ssh.ServerConn
	sshInTotal          uint64
	sshOutTotal         uint64
	startTime           time.Time
	targetHost          string
	targetPort          int
	totalMonitors       uint64
	userName            string
	emacsKeymapEnabled  bool
	wasMonitored        bool
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type altHostFlag struct{}

///////////////////////////////////////////////////////////////////////////////////////////////////

type stringSliceFlag []string

///////////////////////////////////////////////////////////////////////////////////////////////////

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ", ")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

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

type octalPermValue uint

func (op *octalPermValue) String() string {
	return fmt.Sprintf("%o", *op)
}

func (op *octalPermValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid octal permission value: %w", err)
	}
	*op = octalPermValue(v)
	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	flag.Var(&sshAddr,
		"ssh-addr", "SSH listener address (e.g.: \":2222\", \"[::1]:8000\") [allowed multiple times]")

	flag.StringVar(&telnetHostPort,
		"telnet-host", "127.0.0.1:6180", "Default TELNET target (host:port)")

	flag.BoolVar(&debugNegotiation,
		"debug", false, "Debug TELNET negotiation")

	flag.StringVar(&logDir,
		"log-dir", "./log", "Base directory for logs")

	flag.BoolVar(&noCompress,
		"no-compress", false, "Disable session and console log compression")

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

	flag.StringVar(&blacklistFile,
		"blacklist", "", "Blacklist file (optional)")

	flag.StringVar(&whitelistFile,
		"whitelist", "", "Whitelist file (optional)")

	flag.BoolVar(&allowRoot,
		"allow-root", false, "Allow running as root (UID 0) [strongly discouraged!]")

	flag.BoolVar(&showVersion,
		"version", false, "Show version information")

	flag.StringVar(&consoleLog,
		"console-log", "", "Enable console logging [requires 'quiet' or 'noquiet' argument]")

	flag.StringVar(&compressAlgo,
		"compress-algo", "gzip", "Compression algorithm [gzip, xz, zstd]")

	flag.Var((*octalPermValue)(&logPerm),
		"log-perm", "Permissions for log files (umask, e.g., 0600, 0644)")

	originalLogOutput = log.Writer()
	logBuffer = &strings.Builder{}
	shutdownSignal = make(chan struct{})

	for k := range emacsKeymap {
		for i := 1; i < len(k); i++ {
			emacsKeymapPrefixes[k[:i]] = true
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	flag.Parse()

	printVersion()

	if showVersion {
		os.Exit(0)
	}

	if os.Getuid() == 0 && !allowRoot {
		log.Fatalf("ERROR: Running as root is strongly discouraged!  Use -allow-root to override.")
	}

	switch compressAlgo {
	case "gzip", "xz", "zstd":
	default:
		log.Fatalf("ERROR: Invalid -compress-algo: %s", compressAlgo)
	}

	setupConsoleLogging()

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	reloadLists()

	if strings.Contains(telnetHostPort, "@") {
		log.Fatalf("ERROR: -telnet-host cannot contain a username (e.g., 'user@'). Received: %s",
			telnetHostPort)
	}

	if idleMax > 0 && timeMax > 0 && idleMax >= timeMax {
		log.Fatalf("ERROR: -idle-max (%d) cannot be greater than or equal to -time-max (%d)",
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

	if len(sshAddr) == 0 {
		sshAddr = []string{":2222"}
	}

	for _, addr := range sshAddr {
		go func(addr string) {
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				log.Fatalf("LISTEN %s: %v", addr, err)
			}
			defer listener.Close()

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
		}(addr)
	}

	pid := os.Getpid()
	var startMsg string
	if pid != 0 {
		startMsg = fmt.Sprintf("STARTING PROXY [PID %d]", pid)
	} else {
		startMsg = "STARTING PROXY"
	}

	fmt.Fprintf(os.Stderr, "%s %s\n", nowStamp(), startMsg)
	log.Printf("%s", startMsg)

	for _, addr := range sshAddr {
		log.Printf("SSH LISTEN ON %s", addr)
	}

	defaultHost, defaultPort, err := parseHostPort(telnetHostPort)
	if err != nil {
		log.Fatalf("Error parsing default telnet-host: %v", err)
	}
	log.Printf("DEFAULT TARGET: %s:%d", defaultHost, defaultPort)

	for user, hostPort := range altHosts {
		log.Printf("ALT TARGET: %s [%s]", hostPort, user)
	}

	setupSignalHandlers()

	go handleConsoleInput()

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
					if conn.monitoring {
						continue
					}
					idleTime := time.Since(conn.lastActivityTime)
					connUptime := time.Since(conn.startTime)

					if idleMax > 0 && idleTime > time.Duration(idleMax)*time.Second {
						connUptime := time.Since(conn.startTime)
						log.Printf("IDLEKILL [%s] %s@%s (idle %s, link %s)",
							id, conn.userName, conn.hostName, idleTime.Round(time.Second),
							connUptime.Round(time.Second))
						conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nIDLE TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second))))
						conn.sshConn.Close()
						delete(connections, id)
					} else if timeMax > 0 && connUptime > time.Duration(timeMax)*time.Second {
						connUptime := time.Since(conn.startTime)
						log.Printf("TIMEKILL [%s] %s@%s (link time %s)",
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

	select {}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isGitSHA(s string) bool {
	match, _ := regexp.MatchString("^[0-9a-f]{40}$", s)
	return match
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func printVersion() {
	versionString := "DPS8M Proxy"

	if info, ok := debug.ReadBuildInfo(); ok {
		var date, commit string
		var modified bool

		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.time":
				date = setting.Value

			case "vcs.revision":
				commit = setting.Value

			case "vcs.modified":
				modified = (setting.Value == "true")
			}
		}

		t, err := time.Parse(time.RFC3339, date)
		if err != nil {
			t = time.Now()
		}

		tdate := t.Format("2006-Jan-02")

		if commit != "" && isGitSHA(commit) {
			commit = commit[:7]
		}

		if date != "" && commit != "" {
			if modified == true {
				versionString += fmt.Sprintf(" (%s g%s+)", tdate, commit)
			} else {
				versionString += fmt.Sprintf(" (%s g%s)", tdate, commit)
			}
		}
	}

	versionString += fmt.Sprintf(" [%s/%s]", runtime.GOOS, runtime.GOARCH)

	if showVersion {
		fmt.Println(versionString)
	} else {
		log.Println(versionString)
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
			if err == io.EOF {
				if !gracefulShutdownMode.Load() {
					log.Println("Console EOF, initiating immediate shutdown.")
					immediateShutdown()
				}
				return
			}
			log.Printf("Console read error: %v", err)
			return
		}
		cmd := strings.TrimSpace(input)
		switch cmd {
		case "?", "h", "H":
			showHelp()

		case "q":
			toggleGracefulShutdown()

		case "d", "D":
			toggleDenyNewConnections()

		case "Q":
			immediateShutdown()

		case "l", "L":
			listConnections()

		case "c", "C":
			listConfiguration()

		case "k", "K":
			killConnection()

		case "R", "r":
			if blacklistFile == "" && whitelistFile == "" {
				log.Printf("NO ACCESS CONTROL LISTS ARE ENABLED.")
			} else {
				reloadLists()
			}

		case "":

		default:
			log.Printf("Unknown command: %s", cmd)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showHelp() {
	fmt.Print("\r\n" +
		"\r+========== HELP ===========+\r\n" +
		"\r|                           |\r\n" +
		"\r|  c - Show Configuration   |\r\n" +
		"\r|  l - List Connections     |\r\n" +
		"\r|  k - Kill Connection      |\r\n" +
		"\r|  d - Deny Connections     |\r\n" +
		"\r|  r - Reload Access Lists  |\r\n" +
		"\r|  q - Graceful Shutdown    |\r\n" +
		"\r|  Q - Immediate Shutdown   |\r\n" +
		"\r|                           |\r\n" +
		"\r+===========================+\r\n" +
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
		if conn.monitoring {
			fmt.Printf("\r* ID %s: %s@%s -> %s [Link: %s]\r\n",
				id, conn.sshConn.User(), conn.sshConn.RemoteAddr(), conn.monitoredConnection.ID,
				time.Since(conn.startTime).Round(time.Second))
		} else {
			targetInfo := ""
			if conn.targetHost != "" {
				targetInfo = fmt.Sprintf(" -> %s:%d", conn.targetHost, conn.targetPort)
			}
			fmt.Printf("\r* ID %s: %s@%s%s [Link: %s, Idle: %s]\r\n",
				id, conn.sshConn.User(), conn.sshConn.RemoteAddr(), targetInfo,
				time.Since(conn.startTime).Round(time.Second),
				time.Since(conn.lastActivityTime).Round(time.Second))
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConfiguration() {
	fmt.Println("")
	originalWriter := log.Writer()

	if consoleLogFile != nil {
		log.SetOutput(io.MultiWriter(os.Stdout))
	} else {
		log.SetOutput(os.Stdout)
	}

	printVersion()
	log.SetOutput(originalWriter)
	fmt.Println("\r\n\rDPS8M PROXY Configuration")
	fmt.Println("\r=========================")
	fmt.Printf("\r\n* SSH LISTEN ON: %s\r\n", strings.Join(sshAddr, ", "))
	fmt.Printf("\r\n* DEFAULT TARGET: %s\r\n", telnetHostPort)

	if len(altHosts) > 0 {
		fmt.Println("\r* ALT TARGETS:")
		for user, hostPort := range altHosts {
			fmt.Printf("\r  * %s [%s]\r\n", hostPort, user)
		}
	} else {
		fmt.Println("\r* ALT TARGETS: None configured")
	}

	fmt.Printf("\r\n* TIME MAX: %d seconds\r\n", timeMax)
	fmt.Printf("\r* IDLE MAX: %d seconds\r\n", idleMax)

	fmt.Printf("\r\n* LOG DIR: %s\r\n", logDir)
	fmt.Printf("\r* NO SESSION LOG: %t\r\n", noLog)
	if consoleLog != "" {
		logPath := getConsoleLogPath(time.Now())
		quietMode := ""
		if strings.ToLower(consoleLog) == "quiet" {
			quietMode = " (quiet mode)"
		}
		fmt.Printf("\r* CONSOLE LOG: %s%s\r\n", logPath, quietMode)
	} else {
		fmt.Printf("\r* CONSOLE LOG: Disabled\r\n")
	}
	fmt.Printf("\r* NO LOG COMPRESS: %t\r\n", noCompress)
	fmt.Printf("\r* COMPRESS ALGO: %s\r\n", compressAlgo)
	fmt.Printf("\r* LOG PERMISSIONS: %04o\r\n", logPerm)

	fmt.Printf("\r\n* GRACEFUL SHUTDOWN: %t\r\n", gracefulShutdownMode.Load())
	fmt.Printf("\r* DENY NEW CONNECTIONS: %t\r\n", denyNewConnectionsMode.Load())

	if blacklistFile == "" && len(blacklistedNetworks) == 0 {
		fmt.Printf("\r\n* BLACKLIST: disabled\r\n")
	} else if whitelistFile != "" && blacklistFile == "" {
		fmt.Printf("\r* BLACKLIST: deny all (due to whitelist only)\r\n")
	} else {
		if len(blacklistedNetworks) == 1 {
			fmt.Printf("\r* BLACKLIST: 1 entry loaded\r\n")
		} else {
			fmt.Printf("\r* BLACKLIST: %d entries loaded\r\n",
				len(blacklistedNetworks))
		}
	}

	if whitelistFile == "" {
		fmt.Printf("\r* WHITELIST: disabled\r\n")
	} else {
		if len(whitelistedNetworks) == 1 {
			fmt.Printf("\r* WHITELIST: 1 entry loaded\r\n")
		} else {
			fmt.Printf("\r* WHITELIST: %d entries loaded\r\n",
				len(whitelistedNetworks))
		}
	}

	fmt.Printf("\r\n* DEBUG: %t\r\n", debugNegotiation)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	samples := make([]metrics.Sample, 1)
	samples[0].Name = "/cpu/classes/user:cpu-seconds"
	metrics.Read(samples)
	cpuSeconds := samples[0].Value.Float64()

	fmt.Printf("\r\n* RESOURCE USAGE:"+
		"\r\n  * Memory usage: %s"+
		"\r\n  * Goroutines: %d active"+
		"\r\n  * CPU time used: %s\r\n\r\n",
		byteCountIEC(m.Alloc),
		runtime.NumGoroutine(),
		formatDuration(cpuSeconds))
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func reloadLists() {
	var newBlacklistedNetworks []*net.IPNet
	var newWhitelistedNetworks []*net.IPNet
	var reloadErrors []string

	blacklistReloaded := false
	whitelistReloaded := false

	if blacklistFile != "" {
		networks, err := parseIPListFile(blacklistFile)
		if err != nil {
			reloadErrors = append(
				reloadErrors, fmt.Sprintf("BLACKLIST REJECTED: %v", err))
		} else {
			newBlacklistedNetworks = networks
			blacklistReloaded = true
		}
	}

	if whitelistFile != "" {
		networks, err := parseIPListFile(whitelistFile)
		if err != nil {
			reloadErrors = append(
				reloadErrors, fmt.Sprintf("WHITELIST REJECTED: %v", err))
		} else {
			newWhitelistedNetworks = networks
			whitelistReloaded = true
		}
	}

	if len(reloadErrors) > 0 {
		for _, errMsg := range reloadErrors {
			log.Printf("%s", errMsg)
		}
		return
	}

	if blacklistReloaded {
		blacklistedNetworks = newBlacklistedNetworks
		if len(blacklistedNetworks) == 1 {
			log.Printf("BLACKLIST: 1 ENTRY LOADED [%s]",
				blacklistFile)
		} else {
			log.Printf("BLACKLIST: %d ENTRIES LOADED [%s]",
				len(blacklistedNetworks), blacklistFile)
		}
	}

	if whitelistReloaded {
		whitelistedNetworks = newWhitelistedNetworks
		if len(whitelistedNetworks) == 1 {
			log.Printf("WHITELIST: 1 ENTRY LOADED [%s]",
				whitelistFile)
		} else {
			log.Printf("WHITELIST: %d ENTRIES LOADED [%s]",
				len(whitelistedNetworks), whitelistFile)
		}
	}

	if whitelistFile != "" && blacklistFile == "" {
		_, ipv4Net, _ := net.ParseCIDR("0.0.0.0/0")
		_, ipv6Net, _ := net.ParseCIDR("::/0")
		blacklistedNetworks = append(blacklistedNetworks, ipv4Net, ipv6Net)
		log.Println("NO BLACKLIST: BLACKLISTING ALL BY DEFAULT")
	}
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

	conn.channel.Write([]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"))
	connUptime := time.Since(conn.startTime)
	log.Printf("TERMKILL [%s] %s@%s (link time %s)",
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
	sid := newSessionID(connections, &connectionsMutex)
	keyLog := []string{}

	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	remoteAddr := rawConn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	if !suppressLogs {
		log.Printf("INITIATE [%s] %s", sid, host)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(
			conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "password"},
			}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			line := fmt.Sprintf("VALIDATE [%s] %s@%s %q:%s",
				sid, c.User(), c.RemoteAddr(), pubKey.Type(), ssh.FingerprintSHA256(pubKey),
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
		ID:                sid,
		sshConn:           sshConn,
		startTime:         time.Now(),
		lastActivityTime:  time.Now(),
		cancelCtx:         ctx,
		cancelFunc:        cancel,
		userName:          sshConn.User(),
		hostName:          sshConn.RemoteAddr().String(),
		shareableUsername: newShareableUsername(connections, &connectionsMutex),
	}

	connectionsMutex.Lock()
	found := false
	for _, existingConn := range connections {
		if existingConn.shareableUsername == conn.userName {
			conn.monitoring = true
			conn.monitoredConnection = existingConn
			atomic.AddUint64(&existingConn.totalMonitors, 1)
			existingConn.wasMonitored = true
			found = true
			break
		}
	}
	if !found && strings.HasPrefix(conn.userName, "_") && len(conn.userName) == 21 {
		conn.invalidShare = true
	}
	connections[sid] = conn
	connectionsMutex.Unlock()

	defer func() {
		conn.cancelFunc()
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
	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	remoteHost, _, err := net.SplitHostPort(conn.sshConn.RemoteAddr().String())
	if err != nil {
		remoteHost = conn.sshConn.RemoteAddr().String()
	}
	clientIP := net.ParseIP(remoteHost)
	if clientIP == nil {
		if !suppressLogs {
			log.Printf("TEARDOWN [%s] Invalid address: %s", conn.ID, remoteHost)
		}
		channel.Close()
		conn.sshConn.Close()
		return
	}

	var rejectedByRule string
	for _, ipNet := range blacklistedNetworks {
		if ipNet.Contains(clientIP) {
			rejectedByRule = ipNet.String()
			break
		}
	}

	if rejectedByRule != "" {
		var exemptedByRule string
		for _, ipNet := range whitelistedNetworks {
			if ipNet.Contains(clientIP) {
				exemptedByRule = ipNet.String()
				break
			}
		}

		if exemptedByRule != "" {
			if !suppressLogs {
				log.Printf("EXEMPTED [%s] %s (matched %s)",
					conn.ID, conn.sshConn.RemoteAddr().String(), exemptedByRule)
			}
		} else {
			if !suppressLogs {
				log.Printf("REJECTED [%s] %s (matched %s)",
					conn.ID, conn.sshConn.RemoteAddr().String(), rejectedByRule)
			}
			if raw, err := getFileContent(blockFile, conn.userName); err == nil {
				blockMessageContent := strings.ReplaceAll(
					strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
				channel.Write([]byte(blockMessageContent + "\r\n"))
			} else {
				channel.Write([]byte("Connection blocked.\r\n"))
			}
			channel.Close()
			conn.sshConn.Close()
			return
		}
	}

	sendBanner(conn.ID, conn.sshConn, channel, conn)
	if conn.monitoring {
		if !suppressLogs {
			log.Printf("UMONITOR [%s] %s -> %s",
				conn.ID, conn.userName, conn.monitoredConnection.ID)
		}

		go func() {
			buf := make([]byte, 1)
			for {
				_, err := channel.Read(buf)
				if err != nil {
					return
				}
				if buf[0] == 0x1D { // Ctrl-]
					channel.Close()
					return
				}
			}
		}()

		<-conn.monitoredConnection.cancelCtx.Done()
		dur := time.Since(conn.startTime)
		channel.Write([]byte(fmt.Sprintf(
			"\r\nMONITORING SESSION CLOSED (monitored for %s)\r\n\r\n", dur.Round(time.Second))))
		channel.Close()
		return
	}

	if gracefulShutdownMode.Load() || denyNewConnectionsMode.Load() {
		if denyMsg, err := getFileContent(denyFile, conn.userName); err == nil {
			txt := strings.ReplaceAll(
				strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n")
			channel.Write([]byte("\r\n"))
			channel.Write([]byte(txt))
			channel.Write([]byte("\r\n"))
		}
		channel.Close()
		return
	}

	if raw, err := getFileContent(issueFile, conn.userName); err == nil {
		txt := strings.ReplaceAll(
			strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
		channel.Write([]byte(txt + "\r\n"))
	}

	start := time.Now()
	var sshIn, sshOut, telnetIn, telnetOut uint64

	var logfile *os.File
	var logwriter io.Writer
	var basePath string

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
			dur := time.Since(start)
			logwriter.Write([]byte(fmt.Sprintf(
				nowStamp()+" Session end (link time %s)\r\n", dur.Round(time.Second))))
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
		conn.targetHost = targetHost
		conn.targetPort = targetPort
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
		logwriter.Write([]byte(fmt.Sprintf(
			nowStamp()+" Target: %s:%d\r\n", targetHost, targetPort)))
		logwriter.Write([]byte(fmt.Sprintf(
			nowStamp()+" Connection sharing username: '%s'\r\n", conn.shareableUsername)))
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

		var menuMode bool
		var escSequence []byte
		var escTimer <-chan time.Time
		reader := bufio.NewReader(channel)

		byteChan := make(chan byte)
		errorChan := make(chan error)

		go func() {
			for {
				select {
				case <-ctx.Done():
					close(byteChan)
					close(errorChan)
					return
				default:
					b, err := reader.ReadByte()
					if err != nil {
						errorChan <- err
						close(byteChan)
						close(errorChan)
						return
					}
					byteChan <- b
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				if len(escSequence) > 0 {
					remote.Write(escSequence)
					logwriter.Write(escSequence)
				}
				return

			case <-escTimer:
				m, _ := remote.Write(escSequence)
				atomic.AddUint64(&telnetOut, uint64(m))
				logwriter.Write(escSequence)
				escSequence = nil
				escTimer = nil

			case b := <-byteChan:
				conn.lastActivityTime = time.Now()
				atomic.AddUint64(&sshIn, 1)
				atomic.AddUint64(&conn.sshInTotal, 1)

				if menuMode {
					handleMenuSelection(b, conn, channel, remote, logwriter,
						&sshIn, &sshOut, &telnetIn, &telnetOut, start)
					menuMode = false
					continue
				}

				if b == 0x1d { // Ctrl-]
					showMenu(channel)
					menuMode = true
					escSequence = nil
					escTimer = nil
					continue
				}

				if len(escSequence) > 0 {
					escSequence = append(escSequence, b)
					if conn.emacsKeymapEnabled {
						if replacement, ok :=
							emacsKeymap[string(escSequence)]; ok {
							m, _ := remote.Write([]byte(replacement))
							atomic.AddUint64(&telnetOut, uint64(m))
							logwriter.Write([]byte(replacement))
							escSequence = nil
							escTimer = nil
						} else if _, isPrefix :=
							emacsKeymapPrefixes[string(escSequence)]; isPrefix {
							escTimer = time.After(50 * time.Millisecond)
						} else {
							m, _ := remote.Write(escSequence)
							atomic.AddUint64(&telnetOut, uint64(m))
							logwriter.Write(escSequence)
							escSequence = nil
							escTimer = nil
						}
					} else {
						m, _ := remote.Write(escSequence)
						atomic.AddUint64(&telnetOut, uint64(m))
						logwriter.Write(escSequence)
						escSequence = nil
						escTimer = nil
					}
				} else if b == 0x1b && conn.emacsKeymapEnabled {
					escSequence = append(escSequence, b)
					escTimer = time.After(50 * time.Millisecond)
				} else {
					m, _ := remote.Write([]byte{b})
					atomic.AddUint64(&telnetOut, uint64(m))
					logwriter.Write([]byte{b})
				}

			case err := <-errorChan:
				if len(escSequence) > 0 {
					remote.Write(escSequence)
					logwriter.Write(escSequence)
				}
				if err != io.EOF {
					log.Printf("SSH channel read error: %v", err)
				}
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
			remote.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := remote.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					select {
					case <-ctx.Done():
						return
					default:
					}
					continue
				} else {
					dur := time.Since(start)
					log.Printf("DETACHED [%s] %s@%s (link time %s)",
						conn.ID, conn.userName, conn.hostName, dur.Round(time.Second))
					channel.Write([]byte(fmt.Sprintf(
						"\r\nCONNECTION CLOSED (link time %s)\r\n\r\n",
						dur.Round(time.Second))))

					inRateSSH := uint64(float64(atomic.LoadUint64(&sshIn)) / dur.Seconds())
					outRateSSH := uint64(float64(atomic.LoadUint64(&sshOut)) / dur.Seconds())
					inRateNVT := uint64(float64(atomic.LoadUint64(&telnetIn)) / dur.Seconds())
					outRateNVT := uint64(float64(atomic.LoadUint64(&telnetOut)) / dur.Seconds())

					channel.Write([]byte(fmt.Sprintf(
						">> SSH - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
						atomic.LoadUint64(&sshIn), atomic.LoadUint64(&sshOut),
						inRateSSH, outRateSSH)))
					channel.Write([]byte(fmt.Sprintf(
						">> NVT - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
						atomic.LoadUint64(&telnetIn), atomic.LoadUint64(&telnetOut),
						inRateNVT, outRateNVT)))
					channel.Write([]byte("\r\n"))

					channel.Close()
					conn.sshInTotal = sshIn
					conn.sshOutTotal = sshOut
					return
				}
			}

			if n > 0 {
				atomic.AddUint64(&telnetIn, uint64(n))
				atomic.AddUint64(&conn.sshInTotal, uint64(n))
				fwd := buf[:0]

				for i := 0; i < n; i++ {
					if buf[i] != 0 {
						fwd = append(fwd, buf[i])
					}
				}

				atomic.AddUint64(&sshOut, uint64(len(fwd)))
				atomic.AddUint64(&conn.sshOutTotal, uint64(len(fwd)))
				channel.Write(fwd)
				connectionsMutex.Lock()

				for _, c := range connections {
					if c.monitoring && c.monitoredConnection.ID == conn.ID {
						c.channel.Write(fwd)
					}
				}

				connectionsMutex.Unlock()
				logwriter.Write(buf[:n])
				conn.lastActivityTime = time.Now()
			}
		}
	}()

	wg.Wait()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendBanner(sid string, sshConn *ssh.ServerConn, ch ssh.Channel, conn *Connection) {
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

	if conn.monitoring {
		fmt.Fprint(ch, "This is a READ-ONLY shared monitoring session.\r\n")
		fmt.Fprint(ch, "Send Control-] to disconnect.\r\n")
	} else {
		if conn.invalidShare {
			fmt.Fprintf(ch, "The username '%s' was NOT active for session sharing!\r\n",
				conn.userName)
		}
	}

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
				writeNegotiation(ch, logw,
					"[RCVD "+cmdName(cmd)+" "+optName(opt)+"]")
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
				writeNegotiation(ch, logw,
					"[SENT "+cmdName(reply)+" "+optName(opt)+"]")
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

func showMenu(ch ssh.Channel) {
	menu := "\r\n" +
		"\r+======= MENU ========+\r\n" +
		"\r|                     |\r\n" +
		"\r|  A - Send AYT       |\r\n" +
		"\r|  B - Send Break     |\r\n" +
		"\r|  K - Toggle Keymap  |\r\n" +
		"\r|  N - Send NOP       |\r\n" +
		"\r|  S - Show Status    |\r\n" +
		"\r|  X - Disconnect     |\r\n" +
		"\r|                     |\r\n" +
		"\r+=====================+\r\n"
	ch.Write([]byte(menu))
}

func handleMenuSelection(sel byte, conn *Connection, ch ssh.Channel, remote net.Conn,
	logw io.Writer, sshIn, sshOut, telnetIn, telnetOut *uint64, start time.Time) {
	switch sel {
	case 'a', 'A':
		remote.Write([]byte{IAC, AYT}) // AYT
		logw.Write([]byte{IAC, AYT})
		ch.Write([]byte("\r\n>> Sent AYT\r\n"))
		ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

	case 'b', 'B':
		remote.Write([]byte{IAC, 243}) // BREAK
		logw.Write([]byte{IAC, 243})
		ch.Write([]byte("\r\n>> Sent BREAK\r\n"))
		ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

	case 'k', 'K':
		conn.emacsKeymapEnabled = !conn.emacsKeymapEnabled
		if conn.emacsKeymapEnabled {
			ch.Write([]byte("\r\n>> EMACS KEYMAP ENABLED\r\n"))
		} else {
			ch.Write([]byte("\r\n>> EMACS KEYMAP DISABLED\r\n"))
		}
		ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

	case 'n', 'N':
		remote.Write([]byte{IAC, NOP}) // NOP
		logw.Write([]byte{IAC, NOP})
		ch.Write([]byte("\r\n>> Sent NOP\r\n"))
		ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

	case 's', 'S':
		dur := time.Since(start)
		ch.Write([]byte("\r\n"))
		ch.Write([]byte(fmt.Sprintf(
			">> LNK - Username '%s' can be used to share this session.\r\n",
			conn.shareableUsername)))
		if conn.wasMonitored {
			connectionsMutex.Lock()
			currentMonitors := 0
			for _, c := range connections {
				if c.monitoring && c.monitoredConnection.ID == conn.ID {
					currentMonitors++
				}
			}
			connectionsMutex.Unlock()
			timesStr := "times"
			if conn.totalMonitors == 1 {
				timesStr = "time"
			}
			userStr := "users"
			if currentMonitors == 1 {
				userStr = "user"
			}
			ch.Write([]byte(fmt.Sprintf(
				">> MON - Shared session has been viewed %d %s; %d %s currently online.\r\n",
				conn.totalMonitors, timesStr, currentMonitors, userStr)))
		}

		inSSH := atomic.LoadUint64(sshIn)
		outSSH := atomic.LoadUint64(sshOut)
		inNVT := atomic.LoadUint64(telnetIn)
		outNVT := atomic.LoadUint64(telnetOut)

		inRateSSH := uint64(float64(atomic.LoadUint64(sshIn)) / dur.Seconds())
		outRateSSH := uint64(float64(atomic.LoadUint64(sshOut)) / dur.Seconds())
		inRateNVT := uint64(float64(atomic.LoadUint64(telnetIn)) / dur.Seconds())
		outRateNVT := uint64(float64(atomic.LoadUint64(telnetOut)) / dur.Seconds())

		ch.Write([]byte(fmt.Sprintf(
			">> SSH - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
			inSSH, outSSH, inRateSSH, outRateSSH)))
		ch.Write([]byte(fmt.Sprintf(
			">> NVT - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
			inNVT, outNVT, inRateNVT, outRateNVT)))

		keymapStatus := ""
		if conn.emacsKeymapEnabled {
			keymapStatus = " (Emacs keymap enabled)"
		}
		ch.Write([]byte(fmt.Sprintf(
			">> LNK - link time: %s%s\r\n", dur.Round(time.Second).String(), keymapStatus)))
		ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))

	case 'x', 'X':
		ch.Write([]byte("\r\n>> DISCONNECTING...\r\n"))
		ch.Close()

	default:
		ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func byteCountIEC(b uint64) string {
	const unit = 1024

	if b < unit {
		return fmt.Sprintf("%d B", b)
	}

	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func formatDuration(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	days := int(d / (24 * time.Hour))

	d = d % (24 * time.Hour)
	hours := int(d / time.Hour)

	d = d % time.Hour
	minutes := int(d / time.Minute)

	d = d % time.Minute
	seconds = d.Seconds()

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}

	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}

	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}

	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%.0fs", seconds))
	}
	return strings.Join(parts, " ")
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
	)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", err
	}

	dir = filepath.Join(dir, ipDir)
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
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm))
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

	compressLogFile(logFilePath)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sanitizeIP(s string) string {
	return strings.NewReplacer(":", "_", ".", "_").Replace(s)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func newSessionID(connections map[string]*Connection, mutex *sync.Mutex) string {
	for {
		b := make([]byte, 3)
		rand.Read(b)
		id := hex.EncodeToString(b)

		mutex.Lock()
		_, exists := connections[id]
		mutex.Unlock()

		if !exists {
			return id
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func newShareableUsername(connections map[string]*Connection, mutex *sync.Mutex) string {
	const chars = "abcdghkmnprsvwxyzACDFGJKMNPRSTVXY345679" // LOL
	for {
		b := make([]byte, 20)
		rand.Read(b)
		for i, v := range b {
			b[i] = chars[v%byte(len(chars))]
		}
		username := "_" + string(b)

		mutex.Lock()
		found := false
		for _, conn := range connections {
			if conn.shareableUsername == username {
				found = true
				break
			}
		}
		mutex.Unlock()

		if !found {
			return username
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func nowStamp() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getFileContent(baseFilename, username string) ([]byte, error) {
	userSpecificFile := fmt.Sprintf(
		"%s-%s.txt", strings.TrimSuffix(baseFilename, ".txt"), username)
	content, err := os.ReadFile(userSpecificFile)
	if err == nil {
		return content, nil
	}

	return os.ReadFile(baseFilename)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getConsoleLogPath(t time.Time) string {
	return filepath.Join(
		logDir,
		fmt.Sprintf("%04d", t.Year()),
		fmt.Sprintf("%02d", t.Month()),
		fmt.Sprintf("%02d", t.Day()),
		"console.log",
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func setupConsoleLogging() {
	if consoleLog == "" {
		return
	}

	rotateConsoleLog()

	go func() {
		for {
			now := time.Now()
			nextMidnight := now.Add(24 * time.Hour).Truncate(24 * time.Hour)
			time.Sleep(time.Until(nextMidnight))

			rotateConsoleLog()
		}
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func rotateConsoleLog() {
	consoleLogMutex.Lock()
	defer consoleLogMutex.Unlock()

	if consoleLogFile != nil {
		if !noCompress {
			yesterdayLogPath := getConsoleLogPath(time.Now().AddDate(0, 0, -1))
			compressLogFile(yesterdayLogPath)
		}
		consoleLogFile.Close()
	}

	logPath := getConsoleLogPath(time.Now())
	logDir := filepath.Dir(logPath)

	if err := os.MkdirAll(logDir, 0o755); err != nil {
		log.Fatalf("Failed to create console log directory: %v", err)
	}

	var err error
	consoleLogFile, err = os.OpenFile(logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm))
	if err != nil {
		log.Fatalf("Failed to open console log file: %v", err)
	}

	fmt.Fprintf(os.Stderr, "%s CONSOLE LOG: %s\n", nowStamp(), logPath)

	if consoleLog == "quiet" {
		log.SetOutput(consoleLogFile)
	} else {
		log.SetOutput(io.MultiWriter(os.Stdout, consoleLogFile))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func compressLogFile(logFilePath string) {
	if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
		return
	}

	data, err := ioutil.ReadFile(logFilePath)
	if err != nil {
		log.Printf("Failed to read log %q for compression: %v", logFilePath, err)
		return
	}

	var compressedFilePath string
	var compressedFile *os.File
	var writer io.WriteCloser

	switch compressAlgo {
	case "gzip":
		compressedFilePath = logFilePath + ".gz"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)
			return
		}
		writer, err = gzip.NewWriterLevel(compressedFile, gzip.BestCompression)
		if err != nil {
			log.Printf("Error creating gzip writer for %q: %v", compressedFilePath, err)
			compressedFile.Close()
			return
		}

	case "xz":
		compressedFilePath = logFilePath + ".xz"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)
			return
		}
		writer, err = xz.NewWriter(compressedFile)
		if err != nil {
			log.Printf("Error creating xz writer for %q: %v", compressedFilePath, err)
			compressedFile.Close()
			return
		}

	case "zstd":
		compressedFilePath = logFilePath + ".zst"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)
			return
		}
		writer, err = zstd.NewWriter(
			compressedFile, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
		if err != nil {
			log.Printf("Error creating zstd writer for %q: %v", compressedFilePath, err)
			compressedFile.Close()
			return
		}

	default:
		log.Printf("Unknown compression algorithm: %s", compressAlgo)
		return
	}

	defer compressedFile.Close()
	defer writer.Close()

	_, err = writer.Write(data)
	if err != nil {
		log.Printf("Error writing to compressed file %q: %v", compressedFilePath, err)
		return
	}

	err = writer.Close()
	if err != nil {
		log.Printf("Error closing writer for %q: %v", compressedFilePath, err)
		return
	}

	err = compressedFile.Close()
	if err != nil {
		log.Printf("Error closing compressed file %q: %v", compressedFilePath, err)
		return
	}

	err = os.Remove(logFilePath)
	if err != nil {
		log.Printf("Error removing original log %q after compression: %v", logFilePath, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func parseIPListFile(filePath string) ([]*net.IPNet, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}
	defer file.Close()

	var networks []*net.IPNet
	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err == nil {
			networks = append(networks, ipNet)
			continue
		}

		ip := net.ParseIP(line)
		if ip != nil {
			if ip.To4() != nil {
				networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			} else {
				networks = append(networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
			continue
		}

		return nil, fmt.Errorf("BAD IP OR CIDR BLOCK \"%s\" ON LINE %d [%s]",
			line, lineNumber, filePath)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", filePath, err)
	}

	return networks, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
