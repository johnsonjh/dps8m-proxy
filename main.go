///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/spf13/pflag"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/ssh"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const (
	// TELNET Commands.
	TelcmdNOP  = 241 // No operation
	TelcmdAYT  = 246 // Are You There?
	TelcmdIAC  = 255 // Interpret As Command
	TelcmdDONT = 254 // DONT
	TelcmdDO   = 253 // DO
	TelcmdWONT = 252 // WONT
	TelcmdWILL = 251 // WILL

	// TELNET Command Options.
	TeloptBinary          = 0
	TeloptEcho            = 1
	TeloptSuppressGoAhead = 3

	// IEC sizes.
	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	startTime              = time.Now()
	allowRoot              bool
	logPerm                uint = 0o600
	logDirPerm             uint = 0o750
	altHosts                    = make(map[string]string)
	blacklistedNetworks    []*net.IPNet
	blacklistFile          string
	connections            = make(map[string]*Connection)
	connectionsMutex       sync.Mutex
	consoleInputActive     atomic.Bool
	consoleLogFile         *os.File
	consoleLogMutex        sync.Mutex
	consoleLog             string
	isConsoleLogQuiet      bool
	debugNegotiation       bool
	denyNewConnectionsMode atomic.Bool
	gracefulShutdownMode   atomic.Bool
	idleMax                int
	logDir                 string
	loggingWg              sync.WaitGroup
	noBanner               bool
	noCompress             bool
	noLog                  bool
	showVersion            bool
	shutdownOnce           sync.Once
	shutdownSignal         chan struct{}
	sshAddr                []string
	telnetHostPort         string
	timeMax                int
	whitelistedNetworks    []*net.IPNet
	whitelistFile          string
	issueFile              = "issue.txt"
	denyFile               = "deny.txt"
	blockFile              = "block.txt"
	compressAlgo           string
	compressLevel          string
	emacsKeymap            = map[string]string{
		"\x1b[1;5A": "\x1b\x5b", //    Control-Arrow_Up -> Escape, [
		"\x1b[1;5B": "\x1b\x5d", // Control-Arrrow_Down -> Escape, ]
		"\x1b[1;5C": "\x1b\x66", // Control-Arrow_Right -> Escape, f
		"\x1b[1;5D": "\x1b\x62", //  Control-Arrow_Left -> Escape, b
		"\x1b[1~":   "\x01",     //                Home -> Control-A
		"\x1b[3~":   "\x04",     //              Delete -> Control-D
		"\x1b[4~":   "\x05",     //                 End -> Control-E
		"\x1b[5~":   "\x1b\x76", //             Page_Up -> Escape, v
		"\x1b[6~":   "\x16",     //           Page_Down -> Control-V
		"\x1b[A":    "\x10",     //            Arrow_Up -> Control-P
		"\x1b[B":    "\x0e",     //          Arrow_Down -> Control-N
		"\x1b[C":    "\x06",     //         Arrow_Right -> Control-F
		"\x1b[D":    "\x02",     //          Arrow_Left -> Control-B
	}
	emacsKeymapPrefixes     = make(map[string]bool)
	acceptErrorsTotal       atomic.Uint64
	adminKillsTotal         atomic.Uint64
	exemptedTotal           atomic.Uint64
	idleKillsTotal          atomic.Uint64
	monitorSessionsTotal    atomic.Uint64
	rejectedTotal           atomic.Uint64
	sshConnectionsTotal     atomic.Uint64
	sshHandshakeFailedTotal atomic.Uint64
	sshKeySeenTotal         atomic.Uint64
	sshSessionsTotal        atomic.Uint64
	telnetConnectionsTotal  atomic.Uint64
	telnetSessionsTotal     atomic.Uint64
	timeKillsTotal          atomic.Uint64
	sshAuthSeenTotal        atomic.Uint64
	altHostRoutesTotal      atomic.Uint64
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

func (a *altHostFlag) String() string {
	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) Set(value string) error {
	parts := strings.SplitN(value, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid alt-host format: %s, expected sshuser@host:port", value)
	}

	username := parts[0]
	hostPort := parts[1]

	if _, ok := altHosts[username]; ok {
		return fmt.Errorf("duplicate alt-host entry for sshuser: %s", username)
	}

	_, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return fmt.Errorf("invalid host:port in alt-host '%s': %w", value, err)
	}

	altHosts[username] = hostPort

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (a *altHostFlag) Type() string {
	return "string"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type octalPermValue uint

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) String() string {
	return fmt.Sprintf("%o", *op)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return fmt.Errorf("invalid octal permission value: %w", err)
	}
	*op = octalPermValue(v)

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) Type() string {
	return "octal"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	pflag.CommandLine.SortFlags = false

	pflag.BoolVarP(&allowRoot,
		"allow-root", "0", false,
		"Allow running as root (UID 0)")

	pflag.StringSliceVarP(&sshAddr,
		"ssh-addr", "l", []string{":2222"},
		"SSH listener address(es)\n   [e.g., \":2222\", \"[::1]:8000\"]\n   (multiple allowed)")
	pflag.Lookup("ssh-addr").DefValue = "\":2222\""

	pflag.BoolVarP(&noBanner,
		"no-banner", "n", false,
		"Disable SSH connection banner")

	pflag.StringVarP(&telnetHostPort,
		"telnet-host", "t", "127.0.0.1:6180",
		"Default TELNET target [host:port]\n  ")

	pflag.VarP(&altHostFlag{},
		"alt-host", "a",
		"Alternate TELNET target(s) [sshuser@host:port]\n   (multiple allowed)")

	pflag.BoolVarP(&debugNegotiation,
		"debug", "d", false,
		"Debug TELNET option negotiation")

	pflag.StringVarP(&logDir,
		"log-dir", "L", "./log",
		"Base directory for logs")

	pflag.BoolVarP(&noLog,
		"no-log", "o", false,
		"Disable all session logging\n   (for console logging, see \"--console-log\")")

	pflag.StringVarP(&consoleLog,
		"console-log", "c", "",
		"Enable console logging [\"quiet\", \"noquiet\"]")

	pflag.StringVarP(&compressAlgo,
		"compress-algo", "C", "gzip",
		"Compression algorithm [\"gzip\", \"xz\", \"zstd\"]\n  ")

	pflag.StringVarP(&compressLevel,
		"compress-level", "s", "normal",
		"Compression level for gzip and zstd algorithms\n   [\"fast\", \"normal\", \"high\"]\n  ")

	pflag.BoolVarP(&noCompress,
		"no-compress", "x", false,
		"Disable session and console log compression")

	pflag.VarP((*octalPermValue)(&logPerm),
		"log-perm", "p",
		"Permissions (octal) for new log files\n   [ e.g., \"600\", \"644\"]")
	pflag.Lookup("log-perm").DefValue = "\"600\""

	pflag.VarP((*octalPermValue)(&logDirPerm),
		"log-dir-perm", "P",
		"Permissions (octal) for new log directories\n   [e.g., \"755\", \"750\"]")
	pflag.Lookup("log-dir-perm").DefValue = "\"750\""

	pflag.IntVarP(&idleMax,
		"idle-max", "i", 0,
		"Maximum connection idle time allowed [seconds]")

	pflag.IntVarP(&timeMax,
		"time-max", "m", 0,
		"Maximum connection link time allowed [seconds]")

	pflag.StringVarP(&blacklistFile,
		"blacklist", "b", "",
		"Enable blacklist [filename] (no default)")

	pflag.StringVarP(&whitelistFile,
		"whitelist", "w", "",
		"Enable whitelist [filename] (no default)")

	pflag.BoolVarP(&showVersion,
		"version", "v", false,
		"Show version information")

	shutdownSignal = make(chan struct{})

	for k := range emacsKeymap {
		for i := 1; i < len(k); i++ {
			emacsKeymapPrefixes[k[:i]] = true
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func shutdownWatchdog() {
	<-shutdownSignal
	loggingWg.Wait()

	if isConsoleLogQuiet {
		fmt.Fprintf(os.Stderr, "%s All connections closed. Exiting.\r\n", nowStamp())
	}

	log.Println("All connections closed. Exiting.")

	os.Exit(0)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	pflag.Parse()

	if consoleLog != "" {
		cl := strings.ToLower(consoleLog)
		if cl != "quiet" && cl != "noquiet" { // LINTED: Fatalf
			log.Fatalf("ERROR: Invalid --console-log value: %s.  Must be 'quiet' or 'noquiet'",
				consoleLog)
		}
		isConsoleLogQuiet = (cl == "quiet")
	}

	printVersion()

	if showVersion {
		os.Exit(0)
	}

	if os.Getuid() == 0 && !allowRoot { // LINTED: Fatalf
		log.Fatalf("ERROR: Running as root/UID 0 is not allowed without the -allow-root flag!")
	}

	switch compressAlgo {
	case "gzip", "xz", "zstd":

	default:
		log.Fatalf("ERROR: Invalid --compress-algo: %s", compressAlgo) // LINTED: Fatalf
	}

	switch compressLevel {
	case "fast", "normal", "high": //nolint:goconst

	default:
		log.Fatalf("ERROR: Invalid --compress-level: %s", compressLevel) // LINTED: Fatalf
	}

	setupConsoleLogging()

	if err := os.MkdirAll(logDir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		log.Fatalf("Failed to create log directory: %v", err) // LINTED: Fatalf
	}

	if p, err := filepath.EvalSymlinks(logDir); err == nil {
		logDir = p
	}

	if p, err := filepath.Abs(logDir); err == nil {
		logDir = p
	}

	logDir = filepath.Clean(logDir)

	reloadLists()

	if strings.Contains(telnetHostPort, "@") {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s ERROR: --telnet-host cannot contain a username (e.g., 'user@'). "+
					"Received: %s\r\n", nowStamp(), telnetHostPort)
		}

		log.Fatalf("ERROR: --telnet-host cannot contain a username (e.g., 'user@'). "+
			"Received: %s", telnetHostPort) // LINTED: Fatalf
	}

	if idleMax > 0 && timeMax > 0 && idleMax >= timeMax {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s ERROR: --idle-max (%d) cannot be greater than or equal to --time-max (%d)\r\n",
				nowStamp(), idleMax, timeMax)
		}

		log.Fatalf("ERROR: --idle-max (%d) cannot be greater than or equal to --time-max (%d)",
			idleMax, timeMax) // LINTED: Fatalf
	}

	edSigner, err := loadOrCreateHostKey("ssh_host_ed25519_key.pem", "ed25519")
	if err != nil {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Ed25519 host key error: %v\r\n", nowStamp(), err)
		}

		log.Fatalf("Ed25519 host key error: %v", err) // LINTED: Fatalf
	}

	rsaSigner, err := loadOrCreateHostKey("ssh_host_rsa_key.pem", "rsa")
	if err != nil {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s RSA host key error: %v\r\n", nowStamp(), err)
		}

		log.Fatalf("RSA host key error: %v", err) // LINTED: Fatalf
	}

	for _, addr := range sshAddr {
		go func(addr string) {
			checkPrivilegedPorts(sshAddr)
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				if isConsoleLogQuiet {
					fmt.Fprintf(os.Stderr, "%s LISTEN %s: %v\r\n", nowStamp(), addr, err)
				}

				log.Fatalf("LISTEN %s: %v", addr, err) // LINTED: Fatalf
			}
			defer func() {
				if err := listener.Close(); err != nil {
					log.Printf("Failed to close listener for %s: %v", addr, err)
				}
			}()

			for {
				rawConn, err := listener.Accept()
				if err != nil {
					if gracefulShutdownMode.Load() {
						return
					}

					acceptErrorsTotal.Add(1)
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
		startMsg = fmt.Sprintf("Starting proxy [PID %d]", pid)
	} else {
		startMsg = "Starting proxy"
	}

	if isConsoleLogQuiet {
		fmt.Fprintf(os.Stderr, "%s %s - Type '?' for help\r\n", nowStamp(), startMsg)
	}

	log.Printf("%s - Type '?' for help", startMsg)

	for _, addr := range sshAddr {
		log.Printf("SSH listener on %s", addr)
	}

	defaultHost, defaultPort, err := parseHostPort(telnetHostPort)
	if err != nil {
		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Error parsing default TELNET target: %v\r\n",
				nowStamp(), err)
		}

		log.Fatalf("Error parsing default TELNET target: %v", err) // LINTED: Fatalf
	}

	log.Printf("Default TELNET target: %s:%d", defaultHost, defaultPort)

	for user, hostPort := range altHosts {
		log.Printf("Alt target: %s [%s]", hostPort, user)
	}

	runSignalHandlers()

	go handleConsoleInput()

	go shutdownWatchdog()

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
						idleKillsTotal.Add(1)
						connUptime := time.Since(conn.startTime)
						log.Printf("IDLEKILL [%s] %s@%s (idle %s, link %s)",
							id, conn.userName, conn.hostName, idleTime.Round(time.Second),
							connUptime.Round(time.Second))
						if _, err := conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nIDLE TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second)))); err != nil {
							log.Printf(
								"Error writing idle timeout message to channel for %s: %v",
								id, err)
						}

						if err := conn.sshConn.Close(); err != nil {
							log.Printf("Error closing SSH connection for %s: %v", id, err)
						}

						delete(connections, id)
					} else if timeMax > 0 && connUptime > time.Duration(timeMax)*time.Second {
						timeKillsTotal.Add(1)
						connUptime := time.Since(conn.startTime)
						log.Printf("TIMEKILL [%s] %s@%s (link time %s)",
							id, conn.userName, conn.hostName, connUptime.Round(time.Second))
						if _, err := conn.channel.Write([]byte(fmt.Sprintf(
							"\r\n\r\nCONNECTION TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second)))); err != nil {
							log.Printf(
								"Error writing connection timeout message to channel for %s: %v",
								id, err)
						}

						if err := conn.sshConn.Close(); err != nil {
							log.Printf("Error closing SSH connection for %s: %v", id, err)
						}

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

	versionString += func() string {
		if v := getMainModuleVersion(); v != "" {
			return " " + v
		}

		return ""
	}()

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
			if modified {
				versionString += fmt.Sprintf(" (%s g%s+)", tdate, commit)
			} else {
				versionString += fmt.Sprintf(" (%s g%s)", tdate, commit)
			}
		}
	}

	versionString += fmt.Sprintf(" [%s/%s]", runtime.GOOS, runtime.GOARCH)

	if showVersion {
		fmt.Println(versionString)
		fmt.Printf("\r\n")
		printVersionTable()
		fmt.Printf("\r\n")
	} else {
		log.Println(versionString)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConsoleInput() {
	for {
		if consoleInputActive.Load() {
			time.Sleep(100 * time.Millisecond)

			continue
		}

		reader := bufio.NewReader(os.Stdin)
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

		parts := strings.Fields(input)

		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

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

		case "s", "S":
			showStats()

		case "c", "C":
			listConfiguration()

		case "v", "V":
			fmt.Println("")
			originalWriter := log.Writer()

			if consoleLogFile != nil {
				log.SetOutput(io.MultiWriter(os.Stdout))
			} else {
				log.SetOutput(os.Stdout)
			}

			printVersion()
			fmt.Println("")
			printVersionTable()
			fmt.Println("")
			log.SetOutput(originalWriter)

		case "cg", "CG", "cG", "Cg":
			listGoroutines()

		case "k", "K":
			if len(parts) < 2 {
				fmt.Fprintf(os.Stderr, "%s Error: session ID required for 'k' command.\r\n",
					nowStamp())

				continue
			}
			killConnection(parts[1])

		case "r", "R":
			if blacklistFile == "" || whitelistFile == "" {
				if _, err := fmt.Fprintf(
					os.Stdout, "%s Reload requested but no lists enabled.\r\n",
					nowStamp()); err != nil {
					log.Printf("Error writing to stdout: %v", err)
				}
			}
			reloadLists()

		case "xyzzy": // :)
			if isConsoleLogQuiet {
				fmt.Printf("%s Nothing happens.\r\n", nowStamp())
			}
			log.Println("Nothing happens.")

		case "XYZZY": // =)
			if isConsoleLogQuiet {
				fmt.Printf("%s NOTHING HAPPENS.\r\n", nowStamp())
			}
			log.Println("NOTHING HAPPENS.")

		case "":

		default:
			if _, err := fmt.Fprintf(
				os.Stdout, "%s Unknown command: %s\r\n", nowStamp(), cmd); err != nil {
				log.Printf("Error writing to stdout: %v", err)
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showHelp() {
	type row struct{ Key, Description string }

	rows := []row{
		{"c ", "Show Configuration and Status"},
		{"v ", "Show Version Information"},
		{"s ", "Show Connection Statistics"},
		{"l ", "List Active Connections"},
		{"k ", "Kill A Connection"},
		{"d ", "Deny New Connections"},
		{"r ", "Reload Access Control Lists"},
		{"q ", "Start Graceful Shutdown"},
		{"Q ", "Immediate Shutdown"},
	}

	maxKey := len("Key")
	maxDesc := len("Description")

	for _, r := range rows {
		if len(r.Key) > maxKey {
			maxKey = len(r.Key)
		}

		if len(r.Description) > maxDesc {
			maxDesc = len(r.Description)
		}
	}

	border := fmt.Sprintf(
		"\r+=%s=+=%s=+\r\n", strings.Repeat("=", maxKey), strings.Repeat("=", maxDesc),
	)

	fmt.Print("\r\n")
	fmt.Print(border)
	fmt.Printf("\r| %-*s | %-*s |\r\n", maxKey, "Key", maxDesc, "Description")
	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("\r| %*s | %-*s |\r\n", maxKey, r.Key, maxDesc, r.Description)
	}

	fmt.Print(border)
	fmt.Print("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showStats() {
	type row struct{ Name, Value string }

	rows := []row{
		{"TELNET Connections", fmt.Sprintf("%d", telnetConnectionsTotal.Load())},
		{"TELNET User Sessions", fmt.Sprintf("%d", telnetSessionsTotal.Load())},
		{"TELNET Alt-Host Routings", fmt.Sprintf("%d", altHostRoutesTotal.Load())},
		{"SSH Connections", fmt.Sprintf("%d", sshConnectionsTotal.Load())},
		{"SSH User Sessions", fmt.Sprintf("%d", sshSessionsTotal.Load())},
		{"SSH Monitor Sessions", fmt.Sprintf("%d", monitorSessionsTotal.Load())},
		{"SSH Accept Errors", fmt.Sprintf("%d", acceptErrorsTotal.Load())},
		{"SSH Handshake Errors", fmt.Sprintf("%d", sshHandshakeFailedTotal.Load())},
		{"SSH Public Keys Seen", fmt.Sprintf("%d", sshKeySeenTotal.Load())},
		{"Other SSH Auths", fmt.Sprintf("%d", sshAuthSeenTotal.Load())},
		{"Admin Killed Connections", fmt.Sprintf("%d", adminKillsTotal.Load())},
		{"Idle Killed Connections", fmt.Sprintf("%d", idleKillsTotal.Load())},
		{"Timeout Killed Connections", fmt.Sprintf("%d", timeKillsTotal.Load())},
		{"Exempted Connections", fmt.Sprintf("%d", exemptedTotal.Load())},
		{"Rejected Connections", fmt.Sprintf("%d", rejectedTotal.Load())},
	}

	maxName := len("Statistic")
	maxVal := len("Value")

	for _, r := range rows {
		if len(r.Name) > maxName {
			maxName = len(r.Name)
		}

		if len(r.Value) > maxVal {
			maxVal = len(r.Value)
		}
	}

	border := fmt.Sprintf(
		"\r+=%s=+=%s=+\r\n", strings.Repeat("=", maxName), strings.Repeat("=", maxVal),
	)

	fmt.Print("\r\n")
	fmt.Print(border)
	fmt.Printf("\r| %-*s | %*s |\r\n", maxName, "Statistic", maxVal, "Value")
	fmt.Print(border)

	for i, r := range rows {
		fmt.Printf("\r| %-*s | %*s |\r\n", maxName, r.Name, maxVal, r.Value)
		switch i {
		case 2, 9, 12, 14:
			fmt.Print(border)
		}
	}
	fmt.Print("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleGracefulShutdown() {
	if gracefulShutdownMode.Load() {
		gracefulShutdownMode.Store(false)

		log.Println("Graceful shutdown cancelled.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s Graceful shutdown cancelled.\r\n", nowStamp())
		}
	} else {
		gracefulShutdownMode.Store(true)

		log.Println("No new connections will be accepted.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s No new connections will be accepted.\r\n", nowStamp())
		}

		log.Println("Graceful shutdown initiated.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s Graceful shutdown initiated.\r\n", nowStamp())
		}

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

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s Deny connections cancelled.\r\n", nowStamp())
		}
	} else {
		denyNewConnectionsMode.Store(true)

		log.Println("No new connections will be accepted.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr,
				"%s No new connections will be accepted.\r\n", nowStamp())
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func immediateShutdown() {
	shutdownOnce.Do(func() {
		log.Println("Immediate shutdown initiated.")

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Immediate shutdown initiated.\r\n", nowStamp())
		}

		connectionsMutex.Lock()

		for _, conn := range connections {
			if conn.channel != nil {
				if _, err := conn.channel.Write(
					[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				connUptime := time.Since(conn.startTime)
				log.Printf("LINKDOWN [%s] %s@%s (link time %s)",
					conn.ID, conn.userName, conn.hostName, connUptime.Round(time.Second))
			}

			if conn.cancelFunc != nil {
				conn.cancelFunc()
			}

			if conn.sshConn != nil {
				if err := conn.sshConn.Close(); err != nil {
					log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
				}
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

		if isConsoleLogQuiet {
			fmt.Fprintf(os.Stderr, "%s Exiting.\r\n", nowStamp())
		}

		log.Println("Exiting.")

		os.Exit(0)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConnections() {
	connectionsMutex.Lock()

	defer connectionsMutex.Unlock()

	fmt.Printf("\r\n")
	fmt.Printf("\r+====================+\r\n")
	fmt.Printf("\r| Active Connections |\r\n")
	fmt.Printf("\r+====================+\r\n\r\n")

	if len(connections) == 0 {
		fmt.Printf("\r* None!\r\n\r\n")

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

	fmt.Printf("\r\n")
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
	fmt.Printf("\r\n")
	fmt.Printf("\r+======================================+\r\n")
	fmt.Printf("\r| DPS8M Proxy Configuration and Status |\r\n")
	fmt.Printf("\r+======================================+\r\n")
	fmt.Printf("\r\n")

	fmt.Printf("* Process ID (PID): %d\r\n", os.Getpid())

	if len(sshAddr) == 1 {
		fmt.Printf("* SSH listener on: %s\r\n", sshAddr[0])
	} else {
		fmt.Println("* SSH listeners on:")
		for _, addr := range sshAddr {
			fmt.Printf("\r  * %s\r\n", addr)
		}
	}

	fmt.Printf("* Default TELNET target: %s\r\n", telnetHostPort)

	if len(altHosts) > 0 {
		fmt.Println("* Alt Targets:")
		for user, hostPort := range altHosts {
			fmt.Printf("\r  * %s [%s]\r\n", hostPort, user)
		}
	} else {
		fmt.Println("* Alt Targets: None configured")
	}

	fmt.Printf("* Debug TELNET Negotiation: %t\r\n", debugNegotiation)

	fmt.Printf("* Time Max: %s\r\n", func(t int) string {
		if t == 0 {
			return "disabled"
		}

		return fmt.Sprintf("%d seconds", t)
	}(timeMax))

	fmt.Printf("* Idle Max: %s\r\n", func(t int) string {
		if t == 0 {
			return "disabled"
		}

		return fmt.Sprintf("%d seconds", t)
	}(idleMax))

	fmt.Printf("* Log Base Directory: %s\r\n", logDir)
	fmt.Printf("* No Session Logging: %t\r\n", noLog)

	if consoleLog != "" {
		logPath := getConsoleLogPath(time.Now())
		logPath = filepath.Clean(logPath)

		var quietMode string
		if isConsoleLogQuiet {
			quietMode = "\r\n* Console Logging Mode: quiet"
		} else {
			quietMode = "\r\n* Console Logging Mode: noquiet"
		}

		fmt.Printf("* Console Logging: %s%s\r\n", logPath, quietMode)
	} else {
		fmt.Printf("* Console Logging: disabled\r\n")
	}

	fmt.Printf("* No Log Compression: %t\r\n", noCompress)
	fmt.Printf("* Compression Algorithm: %s\r\n", compressAlgo)
	fmt.Printf("* Compression Level: %s\r\n", compressLevel)
	fmt.Printf("* Log Permissions: Files: %04o, Dirs: %04o\r\n", logPerm, logDirPerm)

	fmt.Printf("* Graceful Shutdown: %t\r\n", gracefulShutdownMode.Load())
	fmt.Printf("* Deny New Connections: %t\r\n", denyNewConnectionsMode.Load())

	if blacklistFile == "" && len(blacklistedNetworks) == 0 { //nolint:gocritic
		fmt.Printf("* Blacklist: disabled\r\n")
	} else if whitelistFile != "" && blacklistFile == "" {
		fmt.Printf("* Blacklist: Deny all (due to whitelist only)\r\n")
	} else {
		if len(blacklistedNetworks) == 1 {
			fmt.Printf("* Blacklist: 1 entry active\r\n")
		} else {
			fmt.Printf("* Blacklist: %d entries active\r\n",
				len(blacklistedNetworks))
		}
	}

	if whitelistFile == "" {
		fmt.Printf("* Whitelist: disabled\r\n")
	} else {
		if len(whitelistedNetworks) == 1 {
			fmt.Printf("* Whitelist: 1 entry active\r\n")
		} else {
			fmt.Printf("* Whitelist: %d entries active\r\n",
				len(whitelistedNetworks))
		}
	}

	uptime := time.Since(startTime)
	years := int(uptime.Hours() / (24 * 365))
	days := int(uptime.Hours()/(24)) % 365
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60
	seconds := int(uptime.Seconds()) % 60

	uptimeString := ""
	if years > 0 {
		if years == 1 {
			uptimeString += fmt.Sprintf("%d year, ", years)
		} else {
			uptimeString += fmt.Sprintf("%d years, ", years)
		}
	}
	if days > 0 {
		if days == 1 {
			uptimeString += fmt.Sprintf("%d day, ", days)
		} else {
			uptimeString += fmt.Sprintf("%d days, ", days)
		}
	}
	uptimeString += fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)

	fmt.Printf("* Uptime: %s (since %s)\r\n",
		uptimeString, startTime.Format("2006-Jan-02 15:04:05"))

	var m runtime.MemStats
	debug.FreeOSMemory()
	runtime.ReadMemStats(&m)

	alloc := float64(m.Alloc)
	sys := float64(m.Sys)

	var allocStr, sysStr string

	switch {
	case alloc >= GiB:
		allocStr = fmt.Sprintf("%.2f GiB", alloc/GiB)

	case alloc >= MiB:
		allocStr = fmt.Sprintf("%.2f MiB", alloc/MiB)

	case alloc >= KiB:
		allocStr = fmt.Sprintf("%.2f KiB", alloc/KiB)

	default:
		allocStr = fmt.Sprintf("%.0f B", alloc)
	}

	switch {
	case sys >= GiB:
		sysStr = fmt.Sprintf("%.2f GiB", sys/GiB)

	case sys >= MiB:
		sysStr = fmt.Sprintf("%.2f MiB", sys/MiB)

	case sys >= KiB:
		sysStr = fmt.Sprintf("%.2f KiB", sys/KiB)

	default:
		sysStr = fmt.Sprintf("%.0f B", sys)
	}

	memStatsStr := fmt.Sprintf("%s used (of %s reserved)", allocStr, sysStr)

	fmt.Printf("* Memory: %s\r\n", memStatsStr)

	fmt.Printf("* Runtime: %d active Goroutines (use 'cg' for details)\r\n",
		runtime.NumGoroutine())

	fmt.Printf("\r\n")
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
				reloadErrors, fmt.Sprintf("Blacklist rejected: %v", err))
		} else {
			newBlacklistedNetworks = networks
			blacklistReloaded = true
		}
	}

	if whitelistFile != "" {
		networks, err := parseIPListFile(whitelistFile)

		if err != nil {
			reloadErrors = append(
				reloadErrors, fmt.Sprintf("Whitelist rejected: %v", err))
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
			log.Printf("Blacklist: 1 entry loaded [%s]",
				blacklistFile)
		} else {
			log.Printf("Blacklist: %d entries loaded [%s]",
				len(blacklistedNetworks), blacklistFile)
		}
	}

	if whitelistReloaded {
		whitelistedNetworks = newWhitelistedNetworks

		if len(whitelistedNetworks) == 1 {
			log.Printf("Whitelist: 1 entry loaded [%s]",
				whitelistFile)
		} else {
			log.Printf("Whitelist: %d entries loaded [%s]",
				len(whitelistedNetworks), whitelistFile)
		}
	}

	if whitelistFile != "" && blacklistFile == "" {
		_, ipv4Net, _ := net.ParseCIDR("0.0.0.0/0")
		_, ipv6Net, _ := net.ParseCIDR("::/0")

		blacklistedNetworks = append(blacklistedNetworks, ipv4Net, ipv6Net)

		log.Println("Blacklist: Blacklisting all host by default")
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killConnection(id string) {
	connectionsMutex.Lock()
	conn, ok := connections[id]
	connectionsMutex.Unlock()

	if !ok {
		fmt.Fprintf(os.Stderr, "%s Session ID '%s' not found.\r\n", nowStamp(), id)

		return
	}

	if isConsoleLogQuiet {
		if _, err := fmt.Fprintf(
			os.Stderr, "%s Killing connection %s...\r\n", nowStamp(), id); err != nil {
			log.Printf("Error writing to stderr: %v", err)
		}
	}

	if _, err := conn.channel.Write(
		[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n")); err != nil {
		log.Printf("Error writing to channel for %s: %v", conn.ID, err)
	}

	connUptime := time.Since(conn.startTime)

	log.Printf("TERMKILL [%s] %s@%s (link time %s)",
		conn.ID, conn.userName, conn.hostName, connUptime.Round(time.Second))

	adminKillsTotal.Add(1)

	if err := conn.sshConn.Close(); err != nil {
		log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func loadOrCreateHostKey(path, keyType string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
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
		if err := os.WriteFile(path, data, 0o600); err != nil {
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
		if err := os.WriteFile(path, data, 0o600); err != nil {
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

	sshConnectionsTotal.Add(1)

	config := &ssh.ServerConfig{
		//revive:disable:unused-parameter
		PasswordCallback: func(
			conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) { //nolint:gofumpt
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "password"},
			}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) { //nolint:gofumpt
			line := fmt.Sprintf("VALIDATE [%s] %s@%s %q:%s",
				sid, c.User(), c.RemoteAddr(), pubKey.Type(), ssh.FingerprintSHA256(pubKey),
			)

			if !suppressLogs {
				log.Print(line)
			}

			sshKeySeenTotal.Add(1)
			keyLog = append(keyLog, line)

			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "publickey"},
			}, fmt.Errorf("next key")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) { //nolint:gofumpt
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "keyboard-interactive"},
			}, nil
		},
		//revive:enable:unused-parameter
	}
	config.AddHostKey(edSigner)
	config.AddHostKey(rsaSigner)

	if tcp, ok := rawConn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		sshHandshakeFailedTotal.Add(1)
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

		const unknownHost = "<UNKNOWN>"
		if !suppressLogs {
			host, _, err := net.SplitHostPort(conn.hostName)
			if err != nil {
				log.Printf("TEARDOWN [%s] %s@"+unknownHost,
					sid, func() string {
						if conn.userName == "" {
							return unknownHost
						}

						return conn.userName
					}())
			} else {
				log.Printf("TEARDOWN [%s] %s@%s",
					sid, func() string {
						if conn.userName == "" {
							return unknownHost
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
	sshAuthSeenTotal.Add(1)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			if err := newCh.Reject(
				ssh.UnknownChannelType, "only session allowed"); err != nil {
				log.Printf("Error rejecting channel: %v", err)
			}

			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}

		conn.channel = ch

		go handleSession(conn.cancelCtx, conn, ch, requests, keyLog)
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

func handleSession(ctx context.Context, conn *Connection, channel ssh.Channel,
	requests <-chan *ssh.Request, keyLog []string) { //nolint:gofumpt
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

		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		if err := conn.sshConn.Close(); err != nil {
			log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
		}

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
			exemptedTotal.Add(1)
		} else {
			if !suppressLogs {
				log.Printf("REJECTED [%s] %s (matched %s)",
					conn.ID, conn.sshConn.RemoteAddr().String(), rejectedByRule)
			}
			rejectedTotal.Add(1)

			if raw, err := getFileContent(blockFile, conn.userName); err == nil {
				blockMessageContent := strings.ReplaceAll(
					strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
				if _, err := channel.Write(
					[]byte(blockMessageContent + "\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}
			} else {
				if _, err := channel.Write(
					[]byte("Connection blocked.\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}
			}

			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			if err := conn.sshConn.Close(); err != nil {
				log.Printf("Error closing SSH connection for %s: %v", conn.ID, err)
			}

			return
		}
	}

	sendBanner(conn.sshConn, channel, conn)
	sshSessionsTotal.Add(1)
	if conn.monitoring {
		monitorSessionsTotal.Add(1)

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
					if err := channel.Close(); err != nil {
						log.Printf("Error closing channel for %s: %v", conn.ID, err)
					}

					return
				}
			}
		}()

		<-conn.monitoredConnection.cancelCtx.Done()
		dur := time.Since(conn.startTime)

		if _, err := channel.Write([]byte(fmt.Sprintf(
			"\r\nMONITORING SESSION CLOSED (monitored for %s)\r\n\r\n",
			dur.Round(time.Second)))); err != nil {
			log.Printf("Error writing to channel for %s: %v", conn.ID, err)
		}

		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		return
	}

	if gracefulShutdownMode.Load() || denyNewConnectionsMode.Load() {
		if denyMsg, err := getFileContent(denyFile, conn.userName); err == nil {
			txt := strings.ReplaceAll(
				strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n")

			if _, err := channel.Write([]byte("\r\n")); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			if _, err := channel.Write([]byte(txt)); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			if _, err := channel.Write([]byte("\r\n")); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}
		}
		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		return
	}

	if raw, err := getFileContent(issueFile, conn.userName); err == nil {
		txt := strings.ReplaceAll(
			strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")

		if _, err := channel.Write([]byte(txt + "\r\n")); err != nil {
			log.Printf("Error writing to channel for %s: %v", conn.ID, err)
		}
	}

	start := time.Now()
	var sshIn, sshOut, telnetIn, telnetOut uint64

	var logfile *os.File
	var logwriter io.Writer
	var basePath string

	if !noLog {
		logfile, basePath, err = createDatedLog(conn.ID, conn.sshConn.RemoteAddr())
		if err != nil {
			if _, err := fmt.Fprintf(channel, "%v\r\n", err); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			return
		}
		conn.logFile = logfile
		conn.basePath = basePath
		logwriter = logfile

		if _, err := logwriter.Write(
			[]byte(nowStamp() + " Session start\r\n")); err != nil {
			log.Printf("Error writing to log for %s: %v", conn.ID, err)
		}

		for _, line := range keyLog {
			if _, err := logwriter.Write([]byte(nowStamp() + " " + line + "\r\n")); err != nil {
				log.Printf("Error writing to log for %s: %v", conn.ID, err)
			}
		}

		defer func() {
			dur := time.Since(start)
			if _, err := logwriter.Write([]byte(fmt.Sprintf(
				nowStamp()+" Session end (link time %s)\r\n",
				dur.Round(time.Second)))); err != nil {
				log.Printf("Error writing to log: %v", err)
			}
			closeAndCompressLog(logfile, basePath+".log")
		}()
	} else {
		logwriter = io.Discard
	}

	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				if err := req.Reply(true, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}

			case "shell":
				if err := req.Reply(true, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}

			default:
				if err := req.Reply(false, nil); err != nil {
					log.Printf("Error replying to request: %v", err)
				}
			}
		}
	}()

	var targetHost string
	var targetPort int

	if altHostPort, ok := altHosts[conn.userName]; ok {
		var err error
		targetHost, targetPort, err = parseHostPort(altHostPort)
		if err != nil {
			if _, err := fmt.Fprintf(channel, "Error parsing alt-host for user %s: %v\r\n\r\n",
				conn.userName, err); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			log.Printf("Error parsing alt-host for user %s: %v", conn.userName, err)
			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			return
		}
		log.Printf("ALTROUTE [%s] %s -> %s:%d", conn.ID, conn.userName, targetHost, targetPort)
		conn.targetHost = targetHost
		conn.targetPort = targetPort
		altHostRoutesTotal.Add(1)
	} else {
		var err error
		targetHost, targetPort, err = parseHostPort(telnetHostPort)
		if err != nil {
			if _, err := fmt.Fprintf(
				channel, "Error parsing default telnet-host: %v\r\n\r\n", err); err != nil {
				log.Printf("Error writing to channel for %s: %v", conn.ID, err)
			}

			log.Printf("Error parsing default telnet-host: %v", err)
			if err := channel.Close(); err != nil {
				log.Printf("Error closing channel for %s: %v", conn.ID, err)
			}

			return
		}
	}

	if !noLog {
		if _, err := logwriter.Write([]byte(fmt.Sprintf(
			nowStamp()+" Target: %s:%d\r\n", targetHost, targetPort))); err != nil {
			log.Printf("Error writing to log for %s: %v", conn.ID, err)
		}

		if _, err := logwriter.Write([]byte(fmt.Sprintf(
			nowStamp()+" Connection sharing username: '%s'\r\n",
			conn.shareableUsername))); err != nil {
			log.Printf("Error writing to log for %s: %v", conn.ID, err)
		}
	}

	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	if err != nil {
		if _, err := fmt.Fprintf(channel, "%v\r\n\r\n", err); err != nil {
			log.Printf("Error writing to channel for %s: %v", conn.ID, err)
		}

		log.Printf("%v", err)
		if err := channel.Close(); err != nil {
			log.Printf("Error closing channel for %s: %v", conn.ID, err)
		}

		return
	}

	telnetConnectionsTotal.Add(1)

	if tcp2, ok := remote.(*net.TCPConn); ok {
		_ = tcp2.SetNoDelay(true)
	}

	defer func() {
		if err := remote.Close(); err != nil {
			log.Printf("Error closing remote connection for %s: %v", conn.ID, err)
		}
	}()

	negotiateTelnet(remote, channel, logwriter)

	telnetSessionsTotal.Add(1)

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
					if _, err := remote.Write(escSequence); err != nil {
						log.Printf("Error writing to remote for %s: %v", conn.ID, err)
					}

					if _, err := logwriter.Write(escSequence); err != nil {
						log.Printf("Error writing to log for %s: %v", conn.ID, err)
					}
				}

				return

			case <-escTimer:
				m, err := remote.Write(escSequence)
				if err != nil {
					log.Printf("Error writing to remote for %s: %v", conn.ID, err)
				}

				atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec
				if _, err := logwriter.Write(escSequence); err != nil {
					log.Printf("Error writing to log for %s: %v", conn.ID, err)
				}

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

				if len(escSequence) > 0 { //nolint:gocritic
					escSequence = append(escSequence, b)
					if conn.emacsKeymapEnabled {
						if replacement, ok := //nolint:gofumpt,nolintlint
							emacsKeymap[string(escSequence)]; ok {
							m, err := remote.Write([]byte(replacement))
							if err != nil {
								log.Printf("Error writing to remote for %s: %v", conn.ID, err)
							}

							atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

							if _, err := logwriter.Write([]byte(replacement)); err != nil {
								log.Printf("Error writing to log for %s: %v", conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						} else if _, isPrefix := //nolint:gofumpt,nolintlint
							emacsKeymapPrefixes[string(escSequence)]; isPrefix {
							escTimer = time.After(50 * time.Millisecond)
						} else {
							m, err := remote.Write(escSequence)
							if err != nil {
								log.Printf("Error writing to remote for %s: %v", conn.ID, err)
							}

							atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

							if _, err := logwriter.Write(escSequence); err != nil {
								log.Printf("Error writing to log for %s: %v", conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						}
					} else {
						m, err := remote.Write(escSequence)
						if err != nil {
							log.Printf("Error writing to remote for %s: %v", conn.ID, err)
						}

						atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

						if _, err := logwriter.Write(escSequence); err != nil {
							log.Printf("Error writing to log for %s: %v", conn.ID, err)
						}

						escSequence = nil
						escTimer = nil
					}
				} else if b == 0x1b && conn.emacsKeymapEnabled {
					escSequence = append(escSequence, b)
					escTimer = time.After(50 * time.Millisecond)
				} else {
					m, err := remote.Write([]byte{b})
					if err != nil {
						log.Printf("Error writing to remote for %s: %v", conn.ID, err)
					}

					atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

					if _, err := logwriter.Write([]byte{b}); err != nil {
						log.Printf("Error writing to log for %s: %v", conn.ID, err)
					}
				}

			case err := <-errorChan:
				if len(escSequence) > 0 {
					if _, err := remote.Write(escSequence); err != nil {
						log.Printf("Error writing to remote for %s: %v", conn.ID, err)
					}

					if _, err := logwriter.Write(escSequence); err != nil {
						log.Printf("Error writing to log for %s: %v", conn.ID, err)
					}
				}
				if !errors.Is(err, io.EOF) {
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
			if err := remote.SetReadDeadline(
				time.Now().Add(100 * time.Millisecond)); err != nil {
				log.Printf("Error setting read deadline for %s: %v", conn.ID, err)
			}
			n, err := remote.Read(buf)
			if err != nil {
				var netErr net.Error

				if errors.As(err, &netErr) && netErr.Timeout() {
					select {
					case <-ctx.Done():
						return

					default:
					}

					continue
				}

				dur := time.Since(start)
				log.Printf("DETACHED [%s] %s@%s (link time %s)",
					conn.ID, conn.userName, conn.hostName, dur.Round(time.Second))

				if _, err := channel.Write([]byte(fmt.Sprintf(
					"\r\nCONNECTION CLOSED (link time %s)\r\n\r\n",
					dur.Round(time.Second)))); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				inRateSSH := uint64(float64(atomic.LoadUint64(&sshIn)) / dur.Seconds())
				outRateSSH := uint64(float64(atomic.LoadUint64(&sshOut)) / dur.Seconds())
				inRateNVT := uint64(float64(atomic.LoadUint64(&telnetIn)) / dur.Seconds())
				outRateNVT := uint64(float64(atomic.LoadUint64(&telnetOut)) / dur.Seconds())

				if _, err := channel.Write([]byte(fmt.Sprintf(
					">> SSH - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
					atomic.LoadUint64(&sshIn), atomic.LoadUint64(&sshOut),
					inRateSSH, outRateSSH))); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				if _, err := channel.Write([]byte(fmt.Sprintf(
					">> NVT - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
					atomic.LoadUint64(&telnetIn), atomic.LoadUint64(&telnetOut),
					inRateNVT, outRateNVT))); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				if _, err := channel.Write([]byte("\r\n")); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				if err := channel.Close(); err != nil {
					log.Printf("Error closing channel for %s: %v", conn.ID, err)
				}

				conn.sshInTotal = sshIn
				conn.sshOutTotal = sshOut

				return
			}

			if n > 0 {
				atomic.AddUint64(&telnetIn, uint64(n))
				atomic.AddUint64(&conn.sshInTotal, uint64(n))
				fwd := bytes.ReplaceAll(buf[:n], []byte{0}, []byte{})

				atomic.AddUint64(&sshOut, uint64(len(fwd)))
				atomic.AddUint64(&conn.sshOutTotal, uint64(len(fwd)))

				if _, err := channel.Write(fwd); err != nil {
					log.Printf("Error writing to channel for %s: %v", conn.ID, err)
				}

				connectionsMutex.Lock()

				for _, c := range connections {
					if c.monitoring && c.monitoredConnection.ID == conn.ID {
						if _, err := c.channel.Write(fwd); err != nil {
							log.Printf("Error writing to channel for %s: %v", c.ID, err)
						}
					}
				}

				connectionsMutex.Unlock()

				if _, err := logwriter.Write(buf[:n]); err != nil {
					log.Printf("Error writing to log for %s: %v", conn.ID, err)
				}

				conn.lastActivityTime = time.Now()
			}
		}
	}()

	wg.Wait()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendBanner(sshConn *ssh.ServerConn, ch ssh.Channel, conn *Connection) {
	if noBanner {
		return
	}

	host, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(ctx, host)

	var origin string

	if len(names) > 0 {
		origin = fmt.Sprintf("%s [%s]", strings.TrimSuffix(names[0], "."), host)
	} else {
		origin = host
	}

	now := nowStamp()

	if _, err := fmt.Fprintf(
		ch, "Session with %s active at %s.\r\n", origin, now); err != nil {
		log.Printf("Error writing session active message to channel: %v", err)
	}

	if conn.monitoring {
		if _, err := fmt.Fprint(
			ch, "This is a READ-ONLY shared monitoring session.\r\n"); err != nil {
			log.Printf("Error writing monitoring session message to channel: %v", err)
		}

		if _, err := fmt.Fprint(ch, "Send Control-] to disconnect.\r\n"); err != nil {
			log.Printf("Error writing disconnect message to channel: %v", err)
		}
	} else if conn.invalidShare {
		if _, err := fmt.Fprintf(
			ch, "The username '%s' was NOT active for session sharing!\r\n",
			conn.userName); err != nil {
			log.Printf("Error writing invalid share message to channel: %v", err)
		}
	}

	if _, err := fmt.Fprint(ch, "\r\n"); err != nil {
		log.Printf("Error writing newline to channel: %v", err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func negotiateTelnet(remote net.Conn, ch ssh.Channel, logw io.Writer) {
	if err := remote.SetReadDeadline(time.Now().Add(time.Second / 3)); err != nil {
		log.Printf("Error setting read deadline: %v", err)
	}

	defer func() {
		if err := remote.SetReadDeadline(time.Time{}); err != nil {
			log.Printf("Error clearing read deadline: %v", err)
		}
	}()

	buf := make([]byte, 512)

	for {
		n, err := remote.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}

			return
		}

		i := 0
		for i < n {
			if buf[i] == TelcmdIAC && i+2 < n {
				cmd, opt := buf[i+1], buf[i+2]
				writeNegotiation(ch, logw,
					"[RCVD "+cmdName(cmd)+" "+optName(opt)+"]")
				var reply byte
				switch cmd {
				case TelcmdWILL:
					reply = TelcmdDO

				case TelcmdWONT:
					reply = TelcmdDONT

				case TelcmdDO:
					reply = TelcmdWILL

				case TelcmdDONT:
					reply = TelcmdWONT

				default:
					i += 3

					continue
				}
				sendIAC(remote, reply, opt)
				writeNegotiation(ch, logw,
					"[SENT "+cmdName(reply)+" "+optName(opt)+"]")
				i += 3
			} else {
				_, _ = ch.Write(buf[i : i+1])
				_, _ = logw.Write(buf[i : i+1])
				i++
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func writeNegotiation(ch io.Writer, logw io.Writer, line string) {
	msg := line + "\r\n"
	if _, err := logw.Write([]byte(msg)); err != nil {
		log.Printf("Error writing negotiation message to log: %v", err)
	}

	if debugNegotiation {
		if _, err := ch.Write([]byte(msg)); err != nil {
			log.Printf("Error writing negotiation message to channel: %v", err)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendIAC(w io.Writer, cmd, opt byte) {
	if _, err := w.Write([]byte{TelcmdIAC, cmd, opt}); err != nil {
		log.Printf("Error writing Telnet command to writer: %v", err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func cmdName(b byte) string {
	switch b {
	case TelcmdDO:
		return "DO"

	case TelcmdDONT:
		return "DONT"

	case TelcmdWILL:
		return "WILL"

	case TelcmdWONT:
		return "WONT"
	}

	return fmt.Sprintf("CMD_%d", b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func optName(b byte) string {
	switch b {
	case TeloptBinary:
		return "BINARY"

	case TeloptEcho:
		return "ECHO"

	case TeloptSuppressGoAhead:
		return "SUPPRESS GO AHEAD"
	}

	return fmt.Sprintf("OPT_%d", b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showMenu(ch ssh.Channel) {
	menu := "\r                         \r\n" +
		"\r +=====+===============+ \r\n" +
		"\r | Key | TELNET Action | \r\n" +
		"\r +=====+===============+ \r\n" +
		"\r |  A  | Send AYT      | \r\n" +
		"\r |  B  | Send Break    | \r\n" +
		"\r |  K  | Toggle Keymap | \r\n" +
		"\r |  N  | Send NOP      | \r\n" +
		"\r |  S  | Show Status   | \r\n" +
		"\r |  X  | Disconnect    | \r\n" +
		"\r +=====+===============+ \r\n"

	if _, err := ch.Write([]byte(menu)); err != nil {
		log.Printf("Error writing menu to channel: %v", err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleMenuSelection(sel byte, conn *Connection, ch ssh.Channel, remote net.Conn,
	logw io.Writer, sshIn, sshOut, telnetIn, telnetOut *uint64, start time.Time) { //nolint:gofumpt
	switch sel {
	case 'a', 'A':
		if _, err := remote.Write([]byte{TelcmdIAC, TelcmdAYT}); err != nil {
			log.Printf("Error writing AYT to remote: %v", err)
		}

		if _, err := logw.Write([]byte{TelcmdIAC, TelcmdAYT}); err != nil {
			log.Printf("Error writing AYT to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent AYT\r\n")); err != nil {
			log.Printf("Error writing 'Sent AYT' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing 'BACK TO HOST' message after AYT to channel: %v", err)
		}

	case 'b', 'B':
		if _, err := remote.Write([]byte{TelcmdIAC, 243}); err != nil {
			log.Printf("Error writing BREAK to remote: %v", err)
		}

		if _, err := logw.Write([]byte{TelcmdIAC, 243}); err != nil {
			log.Printf("Error writing BREAK to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent BREAK\r\n")); err != nil {
			log.Printf("Error writing 'Sent BREAK' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	case 'k', 'K':
		conn.emacsKeymapEnabled = !conn.emacsKeymapEnabled
		if conn.emacsKeymapEnabled {
			if _, err := ch.Write([]byte("\r\n>> Emacs keymap ENABLED\r\n")); err != nil {
				log.Printf("Error writing 'Emacs keymap ENABLED' message to channel: %v", err)
			}
		} else {
			if _, err := ch.Write([]byte("\r\n>> Emacs keymap DISABLED\r\n")); err != nil {
				log.Printf("Error writing 'Emacs keymap DISABLED' message to channel: %v", err)
			}
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	case 'n', 'N':
		if _, err := remote.Write([]byte{TelcmdIAC, TelcmdNOP}); err != nil {
			log.Printf("Error writing NOP to remote: %v", err)
		}

		if _, err := logw.Write([]byte{TelcmdIAC, TelcmdNOP}); err != nil {
			log.Printf("Error writing NOP to log: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n>> Sent NOP\r\n")); err != nil {
			log.Printf("Error writing 'Sent NOP' message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing '[BACK TO HOST]' message to channel: %v", err)
		}

	case 's', 'S':
		dur := time.Since(start)
		if _, err := ch.Write([]byte("\r\n")); err != nil {
			log.Printf("Error writing newline to channel: %v", err)
		}

		if _, err := ch.Write([]byte(fmt.Sprintf(
			">> LNK - Username '%s' can be used to share this session.\r\n",
			conn.shareableUsername))); err != nil {
			log.Printf("Error writing sharable username to channel: %v", err)
		}

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

			if _, err := ch.Write([]byte(fmt.Sprintf(
				">> MON - Shared session has been viewed %d %s; %d %s currently online.\r\n",
				conn.totalMonitors, timesStr, currentMonitors, userStr))); err != nil {
				log.Printf("Error writing shared session information to channel: %v", err)
			}
		}

		inSSH := atomic.LoadUint64(sshIn)
		outSSH := atomic.LoadUint64(sshOut)
		inNVT := atomic.LoadUint64(telnetIn)
		outNVT := atomic.LoadUint64(telnetOut)

		inRateSSH := uint64(float64(atomic.LoadUint64(sshIn)) / dur.Seconds())
		outRateSSH := uint64(float64(atomic.LoadUint64(sshOut)) / dur.Seconds())
		inRateNVT := uint64(float64(atomic.LoadUint64(telnetIn)) / dur.Seconds())
		outRateNVT := uint64(float64(atomic.LoadUint64(telnetOut)) / dur.Seconds())

		if _, err := ch.Write([]byte(fmt.Sprintf(
			">> SSH - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
			inSSH, outSSH, inRateSSH, outRateSSH))); err != nil {
			log.Printf("Error writing SSH statistics to channel: %v", err)
		}

		if _, err := ch.Write([]byte(fmt.Sprintf(
			">> NVT - in: %d bytes, out: %d bytes, in-rate: %d B/s, out-rate: %d B/s\r\n",
			inNVT, outNVT, inRateNVT, outRateNVT))); err != nil {
			log.Printf("Error writing NVT statistics to channel: %v", err)
		}

		keymapStatus := ""
		if conn.emacsKeymapEnabled {
			keymapStatus = " (Emacs keymap enabled)"
		}

		if _, err := ch.Write([]byte(">> LNK - link time: " +
			dur.Round(time.Second).String() + keymapStatus + "\r\n")); err != nil {
			log.Printf("Error writing link time and keymap status message to channel: %v", err)
		}

		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing 'BACK TO HOST' message after link time to channel: %v", err)
		}

	case 'x', 'X':
		if _, err := ch.Write([]byte("\r\n>> DISCONNECTING...\r\n")); err != nil {
			log.Printf("Error writing 'DISCONNECTING' message to channel: %v", err)
		}

		if err := ch.Close(); err != nil {
			log.Printf("Error closing channel: %v", err)
		}

	default:
		if _, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n")); err != nil {
			log.Printf("Error writing 'BACK TO HOST' message for default case to channel: %v", err)
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
	)

	if err := os.MkdirAll(dir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		return nil, "", err
	}

	dir = filepath.Join(dir, ipDir)

	if err := os.MkdirAll(dir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		return nil, "", err
	}

	ts := now.Format("150405")
	files, _ := os.ReadDir(dir)
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
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm)) //nolint:gosec

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

		if _, err := rand.Read(b); err != nil {
			log.Printf("Error reading random bytes for session ID: %v", err)
		}

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
	const chars = "abcdghkmnprsvwxyzACDFGJKMNPRSTVXY345679"
	for {
		b := make([]byte, 20)

		if _, err := rand.Read(b); err != nil {
			log.Printf("Error reading random bytes for shareable username: %v", err)
		}

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
	debug.FreeOSMemory()

	consoleLogMutex.Lock()
	defer consoleLogMutex.Unlock()

	if consoleLogFile != nil {
		if !noCompress {
			yesterdayLogPath := getConsoleLogPath(time.Now().AddDate(0, 0, -1))
			compressLogFile(yesterdayLogPath)
		}

		if err := consoleLogFile.Close(); err != nil {
			log.Printf("Error closing console log file: %v", err)
		}
	}

	logPath := getConsoleLogPath(time.Now())
	logDir := filepath.Dir(logPath)

	if err := os.MkdirAll(logDir, os.FileMode(logDirPerm)); err != nil { //nolint:gosec
		consoleLogMutex.Unlock()
		log.Fatalf( //nolint:gocritic
			"Failed to create console log directory: %v", err) // LINTED: Fatalf
	}

	var err error
	consoleLogFile, err = os.OpenFile(logPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm)) //nolint:gosec
	if err != nil {
		consoleLogMutex.Unlock()
		log.Fatalf(
			"Failed to open console log file: %v", err) // LINTED: Fatalf
	}

	if isConsoleLogQuiet {
		fmt.Fprintf(
			os.Stderr, "%s Console logging enabled (suppressing console output)\n",
			nowStamp())
	} else {
		fmt.Fprintf(
			os.Stderr, "%s Console logging enabled (not suppressing console output)\n",
			nowStamp())
	}

	if isConsoleLogQuiet {
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

	data, err := os.ReadFile(logFilePath)
	if err != nil {
		log.Printf("Failed to read log %q for compression: %v", logFilePath, err)

		return
	}

	var compressedFilePath string
	var compressedFile *os.File
	var writer io.WriteCloser

	var gzipLevel int

	switch compressLevel {
	case "fast":
		gzipLevel = gzip.BestSpeed

	case "normal":
		gzipLevel = gzip.DefaultCompression

	case "high":
		gzipLevel = gzip.BestCompression
	}

	var zstdLevel zstd.EncoderLevel

	switch compressLevel {
	case "fast":
		zstdLevel = zstd.SpeedFastest

	case "normal":
		zstdLevel = zstd.SpeedDefault

	case "high":
		zstdLevel = zstd.SpeedBestCompression
	}

	switch compressAlgo {
	case "gzip":
		compressedFilePath = logFilePath + ".gz"
		compressedFile, err = os.Create(compressedFilePath)
		if err != nil {
			log.Printf("Failed to create compressed file %q: %v", compressedFilePath, err)

			return
		}

		writer, err = gzip.NewWriterLevel(compressedFile, gzipLevel)
		if err != nil {
			log.Printf("Error creating gzip writer for %q: %v", compressedFilePath, err)
			if err := compressedFile.Close(); err != nil {
				log.Printf("Error closing compressed file after gzip writer error: %v", err)
			}

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
			if err := compressedFile.Close(); err != nil {
				log.Printf("Error closing compressed file after xz writer error: %v", err)
			}

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
			compressedFile, zstd.WithEncoderLevel(zstdLevel))
		if err != nil {
			log.Printf("Error creating zstd writer for %q: %v", compressedFilePath, err)
			if err := compressedFile.Close(); err != nil {
				log.Printf("Error closing compressed file after zstd writer error: %v", err)
			}

			return
		}

	default:
		log.Printf("Unknown compression algorithm: %s", compressAlgo)

		return
	}

	defer func() {
		if err := compressedFile.Close(); err != nil {
			if strings.Contains(err.Error(), "writer already closed") {
				log.Printf("Error closing compressed file: %v", err)
			}
		}
	}()

	defer func() {
		if err := writer.Close(); err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				log.Printf("Error closing writer: %v", err)
			}
		}
	}()

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
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}()

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

func listGoroutines() {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	stacks := bytes.Split(buf[:n], []byte("\n\n"))

	fmt.Printf("\r\n")
	fmt.Printf("+===================+\r\n")
	fmt.Printf("| Active Goroutines |\r\n")
	fmt.Printf("+===================+\r\n")
	fmt.Printf("\r\n")

	for i, stack := range stacks {
		lines := bytes.Split(stack, []byte("\n"))

		if len(lines) < 2 {
			continue
		}

		header := string(lines[0]) // L1: header
		entry := string(lines[1])  // L2: entry point
		caller := ""               // L3: caller

		if len(lines) > 2 {
			caller = string(lines[2])
		}

		fmt.Printf("* Goroutine #%d:\n", i+1)

		fmt.Printf("  * Name/State: %s\n", func(s string) string {
			s = strings.TrimSpace(strings.ReplaceAll(s, "\t", " "))
			s = strings.TrimSuffix(s, ":")
			s = regexp.MustCompile(`goroutine \d+ `).ReplaceAllString(s, "")

			return s
		}(header))

		fmt.Printf("  * Entrypoint: %s\n", func(s string) string {
			return strings.TrimSpace(strings.ReplaceAll(s, "\t", " "))
		}(entry))

		if caller != "" {
			fmt.Printf("  * Caller:     %s\n", func(s string) string {
				return strings.TrimSpace(strings.ReplaceAll(s, "\t", " "))
			}(caller))
		}

		fmt.Println()
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func checkPrivilegedPorts(addrs []string) {
	for _, addr := range addrs {
		_, portStr, _ := net.SplitHostPort(addr)
		port, _ := strconv.Atoi(portStr)

		if port > 0 && port < 1024 {
			checkCapability()

			return
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
