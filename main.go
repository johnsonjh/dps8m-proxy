///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 92e1502a-6bd1-11f0-8b9e-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	_ "expvar"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	_ "time/tzdata"
	"unicode/utf8"

	"github.com/arl/statsviz"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
	"github.com/sorairolake/lzip-go"
	"github.com/spf13/pflag"
	"github.com/ulikunitz/xz"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

// Global constants.
const (
	//nolint:godoclint,nolintlint
	// TELNET Commands.
	TelcmdSE    = 240 // Subnegotiation End
	TelcmdNOP   = 241 // No operation
	TelcmdDM    = 242 // Data Mark
	TelcmdBreak = 243 // Break
	TelcmdIP    = 244 // Interrupt Process
	TelcmdAO    = 245 // Abort Output
	TelcmdAYT   = 246 // Are You There?
	TelcmdEC    = 247 // Erase Character
	TelcmdEL    = 248 // Erase Line
	TelcmdGA    = 249 // Go Ahead
	TelcmdSB    = 250 // Subnegotiation Begin
	TelcmdWILL  = 251 // WILL
	TelcmdWONT  = 252 // WONT
	TelcmdDO    = 253 // DO
	TelcmdDONT  = 254 // DONT
	TelcmdIAC   = 255 // Interpret As Command

	//nolint:godoclint,nolintlint
	// TELNET Command Options.
	TeloptBinary            = 0   // Binary
	TeloptEcho              = 1   // Echo
	TeloptReconnect         = 2   // Reconnection
	TeloptSuppressGoAhead   = 3   // Suppress Go Ahead
	TeloptApprox            = 4   // Approx Message Size Negotiation
	TeloptStatus            = 5   // Status
	TeloptTimingMark        = 6   // Timing Mark
	TeloptRemoteControl     = 7   // Remote Controlled Trans and Echo
	TeloptOutputLineWidth   = 8   // Output Line Width
	TeloptOutputPageSize    = 9   // Output Page Size
	TeloptOutputCRD         = 10  // Output Carriage Return Disposition
	TeloptOutputHTS         = 11  // Output Horizontal Tab Stops
	TeloptOutputHTD         = 12  // Output Horizontal Tab Disposition
	TeloptOutputFFD         = 13  // Output Formfeed Disposition
	TeloptOutputVTS         = 14  // Output Vertical Tab Stops
	TeloptOutputVTD         = 15  // Output Vertical Tab Disposition
	TeloptOutputLFD         = 16  // Output Linefeed Disposition
	TeloptExtendedASCII     = 17  // Extended ASCII
	TeloptLogout            = 18  // Logout
	TeloptByteMacro         = 19  // Byte Macro
	TeloptDataEntryTerminal = 20  // Data Entry Terminal
	TeloptSupdup            = 21  // SUPDUP
	TeloptSupdupOutput      = 22  // SUPDUP Output
	TeloptSendLocation      = 23  // Send Location
	TeloptTTYPE             = 24  // Terminal Type
	TeloptEOR               = 25  // End of Record
	TeloptTacacsUserID      = 26  // TACACS User Identification
	TeloptOutputMarking     = 27  // Output Marking
	TeloptTermLocationNum   = 28  // Terminal Location Number
	TeloptTN3270Regime      = 29  // TELNET 3270 Regime
	TeloptX3PAD             = 30  // X.3 PAD
	TeloptNAWS              = 31  // Negotiate About Window Size
	TeloptTS                = 32  // Terminal Speed
	TeloptRM                = 33  // Remote Flow Control
	TeloptLineMode          = 34  // Line Mode
	TeloptXDisplay          = 35  // X Display Location
	TeloptOldEnviron        = 36  // Old Environment Option
	TeloptAuth              = 37  // Authentication Option
	TeloptEncrypt           = 38  // Encryption Option
	TeloptNewEnviron        = 39  // New Environment Option
	TeloptTN3270E           = 40  // TN3270E
	TeloptXAUTH             = 41  // XAUTH
	TeloptCHARSET           = 42  // CHARSET
	TeloptRSP               = 43  // Remote Serial Port (RSP)
	TeloptCompPort          = 44  // COM Port Control
	TeloptSLE               = 45  // Telnet Suppress Local Echo
	TeloptStartTLS          = 46  // Start TLS
	TeloptKermit            = 47  // Kermit
	TeloptSendURL           = 48  // SEND-URL
	TeloptForwardX          = 49  // FORWARD_X
	TeloptMSSP              = 70  // MUD Server Status Protocol
	TeloptMCCP              = 85  // MUD Client Compression Protocol
	TeloptMCCP2             = 86  // MUD Client Compression Protocol 2
	TeloptMCCP3             = 87  // MUD Client Compression Protocol 3
	TeloptMSP               = 90  // MUD Sound Protocol
	TeloptMXP               = 91  // MUD Extension Protocol
	TeloptZMP               = 93  // Zenith MUD Protocol
	TeloptPragmaLogon       = 138 // TELOPT PRAGMA LOGON
	TeloptSspiLogon         = 139 // TELOPT SSPI LOGON
	TeloptPragmaHeartbeat   = 140 // TELOPT PRAGMA HEARTBEAT
	TeloptATCP              = 200 // Achaea Telnet Client Protocol
	TeloptGMCP              = 201 // Generic MUD Client Protocol
	TeloptEnd               = 255 // End of Option List

	//nolint:godoclint,nolintlint
	// TELNET subnegotiation commands.
	TelnetIs    = 0 // IS
	TelnetSend  = 1 // SEND
	TelnetReply = 2 // REPLY
	TelnetName  = 3 // NAME

	//nolint:godoclint,nolintlint
	// IEC sizes.
	KiB = 1024       // Kibibyte
	MiB = 1024 * KiB // Mebibyte
	GiB = 1024 * MiB // Gibibyte
)

///////////////////////////////////////////////////////////////////////////////////////////////////

//go:embed LICENSE
var licenseText string

///////////////////////////////////////////////////////////////////////////////////////////////////

// Global variables.
var (
	startTime                        = time.Now()
	forceUTC                         bool
	allowRoot                        bool
	dbPerm                           uint = 0o600
	logPerm                          uint = 0o600
	logDirPerm                       uint = 0o750
	certPerm                         uint = 0o600
	certDir                          string
	altHosts                         = make(map[string]string)
	blacklistedNetworks              []*net.IPNet
	blacklistFile                    string
	connections                      = make(map[string]*Connection)
	connectionsMutex                 sync.Mutex
	consoleInputActive               atomic.Bool
	consoleLogFile                   *os.File
	consoleLogMutex                  sync.Mutex
	consoleLog                       string
	lastLogDate                      string
	isConsoleLogQuiet                bool
	debugNegotiation                 bool
	debugAddr                        string
	denyNewConnectionsMode           atomic.Bool
	gracefulShutdownMode             atomic.Bool
	idleMax                          int
	logDir                           string
	loggingWg                        sync.WaitGroup
	noBanner                         bool
	noCompress                       bool
	noSanitize                       bool
	enableGops                       bool
	enableMDNS                       bool
	noLog                            bool
	noConsole                        bool
	showVersion                      bool
	showLicense                      bool
	shutdownOnce                     sync.Once
	shutdownSignal                   chan struct{}
	sshAddr                          []string
	telnetHostPort                   string
	timeMax                          int
	whitelistedNetworks              []*net.IPNet
	whitelistFile                    string
	issueFile                        = "issue.txt"
	denyFile                         = "deny.txt"
	blockFile                        = "block.txt"
	compressAlgo                     string
	compressLevel                    string
	dbLogLevel                       string
	sshDelay                         float64
	acceptErrorsTotal                atomic.Uint64
	adminKillsTotal                  atomic.Uint64
	altHostRoutesTotal               atomic.Uint64
	exemptedTotal                    atomic.Uint64
	idleKillsTotal                   atomic.Uint64
	monitorSessionsTotal             atomic.Uint64
	rejectedTotal                    atomic.Uint64
	sshConnectionsTotal              atomic.Uint64
	sshHandshakeFailedTotal          atomic.Uint64
	sshIllegalSubsystemTotal         atomic.Uint64
	sshExecRejectedTotal             atomic.Uint64
	sshRequestTimeoutTotal           atomic.Uint64
	sshSessionsTotal                 atomic.Uint64
	peakUsersTotal                   atomic.Uint64
	telnetConnectionsTotal           atomic.Uint64
	telnetFailuresTotal              atomic.Uint64
	timeKillsTotal                   atomic.Uint64
	trafficInTotal                   atomic.Uint64
	trafficOutTotal                  atomic.Uint64
	delayAbandonedTotal              atomic.Uint64
	lifetimeAcceptErrorsTotal        atomic.Uint64
	lifetimeAdminKillsTotal          atomic.Uint64
	lifetimeAltHostRoutesTotal       atomic.Uint64
	lifetimeExemptedTotal            atomic.Uint64
	lifetimeIdleKillsTotal           atomic.Uint64
	lifetimeMonitorSessionsTotal     atomic.Uint64
	lifetimeRejectedTotal            atomic.Uint64
	lifetimeSSHconnectionsTotal      atomic.Uint64
	lifetimeSSHhandshakeFailedTotal  atomic.Uint64
	lifetimeSSHillegalSubsystemTotal atomic.Uint64
	lifetimeSSHexecRejectedTotal     atomic.Uint64
	lifetimeSSHrequestTimeoutTotal   atomic.Uint64
	lifetimeSSHsessionsTotal         atomic.Uint64
	lifetimePeakUsersTotal           atomic.Uint64
	lifetimeTelnetConnectionsTotal   atomic.Uint64
	lifetimeTelnetFailuresTotal      atomic.Uint64
	lifetimeTimeKillsTotal           atomic.Uint64
	lifetimeTrafficInTotal           atomic.Uint64
	lifetimeTrafficOutTotal          atomic.Uint64
	lifetimeDelayAbandonedTotal      atomic.Uint64
	haveUTF8console                  bool
	emacsKeymapPrefixes              = make(map[string]bool)
	emacsKeymap                      = map[string]string{
		"\x1b[1;5A": "\x1b\x5b", //    Control-Arrow_Up -> Escape, [
		"\x1b[1;5B": "\x1b\x5d", //  Control-Arrow_Down -> Escape, ]
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
)

///////////////////////////////////////////////////////////////////////////////////////////////////

type Connection struct {
	startTime           time.Time
	lastActivityTime    time.Time
	telnetConn          net.Conn
	cancelCtx           context.Context
	channel             ssh.Channel
	sshConn             *ssh.ServerConn
	logFile             *os.File
	monitoredConnection *Connection
	cancelFunc          context.CancelFunc
	ID                  string
	hostName            string
	termType            string
	shareableUsername   string
	targetHost          string
	userName            string
	basePath            string
	totalMonitors       uint64
	targetPort          int
	sshOutTotal         uint64
	sshInTotal          uint64
	initialWindowWidth  uint32
	initialWindowHeight uint32
	emacsKeymapEnabled  bool
	wasMonitored        bool
	monitoring          bool
	nawsActive          bool
	invalidShare        bool
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sanitizeNonASCII(s string) string {
	if noSanitize {
		return s
	}

	var b strings.Builder

	b.Grow(len(s))

	for _, r := range s {
		if r < utf8.RuneSelf {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}

	return b.String()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUnixSocket(path string) bool {
	return strings.HasPrefix(path, "/") || strings.HasPrefix(path, ".") ||
		(runtime.GOOS == "windows" && strings.HasPrefix(path, "\\")) //nolint:goconst
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
		return fmt.Errorf("%sinvalid alt-host format: %s, expected sshuser@host:port",
			errorPrefix(), value)
	}

	username := parts[0]
	hostPort := parts[1]

	_, ok := altHosts[username]
	if ok {
		return fmt.Errorf("%sduplicate alt-host entry for sshuser: %s",
			errorPrefix(), username)
	}

	if !isUnixSocket(hostPort) {
		_, _, err := net.SplitHostPort(hostPort)
		if err != nil {
			return fmt.Errorf("%sinvalid host:port in alt-host '%s': %w",
				errorPrefix(), value, err)
		}
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
	return fmt.Sprintf("%o",
		*op)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (op *octalPermValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return fmt.Errorf("%sinvalid octal permission value: %w",
			errorPrefix(), err)
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
	pflag.CommandLine.SetOutput(os.Stdout)
	pflag.CommandLine.SortFlags = false

	pflag.Usage = func() {
		origVersion := showVersion
		showVersion = true
		printVersion(true)
		showVersion = origVersion

		exePath := resolveExePath()
		_, _ = fmt.Fprintf(os.Stdout,
			"\r\nUsage for %s:\r\n\r\n",
			exePath)
		var buf bytes.Buffer
		pflag.CommandLine.SetOutput(&buf)
		pflag.PrintDefaults()
		pflag.CommandLine.SetOutput(os.Stdout)
		re := regexp.MustCompile(`\[=true\|false\]`)
		output := re.ReplaceAllString(buf.String(), "             ")
		reSpaces := regexp.MustCompile(`(?m)^ {6}`)
		output = reSpaces.ReplaceAllString(output, "  ")
		_, _ = fmt.Fprint(os.Stdout,
			output)
		_, _ = fmt.Fprintf(os.Stdout,
			"  --help"+
				"                        Show this help and usage information\r\n\r\n"+
				"proxy home page (bug reports): <https://gitlab.com/dps8m/proxy/>\r\n")
	}

	// NOTE: Ensure that all pflag --help / -h output renders in less
	//       than 79 columns and that indentation renders as 4 spaces.

	pflag.BoolVar(&allowRoot,
		"allow-root", false,
		"Allow running as root (UID 0)")

	pflag.StringVar(&certDir,
		"cert-dir", "",
		"Directory containing SSH host certificates\r\n"+
			"    (default: current working directory)")

	pflag.Var((*octalPermValue)(&certPerm),
		"cert-perm",
		"Permissions (octal) for new certificate files\r\n"+
			"    [e.g., \"600\", \"644\"]")
	pflag.Lookup("cert-perm").DefValue = "600"

	pflag.StringSliceVar(&sshAddr,
		"ssh-addr", []string{":2222"},
		"SSH listener address(es)\r\n"+
			"    [e.g., \":2222\", \"[::1]:8000\"]\r\n"+
			"    (multiple allowed)")
	pflag.Lookup("ssh-addr").DefValue = "\":2222\""

	pflag.Float64Var(&sshDelay,
		"ssh-delay", 0,
		"Delay for incoming SSH connections\r\n"+
			"    [\"0.0\" to \"30.0\" seconds] (no default)")

	pflag.BoolVar(&noBanner,
		"no-banner", false,
		"Disable SSH connection banner")

	pflag.StringVar(&telnetHostPort,
		"telnet-host", "127.0.0.1:6180",
		"Default TELNET target [host:port]\r\n"+
			"   ")

	pflag.Var(&altHostFlag{},
		"alt-host",
		"Alternate TELNET target(s) [sshuser@host:port]\r\n"+
			"    (multiple allowed)")

	pflag.BoolVar(&debugNegotiation,
		"debug-telnet", false,
		"Debug TELNET option negotiation")

	pflag.StringVar(&debugAddr,
		"debug-server", "",
		"Enable HTTP debug server listening address\r\n"+
			"    [e.g., \":6060\", \"[::1]:6060\"]")

	pflag.BoolVar(&noSanitize,
		"no-sanitize", false,
		"Disable ASCII sanitization of error messages\r\n"+
			"    (allowing non-ASCII error reports via SSH)")

	if gopsEnabled {
		pflag.BoolVar(&enableGops,
			"gops", false,
			"Enable the \"gops\" diagnostic agent\r\n"+
				"    (see https://github.com/google/gops)")
	}

	pflag.BoolVar(&enableMDNS,
		"mdns", false,
		"Enable mDNS (Multicast DNS) advertisements\r\n"+
			"    (i.e., Bonjour, Avahi announcements)")

	pflag.StringVar(&logDir,
		"log-dir", "log",
		"Base directory for logs")

	pflag.BoolVar(&noLog,
		"no-log", false,
		"Disable all session logging\r\n"+
			"    (for console logging see \"--console-log\")")

	pflag.BoolVar(&noConsole,
		"no-console", false,
		"Disable the interactive admin console")

	pflag.StringVar(&consoleLog,
		"console-log", "",
		"Enable console logging [\"quiet\", \"noquiet\"]\r\n"+
			"    (disabled by default)")

	pflag.StringVar(&compressAlgo,
		"compress-algo", "gzip",
		"Compression algorithm for log files\r\n"+
			"    [\"gzip\", \"lzip\", \"xz\", \"zstd\"]\r\n"+
			"   ")

	pflag.StringVar(&compressLevel,
		"compress-level", "normal",
		"Compression level for gzip, lzip, and zstd\r\n"+
			"    algorithms [\"fast\", \"normal\", \"high\"]\r\n"+
			"   ")

	pflag.BoolVar(&noCompress,
		"no-compress", false,
		"Disable session and/or console log compression")

	pflag.Var((*octalPermValue)(&logPerm),
		"log-perm",
		"Permissions (octal) for new log files\r\n"+
			"    [e.g., \"600\", \"644\"]")
	pflag.Lookup("log-perm").DefValue = "600"

	pflag.Var((*octalPermValue)(&logDirPerm),
		"log-dir-perm",
		"Permissions (octal) for new log directories\r\n"+
			"    [e.g., \"755\", \"750\"]")
	pflag.Lookup("log-dir-perm").DefValue = "750"

	if dbEnabled {
		pflag.StringVar(&dbPath,
			"db-file", "",
			"Path to persistent statistics storage database\r\n"+
				"    (disabled by default)")

		pflag.Uint64Var(&dbTime,
			"db-time", 30,
			"Elapsed seconds between database updates\r\n"+
				"    [0 disables periodic writes]")

		pflag.Var((*octalPermValue)(&dbPerm),
			"db-perm",
			"Permissions (octal) for new database files\r\n"+
				"    [e.g., \"600\", \"644\"]")
		pflag.Lookup("log-perm").DefValue = "600"

		pflag.StringVar(&dbLogLevel,
			"db-loglevel", "error",
			"Database engine (BBoltDB) logging output level\r\n"+
				"    [level: \"0\" - \"6\", or \"none\" - \"debug\"]\r\n"+
				"   ")
	}

	pflag.IntVar(&idleMax,
		"idle-max", 0,
		"Maximum connection idle time allowed [seconds]")

	pflag.IntVar(&timeMax,
		"time-max", 0,
		"Maximum connection link time allowed [seconds]")

	pflag.StringVar(&blacklistFile,
		"blacklist", "",
		"Enable blacklist [filename] (no default)")

	pflag.StringVar(&whitelistFile,
		"whitelist", "",
		"Enable whitelist [filename] (no default)")

	pflag.BoolVar(&forceUTC,
		"utc", false,
		"Use UTC (Coordinated Universal Time) for time\r\n"+
			"    display and timestamping in log files")

	if licenseText != "" {
		pflag.BoolVar(&showLicense,
			"license", false,
			"Show license terms and conditions")
	}

	pflag.BoolVar(&showVersion,
		"version", false,
		"Show version information")

	shutdownSignal = make(chan struct{})

	for k := range emacsKeymap {
		for i := 1; i < len(k); i++ {
			emacsKeymapPrefixes[k[:i]] = true
		}
	}

	haveUTF8console = haveUTF8support()

	for _, arg := range os.Args[1:] {
		if arg == "-?" || arg == "-h" || arg == "--help" {
			pflag.Usage()

			if enableGops {
				gopsClose()
			}

			os.Exit(0)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func shutdownWatchdog() {
	<-shutdownSignal
	loggingWg.Wait()

	closeDB()

	if isConsoleLogQuiet {
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sAll connections closed. Exiting.\r\n",
			nowStamp(), byePrefix())
	}

	log.Printf("%sAll connections closed. Exiting.\r\n",
		byePrefix())

	if enableGops {
		gopsClose()
	}

	os.Exit(0)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	pflag.Parse()

	if pflag.NFlag() == 0 && len(pflag.Args()) == 0 && guiLaunched() {
		pflag.Usage()

		fmt.Print("\r\nNOTE: This is NOT a GUI application!\r\n")

		switch runtime.GOOS {
		case "windows":
			fmt.Print(
				"It is intended to be invoked from a Command Prompt or Windows Terminal session.")

		case "darwin":
			fmt.Printf(
				"It is intended to be invoked from a command prompt (e.g., via Terminal.app).")

		case "linux":
			fmt.Printf(
				"It is intended to be invoked from a command prompt (not a file manager or GUI).")

		default:
			fmt.Printf(
				"It is intended to be invoked from a command prompt (and not a GUI launcher).")
		}

		fmt.Print("\r\n\r\nPress Enter (or Return) to exit ... ")

		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')
			fmt.Print("\r\n")

			if enableGops {
				gopsClose()
			}

			os.Exit(1)
		}

		t := term.NewTerminal(os.Stdin, "")
		_, _ = t.ReadLine()
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Print("\r\n")

		if enableGops {
			gopsClose()
		}

		os.Exit(1)
	}

	if showLicense {
		fmt.Println(licenseText)

		if enableGops {
			gopsClose()
		}

		os.Exit(0)
	}

	printVersion(false)

	if showVersion {
		if enableGops {
			gopsClose()
		}

		os.Exit(0)
	}

	if forceUTC {
		tz, err := time.LoadLocation("UTC")
		if err != nil {
			if enableGops {
				gopsClose()
			}

			log.Fatalf("%sERROR: Failed to load UTC zoneinfo: %v",
				errorPrefix(), err) // LINTED: Fatalf
		}

		time.Local = tz //nolint:gosmopolitan
	}

	if consoleLog != "" {
		cl := strings.ToLower(consoleLog)

		if cl != "quiet" && cl != "noquiet" { //nolint:goconst
			if enableGops {
				gopsClose()
			}

			log.Fatalf("%sERROR: Invalid --console-log value: %s.  Must be 'quiet' or 'noquiet'",
				errorPrefix(), consoleLog) // LINTED: Fatalf
		}

		isConsoleLogQuiet = (cl == "quiet")
	}

	if dbEnabled {
		err := SetDbLogLevel(dbLogLevel)
		if err != nil {
			if enableGops {
				gopsClose()
			}

			log.Fatalf("%sERROR: %v",
				errorPrefix(), err) // LINTED: Fatalf
		}
	}

	if sshDelay < 0 {
		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: --ssh-delay cannot be negative!",
			errorPrefix()) // LINTED: Fatalf
	}

	if sshDelay > 30 {
		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: --ssh-delay cannot be greater than 30!",
			errorPrefix()) // LINTED: Fatalf
	}

	if os.Getuid() == 0 && !allowRoot {
		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: Running as root/UID 0 is not allowed without the --allow-root flag!",
			errorPrefix()) // LINTED: Fatalf
	}

	switch compressAlgo {
	case "gzip", "lzip", "xz", "zstd": //nolint:goconst,nolintlint

	default:
		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: Invalid --compress-algo: %s",
			errorPrefix(), compressAlgo) // LINTED: Fatalf
	}

	switch compressLevel {
	case "fast", "normal", "high": //nolint:goconst

	default:
		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: Invalid --compress-level: %s",
			errorPrefix(), compressLevel) // LINTED: Fatalf
	}

	if enableGops {
		log.Printf("%sStarting gops diagnostic agent",
			gopsPrefix())
		gopsInit()
	}

	if debugAddr != "" {
		debugInit(debugAddr)
	}

	initDB()

	if dbEnabled && dbPath != "" && dbTime > 0 {
		const maxSeconds = uint64(math.MaxInt64 / int64(time.Second))

		if dbTime > maxSeconds {
			log.Printf("%sIllegal --db-time value: \"%d\" exceeds safe range. using \"30\"",
				warnPrefix(), dbTime)
			dbTime = 30
		}

		go func() {
			log.Printf("%sStarting database updater with %d second interval.",
				dbPrefix(), dbTime)

			ticker := time.NewTicker(time.Duration(dbTime) * time.Second) //nolint:gosec
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					writeCountersToDB()

				case <-shutdownSignal:
					log.Printf("%sStopping database updater.",
						dbPrefix())
					writeCountersToDB()

					return
				}
			}
		}()
	}

	setupConsoleLogging()

	if !noLog || consoleLog != "" {
		err := os.MkdirAll(logDir, os.FileMode(logDirPerm)) //nolint:gosec
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: Failed to create session log directory: %v\r\n",
				nowStamp(), warnPrefix(), err)
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sSession logging disabled.\r\n",
				nowStamp(), alertPrefix())
			noLog = true
		}

		p, err := filepath.EvalSymlinks(logDir)
		if err == nil {
			logDir = p
		}

		p, err = filepath.Abs(logDir)
		if err == nil {
			logDir = p
		}

		logDir = filepath.Clean(strings.TrimSpace(logDir))
	}

	reloadLists()

	if strings.Contains(telnetHostPort, "@") {
		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: --telnet-host cannot contain a username (e.g., 'user@'); "+
					"you specified: %s\r\n", nowStamp(), errorPrefix(), telnetHostPort)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: --telnet-host cannot contain a username (e.g., 'user@'); "+
			"you specified: %s", errorPrefix(), telnetHostPort) // LINTED: Fatalf
	}

	if idleMax > 0 && timeMax > 0 && idleMax >= timeMax {
		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: --idle-max (%d) cannot be greater than or equal to --time-max"+
					" (%d)\r\n", nowStamp(), errorPrefix(), idleMax, timeMax)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: --idle-max (%d) cannot be greater than or equal to --time-max (%d)",
			errorPrefix(), idleMax, timeMax) // LINTED: Fatalf
	}

	edSigner, err := loadOrCreateHostKey(filepath.Join(
		certDir,
		"ssh_host_ed25519_key.pem"),
		"ed25519")
	if err != nil {
		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: Ed25519 host key error: %v\r\n",
				nowStamp(), errorPrefix(), err)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: Ed25519 host key error: %v",
			errorPrefix(), err) // LINTED: Fatalf
	}

	rsaSigner, err := loadOrCreateHostKey(filepath.Join(
		certDir,
		"ssh_host_rsa_key.pem"),
		"rsa")
	if err != nil {
		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: RSA host key error: %v\r\n",
				nowStamp(), errorPrefix(), err)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: RSA host key error: %v",
			errorPrefix(), err) // LINTED: Fatalf
	}

	ecdsaSigner, err := loadOrCreateHostKey(filepath.Join(
		certDir,
		"ssh_host_ecdsa_key.pem"),
		"ecdsa")
	if err != nil {
		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: ECDSA host key error: %v\r\n",
				nowStamp(), errorPrefix(), err)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: ECDSA host key error: %v",
			errorPrefix(), err) // LINTED: Fatalf
	}

	for _, addr := range sshAddr {
		go func(addr string) {
			checkPrivilegedPorts(sshAddr)
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				if isConsoleLogQuiet {
					_, _ = fmt.Fprintf(os.Stdout,
						"%s %sERROR: LISTEN on %s: %v\r\n",
						nowStamp(), errorPrefix(), addr, err)
				}

				if enableGops {
					gopsClose()
				}

				log.Fatalf("%sERROR: LISTEN on %s: %v",
					errorPrefix(), addr, err) // LINTED: Fatalf
			}
			defer func() {
				err := listener.Close()
				if err != nil {
					log.Printf("%sFailed to close listener for %s: %v",
						warnPrefix(), addr, err)
				}
			}()

			if enableMDNS {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					log.Printf("%sError splitting host from address for mDNS: %v",
						warnPrefix(), err)
				} else {
					announceMDNS(listener, host, altHosts, "_ssh._tcp", telnetHostPort)
				}
			}

			for {
				rawConn, err := listener.Accept()
				if err != nil {
					if gracefulShutdownMode.Load() {
						return
					}

					acceptErrorsTotal.Add(1)

					log.Printf("%sERROR: Accept error: %v",
						warnPrefix(), err)

					continue
				}

				go handleConn(rawConn, edSigner, rsaSigner, ecdsaSigner)
			}
		}(addr)
	}

	pid := os.Getpid()

	var startMsg string

	if pid != 0 {
		startMsg = fmt.Sprintf("Starting proxy %s[PID %d]",
			relayPrefix(), pid)
	} else {
		startMsg = fmt.Sprintf("Starting proxy %s",
			relayPrefix())
	}

	if !noConsole {
		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %s - Type '?' for help\r\n",
				nowStamp(), startMsg)
		}

		log.Printf("%s - Type '?' for help",
			startMsg)
	}

	for _, addr := range sshAddr {
		log.Printf("SSH listener on %s",
			addr)
	}

	if !isUnixSocket(telnetHostPort) {
		_, _, err := net.SplitHostPort(telnetHostPort)
		if err != nil {
			if isConsoleLogQuiet {
				_, _ = fmt.Fprintf(os.Stdout,
					"%s %sERROR: Could not parse default TELNET target: %v\r\n",
					nowStamp(), errorPrefix(), err)
			}

			if enableGops {
				gopsClose()
			}

			log.Fatalf("%sERROR: Could not parse default TELNET target: %v",
				errorPrefix(), err) // LINTED: Fatalf
		}
	}

	log.Printf("Default TELNET target: %s",
		telnetHostPort)
	for user, hostPort := range altHosts {
		log.Printf("Alt target: %s [%s]",
			hostPort, user)
	}

	runSignalHandlers()

	if !noConsole {
		go handleConsoleInput()
	} else {
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sInteractive admin console is disabled; no input will be accepted!\r\n",
			nowStamp(), alertPrefix())
	}

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
						log.Printf("%sIDLEKILL [%s] %s@%s (idle %s, link %s)",
							yellowDotPrefix(), id, conn.userName,
							conn.hostName, idleTime.Round(time.Second),
							connUptime.Round(time.Second))

						_, err := conn.channel.Write(fmt.Appendf(nil,
							"\r\n\r\nIDLE TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second)))
						if err != nil {
							log.Printf(
								"%sError writing idle timeout message to channel for %s: %v",
								warnPrefix(), id, err)
						}

						err = conn.sshConn.Close()
						if err != nil {
							log.Printf("%sError closing SSH connection for %s: %v",
								warnPrefix(), id, err)
						}

						delete(connections, id)
					} else if timeMax > 0 && connUptime > time.Duration(timeMax)*time.Second {
						timeKillsTotal.Add(1)

						connUptime := time.Since(conn.startTime)
						log.Printf("%sTIMEKILL [%s] %s@%s (link time %s)",
							yellowDotPrefix(), id, conn.userName,
							conn.hostName, connUptime.Round(time.Second))

						_, err := conn.channel.Write(fmt.Appendf(nil,
							"\r\n\r\nCONNECTION TIMEOUT (link time %s)\r\n\r\n",
							connUptime.Round(time.Second)))
						if err != nil {
							log.Printf(
								"%sError writing connection timeout message to channel for %s: %v",
								warnPrefix(), id, err)
						}

						err = conn.sshConn.Close()
						if err != nil {
							log.Printf("%sError closing SSH connection for %s: %v",
								warnPrefix(), id, err)
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

func debugInit(addr string) {
	mux := http.NewServeMux()

	_ = statsviz.Register(mux)

	mux.Handle("/debug/pprof/", http.DefaultServeMux)

	mux.Handle("/debug/vars", http.DefaultServeMux)

	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, `
        <html>
        <head><title>DPS8M Proxy Debugging Dashboard</title></head>
        <body>
            <h1>Debug Dashboard</h1>
            <ul>
                <li><a href="/debug/vars">expvar</a></li>
                <li><a href="/debug/pprof/">pprof</a></li>
                <li><a href="/debug/statsviz/">statsviz</a></li>
            </ul>
        </body>
        </html>
    `)
	})

	log.Printf("%sStarting debug HTTP server on %s",
		bugPrefix(), addr)
	go func() {
		log.Fatalf("%s%v", // LINTED: Fatalf
			// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
			errorPrefix(), http.ListenAndServe(addr, mux)) //nolint:gosec
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isGitSHA(s string) bool {
	match, _ := regexp.MatchString("^[0-9a-f]{40}$", s)

	return match
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func printVersion(short bool) {
	versionString := "DPS8M Proxy"

	versionString += func() string {
		v := getMainModuleVersion()
		if v != "" {
			return " " + v
		}

		return ""
	}()

	info, ok := debug.ReadBuildInfo()
	if ok {
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
				versionString += fmt.Sprintf(" (%s g%s+)",
					tdate, commit)
			} else {
				versionString += fmt.Sprintf(" (%s g%s)",
					tdate, commit)
			}
		}
	}

	versionString += fmt.Sprintf(" [%s/%s]",
		runtime.GOOS, runtime.GOARCH)

	if showVersion {
		fmt.Printf("%s\r\n",
			versionString)

		if !short {
			fmt.Printf("\r\n")
			printVersionTable()
			fmt.Printf("\r\n")
		}
	} else {
		log.Printf("%s\r\n",
			versionString)
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
					log.Printf("%sConsole EOF, initiating immediate shutdown.\r\n",
						boomPrefix())
					immediateShutdown()
				}

				return
			}
			log.Printf("%sConsole read error: %v",
				boomPrefix(), err)

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

		case "l":
			listConnections(true)

		case "L":
			listConnections(false)

		case "s", "S":
			showStats()

		case "c", "C":
			listConfiguration()

		case "v", "V":
			fmt.Printf("\r\n")

			originalWriter := log.Writer()

			if consoleLogFile != nil {
				fileWriter := &emojiStripperWriter{w: consoleLogFile}
				log.SetOutput(io.MultiWriter(os.Stdout, fileWriter))
			} else {
				log.SetOutput(os.Stdout)
			}

			printVersion(false)
			fmt.Printf("\r\n")
			printVersionTable()
			fmt.Printf("\r\n")
			log.SetOutput(originalWriter)

		case "cg", "CG", "cG", "Cg":
			listGoroutines()

		case "k", "K":
			if len(parts) < 2 {
				_, _ = fmt.Fprintf(os.Stdout,
					"%s Error: Session ID or '*' required for 'k' command.\r\n",
					nowStamp())

				continue
			}

			if parts[1] == "*" {
				killAllConnections()
			} else {
				killConnection(parts[1])
			}

		case "r", "R":
			if blacklistFile == "" || whitelistFile == "" {
				_, err := fmt.Fprintf(os.Stdout,
					"%s %sReload requested but no lists enabled.\r\n",
					nowStamp(), alertPrefix())
				if err != nil {
					log.Printf("%sError writing to stdout: %v",
						boomPrefix(), err)
				}
			}

			reloadLists()

		case "xyzzy": // :)
			if isConsoleLogQuiet {
				fmt.Printf("%s %sNothing happens.\r\n",
					nowStamp(), easterEggPrefix())
			}

			log.Printf("%sNothing happens.\r\n",
				easterEggPrefix())

		case "XYZZY": // =)
			if isConsoleLogQuiet {
				fmt.Printf("%s %sNOTHING HAPPENS.\r\n",
					nowStamp(), easterEggPrefix())
			}

			log.Printf("%sNOTHING HAPPENS.\r\n",
				easterEggPrefix())

		case "":

		default:
			_, err := fmt.Fprintf(os.Stdout,
				"%s Unknown command: %s\r\n",
				nowStamp(), cmd)
			if err != nil {
				log.Printf("%sError writing to stdout: %v",
					boomPrefix(), err)
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

	border := fmt.Sprintf("\r+=%s=+=%s=+\r\n",
		strings.Repeat("=", maxKey), strings.Repeat("=", maxDesc),
	)

	fmt.Print("\r\n")
	fmt.Print(border)
	fmt.Printf("\r| %-*s | %-*s |\r\n",
		maxKey, "Key", maxDesc, "Description")
	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("\r| %*s | %-*s |\r\n",
			maxKey, r.Key, maxDesc, r.Description)
	}

	fmt.Print(border)
	fmt.Print("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showStats() {
	if dbPath == "" {
		type row struct{ Name, Value string }
		rows := []row{
			{
				"TELNET Total Connections",
				fmt.Sprintf("%d",
					telnetConnectionsTotal.Load()),
			},

			{
				"* TELNET Alt-Host Routings",
				fmt.Sprintf("%d",
					altHostRoutesTotal.Load()),
			},

			{
				"* TELNET Connection Failures",
				fmt.Sprintf("%d",
					telnetFailuresTotal.Load()),
			},

			{
				"Peak Concurrent Connections",
				fmt.Sprintf("%d",
					peakUsersTotal.Load()),
			},

			{
				"Total Proxy Traffic Inbound",
				formatBytes(trafficOutTotal.Load()),
			},

			{
				"Total Proxy Traffic Outbound",
				formatBytes(trafficInTotal.Load()),
			},

			{
				"SSH Total Connections",
				fmt.Sprintf("%d",
					sshConnectionsTotal.Load()),
			},

			{
				"* SSH User Sessions",
				fmt.Sprintf("%d",
					sshSessionsTotal.Load()),
			},

			{
				"* SSH Monitoring Sessions",
				fmt.Sprintf("%d",
					monitorSessionsTotal.Load()),
			},

			{
				"* SSH Session Request Timeout",
				fmt.Sprintf("%d",
					sshRequestTimeoutTotal.Load()),
			},

			{
				"* SSH Illegal Request (SFTP)",
				fmt.Sprintf("%d",
					sshIllegalSubsystemTotal.Load()),
			},

			{
				"* SSH Illegal Request (SCP/EXEC)",
				fmt.Sprintf("%d",
					sshExecRejectedTotal.Load()),
			},

			{
				"* SSH Accept Errors",
				fmt.Sprintf("%d",
					acceptErrorsTotal.Load()),
			},

			{
				"* SSH Handshake Errors",
				fmt.Sprintf("%d",
					sshHandshakeFailedTotal.Load()),
			},

			{
				"* SSH Other Errors/Disconnects",
				fmt.Sprintf("%d",
					sshSessionsTotal.Load()-
						monitorSessionsTotal.Load()-
						sshRequestTimeoutTotal.Load()-
						sshIllegalSubsystemTotal.Load()-
						sshExecRejectedTotal.Load()-
						acceptErrorsTotal.Load()-
						sshHandshakeFailedTotal.Load()),
			},

			{
				"Connections Killed by Admin",
				fmt.Sprintf("%d",
					adminKillsTotal.Load()),
			},

			{
				"Connections Killed for Idle Time",
				fmt.Sprintf("%d",
					idleKillsTotal.Load()),
			},

			{
				"Connections Killed for Max Time",
				fmt.Sprintf("%d",
					timeKillsTotal.Load()),
			},

			{
				"Connections Killed via Delay",
				fmt.Sprintf("%d",
					delayAbandonedTotal.Load()),
			},

			{
				"Blacklist Rejected Connections",
				fmt.Sprintf("%d",
					rejectedTotal.Load()),
			},

			{
				"Whitelist Exempted Connections",
				fmt.Sprintf("%d",
					exemptedTotal.Load()),
			},
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

		border := fmt.Sprintf("\r+=%s=+=%s=+\r\n",
			strings.Repeat("=", maxName), strings.Repeat("=", maxVal))
		fmt.Print("\r\n")
		fmt.Print(border)
		fmt.Printf("\r| %-*s | %*s |\r\n",
			maxName, "Statistic", maxVal, "Value")
		fmt.Print(border)

		for i, r := range rows {
			fmt.Printf("\r| %-*s | %*s |\r\n",
				maxName, r.Name, maxVal, r.Value)

			if i == 2 || i == 5 || i == 14 || i == 18 || i == 20 {
				fmt.Print(border)
			}
		}

		fmt.Print("\r\n")
	} else {
		type row struct{ Name, Value, Lifetime string }
		rows := []row{
			{
				"TELNET Total Connections",
				fmt.Sprintf("%d",
					telnetConnectionsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeTelnetConnectionsTotal.Load()+telnetConnectionsTotal.Load()),
			},

			{
				"* TELNET Alt-Host Routings",
				fmt.Sprintf("%d",
					altHostRoutesTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeAltHostRoutesTotal.Load()+altHostRoutesTotal.Load()),
			},

			{
				"* TELNET Connection Failures",
				fmt.Sprintf("%d",
					telnetFailuresTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeTelnetFailuresTotal.Load()+telnetFailuresTotal.Load()),
			},

			{
				"Peak Concurrent Connections",
				fmt.Sprintf("%d",
					peakUsersTotal.Load()),
				fmt.Sprintf("%d",
					lifetimePeakUsersTotal.Load()),
			},

			{
				"Total Proxy Traffic Inbound",
				formatBytes(trafficOutTotal.Load()),
				formatBytes(lifetimeTrafficOutTotal.Load() + trafficOutTotal.Load()),
			},

			{
				"Total Proxy Traffic Outbound",
				formatBytes(trafficInTotal.Load()),
				formatBytes(lifetimeTrafficInTotal.Load() + trafficInTotal.Load()),
			},

			{
				"SSH Total Connections",
				fmt.Sprintf("%d",
					sshConnectionsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeSSHconnectionsTotal.Load()+sshConnectionsTotal.Load()),
			},

			{
				"* SSH User Sessions",
				fmt.Sprintf("%d",
					sshSessionsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeSSHsessionsTotal.Load()+sshSessionsTotal.Load()),
			},

			{
				"* SSH Monitoring Sessions",
				fmt.Sprintf("%d",
					monitorSessionsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeMonitorSessionsTotal.Load()+monitorSessionsTotal.Load()),
			},

			{
				"* SSH Session Request Timeout",
				fmt.Sprintf("%d",
					sshRequestTimeoutTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeSSHrequestTimeoutTotal.Load()+sshRequestTimeoutTotal.Load()),
			},

			{
				"* SSH Illegal Request (SFTP)",
				fmt.Sprintf("%d",
					sshIllegalSubsystemTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeSSHillegalSubsystemTotal.Load()+sshIllegalSubsystemTotal.Load()),
			},

			{
				"* SSH Illegal Request (SCP/EXEC)",
				fmt.Sprintf("%d",
					sshExecRejectedTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeSSHexecRejectedTotal.Load()+sshExecRejectedTotal.Load()),
			},

			{
				"* SSH Accept Errors",
				fmt.Sprintf("%d",
					acceptErrorsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeAcceptErrorsTotal.Load()+acceptErrorsTotal.Load()),
			},

			{
				"* SSH Handshake Errors",
				fmt.Sprintf("%d",
					sshHandshakeFailedTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeSSHhandshakeFailedTotal.Load()+sshHandshakeFailedTotal.Load()),
			},

			{
				"* SSH Other Errors/Disconnects",
				fmt.Sprintf("%d",
					sshConnectionsTotal.Load()-
						sshSessionsTotal.Load()-
						monitorSessionsTotal.Load()-
						sshRequestTimeoutTotal.Load()-
						sshIllegalSubsystemTotal.Load()-
						sshExecRejectedTotal.Load()-
						acceptErrorsTotal.Load()-
						sshHandshakeFailedTotal.Load()),
				fmt.Sprintf("%d",
					(lifetimeSSHconnectionsTotal.Load()+sshConnectionsTotal.Load())-
						(lifetimeSSHsessionsTotal.Load()+sshSessionsTotal.Load())-
						(lifetimeMonitorSessionsTotal.Load()+monitorSessionsTotal.Load())-
						(lifetimeSSHrequestTimeoutTotal.Load()+sshRequestTimeoutTotal.Load())-
						(lifetimeSSHillegalSubsystemTotal.Load()+sshIllegalSubsystemTotal.Load())-
						(lifetimeSSHexecRejectedTotal.Load()+sshExecRejectedTotal.Load())-
						(lifetimeAcceptErrorsTotal.Load()+acceptErrorsTotal.Load())-
						(lifetimeSSHhandshakeFailedTotal.Load()+sshHandshakeFailedTotal.Load())),
			},

			{
				"Connections Killed by Admin",
				fmt.Sprintf("%d",
					adminKillsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeAdminKillsTotal.Load()+adminKillsTotal.Load()),
			},

			{
				"Connections Killed for Idle Time",
				fmt.Sprintf("%d",
					idleKillsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeIdleKillsTotal.Load()+idleKillsTotal.Load()),
			},

			{
				"Connections Killed for Max Time",
				fmt.Sprintf("%d",
					timeKillsTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeTimeKillsTotal.Load()+timeKillsTotal.Load()),
			},

			{
				"Connections Killed via Delay",
				fmt.Sprintf("%d",
					delayAbandonedTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeDelayAbandonedTotal.Load()+delayAbandonedTotal.Load()),
			},

			{
				"Blacklist Rejected Connections",
				fmt.Sprintf("%d",
					rejectedTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeRejectedTotal.Load()+rejectedTotal.Load()),
			},

			{
				"Whitelist Exempted Connections",
				fmt.Sprintf("%d",
					exemptedTotal.Load()),
				fmt.Sprintf("%d",
					lifetimeExemptedTotal.Load()+exemptedTotal.Load()),
			},
		}

		maxName := len("Statistic")
		maxVal := len("Value")
		maxLifetime := len("Lifetime")

		for _, r := range rows {
			if len(r.Name) > maxName {
				maxName = len(r.Name)
			}

			if len(r.Value) > maxVal {
				maxVal = len(r.Value)
			}

			if len(r.Lifetime) > maxLifetime {
				maxLifetime = len(r.Lifetime)
			}
		}

		border := fmt.Sprintf("\r+=%s=+=%s=+=%s=+\r\n",
			strings.Repeat("=", maxName),
			strings.Repeat("=", maxVal),
			strings.Repeat("=", maxLifetime))
		fmt.Print("\r\n")
		fmt.Print(border)
		fmt.Printf("\r| %-*s | %*s | %*s |\r\n",
			maxName, "Statistic",
			maxVal, "Value",
			maxLifetime, "Lifetime")
		fmt.Print(border)

		for i, r := range rows {
			fmt.Printf("\r| %-*s | %*s | %*s |\r\n",
				maxName, r.Name, maxVal, r.Value, maxLifetime, r.Lifetime)

			if i == 2 || i == 5 || i == 14 || i == 18 || i == 20 {
				fmt.Print(border)
			}
		}

		fmt.Print("\r\n")
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleGracefulShutdown() {
	if gracefulShutdownMode.Load() {
		gracefulShutdownMode.Store(false)

		log.Printf("%sGraceful shutdown canceled.\r\n",
			bellPrefix())

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sGraceful shutdown canceled.\r\n",
				nowStamp(), bellPrefix())
		}
	} else {
		gracefulShutdownMode.Store(true)

		log.Printf("%sNo new connections will be accepted.\r\n",
			skullPrefix())

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sNo new connections will be accepted.\r\n",
				nowStamp(), skullPrefix())
		}

		log.Printf("%sGraceful shutdown initiated.\r\n",
			bellPrefix())

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sGraceful shutdown initiated.\r\n",
				nowStamp(), bellPrefix())
		}

		connectionsMutex.Lock()

		if len(connections) == 0 {
			connectionsMutex.Unlock()

			shutdownOnce.Do(func() { close(shutdownSignal) })
		} else {
			connectionsMutex.Unlock()
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleDenyNewConnections() {
	if denyNewConnectionsMode.Load() {
		denyNewConnectionsMode.Store(false)

		log.Printf("%sDeny connections canceled.\r\n",
			thumbsUpPrefix())

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sDeny connections canceled.\r\n",
				nowStamp(), thumbsUpPrefix())
		}
	} else {
		denyNewConnectionsMode.Store(true)

		log.Printf("%sNo new connections will be accepted.\r\n",
			skullPrefix())

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sNo new connections will be accepted.\r\n",
				nowStamp(), skullPrefix())
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func immediateShutdown() {
	shutdownOnce.Do(func() {
		log.Printf("%sImmediate shutdown initiated.\r\n",
			boomPrefix())

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sImmediate shutdown initiated.\r\n",
				nowStamp(), boomPrefix())
		}

		connectionsMutex.Lock()

		for _, conn := range connections {
			if conn.channel != nil {
				_, err := conn.channel.Write(
					[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				connUptime := time.Since(conn.startTime)
				log.Printf("%sLINKDOWN [%s] %s@%s (link time %s)",
					yellowDotPrefix(), conn.ID, conn.userName,
					conn.hostName, connUptime.Round(time.Second))
			}

			if conn.cancelFunc != nil {
				conn.cancelFunc()
			}

			if conn.sshConn != nil {
				err := conn.sshConn.Close()
				if err != nil {
					log.Printf("%sError closing SSH connection for %s: %v",
						alertPrefix(), conn.ID, err)
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

		closeDB()

		if isConsoleLogQuiet {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sExiting.\r\n",
				nowStamp(), byePrefix())
		}

		log.Printf("%sExiting.\r\n",
			byePrefix())

		if enableGops {
			gopsClose()
		}

		os.Exit(0)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConnections(truncate bool) {
	connectionsMutex.Lock()

	defer connectionsMutex.Unlock()

	if len(connections) == 0 {
		fmt.Printf("\r%s No active connections.\r\n",
			nowStamp())

		return
	}

	conns := make([]*Connection, 0, len(connections))
	for _, conn := range connections {
		conns = append(conns, conn)
	}

	sort.Slice(conns, func(i, j int) bool {
		return conns[i].startTime.Before(conns[j].startTime)
	})

	type row struct {
		ID      string
		Details string
		Link    string
		Idle    string
	}

	userTruncat := false
	rows := make([]row, 0, len(connections))

	for _, conn := range conns {
		user := conn.sshConn.User()

		if truncate && len(user) > 21 {
			userTruncat = true
			user = "..." + user[len(user)-18:]
		}

		var details, idle string

		if conn.monitoring {
			details = fmt.Sprintf("%s@%s -> %s",
				user, conn.sshConn.RemoteAddr(), conn.monitoredConnection.ID)
			idle = "---------"
		} else {
			targetInfo := ""

			if conn.targetHost != "" {
				if conn.targetPort != 0 {
					targetInfo = fmt.Sprintf(" -> %s:%d",
						conn.targetHost, conn.targetPort)
				} else {
					targetInfo = fmt.Sprintf(" -> %s",
						conn.targetHost)
				}
			}

			details = fmt.Sprintf("%s@%s%s",
				user, conn.sshConn.RemoteAddr(), targetInfo)
			idle = time.Since(conn.lastActivityTime).Round(time.Second).String()
		}

		rows = append(rows, row{
			ID:      conn.ID,
			Details: details,
			Link:    time.Since(conn.startTime).Round(time.Second).String(),
			Idle:    idle,
		})
	}

	maxID := len("Session ID")
	maxDetails := len("Connection Details")
	maxLink := len("Link Time")
	maxIdle := len("Idle Time")

	for _, r := range rows {
		if len(r.ID) > maxID {
			maxID = len(r.ID)
		}

		if len(r.Details) > maxDetails {
			maxDetails = len(r.Details)
		}

		if len(r.Link) > maxLink {
			maxLink = len(r.Link)
		}

		if len(r.Idle) > maxIdle {
			maxIdle = len(r.Idle)
		}
	}

	border := fmt.Sprintf("\r+=%s=+=%s=+=%s=+=%s=+\r\n",
		strings.Repeat("=", maxID),
		strings.Repeat("=", maxDetails),
		strings.Repeat("=", maxLink),
		strings.Repeat("=", maxIdle),
	)

	fmt.Printf("\r\n")

	fmt.Print(border)

	fmt.Printf("\r| %-*s | %-*s | %*s | %*s |\r\n",
		maxID, "Session ID", maxDetails, "Connection Details",
		maxLink, "Link Time", maxIdle, "Idle Time")

	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("\r| %*s | %-*s | %*s | %*s |\r\n",
			maxID, r.ID, maxDetails, r.Details,
			maxLink, r.Link, maxIdle, r.Idle)
	}

	fmt.Print(border)

	if userTruncat {
		fmt.Printf(
			"\r\n* %sSome Connections Details have been truncated, use 'cg' for wider output.\r\n",
			alertPrefix())
	}

	fmt.Printf("\r\n")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConfiguration() {
	pid := os.Getpid()

	var b strings.Builder
	maxLength := 0

	updateMaxLength := func(s string) {
		if len(s) > maxLength {
			maxLength = len(s)
		}
	}

	bHerald := fmt.Sprintf("DPS8M Proxy Configuration and Status - PID: %-8d",
		pid)

	updateMaxLength(bHerald)

	updateMaxLength("SSH listeners on:")
	for _, addr := range sshAddr {
		updateMaxLength("* " + addr)
	}

	certDirStr, err := os.Getwd()
	if err != nil {
		certDirStr = "."
	}

	if certDir != "" {
		certDirStr = certDir
	}

	s10 := fmt.Sprintf("SSH Certificate Directory: %s",
		certDirStr)

	updateMaxLength(s10)

	var gopsStr string

	if enableGops {
		gopsStr = "enabled"
	} else {
		gopsStr = "disabled" //nolint:goconst
	}

	s14 := fmt.Sprintf("Gops diagnostic agent: %s", gopsStr)

	updateMaxLength(s14)

	var MDNSStr string

	if enableMDNS {
		MDNSStr = "enabled"
	} else {
		MDNSStr = "disabled"
	}

	s13 := fmt.Sprintf("Multicast DNS announcements: %s", MDNSStr)

	updateMaxLength(s13)

	updateMaxLength("Default TELNET target: " + telnetHostPort)

	s2 := fmt.Sprintf("Debug TELNET Negotiation: %t",
		debugNegotiation)

	updateMaxLength(s2)

	if len(altHosts) > 0 {
		updateMaxLength("Alt Targets:")
		for user, hostPort := range altHosts {
			s3 := fmt.Sprintf("* %s [%s]",
				hostPort, user)
			updateMaxLength(s3)
		}
	}

	timeMaxStr := "disabled"

	if timeMax > 0 {
		timeMaxStr = fmt.Sprintf("%d seconds",
			timeMax)
	}

	updateMaxLength("Time Max: " + timeMaxStr)

	idleMaxStr := "disabled"

	if idleMax > 0 {
		idleMaxStr = fmt.Sprintf("%d seconds",
			idleMax)
	}

	updateMaxLength("Idle Max: " + idleMaxStr)

	updateMaxLength("Log Base Directory: " + logDir)

	s4 := fmt.Sprintf("No Session Logging: %t",
		noLog)

	updateMaxLength(s4)

	if consoleLog != "" {
		var quietMode string
		if isConsoleLogQuiet {
			quietMode = "quiet"
		} else {
			quietMode = "noquiet"
		}
		updateMaxLength("Console Logging: " + quietMode)
	} else {
		updateMaxLength("Console Logging: disabled")
	}

	s5 := fmt.Sprintf("No Log Compression: %t",
		noCompress)

	updateMaxLength(s5)

	updateMaxLength("Compression Algorithm: " + compressAlgo)

	updateMaxLength("Compression Level: " + compressLevel)

	s6 := fmt.Sprintf("Log Permissions: Files: %04o, Dirs: %04o",
		logPerm, logDirPerm)

	updateMaxLength(s6)

	s7 := fmt.Sprintf("Graceful Shutdown: %t",
		gracefulShutdownMode.Load())

	updateMaxLength(s7)

	s8 := fmt.Sprintf("Deny New Connections: %t",
		denyNewConnectionsMode.Load())

	updateMaxLength(s8)

	debugHTTPStr := "disabled"

	if debugAddr != "" {
		debugHTTPStr = debugAddr
	}

	updateMaxLength("Debug HTTP Server: " + debugHTTPStr)

	if blacklistFile == "" && len(blacklistedNetworks) == 0 { //nolint:gocritic
		updateMaxLength("Blacklist: 0 entries active")
	} else if whitelistFile != "" && blacklistFile == "" {
		updateMaxLength("Blacklist: Deny all (due to whitelist only)")
	} else {
		s9 := fmt.Sprintf("Blacklist: %d entries active",
			len(blacklistedNetworks))
		updateMaxLength(s9)
	}

	if whitelistFile == "" {
		updateMaxLength("Whitelist: 0 entries active")
	} else {
		s10 := fmt.Sprintf("Whitelist: %d entries active",
			len(whitelistedNetworks))
		updateMaxLength(s10)
	}

	uptime := time.Since(startTime)

	uptimeString := fmt.Sprintf("%dh%dm%ds (since %s)",
		int(uptime.Hours())%24, int(uptime.Minutes())%60, int(uptime.Seconds())%60,
		startTime.Format("2006-Jan-02 15:04:05"))

	updateMaxLength("Proxy Uptime: " + uptimeString)

	var lifetimeString string

	if dbTime > 1 && lifetimeString != "" { //nolint:gocritic
		updateMaxLength(fmt.Sprintf("Database enabled: %s, %d seconds between writes",
			dbPath, dbTime))
	} else if dbTime == 1 && lifetimeString != "" {
		updateMaxLength(fmt.Sprintf("Database enabled: %s, 1 second between writes",
			dbPath))
	} else if dbTime == 0 && lifetimeString != "" {
		updateMaxLength(fmt.Sprintf("Database enabled: %s, periodic updates disabled",
			dbPath))
	}

	if !persistedStartTime.IsZero() {
		lifetime := time.Since(persistedStartTime)
		days := int(lifetime.Hours() / 24)
		hours := int(lifetime.Hours()) % 24
		minutes := int(lifetime.Minutes()) % 60
		seconds := int(lifetime.Seconds()) % 60
		lifetimeString = fmt.Sprintf("%dd%dh%dm%ds (created %s)",
			days, hours, minutes, seconds,
			persistedStartTime.Format("2006-Jan-02 15:04:05"))
		updateMaxLength("Database age: " + lifetimeString)
	}

	var m runtime.MemStats

	debug.FreeOSMemory()
	runtime.ReadMemStats(&m)

	var allocStr, sysStr string

	allocStr = formatBytes(m.Alloc)
	sysStr = formatBytes(m.Sys)

	memStatsStr := fmt.Sprintf("%s used (of %s reserved)",
		allocStr, sysStr)
	updateMaxLength("Memory: " + memStatsStr)

	s11 := fmt.Sprintf("Runtime: %d active Goroutines (use 'cg' for details)",
		runtime.NumGoroutine())
	updateMaxLength(s11)

	if maxLength < 50 {
		maxLength = 50
	}

	textWidth := maxLength

	printRow := func(b *strings.Builder, text string) {
		b.WriteString("| ")
		b.WriteString(text)

		padding := textWidth - len(text)

		padding = max(0, padding)

		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" |\r\n")
	}

	separator := fmt.Sprintf("+%s+\r\n",
		strings.Repeat("=", textWidth+2))

	b.WriteString("\r\n")

	b.WriteString(separator)

	printRow(&b, bHerald)

	b.WriteString(separator)

	sshDelayStr := "disabled"

	if sshDelay > 0 {
		sshDelayStr = fmt.Sprintf("%.1f seconds",
			sshDelay)
	}

	printRow(&b, "SSH Connection Delay: "+sshDelayStr)

	printRow(&b, "SSH Listeners:")

	for _, addr := range sshAddr {
		printRow(&b, "* "+addr)
	}

	printRow(&b, s10) // Certificate Directory

	b.WriteString(separator)

	printRow(&b, "Default TELNET Target: "+telnetHostPort)

	printRow(&b, fmt.Sprintf("Debug TELNET Negotiation: %t",
		debugNegotiation))

	if len(altHosts) > 0 {
		printRow(&b, "Alt Targets:")
		users := make([]string, 0, len(altHosts))
		for user := range altHosts {
			users = append(users, user)
		}
		sort.Strings(users)
		for _, user := range users {
			hostPort := altHosts[user]
			printRow(&b, fmt.Sprintf("* %s [%s]",
				hostPort, user))
		}
	}

	b.WriteString(separator)

	printRow(&b, "Time Max: "+timeMaxStr)
	printRow(&b, "Idle Max: "+idleMaxStr)

	b.WriteString(separator)

	printRow(&b, "Log Base Directory: "+logDir)
	printRow(&b, fmt.Sprintf("No Session Logging: %t",
		noLog))

	if consoleLog != "" {
		var quietMode string

		if isConsoleLogQuiet {
			quietMode = "quiet"
		} else {
			quietMode = "noquiet"
		}

		printRow(&b, "Console Logging: "+quietMode)
	} else {
		printRow(&b, "Console Logging: disabled")
	}

	printRow(&b, fmt.Sprintf("No Log Compression: %t",
		noCompress))
	printRow(&b, "Compression Algorithm: "+compressAlgo)
	printRow(&b, "Compression Level: "+compressLevel)
	printRow(&b, fmt.Sprintf("Log Permissions: Files: %04o, Dirs: %04o",
		logPerm, logDirPerm))

	b.WriteString(separator)

	printRow(&b, fmt.Sprintf("Graceful Shutdown: %t",
		gracefulShutdownMode.Load()))
	printRow(&b, fmt.Sprintf("Deny New Connections: %t",
		denyNewConnectionsMode.Load()))

	b.WriteString(separator)

	if blacklistFile == "" && len(blacklistedNetworks) == 0 { //nolint:gocritic
		printRow(&b, "Blacklist: 0 entries active")
	} else if whitelistFile != "" && blacklistFile == "" {
		printRow(&b, "Blacklist: Deny all (due to whitelist only)")
	} else {
		printRow(&b, fmt.Sprintf("Blacklist: %d entries active",
			len(blacklistedNetworks)))
	}

	if whitelistFile == "" {
		printRow(&b, "Whitelist: 0 entries active")
	} else {
		printRow(&b, fmt.Sprintf("Whitelist: %d entries active",
			len(whitelistedNetworks)))
	}

	b.WriteString(separator)

	debugHTTP := "disabled"

	if debugAddr != "" {
		debugHTTP = debugAddr
	}

	printRow(&b, s13) // mDNS
	printRow(&b, s14) // gops

	printRow(&b, "Debug HTTP Server: "+debugHTTP)
	printRow(&b, "Proxy Uptime: "+uptimeString)

	if dbTime > 1 && lifetimeString != "" { //nolint:gocritic
		printRow(&b, fmt.Sprintf("Database enabled: %s, %d seconds between writes",
			dbPath, dbTime))
	} else if dbTime == 1 && lifetimeString != "" {
		printRow(&b, fmt.Sprintf("Database enabled: %s, 1 second between writes",
			dbPath))
	} else if dbTime == 0 && lifetimeString != "" {
		printRow(&b, fmt.Sprintf("Database enabled: %s, periodic updates disabled",
			dbPath))
	}

	if lifetimeString != "" {
		printRow(&b, "Database age: "+lifetimeString)
	}

	printRow(&b, "Memory: "+memStatsStr)
	printRow(&b, fmt.Sprintf("Runtime: %d active Goroutines (use 'cg' for details)",
		runtime.NumGoroutine()))

	b.WriteString(separator)

	fmt.Print(b.String())
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
				reloadErrors, fmt.Sprintf("Blacklist rejected: %v",
					err))
		} else {
			newBlacklistedNetworks = networks
			blacklistReloaded = true
		}
	}

	if whitelistFile != "" {
		networks, err := parseIPListFile(whitelistFile)
		if err != nil {
			reloadErrors = append(
				reloadErrors, fmt.Sprintf("Whitelist rejected: %v",
					err))
		} else {
			newWhitelistedNetworks = networks
			whitelistReloaded = true
		}
	}

	if len(reloadErrors) > 0 {
		for _, errMsg := range reloadErrors {
			log.Printf("%s%s",
				warnPrefix(), errMsg)
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

		log.Printf("%sBlacklist: Blacklisting all host by default\r\n",
			alertPrefix())
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killConnection(id string) {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	conn, ok := connections[id]
	if !ok {
		_, _ = fmt.Fprintf(os.Stdout,
			"%s Session ID '%s' not found.\r\n",
			nowStamp(), id)

		return
	}

	if isConsoleLogQuiet {
		_, err := fmt.Fprintf(os.Stdout,
			"%s %sKilling connection %s...\r\n",
			nowStamp(), skullPrefix(), id)
		if err != nil {
			log.Printf("%sError writing to Stdout: %v",
				warnPrefix(), err)
		}
	}

	log.Printf("%sKilling connection %s...\r\n",
		skullPrefix(), id)

	if conn.channel != nil {
		_, err := conn.channel.Write(
			[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"))
		if err != nil {
			log.Printf("%sError writing to channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}

	connUptime := time.Since(conn.startTime)

	log.Printf("%sTERMKILL [%s] %s@%s (link time %s)",
		yellowDotPrefix(), conn.ID, conn.userName,
		conn.hostName, connUptime.Round(time.Second))

	adminKillsTotal.Add(1)

	if conn.sshConn != nil {
		err := conn.sshConn.Close()
		if err != nil {
			log.Printf("%sError closing SSH connection for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}

	delete(connections, id)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killAllConnections() {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()

	if len(connections) == 0 {
		fmt.Printf("\r%s No active connections to kill.\r\n",
			nowStamp())

		return
	}

	fmt.Printf("\r%s %sKilling all %d active connections...\r\n",
		nowStamp(), skullPrefix(), len(connections))

	idsToKill := make([]string, 0, len(connections))

	for id := range connections {
		idsToKill = append(idsToKill, id)
	}

	for _, id := range idsToKill {
		conn := connections[id]

		if conn == nil {
			continue
		}

		if isConsoleLogQuiet {
			_, err := fmt.Fprintf(os.Stdout,
				"%s %sKilling connection %s...\r\n",
				nowStamp(), skullPrefix(), id)
			if err != nil {
				log.Printf("%sError writing to Stdout: %v",
					warnPrefix(), err)
			}
		}

		if conn.channel != nil {
			_, err := conn.channel.Write(
				[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"))
			if err != nil {
				log.Printf("%sError writing to channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}
		}

		connUptime := time.Since(conn.startTime)
		log.Printf("%sTERMKILL [%s] %s@%s (link time %s)",
			yellowDotPrefix(), conn.ID, conn.userName,
			conn.hostName, connUptime.Round(time.Second))

		adminKillsTotal.Add(1)

		err := conn.sshConn.Close()
		if err != nil {
			log.Printf("%sError closing SSH connection for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		delete(connections, id)
	}

	fmt.Printf("\r%s %sAll active connections killed.\r\n",
		nowStamp(), alertPrefix())
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendNaws(conn *Connection, width, height uint32) {
	if width == 0 ||
		width > 65535 {
		width = 1
	}

	if height == 0 ||
		height > 65535 {
		height = 1
	}

	packet := []byte{
		TelcmdIAC, TelcmdSB, TeloptNAWS,
		byte(width >> 8), byte(width & 0xff),
		byte(height >> 8), byte(height & 0xff),
		TelcmdIAC, TelcmdSE,
	}

	_, err := conn.telnetConn.Write(packet)
	if err != nil {
		log.Printf("%sError sending NAWS to TELNET target for %s: %v",
			warnPrefix(), conn.ID, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func loadOrCreateHostKey(keyPath, keyType string) (ssh.Signer, error) { //nolint:ireturn
	keyData, err := os.ReadFile(keyPath) //nolint:gosec
	if err == nil {
		return ssh.ParsePrivateKey(keyData)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read key: %w",
			err)
	}

	var privateKey any
	var pemBlock *pem.Block

	switch keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}

		privateKey = key
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type %T",
				key)
		}

		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		}

	case "ed25519":
		_, rawPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		privateKey = rawPriv
		edKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type %T",
				privateKey)
		}

		derBytes, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			return nil, err
		}

		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		}

	case "ecdsa":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		privateKey = key
		ecKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type %T",
				key)
		}

		derBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, err
		}

		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		}

	default:
		return nil, fmt.Errorf("unsupported key type %s",
			keyType)
	}

	keyPath, err = filepath.Abs(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for key: %w",
			err)
	}

	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), os.FileMode(certPerm)) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("failed to write new key: %w",
			err)
	}

	log.Printf("%sNew %s host key generated at %s",
		keyPrefix(), strings.ToUpper(keyType), keyPath)

	return ssh.NewSignerFromKey(privateKey)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConn(rawConn net.Conn, edSigner, rsaSigner, ecdsaSigner ssh.Signer) {
	sid := newSessionID(connections, &connectionsMutex)
	keyLog := []string{}

	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	remoteAddr := rawConn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	if !suppressLogs {
		log.Printf("%sINITIATE [%s] %s",
			greenDotPrefix(), sid, host)
	}

	sshConnectionsTotal.Add(1)

	config := &ssh.ServerConfig{
		//revive:disable:unused-parameter
		PasswordCallback: func(
			conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error,
		) {
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "password"},
			}, nil
		},
		PublicKeyCallback: func(
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error,
		) {
			line := fmt.Sprintf("VALIDATE [%s] %s@%s %q:%s",
				sid, c.User(), c.RemoteAddr(),
				pubKey.Type(), ssh.FingerprintSHA256(pubKey),
			)

			if !suppressLogs {
				log.Printf("%s%s",
					blueDotPrefix(), line)
			}

			keyLog = append(keyLog, line)

			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "publickey"},
			}, fmt.Errorf("next key")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error,
		) {
			return &ssh.Permissions{
				Extensions: map[string]string{"auth-method": "keyboard-interactive"},
			}, nil
		},
		//revive:enable:unused-parameter
	}
	config.AddHostKey(edSigner)
	config.AddHostKey(rsaSigner)
	config.AddHostKey(ecdsaSigner)

	tcp, ok := rawConn.(*net.TCPConn)
	if ok {
		_ = tcp.SetNoDelay(true)
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		sshHandshakeFailedTotal.Add(1)

		log.Printf("%sTEARDOWN [%s] HANDSHAKE FAILED: %v",
			yellowDotPrefix(), sid, err)

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

	defaultHost, defaultPort, err := parseHostPort(telnetHostPort)
	if err != nil {
		log.Printf("%sError parsing default TELNET target: %v",
			warnPrefix(), err)

		return
	}
	conn.targetHost = defaultHost
	conn.targetPort = defaultPort

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

	currentLen := uint64(len(connections))
	if currentLen > peakUsersTotal.Load() {
		peakUsersTotal.Store(currentLen)
		if dbEnabled {
			if currentLen > lifetimePeakUsersTotal.Load() {
				lifetimePeakUsersTotal.Store(currentLen)
			}
		}
	}

	connectionsMutex.Unlock()

	defer func() {
		conn.cancelFunc()

		connectionsMutex.Lock()

		if conn.sshConn != nil {
			err := conn.sshConn.Close()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("%sError closing SSH connection for %s: %v",
						warnPrefix(), conn.ID, err)
				}
			}
		}

		delete(connections, sid)

		if gracefulShutdownMode.Load() && len(connections) == 0 {
			connectionsMutex.Unlock()

			shutdownOnce.Do(func() { close(shutdownSignal) })
		} else {
			connectionsMutex.Unlock()
		}

		const unknownHost = "<UNKNOWN>"

		if !suppressLogs {
			host, _, err := net.SplitHostPort(conn.hostName)
			if err != nil {
				log.Printf("%sTEARDOWN [%s] %s@"+unknownHost,
					yellowDotPrefix(), sid, func() string {
						if conn.userName == "" {
							return unknownHost
						}

						return conn.userName
					}())
			} else {
				log.Printf("%sTEARDOWN [%s] %s@%s",
					yellowDotPrefix(), sid, func() string {
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
		log.Printf("%s%s",
			blueDotPrefix(), handshakeLog)
	}

	keyLog = append(keyLog, handshakeLog)

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			err := newCh.Reject(
				ssh.UnknownChannelType, "only session allowed")
			if err != nil {
				log.Printf("%sError rejecting channel: %v",
					warnPrefix(), err)
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
	if isUnixSocket(hostPort) {
		return hostPort, 0, nil
	}

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", 0, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s",
			portStr)
	}

	return host, port, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func dialDest(dest string) (net.Conn, error) {
	if isUnixSocket(dest) {
		return net.Dial("unix", dest)
	}

	return net.Dial("tcp", dest)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleSession(ctx context.Context, conn *Connection, channel ssh.Channel,
	requests <-chan *ssh.Request, keyLog []string,
) {
	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	sessionStarted := make(chan bool, 1)
	go func() {
		for req := range requests {
			switch req.Type {
			case "pty-req":
				termLen := req.Payload[3]
				term := string(req.Payload[4 : 4+termLen])
				conn.termType = term

				if len(req.Payload) >= int(4+termLen+8) {
					width := binary.BigEndian.Uint32(req.Payload[4+termLen : 4+termLen+4])
					height := binary.BigEndian.Uint32(req.Payload[4+termLen+4 : 4+termLen+8])

					conn.initialWindowWidth = width
					conn.initialWindowHeight = height

					if conn.telnetConn != nil {
						nawsWill := []byte{TelcmdIAC, TelcmdWILL, TeloptNAWS}
						_, err := conn.telnetConn.Write(nawsWill)
						if err != nil {
							log.Printf("%sError sending IAC WILL NAWS to TELNET target for %s: %v",
								warnPrefix(), conn.ID, err)
						}
					}
				}

				err := req.Reply(true, nil)
				if err != nil {
					log.Printf("%sError replying to request: %v",
						warnPrefix(), err)
				}

			case "window-change":
				if len(req.Payload) == 16 {
					width := binary.BigEndian.Uint32(req.Payload[:4])
					height := binary.BigEndian.Uint32(req.Payload[4:8])

					if conn.telnetConn != nil {
						sendNaws(conn, width, height)
					}

					err := req.Reply(true, nil)
					if err != nil {
						log.Printf("%sError replying to window-change request: %v",
							warnPrefix(), err)
					}
				} else {
					err := req.Reply(false, nil)
					if err != nil {
						log.Printf("%sError replying to window-change request (failure): %v",
							warnPrefix(), err)
					}
				}

			case "shell":
				select {
				case sessionStarted <- true:

				default:
				}

				err := req.Reply(true, nil)
				if err != nil {
					log.Printf("%sError replying to request: %v",
						warnPrefix(), err)
				}

			case "exec":
				if !suppressLogs {
					log.Printf("%sREJECTED [%s] %s (Illegal request: exec)",
						redDotPrefix(), conn.ID, conn.sshConn.RemoteAddr().String())
				}

				sshExecRejectedTotal.Add(1)

				err := req.Reply(false, nil)
				if err != nil {
					log.Printf("%sError replying to request: %v",
						warnPrefix(), err)
				}

				select {
				case sessionStarted <- false:

				default:
				}

				err = conn.sshConn.Close()
				if err != nil {
					log.Printf("%sError closing SSH connection for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				return

			case "subsystem":
				if len(req.Payload) >= 4 {
					subsystemLen := binary.BigEndian.Uint32(req.Payload[0:4])

					if len(req.Payload) >= 4+int(subsystemLen) {
						subsystem := string(req.Payload[4 : 4+subsystemLen])

						if subsystem == "sftp" {
							if !suppressLogs {
								log.Printf("%sREJECTED [%s] %s (Illegal request: SFTP)",
									redDotPrefix(), conn.ID, conn.sshConn.RemoteAddr().String())
							}

							sshIllegalSubsystemTotal.Add(1)

							err := req.Reply(false, nil)
							if err != nil {
								log.Printf("%sError replying to request: %v",
									warnPrefix(), err)
							}
							select {
							case sessionStarted <- false:

							default:
							}

							err = conn.sshConn.Close()
							if err != nil {
								log.Printf("%sError closing SSH connection for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							return
						}
					}
				}

				err := req.Reply(false, nil)
				if err != nil {
					log.Printf("%sError replying to request: %v",
						warnPrefix(), err)
				}

			default:
				err := req.Reply(false, nil)
				if err != nil {
					log.Printf("%sError replying to request: %v",
						warnPrefix(), err)
				}
			}
		}
	}()

	select {
	case proceed := <-sessionStarted:
		if !proceed {
			return
		}

	case <-time.After(2 * time.Second):
		sshRequestTimeoutTotal.Add(1)

		if !suppressLogs {
			log.Printf("%sTEARDOWN [%s] %s (Timeout waiting for session request)",
				yellowDotPrefix(), conn.ID, conn.sshConn.RemoteAddr().String())
		}

		err := conn.sshConn.Close()
		if err != nil {
			log.Printf("%sError closing SSH connection for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		return
	}

	remoteHost, _, err := net.SplitHostPort(conn.sshConn.RemoteAddr().String())
	if err != nil {
		remoteHost = conn.sshConn.RemoteAddr().String()
	}

	clientIP := net.ParseIP(remoteHost)
	if clientIP == nil {
		if !suppressLogs {
			log.Printf("%sTEARDOWN [%s] Invalid address: %s",
				yellowDotPrefix(), conn.ID, remoteHost)
		}

		err := channel.Close()
		if err != nil {
			log.Printf("%sError closing channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		err = conn.sshConn.Close()
		if err != nil {
			log.Printf("%sError closing SSH connection for %s: %v",
				warnPrefix(), conn.ID, err)
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
				log.Printf("%sEXEMPTED [%s] %s (matched %s)",
					greenHeartPrefix(), conn.ID,
					conn.sshConn.RemoteAddr().String(), exemptedByRule)
			}

			exemptedTotal.Add(1)
		} else {
			if !suppressLogs {
				log.Printf("%sREJECTED [%s] %s (matched %s)",
					redDotPrefix(), conn.ID,
					conn.sshConn.RemoteAddr().String(), rejectedByRule)
			}

			rejectedTotal.Add(1)

			raw, err := getFileContent(blockFile, conn.userName)
			if err == nil {
				blockMessageContent := strings.ReplaceAll(
					strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
				_, err := channel.Write(
					[]byte(blockMessageContent + "\r\n"))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}
			} else {
				_, err := channel.Write(
					[]byte("Connection blocked.\r\n"))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}
			}

			err = channel.Close()
			if err != nil {
				log.Printf("%sError closing channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			err = conn.sshConn.Close()
			if err != nil {
				log.Printf("%sError closing SSH connection for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			return
		}
	}

	sendBanner(conn.sshConn, channel, conn)

	if sshDelay > 0 {
		spinner := []rune{'|', '/', '-', '\\'}
		spinnerIndex := 0
		startTime := time.Now()

		for time.Since(startTime).Seconds() < sshDelay {
			char := string(spinner[spinnerIndex])

			_, err := channel.Write(fmt.Appendf(nil, "\r%s",
				char))
			if err != nil {
				if errors.Is(err, io.EOF) {
					delayAbandonedTotal.Add(1)

					log.Printf("%sWAITKILL [%s] %s@%s: %v",
						yellowDotPrefix(), conn.ID, conn.userName, conn.hostName, err)

					err := conn.sshConn.Close()
					if err != nil {
						if !strings.Contains(err.Error(), "use of closed network connection") {
							log.Printf("%sError closing SSH connection for %s: %v",
								warnPrefix(), conn.ID, err)
						}
					}

					return
				}

				log.Printf("%sError writing delay spinner to channel for %s: %v",
					warnPrefix(), conn.ID, err)

				break
			}

			spinnerIndex = (spinnerIndex + 1) % len(spinner)
			time.Sleep(100 * time.Millisecond)
		}

		_, err := channel.Write([]byte("\r \r"))
		if err != nil {
			if errors.Is(err, io.EOF) {
				delayAbandonedTotal.Add(1)

				log.Printf("%sWAITKILL [%s] %s@%s: %v",
					yellowDotPrefix(), conn.ID, conn.userName, conn.hostName, err)

				err := conn.sshConn.Close()
				if err != nil {
					if !strings.Contains(err.Error(), "use of closed network connection") {
						log.Printf("%sError closing SSH connection for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}

				return
			}

			log.Printf("%sError clearing delay spinner from channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}

	sshSessionsTotal.Add(1)

	if conn.monitoring {
		monitorSessionsTotal.Add(1)

		if !suppressLogs {
			log.Printf("%sUMONITOR [%s] %s -> %s",
				greenDotPrefix(), conn.ID, conn.userName, conn.monitoredConnection.ID)
		}

		go func() {
			buf := make([]byte, 1)

			for {
				_, err := channel.Read(buf)
				if err != nil {
					return
				}

				if buf[0] == 0x1d { // Ctrl-]
					err := channel.Close()
					if err != nil {
						log.Printf("%sError closing channel for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					return
				}
			}
		}()

		<-conn.monitoredConnection.cancelCtx.Done()
		dur := time.Since(conn.startTime)

		_, err := channel.Write(fmt.Appendf(nil,
			"\r\nMONITORING SESSION CLOSED (monitored for %s)\r\n\r\n",
			dur.Round(time.Second)))
		if err != nil {
			log.Printf("%sError writing to channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		err = channel.Close()
		if err != nil {
			log.Printf("%sError closing channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		return
	}

	if gracefulShutdownMode.Load() || denyNewConnectionsMode.Load() {
		denyMsg, err := getFileContent(denyFile, conn.userName)
		if err == nil {
			txt := strings.ReplaceAll(
				strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n")

			_, err := channel.Write([]byte("\r\n"))
			if err != nil {
				log.Printf("%sError writing to channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			_, err = channel.Write([]byte(txt))
			if err != nil {
				log.Printf("%sError writing to channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			_, err = channel.Write([]byte("\r\n"))
			if err != nil {
				log.Printf("%sError writing to channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}
		}

		err = channel.Close()
		if err != nil {
			log.Printf("%sError closing channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		return
	}

	raw, err := getFileContent(issueFile, conn.userName)
	if err == nil {
		txt := strings.ReplaceAll(
			strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")

		_, err := channel.Write([]byte(txt + "\r\n"))
		if err != nil {
			log.Printf("%sError writing to channel for %s: %v",
				warnPrefix(), conn.ID, err)
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
			_, err := fmt.Fprintf(channel,
				"%v\r\n", sanitizeNonASCII(err.Error()))
			if err != nil {
				log.Printf("%sError writing to channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			err = channel.Close()
			if err != nil {
				log.Printf("%sError closing channel for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			return
		}
		conn.logFile = logfile
		conn.basePath = basePath
		logwriter = logfile

		_, err := logwriter.Write(
			[]byte(nowStamp() + " Session start\r\n"))
		if err != nil {
			log.Printf("%sError writing to log for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		for _, line := range keyLog {
			_, err := logwriter.Write([]byte(nowStamp() + " " + line + "\r\n"))
			if err != nil {
				log.Printf("%sError writing to log for %s: %v",
					warnPrefix(), conn.ID, err)
			}
		}

		defer func() {
			dur := time.Since(start)
			_, err := logwriter.Write(fmt.Appendf(nil,
				nowStamp()+" Session end (link time %s)\r\n",
				dur.Round(time.Second)))
			if err != nil {
				log.Printf("%sError writing to log: %v",
					warnPrefix(), err)
			}
			closeAndCompressLog(logfile, basePath+".log")
		}()
	} else {
		logwriter = io.Discard
	}

	var targetDest string
	var isAltHost bool

	altHostPort, ok := altHosts[conn.userName]
	if ok {
		targetDest = altHostPort
		isAltHost = true
	} else {
		targetDest = telnetHostPort
		isAltHost = false
	}

	targetHost, targetPort, err := parseHostPort(targetDest)
	if err != nil {
		var errMsg string

		sanitizedErrStr := sanitizeNonASCII(err.Error())
		if isAltHost {
			errMsg = fmt.Sprintf("Error parsing alt-host for user %s: %v",
				conn.userName, sanitizedErrStr)
		} else {
			errMsg = fmt.Sprintf("Error parsing default telnet-host: %v",
				sanitizedErrStr)
		}

		_, writeErr := fmt.Fprintf(channel,
			"%s\r\n\r\n", errMsg)
		if writeErr != nil {
			log.Printf("%sError writing to channel for %s: %v",
				warnPrefix(), conn.ID, writeErr)
		}

		log.Printf("%s%s", warnPrefix(), errMsg)

		closeErr := channel.Close()
		if closeErr != nil {
			log.Printf("%sError closing channel for %s: %v",
				warnPrefix(), conn.ID, closeErr)
		}

		return
	}

	if isAltHost {
		altHostRoutesTotal.Add(1)

		log.Printf("%sALTROUTE [%s] %s -> %s",
			greenDotPrefix(), conn.ID, conn.userName, targetDest)
	}

	conn.targetHost = targetHost
	conn.targetPort = targetPort

	if !noLog {
		_, err := logwriter.Write(fmt.Appendf(nil,
			nowStamp()+" Target: %s\r\n", targetDest))
		if err != nil {
			log.Printf("%sError writing to log for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		_, err = logwriter.Write(fmt.Appendf(nil,
			nowStamp()+" Connection sharing username: '%s'\r\n",
			conn.shareableUsername))
		if err != nil {
			log.Printf("%sError writing to log for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}

	telnetConnectionsTotal.Add(1)

	remote, err := dialDest(targetDest)
	if err != nil {
		telnetFailuresTotal.Add(1)

		log.Printf("%sError connecting %s -> %s: %v",
			warnPrefix(), conn.ID, targetDest, err)

		_, err2 := fmt.Fprintf(channel,
			"%v\r\n\r\n", sanitizeNonASCII(err.Error()))
		if err2 != nil {
			log.Printf("%sError writing to channel for %s: %v",
				warnPrefix(), conn.ID, err2)
		}

		err = channel.Close()
		if err != nil {
			log.Printf("%sError closing channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}

		return
	}

	tcp2, ok := remote.(*net.TCPConn)
	if ok {
		_ = tcp2.SetNoDelay(true)
	}

	conn.telnetConn = remote

	defer func() {
		err := remote.Close()
		if err != nil {
			log.Printf("%sError closing remote connection for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}()

	negotiateTelnet(remote, channel, logwriter, conn)

	if conn.nawsActive && conn.initialWindowWidth > 0 && conn.initialWindowHeight > 0 {
		sendNaws(conn, conn.initialWindowWidth, conn.initialWindowHeight)
	}

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
					_, err := remote.Write(escSequence)
					if err != nil {
						log.Printf("%sError writing to remote for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					_, err = logwriter.Write(escSequence)
					if err != nil {
						log.Printf("%sError writing to log for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}

				return

			case <-escTimer:
				m, err := remote.Write(escSequence)
				if err != nil {
					log.Printf("%sError writing to remote for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec
				_, err = logwriter.Write(escSequence)
				if err != nil {
					log.Printf("%sError writing to log for %s: %v",
						warnPrefix(), conn.ID, err)
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
						replacement, ok := emacsKeymap[string(escSequence)]
						if ok {
							m, err := remote.Write([]byte(replacement))
							if err != nil {
								log.Printf("%sError writing to remote for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

							trafficOutTotal.Add(uint64(m)) //nolint:gosec

							_, err = logwriter.Write([]byte(replacement))
							if err != nil {
								log.Printf("%sError writing to log for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						} else if _,
							isPrefix := emacsKeymapPrefixes[string(escSequence)]; isPrefix {
							escTimer = time.After(50 * time.Millisecond)
						} else {
							m, err := remote.Write(escSequence)
							if err != nil {
								log.Printf("%sError writing to remote for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

							trafficOutTotal.Add(uint64(m)) //nolint:gosec

							_, err = logwriter.Write(escSequence)
							if err != nil {
								log.Printf("%sError writing to log for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						}
					} else {
						m, err := remote.Write(escSequence)
						if err != nil {
							log.Printf("%sError writing to remote for %s: %v",
								warnPrefix(), conn.ID, err)
						}

						atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

						trafficOutTotal.Add(uint64(m)) //nolint:gosec

						_, err = logwriter.Write(escSequence)
						if err != nil {
							log.Printf("%sError writing to log for %s: %v",
								warnPrefix(), conn.ID, err)
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
						log.Printf("%sError writing to remote for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					atomic.AddUint64(&telnetOut, uint64(m)) //nolint:gosec

					trafficOutTotal.Add(uint64(m)) //nolint:gosec

					_, err = logwriter.Write([]byte{b})
					if err != nil {
						log.Printf("%sError writing to log for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}

			case err := <-errorChan:
				if len(escSequence) > 0 {
					_, err := remote.Write(escSequence)
					if err != nil {
						log.Printf("%sError writing to remote for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					_, err = logwriter.Write(escSequence)
					if err != nil {
						log.Printf("%sError writing to log for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}
				if !errors.Is(err, io.EOF) {
					log.Printf("%sSSH channel read error: %v",
						warnPrefix(), err)
				}

				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)

		for {
			err := remote.SetReadDeadline(
				time.Now().Add(100 * time.Millisecond))
			if err != nil {
				log.Printf("%sError setting read deadline for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			n, err := remote.Read(buf)
			trafficInTotal.Add(uint64(n)) //nolint:gosec
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
				log.Printf("%sDETACHED [%s] %s@%s (link time %s)",
					yellowDotPrefix(), conn.ID, conn.userName,
					conn.hostName, dur.Round(time.Second))

				_, err := channel.Write(fmt.Appendf(nil,
					"\r\nCONNECTION CLOSED (link time %s)\r\n\r\n",
					dur.Round(time.Second)))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				inRateSSH := uint64(float64(atomic.LoadUint64(&sshIn)) / dur.Seconds())
				outRateSSH := uint64(float64(atomic.LoadUint64(&sshOut)) / dur.Seconds())
				inRateNVT := uint64(float64(atomic.LoadUint64(&telnetIn)) / dur.Seconds())
				outRateNVT := uint64(float64(atomic.LoadUint64(&telnetOut)) / dur.Seconds())

				_, err = channel.Write(fmt.Appendf(nil,
					">> SSH - in: %s, out: %s, in-rate: %s/s, out-rate: %s/s\r\n",
					formatBytes(atomic.LoadUint64(&sshIn)),
					formatBytes(atomic.LoadUint64(&sshOut)),
					formatBytes(inRateSSH),
					formatBytes(outRateSSH)))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				_, err = channel.Write(fmt.Appendf(nil,
					">> NVT - in: %s, out: %s, in-rate: %s/s, out-rate: %s/s\r\n",
					formatBytes(atomic.LoadUint64(&telnetIn)),
					formatBytes(atomic.LoadUint64(&telnetOut)),
					formatBytes(inRateNVT),
					formatBytes(outRateNVT)))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				_, err = channel.Write([]byte("\r\n"))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				err = channel.Close()
				if err != nil {
					log.Printf("%sError closing channel for %s: %v",
						warnPrefix(), conn.ID, err)
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

				_, err := channel.Write(fwd)
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				connectionsMutex.Lock()

				for _, c := range connections {
					if c.monitoring && c.monitoredConnection.ID == conn.ID {
						_, err := c.channel.Write(fwd)
						if err != nil {
							log.Printf("%sError writing to channel for %s: %v",
								warnPrefix(), c.ID, err)
						}
					}
				}

				connectionsMutex.Unlock()

				_, err = logwriter.Write(buf[:n])
				if err != nil {
					log.Printf("%sError writing to log for %s: %v",
						warnPrefix(), conn.ID, err)
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
		origin = fmt.Sprintf("%s [%s]",
			strings.TrimSuffix(names[0], "."), host)
	} else {
		origin = host
	}

	now := nowStamp()

	_, err := fmt.Fprintf(ch,
		"Session with %s active at %s.\r\n", origin, now)
	if err != nil {
		log.Printf("%sError writing session active message to channel: %v",
			warnPrefix(), err)
	}

	if conn.monitoring {
		_, err := fmt.Fprint(ch,
			"This is a READ-ONLY shared monitoring session.\r\n")
		if err != nil {
			log.Printf("%sError writing monitoring session message to channel: %v",
				warnPrefix(), err)
		}

		_, err = fmt.Fprint(ch,
			"Send Control-] to disconnect.\r\n")
		if err != nil {
			log.Printf("%sError writing disconnect message to channel: %v",
				warnPrefix(), err)
		}
	} else if conn.invalidShare {
		_, err := fmt.Fprintf(ch,
			"The username '%s' was NOT active for session sharing!\r\n",
			conn.userName)
		if err != nil {
			log.Printf("%sError writing invalid share message to channel: %v",
				warnPrefix(), err)
		}
	}

	_, err = fmt.Fprint(ch,
		"\r\n")
	if err != nil {
		log.Printf("%sError writing newline to channel: %v",
			warnPrefix(), err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func negotiateTelnet(remote net.Conn, ch ssh.Channel, logw io.Writer, conn *Connection) {
	type telnetState struct {
		weWill   bool
		theyWill bool
		// weDo  bool
		// theyD bool
	}

	telnetStates := make(map[byte]*telnetState)

	supportedOptions := map[byte]bool{
		TeloptBinary:          true,
		TeloptEcho:            true,
		TeloptNAWS:            true,
		TeloptSuppressGoAhead: true,
		TeloptTTYPE:           true,
	}

	err := remote.SetReadDeadline(time.Now().Add(time.Second / 3))
	if err != nil {
		log.Printf("%sError setting read deadline: %v",
			warnPrefix(), err)
	}

	defer func() {
		err := remote.SetReadDeadline(time.Time{})
		if err != nil {
			log.Printf("%sError clearing TELNET negotiation read deadline: %v",
				warnPrefix(), err)
		}
	}()

	buf := make([]byte, 512)

	for {
		n, err := remote.Read(buf)
		trafficInTotal.Add(uint64(n)) //nolint:gosec
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}

			return
		}

		i := 0
		for i < n {
			if buf[i] == TelcmdIAC {
				if i+2 < n { //nolint:gocritic
					cmd, opt := buf[i+1], buf[i+2]
					writeNegotiation(ch, logw,
						"[RCVD "+cmdName(cmd)+" "+optName(opt)+"]", conn.userName)

					state, ok := telnetStates[opt]
					if !ok {
						state = &telnetState{}
						telnetStates[opt] = state
					}

					switch cmd {
					case TelcmdWILL:
						if supportedOptions[opt] {
							if !state.theyWill {
								state.theyWill = true
								sendIAC(remote, TelcmdDO, opt)
								writeNegotiation(ch, logw,
									"[SENT "+cmdName(TelcmdDO)+" "+optName(opt)+"]",
									conn.userName)
							}
						} else {
							sendIAC(remote, TelcmdDONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdDONT)+" "+optName(opt)+"]",
								conn.userName)
						}

					case TelcmdWONT:
						if state.theyWill {
							state.theyWill = false
							sendIAC(remote, TelcmdDONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdDONT)+" "+optName(opt)+"]",
								conn.userName)
						}

					case TelcmdDO:
						if opt == TeloptNAWS { //nolint:gocritic
							if !conn.nawsActive {
								conn.nawsActive = true
							}

							sendIAC(remote, TelcmdWILL, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWILL)+" "+optName(opt)+"]",
								conn.userName)
						} else if supportedOptions[opt] {
							if !state.weWill {
								state.weWill = true
								sendIAC(remote, TelcmdWILL, opt)
								writeNegotiation(ch, logw,
									"[SENT "+cmdName(TelcmdWILL)+" "+optName(opt)+"]",
									conn.userName)
							}
						} else {
							sendIAC(remote, TelcmdWONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWONT)+" "+optName(opt)+"]",
								conn.userName)
						}

					case TelcmdDONT:
						if state.weWill {
							state.weWill = false
							sendIAC(remote, TelcmdWONT, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWONT)+" "+optName(opt)+"]",
								conn.userName)
						}

					case TelcmdSB:
						seIndex := -1

						for j := i + 3; j < n-1; j++ {
							if buf[j] == TelcmdIAC && buf[j+1] == TelcmdSE {
								seIndex = j

								break
							}
						}

						if seIndex != -1 {
							if i+2 >= len(buf) || i+3 > seIndex { // Malformed packet?
								continue // Skip this sub-negotiation.
							}

							subOpt := buf[i+2]
							subData := buf[i+3 : seIndex]

							writeNegotiation(ch, logw,
								"[RCVD SB "+optName(subOpt)+" ... IAC SE]", conn.userName)

							if !supportedOptions[subOpt] {
								i = seIndex + 2

								continue
							}

							if subOpt ==
								TeloptTTYPE && len(subData) > 0 && subData[0] == TelnetSend {
								if conn.termType != "" {
									data := []byte{TelcmdIAC, TelcmdSB, TeloptTTYPE, TelnetIs}
									data = append(data, []byte(conn.termType)...)
									data = append(data, TelcmdIAC, TelcmdSE)
									_, err := remote.Write(data)
									if err != nil {
										log.Printf("%sError writing TELNET TTYPE response: %v",
											warnPrefix(), err)
									}
									writeNegotiation(ch, logw,
										"[SENT SB "+optName(TeloptTTYPE)+" IS "+
											conn.termType+" IAC SE]", conn.userName)
								} else {
									sendIAC(remote, TelcmdWONT, TeloptTTYPE)
									writeNegotiation(ch, logw,
										"[SENT WONT "+optName(TeloptTTYPE)+"]", conn.userName)
								}
							}

							i = seIndex + 2

							continue
						}

					default:
					}
					i += 3
				} else if i+1 < n && buf[i+1] == TelcmdSB {
					writeNegotiation(ch, logw, "[RCVD IAC SB (incomplete)]", conn.userName)
					i += 2
				} else {
					writeNegotiation(ch, logw, "[RCVD IAC (incomplete)]", conn.userName)
					i++
				}
			} else {
				_, _ = ch.Write(buf[i : i+1])
				_, _ = logw.Write(buf[i : i+1])
				i++
			}
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func writeNegotiation(ch, logw io.Writer, line, username string) {
	msg := line

	if debugNegotiation {
		msg = fmt.Sprintf("%s %s",
			username, line)
	}

	msg += "\r\n"

	_, err := logw.Write([]byte(msg))
	if err != nil {
		log.Printf("%sError writing TELNET negotiation message to log: %v",
			warnPrefix(), err)
	}

	if debugNegotiation {
		_, err := ch.Write([]byte(msg))
		if err != nil {
			log.Printf("%sError writing TELNET negotiation message to channel: %v",
				warnPrefix(), err)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendIAC(w io.Writer, cmd byte, opts ...byte) {
	data := []byte{TelcmdIAC, cmd}
	data = append(data, opts...)

	_, err := w.Write(data)
	if err != nil {
		log.Printf("%sError writing TELNET IAC command to writer: %v",
			warnPrefix(), err)
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

	return fmt.Sprintf("CMD_%d",
		b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func optName(b byte) string {
	switch b {
	case TeloptBinary: // 0
		return "BINARY"

	case TeloptEcho: // 1
		return "ECHO"

	case TeloptReconnect: // 2
		return "RECONNECTION"

	case TeloptSuppressGoAhead: // 3
		return "SUPPRESS GO AHEAD"

	case TeloptApprox: // 4
		return "APPROX MESSAGE SIZE NEGOTIATION"

	case TeloptStatus: // 5
		return "STATUS"

	case TeloptTimingMark: // 6
		return "TIMING MARK"

	case TeloptRemoteControl: // 7
		return "REMOTE CONTROL"

	case TeloptOutputLineWidth: // 8
		return "OUTPUT LINE WIDTH"

	case TeloptOutputPageSize: // 9
		return "OUTPUT PAGE SIZE"

	case TeloptOutputCRD: // 10
		return "OUTPUT CARRIAGE RETURN DISPOSITION"

	case TeloptOutputHTS: // 11
		return "OUTPUT HORIZONTAL TAB STOPS"

	case TeloptOutputHTD: // 12
		return "OUTPUT HORIZONTAL TAB DISPOSITION"

	case TeloptOutputFFD: // 13
		return "OUTPUT FORMFEED DISPOSITION"

	case TeloptOutputVTS: // 14
		return "OUTPUT VERTICAL TABSTOPS"

	case TeloptOutputVTD: // 15
		return "OUTPUT VERTICAL TAB DISPOSITION"

	case TeloptOutputLFD: // 16
		return "OUTPUT LINEFEED DISPOSITION"

	case TeloptExtendedASCII: // 17
		return "EXTENDED ASCII"

	case TeloptLogout: // 18
		return "LOGOUT"

	case TeloptByteMacro: // 19
		return "Byte Macro"

	case TeloptDataEntryTerminal: // 20
		return "DATA ENTRY TERMINAL"

	case TeloptSupdup: // 21
		return "SUPDUP"

	case TeloptSupdupOutput: // 22
		return "SUPDUP OUTPUT"

	case TeloptSendLocation: // 23
		return "SEND LOCATION"

	case TeloptTTYPE: // 24
		return "TERMINAL TYPE"

	case TeloptEOR: // 25
		return "END OF RECORD"

	case TeloptTacacsUserID: // 26
		return "TACACS USER IDENTIFICATION"

	case TeloptOutputMarking: // 27
		return "OUTPUT MARKING"

	case TeloptTermLocationNum: // 28
		return "TERMINAL LOCATION NUMBER"

	case TeloptTN3270Regime: // 29
		return "TELNET 3270 REGIME"

	case TeloptX3PAD: // 30
		return "X.3 PAD"

	case TeloptNAWS: // 31
		return "NEGOTIATE ABOUT WINDOW SIZE"

	case TeloptTS: // 32
		return "TERMINAL SPEED"

	case TeloptRM: // 33
		return "REMOTE FLOW CONTROL"

	case TeloptLineMode: // 34
		return "LINE MODE"

	case TeloptXDisplay: // 35
		return "X DISPLAY"

	case TeloptOldEnviron: // 36
		return "OLD ENVIRON"

	case TeloptAuth: // 37
		return "AUTHENTICATION"

	case TeloptEncrypt: // 38
		return "ENCRYPTION"

	case TeloptNewEnviron: // 39
		return "NEW ENVIRON"

	case TeloptTN3270E: // 40
		return "TN3270E"

	case TeloptXAUTH: // 41
		return "XAUTH"

	case TeloptCHARSET: // 42
		return "CHARSET"

	case TeloptRSP: // 43
		return "REMOTE SERIAL PORT"

	case TeloptCompPort: // 44
		return "COM PORT CONTROL"

	case TeloptSLE: // 45
		return "SUPPRESS LOCAL ECHO"

	case TeloptStartTLS: // 46
		return "START TLS"

	case TeloptKermit: // 47
		return "KERMIT"

	case TeloptSendURL: // 48
		return "SEND-URL"

	case TeloptForwardX: // 49
		return "FORWARD_X"

	case TeloptMSSP: // 70
		return "MSSP"

	case TeloptMCCP: // 85
		return "MCCP"

	case TeloptMCCP2: // 86
		return "MCCP2"

	case TeloptMCCP3: // 87
		return "MCCP3"

	case TeloptMSP: // 90
		return "MSP"

	case TeloptMXP: // 91
		return "MXP"

	case TeloptZMP: // 93
		return "ZMP"

	case TeloptPragmaLogon: // 138
		return "PRAGMA LOGON"

	case TeloptSspiLogon: // 139
		return "SSPI LOGON"

	case TeloptPragmaHeartbeat: // 140
		return "PRAGMA HEARTBEAT"

	case TeloptATCP: // 200
		return "ATCP"

	case TeloptGMCP: // 201
		return "GMCP"

	case TeloptEnd: // 255
		return "END"
	}

	return fmt.Sprintf("OPT_%d",
		b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func formatBytes(b uint64) string {
	const (
		KiB = 1024       // Kibibytes
		MiB = 1024 * KiB // Mebibytes
		GiB = 1024 * MiB // Gibibytes
	)

	switch {
	case b >= GiB:
		return fmt.Sprintf("%.2f GiB",
			float64(b)/GiB)

	case b >= MiB:
		return fmt.Sprintf("%.2f MiB",
			float64(b)/MiB)

	case b >= KiB:
		return fmt.Sprintf("%.2f KiB",
			float64(b)/KiB)

	default:
		return fmt.Sprintf("%d B",
			b)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func showMenu(ch ssh.Channel) {
	menu := "\r                         \r\n" +
		"\r +=====+=================+ \r\n" +
		"\r | Key | TELNET Action   | \r\n" +
		"\r +=====+=================+ \r\n" +
		"\r |  0  | Send NUL        | \r\n" +
		"\r |  A  | Send AYT        | \r\n" +
		"\r |  B  | Send Break      | \r\n" +
		"\r |  I  | Send Interrupt  | \r\n" +
		"\r |  N  | Send NOP        | \r\n" +
		"\r |  ]  | Send Control-]  | \r\n" +
		"\r +=====+=================+ \r\n" +
		"\r |  K  | Toggle Keymap   | \r\n" +
		"\r |  S  | Show Status     | \r\n" +
		"\r |  X  | Disconnect      | \r\n" +
		"\r +=====+=================+ \r\n"

	_, err := ch.Write([]byte(menu))
	if err != nil {
		log.Printf("%sError writing menu to channel: %v",
			warnPrefix(), err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleMenuSelection(sel byte, conn *Connection, ch ssh.Channel, remote net.Conn,
	logw io.Writer, sshIn, sshOut, telnetIn, telnetOut *uint64, start time.Time,
) {
	switch sel {
	case '0':
		_, err := remote.Write([]byte{0})
		if err != nil {
			log.Printf("%sError writing NUL to remote: %v",
				warnPrefix(), err)
		}

		_, err = logw.Write([]byte{0})
		if err != nil {
			log.Printf("%sError writing NUL to log: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n>> Sent NUL\r\n"))
		if err != nil {
			log.Printf("%sError writing 'Sent NUL' message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}

	case 'a', 'A':
		sendIAC(remote, TelcmdAYT)

		_, err := logw.Write([]byte{TelcmdIAC, TelcmdAYT})
		if err != nil {
			log.Printf("%sError writing AYT to log: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n>> Sent AYT\r\n"))
		if err != nil {
			log.Printf("%sError writing 'Sent AYT' message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing 'BACK TO HOST' message after AYT to channel: %v",
				warnPrefix(), err)
		}

	case 'b', 'B':
		sendIAC(remote, TelcmdBreak)

		_, err := logw.Write([]byte{TelcmdIAC, TelcmdBreak})
		if err != nil {
			log.Printf("%sError writing BREAK to log: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n>> Sent BREAK\r\n"))
		if err != nil {
			log.Printf("%sError writing 'Sent BREAK' message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}

	case 'i', 'I':
		sendIAC(remote, TelcmdIP)

		_, err := logw.Write([]byte{TelcmdIAC, TelcmdIP})
		if err != nil {
			log.Printf("%sError writing Interrupt to log: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n>> Sent Interrupt\r\n"))
		if err != nil {
			log.Printf("%sError writing 'Sent Interrupt' message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}

	case 'k', 'K':
		conn.emacsKeymapEnabled = !conn.emacsKeymapEnabled

		if conn.emacsKeymapEnabled {
			_, err := ch.Write([]byte("\r\n>> Emacs keymap ENABLED\r\n"))
			if err != nil {
				log.Printf("%sError writing 'Emacs keymap ENABLED' message to channel: %v",
					warnPrefix(), err)
			}
		} else {
			_, err := ch.Write([]byte("\r\n>> Emacs keymap DISABLED\r\n"))
			if err != nil {
				log.Printf("%sError writing 'Emacs keymap DISABLED' message to channel: %v",
					warnPrefix(), err)
			}
		}

		_, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}

	case 'n', 'N':
		sendIAC(remote, TelcmdNOP)

		_, err := logw.Write([]byte{TelcmdIAC, TelcmdNOP})
		if err != nil {
			log.Printf("%sError writing NOP to log: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n>> Sent NOP\r\n"))
		if err != nil {
			log.Printf("%sError writing 'Sent NOP' message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}
	case 's', 'S':
		dur := time.Since(start)

		_, err := ch.Write([]byte("\r\n"))
		if err != nil {
			log.Printf("%sError writing newline to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write(fmt.Appendf(nil,
			">> LNK - Username '%s' can be used to share this session.\r\n",
			conn.shareableUsername))
		if err != nil {
			log.Printf("%sError writing sharable username to channel: %v",
				warnPrefix(), err)
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

			_, err := ch.Write(fmt.Appendf(nil,
				">> MON - Shared session has been viewed %d %s; %d %s currently online.\r\n",
				conn.totalMonitors, timesStr, currentMonitors, userStr))
			if err != nil {
				log.Printf("%sError writing shared session information to channel: %v",
					warnPrefix(), err)
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

		_, err = ch.Write(fmt.Appendf(nil,
			">> SSH - in: %s, out: %s, in-rate: %s/s, out-rate: %s/s\r\n",
			formatBytes(inSSH), formatBytes(outSSH),
			formatBytes(inRateSSH), formatBytes(outRateSSH)))
		if err != nil {
			log.Printf("%sError writing SSH statistics to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write(fmt.Appendf(nil,
			">> NVT - in: %s, out: %s, in-rate: %s/s, out-rate: %s/s\r\n",
			formatBytes(inNVT), formatBytes(outNVT),
			formatBytes(inRateNVT), formatBytes(outRateNVT)))
		if err != nil {
			log.Printf("%sError writing NVT statistics to channel: %v",
				warnPrefix(), err)
		}

		keymapStatus := ""

		if conn.emacsKeymapEnabled {
			keymapStatus = " (Emacs keymap enabled)"
		}

		_, err = ch.Write([]byte(">> LNK - link time: " +
			dur.Round(time.Second).String() + keymapStatus + "\r\n"))
		if err != nil {
			log.Printf("%sError writing link time and keymap status message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing 'BACK TO HOST' message after link time to channel: %v",
				warnPrefix(), err)
		}

	case 'x', 'X':
		_, err := ch.Write([]byte("\r\n>> DISCONNECTING...\r\n"))
		if err != nil {
			log.Printf("%sError writing 'DISCONNECTING' message to channel: %v",
				warnPrefix(), err)
		}

		err = ch.Close()
		if err != nil {
			log.Printf("%sError closing channel: %v",
				warnPrefix(), err)
		}

	case ']':
		_, err := remote.Write([]byte{0x1d})
		if err != nil {
			log.Printf("%sError writing Ctrl-] to remote: %v",
				warnPrefix(), err)
		}

		_, err = logw.Write([]byte{0x1d})
		if err != nil {
			log.Printf("%sError writing Ctrl-] to log: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n>> Sent Ctrl-]\r\n"))
		if err != nil {
			log.Printf("%sError writing 'Sent Ctrl-]' message to channel: %v",
				warnPrefix(), err)
		}

		_, err = ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}

	default:
		_, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
		if err != nil {
			log.Printf("%sError writing 'BACK TO HOST' message for default case to channel: %v",
				warnPrefix(), err)
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
		fmt.Sprintf("%04d",
			now.Year()),
		fmt.Sprintf("%02d",
			now.Month()),
		fmt.Sprintf("%02d",
			now.Day()),
	)

	err := os.MkdirAll(dir, os.FileMode(logDirPerm)) //nolint:gosec
	if err != nil {
		return nil, "", err
	}

	dir = filepath.Join(dir, ipDir)

	err = os.MkdirAll(dir, os.FileMode(logDirPerm)) //nolint:gosec
	if err != nil {
		return nil, "", err
	}

	ts := now.Format("150405")
	files, _ := os.ReadDir(dir)
	maxSeq := 0
	prefix := ts + "_" + sid + "_"

	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			parts := strings.SplitN(f.Name()[len(prefix):], ".", 2)

			n, err := strconv.Atoi(parts[0])
			if err == nil && n > maxSeq {
				maxSeq = n
			}
		}
	}

	loggingWg.Add(1)

	seq := maxSeq + 1
	base := fmt.Sprintf("%s_%s_%d",
		ts, sid, seq)
	pathBase := filepath.Join(dir, base)
	f, err := os.OpenFile(pathBase+".log", //nolint:gosec
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

		_, err := rand.Read(b)
		if err != nil {
			log.Printf("%sError reading random bytes for session ID: %v",
				warnPrefix(), err)
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
	const chars = "cdhkmnprswxyzCDFGJKMNPRSTXY57"
	for {
		b := make([]byte, 20)

		_, err := rand.Read(b)
		if err != nil {
			log.Printf("%sError reading random bytes for shareable username: %v",
				warnPrefix(), err)
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
	content, err := os.ReadFile(userSpecificFile) //nolint:gosec
	if err == nil {
		return content, nil
	}

	return os.ReadFile(baseFilename) //nolint:gosec
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getConsoleLogPath(t time.Time) string {
	return filepath.Join(
		logDir,
		fmt.Sprintf("%04d",
			t.Year()),
		fmt.Sprintf("%02d",
			t.Month()),
		fmt.Sprintf("%02d",
			t.Day()),
		"console.log",
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func setupConsoleLogging() {
	if consoleLog == "" {
		return
	}

	if isConsoleLogQuiet {
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sConsole logging requested (suppressing console output)\r\n",
			nowStamp(), alertPrefix())
	} else {
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sConsole logging requested (not suppressing console output)\r\n",
			nowStamp(), alertPrefix())
	}

	rotateConsoleLogAt(time.Now())
	go startConsoleLogRolloverChecker()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func startConsoleLogRolloverChecker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			currentDate := now.Format("2006-01-02")

			if lastLogDate != currentDate {
				log.Printf("%sDate changed, rotating console log.",
					bellPrefix())
				rotateConsoleLogAt(now)
			}

		case <-shutdownSignal:
			return
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func rotateConsoleLogAt(t time.Time) {
	consoleLogMutex.Lock()

	logPath := getConsoleLogPath(t)
	logDir := filepath.Dir(logPath)

	err := os.MkdirAll(
		logDir, os.FileMode(logDirPerm)) //nolint:gosec
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sERROR: Failed to create console log directory: %v\r\n",
			nowStamp(), warnPrefix(), err)
		isConsoleLogQuiet = false
		consoleLog = ""

		if consoleLogFile != nil {
			_ = consoleLogFile.Close()
		}

		consoleLogFile = nil
		log.SetOutput(os.Stdout)
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sConsole logging disabled.\r\n",
			nowStamp(), alertPrefix())

		consoleLogMutex.Unlock()

		return
	}

	file, err := os.OpenFile( //nolint:gosec
		logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(logPerm)) //nolint:gosec
	if err != nil {
		if isConsoleLogQuiet {
			isConsoleLogQuiet = false
		}

		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sERROR: Failed to open new console log file: %v\r\n",
			nowStamp(), warnPrefix(), err)
		consoleLog = ""

		if consoleLogFile != nil {
			_ = consoleLogFile.Close()
		}

		consoleLogFile = nil
		log.SetOutput(os.Stdout)
		_, _ = fmt.Fprintf(os.Stdout,
			"%s %sConsole logging disabled.\r\n",
			nowStamp(), alertPrefix())

		consoleLogMutex.Unlock()

		return
	}

	oldLogFile := consoleLogFile
	consoleLogFile = file
	lastLogDate = t.Format("2006-01-02")

	fileWriter := &emojiStripperWriter{w: consoleLogFile}

	if isConsoleLogQuiet {
		log.SetOutput(fileWriter)
	} else {
		log.SetOutput(io.MultiWriter(os.Stdout, fileWriter))
	}

	consoleLogMutex.Unlock()

	if oldLogFile != nil {
		oldLogPath := oldLogFile.Name()
		err := oldLogFile.Close()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sError closing previous console log file: %v\r\n",
				nowStamp(), warnPrefix(), err)
		}

		if !noCompress {
			compressLogFile(oldLogPath)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func compressLogFile(logFilePath string) {
	_, err := os.Stat(logFilePath)
	if os.IsNotExist(err) {
		return
	}

	data, err := os.ReadFile(logFilePath) //nolint:gosec
	if err != nil {
		log.Printf("%sFailed to read log %q for compression: %v",
			warnPrefix(), logFilePath, err)

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

	var lzipDictSize uint32

	switch compressLevel {
	case "fast":
		lzipDictSize = 1 << 16 // 64 KiB

	case "normal":
		lzipDictSize = lzip.DefaultDictSize

	case "high":
		lzipDictSize = lzip.MaxDictSize
	}

	switch compressAlgo {
	case "gzip":
		compressedFilePath = logFilePath + ".gz"
		compressedFile, err = os.Create(compressedFilePath) //nolint:gosec
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v",
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = gzip.NewWriterLevel(compressedFile, gzipLevel)
		if err != nil {
			log.Printf("%sError creating gzip writer for %q: %v",
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after gzip writer error: %v",
					warnPrefix(), err)
			}

			return
		}

	case "xz":
		compressedFilePath = logFilePath + ".xz"
		compressedFile, err = os.Create(compressedFilePath) //nolint:gosec
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v",
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = xz.NewWriter(compressedFile)
		if err != nil {
			log.Printf("%sError creating xz writer for %q: %v",
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after xz writer error: %v",
					warnPrefix(), err)
			}

			return
		}

	case "lzip":
		compressedFilePath = logFilePath + ".lz"
		compressedFile, err = os.Create(compressedFilePath) //nolint:gosec
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v",
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = lzip.NewWriterOptions(
			compressedFile, &lzip.WriterOptions{DictSize: lzipDictSize})
		if err != nil {
			log.Printf("%sError creating lzip writer for %q: %v",
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after lzip writer error: %v",
					warnPrefix(), err)
			}

			return
		}

	case "zstd":
		compressedFilePath = logFilePath + ".zst"
		compressedFile, err = os.Create(compressedFilePath) //nolint:gosec
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v",
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = zstd.NewWriter(
			compressedFile, zstd.WithEncoderLevel(zstdLevel))
		if err != nil {
			log.Printf("%sError creating zstd writer for %q: %v",
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after zstd writer error: %v",
					warnPrefix(), err)
			}

			return
		}

	default:
		log.Printf("%sUnknown compression algorithm: %s",
			warnPrefix(), compressAlgo)

		return
	}

	defer func() {
		err := compressedFile.Close()
		if err != nil {
			if strings.Contains(err.Error(), "writer already closed") {
				log.Printf("%sError closing compressed file: %v",
					warnPrefix(), err)
			}
		}
	}()

	defer func() {
		err := writer.Close()
		if err != nil {
			if strings.Contains(err.Error(), "file already closed") {
				log.Printf("%sError closing writer: %v",
					warnPrefix(), err)
			}
		}
	}()

	_, err = writer.Write(data)
	if err != nil {
		log.Printf("%sError writing to compressed file %q: %v",
			warnPrefix(), compressedFilePath, err)

		return
	}

	err = writer.Close()
	if err != nil {
		log.Printf("%sError closing writer for %q: %v",
			warnPrefix(), compressedFilePath, err)

		return
	}

	err = compressedFile.Close()
	if err != nil {
		log.Printf("%sError closing compressed file %q: %v",
			warnPrefix(), compressedFilePath, err)

		return
	}

	err = os.Remove(logFilePath)
	if err != nil {
		log.Printf("%sError removing original log %q after compression: %v",
			warnPrefix(), logFilePath, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func parseIPListFile(filePath string) ([]*net.IPNet, error) {
	file, err := os.Open(filePath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("%w",
			err)
	}

	defer func() {
		err := file.Close()
		if err != nil {
			log.Printf("Error closing file: %v",
				err)
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

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("%s: %w",
			filePath, err)
	}

	return networks, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listGoroutines() {
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	stackTrace := string(buf[:stacklen])

	goroutinesRaw := strings.Split(stackTrace, "\n\n")

	type GoroutineInfo struct {
		ID         string
		State      string
		Entrypoint string
		Caller     string
	}

	goroutines := make([]GoroutineInfo, 0, len(goroutinesRaw))

	for _, g := range goroutinesRaw {
		if strings.TrimSpace(g) == "" {
			continue
		}

		lines := strings.Split(g, "\n")

		if len(lines) < 2 {
			continue
		}

		header := strings.Fields(lines[0])

		if len(header) < 2 {
			continue
		}

		id := header[1]
		state := strings.Trim(lines[0][len(header[0])+len(id)+2:], " :")

		entrypoint := lines[1]
		caller := ""

		if len(lines) > 2 {
			caller = strings.TrimSpace(lines[2])
		}

		goroutines = append(goroutines, GoroutineInfo{
			ID:         id,
			State:      state,
			Entrypoint: entrypoint,
			Caller:     caller,
		})
	}

	if len(goroutines) == 0 { // Not possible!
		return
	}

	type row struct{ Name, Value string }
	allRows := make([]row, 0, len(goroutines)*4)

	for _, g := range goroutines {
		allRows = append(allRows, row{"Name", "Goroutine #" + g.ID})
		allRows = append(allRows, row{"State", g.State})
		allRows = append(allRows, row{"Entrypoint", g.Entrypoint})
		allRows = append(allRows, row{"Caller", g.Caller})
	}

	maxName := 0
	maxVal := 0

	for _, r := range allRows {
		if len(r.Name) > maxName {
			maxName = len(r.Name)
		}

		if len(r.Value) > maxVal {
			maxVal = len(r.Value)
		}
	}

	border := fmt.Sprintf("+=%s=+=%s=+\n",
		strings.Repeat("=", maxName), strings.Repeat("=", maxVal),
	)

	fmt.Printf("\r\n")

	fmt.Print(border)

	for _, g := range goroutines {
		fmt.Printf("| %-*s | %-*s |\r\n",
			maxName, "Name", maxVal, "Goroutine #"+g.ID)
		fmt.Printf("| %-*s | %-*s |\r\n",
			maxName, "State", maxVal, g.State)
		fmt.Printf("| %-*s | %-*s |\r\n",
			maxName, "Entrypoint", maxVal, g.Entrypoint)
		fmt.Printf("| %-*s | %-*s |\r\n",
			maxName, "Caller", maxVal, g.Caller)

		fmt.Print(border)
	}

	fmt.Printf("\r\n")
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

func resolveExePath() string {
	var exe string
	var err error

	exe, err = os.Executable()
	if err != nil { // Fallback to /proc
		realPath, err2 := os.Readlink("/proc/self/exe")
		if err2 == nil {
			exe = realPath
			err = nil
		}
	}

	if err != nil || exe == "" { // Fallback to argv[0]
		if len(os.Args) > 0 && os.Args[0] != "" {
			exe = os.Args[0]
		} else { // Fallback to "proxy"
			exe = "proxy"
		}
	}

	realPath, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = realPath
	}

	abs, err := filepath.Abs(exe)
	if err == nil {
		exe = abs
	}

	return exe
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
