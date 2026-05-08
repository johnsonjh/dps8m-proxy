///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main.go
// Copyright (c) 2025-2026 Jeffrey H. Johnson
// Copyright (c) 2025-2026 The DPS8M Development Team
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
	_ "net/http/pprof" //nolint:gosec,nolintlint
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
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/transform"
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
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const (
	//nolint:godoclint,nolintlint
	// A shareable username is a leading "_" followed by random chars.
	shareableUsernameRandomLen = 20                             // random suffix length
	shareableUsernameLen       = 1 + shareableUsernameRandomLen // including the leading "_"
	shareableUsernameTailLen   = shareableUsernameLen - 3       // chars kept after "..." in displays
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
	certRSABits                      uint = 2048
	certECDSABits                    uint = 256
	certDir                          string
	altHosts                         = make(map[string]string)
	blacklistedNetworks              []*net.IPNet
	blacklistFile                    string
	networksMutex                    sync.RWMutex
	connections                      = make(map[string]*Connection)
	shareableConnections             = make(map[string]*Connection)
	connectionsMutex                 sync.Mutex
	consoleLogFile                   *os.File
	consoleLogMutex                  sync.Mutex
	consoleLog                       string
	lastLogDate                      string
	isConsoleLogQuiet                atomic.Bool
	debugNegotiation                 bool
	debugAddr                        string
	denyNewConnectionsMode           atomic.Bool
	gracefulShutdownMode             atomic.Bool
	idleMax                          uint64
	idleDefMax                       uint64
	iconv                            string
	keymapByDefault                  bool
	logDir                           string
	loggingWg                        sync.WaitGroup
	noBanner                         bool
	noCompress                       bool
	noFilter                         bool
	noSanitize                       bool
	enableGops                       bool
	enableMDNS                       bool
	noLog                            bool
	noMenu                           bool
	noConsole                        bool
	showVersion                      bool
	showLicense                      bool
	shutdownOnce                     sync.Once
	immediateOnce                    sync.Once
	shutdownSignal                   chan struct{}
	sshAddr                          []string
	telnetHostPort                   string
	timeMax                          uint64
	timeDefMax                       uint64
	whitelistedNetworks              []*net.IPNet
	whitelistFile                    string
	issueFile                        = "issue.txt"
	denyFile                         = "deny.txt"
	blockFile                        = "block.txt"
	naturalSortRegexp                = regexp.MustCompile(`(\d+)|(\D+)`)
	helpBoolFlagRegexp               = regexp.MustCompile(`\[=true\|false\]`)
	helpLeadingSpacesRegexp          = regexp.MustCompile(`(?m)^ {6}`)
	helpSSHAddrRegexp                = regexp.MustCompile(`--ssh-addr strings`)
	helpStringTypeRegexp             = regexp.MustCompile(` string   `)
	helpUintTypeRegexp               = regexp.MustCompile(` uint   `)
	helpOctalTypeRegexp              = regexp.MustCompile(` octal   `)
	helpFloatTypeRegexp              = regexp.MustCompile(` float   `)
	compressAlgo                     string
	compressLevel                    string
	dbLogLevel                       string
	sshDelay                         float64
	connectionsInFlight              atomic.Uint64
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

type nawsSize struct {
	width  uint32
	height uint32
}

type targetEndpoint struct {
	host string
	port int32
}

type Connection struct {
	totalMonitors       atomic.Uint64
	startTime           time.Time
	lastActivityTime    atomic.Int64
	telnetConn          net.Conn
	telnetWriteMutex    sync.Mutex
	cancelCtx           context.Context
	channel             ssh.Channel
	sshConn             *ssh.ServerConn
	monitoredConnection *Connection
	cancelFunc          context.CancelFunc
	ID                  string
	hostName            string
	termType            atomic.Pointer[string]
	target              atomic.Pointer[targetEndpoint]
	reverseHost         atomic.Pointer[string]
	nawsPending         atomic.Pointer[nawsSize]
	nawsKick            chan struct{}
	shareableUsername   string
	userName            string
	initialWindow       atomic.Pointer[nawsSize]
	iconvDecoder        *encoding.Decoder
	iconvEnabled        atomic.Bool
	wasMonitored        atomic.Bool
	nawsActive          atomic.Bool
	monitoring          atomic.Bool
	emacsKeymapEnabled  atomic.Bool
	isDefaultTarget     bool
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

func sanitizeForLog(s string) string {
	if noSanitize {
		return s
	}

	var b strings.Builder

	b.Grow(len(s))

	for _, r := range s {
		if r >= 0x20 && r < 0x7F {
			b.WriteRune(r)
		} else {
			b.WriteRune('?')
		}
	}

	return b.String()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func atomicToggleBool(b *atomic.Bool) bool {
	for {
		cur := b.Load()
		if b.CompareAndSwap(cur, !cur) {
			return !cur
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func recoverGoroutine(label string) {
	if r := recover(); r != nil {
		log.Printf("%sRecovered from panic in: %s: %v\n%s",
			alertPrefix(), label, r, debug.Stack())
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

//nolint:ireturn
func findCharmap(name string) encoding.Encoding {
	normalize := func(s string) string {
		s = strings.ToLower(s)
		s = strings.ReplaceAll(s, " ", "")
		s = strings.ReplaceAll(s, "-", "")
		s = strings.ReplaceAll(s, "_", "")
		s = strings.ReplaceAll(s, "codepage", "cp")
		s = strings.ReplaceAll(s, "windows", "win")
		s = strings.ReplaceAll(s, "macintosh", "mac")

		return s
	}

	normalizedInput := normalize(name)

	if len(normalizedInput) < 3 {
		return nil
	}

	for _, cm := range charmap.All {
		cmName := fmt.Sprintf("%v", cm)
		normalizedName := normalize(cmName)

		if normalizedInput == normalizedName ||
			(len(normalizedInput) >= 5 && strings.HasSuffix(normalizedName, normalizedInput)) {
			return cm
		}
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func naturalLess(s1, s2 string) bool {
	n1 := strings.ReplaceAll(s1, " ", "-")
	n2 := strings.ReplaceAll(s2, " ", "-")

	parts1 := naturalSortRegexp.FindAllString(n1, -1)
	parts2 := naturalSortRegexp.FindAllString(n2, -1)

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		if parts1[i] == parts2[i] {
			continue
		}

		num1, err1 := strconv.Atoi(parts1[i])
		num2, err2 := strconv.Atoi(parts2[i])

		if err1 == nil && err2 == nil {
			if num1 != num2 {
				return num1 < num2
			}
		}

		if parts1[i] != parts2[i] {
			return parts1[i] < parts2[i]
		}
	}

	if len(parts1) != len(parts2) {
		return len(parts1) < len(parts2)
	}

	return s1 < s2
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func decodeTelnetData(decoder *encoding.Decoder, fwd []byte) []byte {
	if decoder == nil {
		return fwd
	}

	var result []byte

	i := 0

	for i < len(fwd) {
		if fwd[i] == TelcmdIAC {
			if i+1 < len(fwd) {
				cmd := fwd[i+1]

				switch cmd {
				case TelcmdWILL, TelcmdWONT, TelcmdDO, TelcmdDONT:
					result = append(result, fwd[i:i+3]...)
					i += 3

				case TelcmdSB:
					foundSE := false

					j := i + 2
					for j < len(fwd)-1 {
						if fwd[j] == TelcmdIAC {
							if fwd[j+1] == TelcmdSE {
								result = append(result, fwd[i:j+2]...)
								i = j + 2
								foundSE = true

								break
							}

							j += 2

							continue
						}

						j++
					}

					if !foundSE {
						result = append(result, fwd[i:]...)
						i = len(fwd)
					}

				case TelcmdIAC: // Escaped IAC
					data := []byte{TelcmdIAC}

					decoded, _, err := transform.Bytes(decoder, data)
					if err == nil {
						result = append(result, decoded...)
					} else {
						result = append(result, data...)
					}

					i += 2

				default:
					result = append(result, fwd[i:i+2]...)
					i += 2
				}
			} else {
				result = append(result, fwd[i])
				i++
			}
		} else {
			start := i
			for i < len(fwd) && fwd[i] != TelcmdIAC {
				i++
			}

			data := fwd[start:i]

			decoded, _, err := transform.Bytes(decoder, data)
			if err == nil {
				result = append(result, decoded...)
			} else {
				result = append(result, data...)
			}
		}
	}

	return result
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUnixSocket(path string) bool {
	return strings.HasPrefix(path, "/") || strings.HasPrefix(path, ".") ||
		(runtime.GOOS == "windows" && strings.HasPrefix(path, "\\")) //nolint:goconst,nolintlint
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

type rsaBitsValue uint

///////////////////////////////////////////////////////////////////////////////////////////////////

func (rv *rsaBitsValue) String() string {
	return strconv.FormatUint(uint64(*rv), 10)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (rv *rsaBitsValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return fmt.Errorf("%sinvalid RSA bits value: %w",
			errorPrefix(), err)
	}

	if v < 1024 || v > 4096 {
		return fmt.Errorf("%sRSA key size must be between 1024 and 4096",
			errorPrefix())
	}

	*rv = rsaBitsValue(v)

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (rv *rsaBitsValue) Type() string {
	return "uint"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type ecdsaBitsValue uint

///////////////////////////////////////////////////////////////////////////////////////////////////

func (ev *ecdsaBitsValue) String() string {
	return strconv.FormatUint(uint64(*ev), 10)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (ev *ecdsaBitsValue) Set(s string) error {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return fmt.Errorf("%sinvalid ECDSA bits value: %w",
			errorPrefix(), err)
	}

	if (v == 256) || (v == 384) || (v == 521) {
		*ev = ecdsaBitsValue(v)
	} else {
		return fmt.Errorf("%sECDSA key size must be 256, 384, or 521",
			errorPrefix())
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (ev *ecdsaBitsValue) Type() string {
	return "uint"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() { //nolint:gochecknoinits
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

		output := helpBoolFlagRegexp.ReplaceAllString(buf.String(), "             ")
		output = helpLeadingSpacesRegexp.ReplaceAllString(output, "  ")
		output = helpSSHAddrRegexp.ReplaceAllString(output, "--ssh-addr string ")
		output = helpStringTypeRegexp.ReplaceAllString(output, " <string> ")
		output = helpUintTypeRegexp.ReplaceAllString(output, " <uint> ")
		output = helpOctalTypeRegexp.ReplaceAllString(output, " <octal> ")
		output = helpFloatTypeRegexp.ReplaceAllString(output, " <float> ")
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

	pflag_mustLookup("cert-perm").DefValue = "600"

	pflag.Var((*rsaBitsValue)(&certRSABits),
		"cert-rsa-bits",
		"RSA key size in bits for new certificates\r\n"+
			"    [\"1024\" to \"4096\"]")

	pflag_mustLookup("cert-rsa-bits").DefValue = "2048"

	pflag.Var((*ecdsaBitsValue)(&certECDSABits),
		"cert-ecdsa-bits",
		"ECDSA key size in bits for new certificates\r\n"+
			"    [\"256\", \"384\", \"521\"]")

	pflag_mustLookup("cert-ecdsa-bits").DefValue = "256"

	pflag.StringSliceVar(&sshAddr,
		"ssh-addr", []string{":2222"},
		"SSH listener address(es)\r\n"+
			"    [e.g., \":2222\", \"[::1]:8000\"]\r\n"+
			"    (multiple allowed)")

	pflag_mustLookup("ssh-addr").DefValue = "\":2222\""

	pflag.Float64Var(&sshDelay,
		"ssh-delay", 0,
		"Delay for incoming SSH connections\r\n"+
			"    [\"0.0\" to \"30.0\" seconds] (no default)")

	pflag.BoolVar(&noBanner,
		"no-banner", false,
		"Disable the user SSH connection banner")

	pflag.BoolVar(&noMenu,
		"no-menu", false,
		"Disable the user SSH 'Control-]' menu")

	pflag.StringVar(&telnetHostPort,
		"telnet-host", "127.0.0.1:6180",
		"Default TELNET target [host:port\r\n"+
			"   or socket path]")

	pflag.Var(&altHostFlag{},
		"alt-host",
		"Alternate TELNET target(s) [sshuser@host:port\r\n"+
			"    or \"sshuser@/path\"] (multiple allowed)")

	pflag.StringVar(&iconv,
		"iconv", "",
		"Character map conversion of text to UTF-8\r\n"+
			"    [e.g., \"IBM Code Page 437\"] (no default)")

	pflag.BoolVar(&debugNegotiation,
		"debug-telnet", false,
		"Debug TELNET option negotiation")

	pflag.StringVar(&debugAddr,
		"debug-server", "",
		"Enable HTTP debug server listening address\r\n"+
			"    [e.g., \":6060\", \"[::1]:6060\"]")

	pflag.BoolVar(&noFilter,
		"no-filter", false,
		"Disable link filtering of NULL characters")

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

	pflag.BoolVar(&keymapByDefault,
		"keymap", false,
		"Enable Emacs keymapping mode by default")

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
			"    [\"fast\", \"normal\", \"high\"]\r\n"+
			"   ")

	pflag.BoolVar(&noCompress,
		"no-compress", false,
		"Disable session and/or console log compression")

	pflag.Var((*octalPermValue)(&logPerm),
		"log-perm",
		"Permissions (octal) for new log files\r\n"+
			"    [e.g., \"600\", \"644\"]")

	pflag_mustLookup("log-perm").DefValue = "600"

	pflag.Var((*octalPermValue)(&logDirPerm),
		"log-dir-perm",
		"Permissions (octal) for new log directories\r\n"+
			"    [e.g., \"750\", \"755\"]")

	pflag_mustLookup("log-dir-perm").DefValue = "750"

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

		pflag_mustLookup("db-perm").DefValue = "600"

		pflag.StringVar(&dbLogLevel,
			"db-loglevel", "error",
			"Database engine (BBoltDB) logging output level\r\n"+
				"    [level: \"0\" - \"6\", or \"none\" - \"debug\"]\r\n"+
				"   ")
	}

	pflag.Uint64Var(&idleMax,
		"idle-max", 0,
		"Maximum connection idle time allowed [seconds]")

	pflag.Uint64Var(&idleDefMax,
		"idle-def-max", 0,
		"Maximum connection idle time allowed\r\n"+
			"    for only the default target [seconds]")

	pflag.Uint64Var(&timeMax,
		"time-max", 0,
		"Maximum connection link time allowed [seconds]")

	pflag.Uint64Var(&timeDefMax,
		"time-def-max", 0,
		"Maximum connection link time allowed\r\n"+
			"    for only the default target [seconds]")

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

	args := os.Args
	if args == nil {
		args = []string{}
	}

	start := 1
	if len(args) < 1 {
		start = 0
	}

	for _, arg := range args[start:] {
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

//revive:disable:var-naming
func pflag_mustLookup(name string) *pflag.Flag { //nolint:revive
	f := pflag.Lookup(name)
	if f == nil {
		if enableGops {
			gopsClose()
		}

		panic("internal error: flag " + name + " not defined")
	}

	return f
}

//revive:enable:var-naming

///////////////////////////////////////////////////////////////////////////////////////////////////

func shutdownWatchdog() {
	<-shutdownSignal

	loggingDone := make(chan struct{})

	go func() {
		defer recoverGoroutine("shutdownWatchdog logging-wait")

		loggingWg.Wait()
		close(loggingDone)
	}()

	select {
	case <-loggingDone:

	case <-time.After(30 * time.Second):
		log.Printf(
			"%sShutdown timed out waiting for logs to flush; forcing exit.",
			alertPrefix(),
		)
	}

	closeDB()

	if isConsoleLogQuiet.Load() {
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
				"It is intended to be invoked from a Command Prompt or Windows Terminal session.",
			)

		case "darwin":
			fmt.Printf(
				"It is intended to be invoked from a command prompt (e.g., via Terminal.app).",
			)

		case "linux":
			fmt.Printf(
				"It is intended to be invoked from a command prompt (not a file manager or GUI).",
			)

		default:
			fmt.Printf(
				"It is intended to be invoked from a command prompt (and not a GUI launcher).",
			)
		}

		fmt.Print("\r\n\r\nPress Enter (or Return) to exit ... ")

		oldState, err := term.MakeRaw(int(os.Stdin.Fd())) //nolint:gosec,nolintlint
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
		_ = term.Restore(int(os.Stdin.Fd()), oldState) //nolint:gosec,nolintlint

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

		if cl != "quiet" && cl != "noquiet" { //nolint:goconst,nolintlint
			if enableGops {
				gopsClose()
			}

			log.Fatalf("%sERROR: Illegal --console-log value: %s.  Must be 'quiet' or 'noquiet'",
				errorPrefix(), consoleLog) // LINTED: Fatalf
		}

		isConsoleLogQuiet.Store(cl == "quiet")
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

	if iconv != "" {
		if findCharmap(iconv) == nil {
			if enableGops {
				gopsClose()
			}

			available := make([]string, 0, len(charmap.All))
			for _, cm := range charmap.All {
				available = append(available, fmt.Sprintf("%v", cm))
			}

			sort.Slice(
				available,
				func(i, j int) bool {
					return naturalLess(available[i], available[j])
				},
			)

			_, _ = fmt.Fprintf(os.Stdout, "\r\nValid --iconv character map strings:\r\n\r\n")

			for _, name := range available {
				_, _ = fmt.Fprintf(os.Stdout, "  \"%s\"\r\n", name)
			}

			_, _ = fmt.Fprintf(os.Stdout, "\r\n")

			log.Fatalf("%sERROR: Illegal --iconv charmap string: \"%s\"",
				errorPrefix(), iconv) // LINTED: Fatalf
		}
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

		log.Fatalf("%sERROR: Illegal --compress-algo: %s",
			errorPrefix(), compressAlgo) // LINTED: Fatalf
	}

	switch compressLevel {
	case "fast", "normal", "high": //nolint:goconst,nolintlint

	default:
		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: Illegal --compress-level: %s",
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
			defer func() {
				select {
				case <-shutdownSignal:

				default:
					log.Printf(
						"%sDatabase updater has stopped unexpectedly; counters will not be persisted.",
						alertPrefix(),
					)
				}
			}()
			defer recoverGoroutine("dbUpdater")

			log.Printf("%sStarting database updater with %d second interval.",
				dbPrefix(), dbTime)

			ticker := time.NewTicker(time.Duration(dbTime) * time.Second) //nolint:gosec,nolintlint
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
		err := os.MkdirAll(logDir, os.FileMode(logDirPerm)) //nolint:gosec,nolintlint
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
		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: --telnet-host cannot contain a username (e.g., 'user@'); "+
					"you specified: %s\r\n",
				nowStamp(), errorPrefix(), telnetHostPort)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: --telnet-host cannot contain a username (e.g., 'user@'); "+
			"you specified: %s",
			errorPrefix(), telnetHostPort) // LINTED: Fatalf
	}

	if idleMax > 0 {
		maxSeconds := uint64(math.MaxInt64 / int64(time.Second))
		if idleMax > maxSeconds {
			log.Printf("%sIllegal --idle-max value: \"%d\" exceeds safe range, using \"%d\"",
				warnPrefix(), idleMax, maxSeconds)
			idleMax = maxSeconds
		}
	}

	if idleDefMax > 0 {
		maxSeconds := uint64(math.MaxInt64 / int64(time.Second))
		if idleDefMax > maxSeconds {
			log.Printf("%sIllegal --idle-def-max value: \"%d\" exceeds safe range, using \"%d\"",
				warnPrefix(), idleDefMax, maxSeconds)
			idleDefMax = maxSeconds
		}
	}

	if timeMax > 0 {
		maxSeconds := uint64(math.MaxInt64 / int64(time.Second))
		if timeMax > maxSeconds {
			log.Printf("%sIllegal --time-max value: \"%d\" exceeds safe range, using \"%d\"",
				warnPrefix(), timeMax, maxSeconds)
			timeMax = maxSeconds
		}
	}

	if timeDefMax > 0 {
		maxSeconds := uint64(math.MaxInt64 / int64(time.Second))
		if timeDefMax > maxSeconds {
			log.Printf("%sIllegal --time-def-max value: \"%d\" exceeds safe range, using \"%d\"",
				warnPrefix(), timeDefMax, maxSeconds)
			timeDefMax = maxSeconds
		}
	}

	if idleMax > 0 && timeMax > 0 && idleMax >= timeMax {
		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: --idle-max (%d) cannot be greater than or equal to --time-max"+
					" (%d)\r\n",
				nowStamp(), errorPrefix(), idleMax, timeMax)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: --idle-max (%d) cannot be greater than or equal to --time-max (%d)",
			errorPrefix(), idleMax, timeMax) // LINTED: Fatalf
	}

	effIdleDefMax := idleMax
	if idleDefMax > 0 {
		effIdleDefMax = idleDefMax
	}

	effTimeDefMax := timeMax
	if timeDefMax > 0 {
		effTimeDefMax = timeDefMax
	}

	if effIdleDefMax > 0 && effTimeDefMax > 0 && effIdleDefMax >= effTimeDefMax {
		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: effective default target idle-max (%d) cannot be greater than "+
					"or equal to effective default target time-max (%d)\r\n",
				nowStamp(), errorPrefix(), effIdleDefMax, effTimeDefMax)
		}

		if enableGops {
			gopsClose()
		}

		log.Fatalf("%sERROR: effective default target idle-max (%d) cannot be greater than "+
			"or equal to effective default target time-max (%d)",
			errorPrefix(), effIdleDefMax, effTimeDefMax) // LINTED: Fatalf
	}

	edSigner, err := loadOrCreateHostKey(filepath.Join(
		certDir,
		"ssh_host_ed25519_key.pem",
	),
		"ed25519")
	if err != nil {
		if isConsoleLogQuiet.Load() {
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
		"ssh_host_rsa_key.pem",
	),
		"rsa")
	if err != nil {
		if isConsoleLogQuiet.Load() {
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
		"ssh_host_ecdsa_key.pem",
	),
		"ecdsa")
	if err != nil {
		if isConsoleLogQuiet.Load() {
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

	checkPrivilegedPorts(sshAddr)

	for _, addr := range sshAddr {
		go func(addr string) {
			defer recoverGoroutine("accept loop")

			listener, err := net.Listen("tcp", addr)
			if err != nil {
				if isConsoleLogQuiet.Load() {
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

			acceptDelay := time.Duration(0)

			for {
				rawConn, err := listener.Accept()
				if err != nil {
					if gracefulShutdownMode.Load() {
						return
					}

					acceptErrorsTotal.Add(1)

					log.Printf("%sERROR: Accept error: %v",
						warnPrefix(), err)

					if acceptDelay == 0 {
						acceptDelay = 10 * time.Millisecond
					} else {
						acceptDelay *= 2
						if acceptDelay > time.Second {
							acceptDelay = time.Second
						}
					}

					time.Sleep(acceptDelay)

					continue
				}

				acceptDelay = 0

				if gracefulShutdownMode.Load() {
					if rawConn != nil {
						_ = rawConn.Close()
					}

					continue
				}

				go handleConn(rawConn, edSigner, rsaSigner, ecdsaSigner)
			}
		}(addr)
	}

	pid := os.Getpid()

	var startMsg string

	if pid != 0 {
		startMsg = "Starting proxy " + relayPrefix() + "[PID " + strconv.Itoa(pid) + "]"
	} else {
		startMsg = "Starting proxy " + relayPrefix()
	}

	if !noConsole {
		if isConsoleLogQuiet.Load() {
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
			if isConsoleLogQuiet.Load() {
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

	if idleMax > 0 || timeMax > 0 || idleDefMax > 0 || timeDefMax > 0 {
		go func() {
			defer func() {
				select {
				case <-shutdownSignal:

				default:
					log.Printf(
						"%sIdle/time killer has stopped unexpectedly; idle and time limits will not be enforced.",
						alertPrefix(),
					)
				}
			}()
			defer recoverGoroutine("idleKiller")

			checkInterval := 10 * time.Second

			for {
				select {
				case <-shutdownSignal:
					return

				case <-time.After(checkInterval):
					type pendingKill struct {
						channel  ssh.Channel
						sshConn  *ssh.ServerConn
						msg      []byte
						id       string
						msgLabel string
						logLine  string
						sshNil   bool
					}

					var toKill []pendingKill

					connectionsMutex.Lock()

					for id, conn := range connections {
						if conn.monitoring.Load() {
							continue
						}

						idleTime := time.Since(time.Unix(0, conn.lastActivityTime.Load()))
						connUptime := time.Since(conn.startTime)

						effIdleMax := idleMax
						effTimeMax := timeMax

						if conn.isDefaultTarget {
							if idleDefMax > 0 {
								effIdleMax = idleDefMax
							}

							if timeDefMax > 0 {
								effTimeMax = timeDefMax
							}
						}

						if effIdleMax > 0 &&
							idleTime > time.Duration( //nolint:gosec,nolintlint
								effIdleMax,
							)*time.Second {
							idleKillsTotal.Add(1)

							toKill = append(toKill, pendingKill{
								channel: conn.channel,
								sshConn: conn.sshConn,
								msg: fmt.Appendf(nil,
									"\r\n\r\nIDLE TIMEOUT (link time %s)\r\n\r\n",
									connUptime.Round(time.Second)),
								id:       id,
								msgLabel: "idle timeout",
								logLine: fmt.Sprintf(
									"%sIDLEKILL [%s] %s@%s (idle %s, link %s)",
									yellowDotPrefix(), id, conn.userName,
									conn.hostName, idleTime.Round(time.Second),
									connUptime.Round(time.Second),
								),
								sshNil: conn.sshConn == nil,
							})

							delete(connections, id)
							delete(shareableConnections, conn.shareableUsername)
						} else if effTimeMax > 0 &&
							connUptime > time.Duration( //nolint:gosec,nolintlint
								effTimeMax,
							)*time.Second {
							timeKillsTotal.Add(1)

							toKill = append(toKill, pendingKill{
								channel: conn.channel,
								sshConn: conn.sshConn,
								msg: fmt.Appendf(nil,
									"\r\n\r\nCONNECTION TIMEOUT (link time %s)\r\n\r\n",
									connUptime.Round(time.Second)),
								id:       id,
								msgLabel: "connection timeout",
								logLine: fmt.Sprintf(
									"%sTIMEKILL [%s] %s@%s (link time %s)",
									yellowDotPrefix(), id, conn.userName,
									conn.hostName, connUptime.Round(time.Second),
								),
								sshNil: conn.sshConn == nil,
							})

							delete(connections, id)
							delete(shareableConnections, conn.shareableUsername)
						}
					}

					connectionsMutex.Unlock()

					for _, k := range toKill {
						log.Printf("%s", k.logLine)

						if k.sshNil {
							log.Printf("%sError: sshConn is nil for connection %s",
								warnPrefix(), k.id)
						}

						if k.channel != nil {
							done := make(chan struct{})

							go func(ch ssh.Channel, msg []byte) {
								defer recoverGoroutine("idleKiller channel write")
								defer close(done)

								_, _ = ch.Write(msg)
							}(k.channel, k.msg)

							select {
							case <-done:

							case <-time.After(100 * time.Millisecond):
							}
						}

						if k.sshConn != nil {
							err := k.sshConn.Close()
							if err != nil {
								log.Printf("%sError closing SSH connection for %s: %v",
									warnPrefix(), k.id, err)
							}
						}
					}
				}
			}
		}()
	}

	select {}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func debugInit(addr string) {
	mux := http.NewServeMux()

	_ = statsviz.Register(mux)

	mux.Handle("/debug/pprof/", http.DefaultServeMux)

	mux.Handle("/debug/vars", http.DefaultServeMux)

	mux.HandleFunc(
		"/",
		func(w http.ResponseWriter, _ *http.Request) {
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
		},
	)

	log.Printf("%sStarting debug HTTP server on %s",
		bugPrefix(), addr)

	go func() {
		log.Fatalf("%s%v", // LINTED: Fatalf
			// nosemgrep: go.lang.security.audit.net.use-tls.use-tls
			errorPrefix(), http.ListenAndServe(addr, mux)) //nolint:gosec,nolintlint
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConsoleInput() {
	defer func() {
		if gracefulShutdownMode.Load() {
			return
		}

		select {
		case <-shutdownSignal:

		default:
			log.Printf(
				"%sConsole input handler has stopped unexpectedly; the interactive console will not respond.",
				alertPrefix(),
			)
		}
	}()
	defer recoverGoroutine("handleConsoleInput")

	reader := bufio.NewReader(os.Stdin)

	for {
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

			consoleLogMutex.Lock()

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

			consoleLogMutex.Unlock()

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
			var msg string

			switch {
			case blacklistFile == "" && whitelistFile == "":
				msg = "Reload requested but no lists enabled."

			case blacklistFile == "" && whitelistFile != "":
				msg = "Reload requested; only whitelist enabled."

			case blacklistFile != "" && whitelistFile == "":
				msg = "Reload requested; only blacklist enabled."
			}

			if msg != "" {
				_, err := fmt.Fprintf(os.Stdout,
					"%s %s%s\r\n",
					nowStamp(), alertPrefix(), msg)
				if err != nil {
					log.Printf("%sError writing to stdout: %v",
						boomPrefix(), err)
				}
			}

			if blacklistFile != "" || whitelistFile != "" {
				reloadLists()
			}

		case "xyzzy": // :)
			if isConsoleLogQuiet.Load() {
				fmt.Printf("%s %sNothing happens.\r\n",
					nowStamp(), easterEggPrefix())
			}

			log.Printf("%sNothing happens.\r\n",
				easterEggPrefix())

		case "XYZZY": // =)
			if isConsoleLogQuiet.Load() {
				fmt.Printf("%s %sNOTHING HAPPENS.\r\n",
					nowStamp(), easterEggPrefix())
			}

			log.Printf("%sNOTHING HAPPENS.\r\n",
				easterEggPrefix())

		case "":

		default:
			_, err := fmt.Fprintf(os.Stdout, //nolint:gosec,nolintlint
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
	type row struct {
		Key, Description string
	}

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
		"\r+=%s=+=%s=+\r\n",
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
		type row struct {
			Name,
			Value string
		}

		rows := []row{
			{
				"TELNET Total Connections",
				strconv.FormatUint(telnetConnectionsTotal.Load(), 10),
			},

			{
				"* TELNET Alt-Host Routings",
				strconv.FormatUint(altHostRoutesTotal.Load(), 10),
			},

			{
				"* TELNET Connection Failures",
				strconv.FormatUint(telnetFailuresTotal.Load(), 10),
			},

			{
				"Peak Concurrent Connections",
				strconv.FormatUint(peakUsersTotal.Load(), 10),
			},

			{
				"Total Bytes SSH to TELNET",
				formatBytes(trafficOutTotal.Load()),
			},

			{
				"Total Bytes TELNET to SSH",
				formatBytes(trafficInTotal.Load()),
			},

			{
				"SSH Total Connections",
				strconv.FormatUint(sshConnectionsTotal.Load(), 10),
			},

			{
				"* SSH User Sessions",
				strconv.FormatUint(sshSessionsTotal.Load(), 10),
			},

			{
				"* SSH Monitoring Sessions",
				strconv.FormatUint(monitorSessionsTotal.Load(), 10),
			},

			{
				"* SSH Session Request Timeout",
				strconv.FormatUint(sshRequestTimeoutTotal.Load(), 10),
			},

			{
				"* SSH Illegal Request (SFTP)",
				strconv.FormatUint(sshIllegalSubsystemTotal.Load(), 10),
			},

			{
				"* SSH Illegal Request (SCP/EXEC)",
				strconv.FormatUint(sshExecRejectedTotal.Load(), 10),
			},

			{
				"* SSH Accept Errors",
				strconv.FormatUint(acceptErrorsTotal.Load(), 10),
			},

			{
				"* SSH Handshake Errors",
				strconv.FormatUint(sshHandshakeFailedTotal.Load(), 10),
			},

			{
				"* SSH Other Errors/Disconnects",
				strconv.FormatUint(subSatU64(
					sshConnectionsTotal.Load(),
					sshSessionsTotal.Load(),
					sshRequestTimeoutTotal.Load(),
					sshIllegalSubsystemTotal.Load(),
					sshExecRejectedTotal.Load(),
					sshHandshakeFailedTotal.Load(),
					rejectedTotal.Load(),
					delayAbandonedTotal.Load(),
				), 10),
			},
			{
				"Connections Killed by Admin",
				strconv.FormatUint(adminKillsTotal.Load(), 10),
			},

			{
				"Connections Killed for Idle Time",
				strconv.FormatUint(idleKillsTotal.Load(), 10),
			},

			{
				"Connections Killed for Max Time",
				strconv.FormatUint(timeKillsTotal.Load(), 10),
			},

			{
				"Connections Killed via Delay",
				strconv.FormatUint(delayAbandonedTotal.Load(), 10),
			},

			{
				"Blacklist Rejected Connections",
				strconv.FormatUint(rejectedTotal.Load(), 10),
			},

			{
				"Whitelist Exempted Connections",
				strconv.FormatUint(exemptedTotal.Load(), 10),
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
		type row struct {
			Name,
			Value, Lifetime string
		}

		rows := []row{
			{
				"TELNET Total Connections",
				strconv.FormatUint(telnetConnectionsTotal.Load(), 10),
				strconv.FormatUint(lifetimeTelnetConnectionsTotal.Load()+
					telnetConnectionsTotal.Load(), 10),
			},

			{
				"* TELNET Alt-Host Routings",
				strconv.FormatUint(altHostRoutesTotal.Load(), 10),
				strconv.FormatUint(lifetimeAltHostRoutesTotal.Load()+
					altHostRoutesTotal.Load(), 10),
			},

			{
				"* TELNET Connection Failures",
				strconv.FormatUint(telnetFailuresTotal.Load(), 10),
				strconv.FormatUint(lifetimeTelnetFailuresTotal.Load()+
					telnetFailuresTotal.Load(), 10),
			},

			{
				"Peak Concurrent Connections",
				strconv.FormatUint(peakUsersTotal.Load(), 10),
				strconv.FormatUint(lifetimePeakUsersTotal.Load(), 10),
			},

			{
				"Total Bytes SSH to TELNET",
				formatBytes(trafficOutTotal.Load()),
				formatBytes(lifetimeTrafficOutTotal.Load() +
					trafficOutTotal.Load()),
			},

			{
				"Total Bytes TELNET to SSH",
				formatBytes(trafficInTotal.Load()),
				formatBytes(lifetimeTrafficInTotal.Load() +
					trafficInTotal.Load()),
			},

			{
				"SSH Total Connections",
				strconv.FormatUint(sshConnectionsTotal.Load(), 10),
				strconv.FormatUint(lifetimeSSHconnectionsTotal.Load()+
					sshConnectionsTotal.Load(), 10),
			},

			{
				"* SSH User Sessions",
				strconv.FormatUint(sshSessionsTotal.Load(), 10),
				strconv.FormatUint(lifetimeSSHsessionsTotal.Load()+
					sshSessionsTotal.Load(), 10),
			},

			{
				"* SSH Monitoring Sessions",
				strconv.FormatUint(monitorSessionsTotal.Load(), 10),
				strconv.FormatUint(lifetimeMonitorSessionsTotal.Load()+
					monitorSessionsTotal.Load(), 10),
			},

			{
				"* SSH Session Request Timeout",
				strconv.FormatUint(sshRequestTimeoutTotal.Load(), 10),
				strconv.FormatUint(lifetimeSSHrequestTimeoutTotal.Load()+
					sshRequestTimeoutTotal.Load(), 10),
			},

			{
				"* SSH Illegal Request (SFTP)",
				strconv.FormatUint(sshIllegalSubsystemTotal.Load(), 10),
				strconv.FormatUint(lifetimeSSHillegalSubsystemTotal.Load()+
					sshIllegalSubsystemTotal.Load(), 10),
			},

			{
				"* SSH Illegal Request (SCP/EXEC)",
				strconv.FormatUint(sshExecRejectedTotal.Load(), 10),
				strconv.FormatUint(lifetimeSSHexecRejectedTotal.Load()+
					sshExecRejectedTotal.Load(), 10),
			},

			{
				"* SSH Accept Errors",
				strconv.FormatUint(acceptErrorsTotal.Load(), 10),
				strconv.FormatUint(lifetimeAcceptErrorsTotal.Load()+
					acceptErrorsTotal.Load(), 10),
			},

			{
				"* SSH Handshake Errors",
				strconv.FormatUint(sshHandshakeFailedTotal.Load(), 10),
				strconv.FormatUint(lifetimeSSHhandshakeFailedTotal.Load()+
					sshHandshakeFailedTotal.Load(), 10),
			},

			{
				"* SSH Other Errors/Disconnects",
				strconv.FormatUint(subSatU64(
					sshConnectionsTotal.Load(),
					sshSessionsTotal.Load(),
					sshRequestTimeoutTotal.Load(),
					sshIllegalSubsystemTotal.Load(),
					sshExecRejectedTotal.Load(),
					sshHandshakeFailedTotal.Load(),
					rejectedTotal.Load(),
					delayAbandonedTotal.Load(),
				), 10),
				strconv.FormatUint(subSatU64(
					lifetimeSSHconnectionsTotal.Load()+sshConnectionsTotal.Load(),
					lifetimeSSHsessionsTotal.Load()+sshSessionsTotal.Load(),
					lifetimeSSHrequestTimeoutTotal.Load()+sshRequestTimeoutTotal.Load(),
					lifetimeSSHillegalSubsystemTotal.Load()+sshIllegalSubsystemTotal.Load(),
					lifetimeSSHexecRejectedTotal.Load()+sshExecRejectedTotal.Load(),
					lifetimeSSHhandshakeFailedTotal.Load()+sshHandshakeFailedTotal.Load(),
					lifetimeRejectedTotal.Load()+rejectedTotal.Load(),
					lifetimeDelayAbandonedTotal.Load()+delayAbandonedTotal.Load(),
				), 10),
			},

			{
				"Connections Killed by Admin",
				strconv.FormatUint(adminKillsTotal.Load(), 10),
				strconv.FormatUint(lifetimeAdminKillsTotal.Load()+
					adminKillsTotal.Load(), 10),
			},

			{
				"Connections Killed for Idle Time",
				strconv.FormatUint(idleKillsTotal.Load(), 10),
				strconv.FormatUint(lifetimeIdleKillsTotal.Load()+
					idleKillsTotal.Load(), 10),
			},

			{
				"Connections Killed for Max Time",
				strconv.FormatUint(timeKillsTotal.Load(), 10),
				strconv.FormatUint(lifetimeTimeKillsTotal.Load()+
					timeKillsTotal.Load(), 10),
			},

			{
				"Connections Killed via Delay",
				strconv.FormatUint(delayAbandonedTotal.Load(), 10),
				strconv.FormatUint(lifetimeDelayAbandonedTotal.Load()+
					delayAbandonedTotal.Load(), 10),
			},

			{
				"Blacklist Rejected Connections",
				strconv.FormatUint(rejectedTotal.Load(), 10),
				strconv.FormatUint(lifetimeRejectedTotal.Load()+
					rejectedTotal.Load(), 10),
			},

			{
				"Whitelist Exempted Connections",
				strconv.FormatUint(exemptedTotal.Load(), 10),
				strconv.FormatUint(lifetimeExemptedTotal.Load()+
					exemptedTotal.Load(), 10),
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

		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sGraceful shutdown canceled.\r\n",
				nowStamp(), bellPrefix())
		}
	} else {
		gracefulShutdownMode.Store(true)

		log.Printf("%sNo new connections will be accepted.\r\n",
			skullPrefix())

		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sNo new connections will be accepted.\r\n",
				nowStamp(), skullPrefix())
		}

		log.Printf("%sGraceful shutdown initiated.\r\n",
			bellPrefix())

		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sGraceful shutdown initiated.\r\n",
				nowStamp(), bellPrefix())
		}

		connectionsMutex.Lock()

		canShutdown := connectionsInFlight.Load() == 0

		connectionsMutex.Unlock()

		if canShutdown {
			shutdownOnce.Do(
				func() {
					close(shutdownSignal)
				},
			)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toggleDenyNewConnections() {
	if denyNewConnectionsMode.Load() {
		denyNewConnectionsMode.Store(false)

		log.Printf("%sDeny connections canceled.\r\n",
			thumbsUpPrefix())

		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sDeny connections canceled.\r\n",
				nowStamp(), thumbsUpPrefix())
		}
	} else {
		denyNewConnectionsMode.Store(true)

		log.Printf("%sNo new connections will be accepted.\r\n",
			skullPrefix())

		if isConsoleLogQuiet.Load() {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sNo new connections will be accepted.\r\n",
				nowStamp(), skullPrefix())
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func immediateShutdown() {
	immediateOnce.Do(
		func() {
			log.Printf("%sImmediate shutdown initiated.\r\n",
				boomPrefix())

			if isConsoleLogQuiet.Load() {
				_, _ = fmt.Fprintf(os.Stdout,
					"%s %sImmediate shutdown initiated.\r\n",
					nowStamp(), boomPrefix())
			}

			type connInfo struct {
				channel    ssh.Channel
				cancelFunc context.CancelFunc
				sshConn    *ssh.ServerConn
				id         string
				userName   string
				hostName   string
				startTime  time.Time
			}

			connectionsMutex.Lock()

			conns := make([]connInfo, 0, len(connections))
			for _, conn := range connections {
				conns = append(
					conns,
					connInfo{
						channel:    conn.channel,
						cancelFunc: conn.cancelFunc,
						sshConn:    conn.sshConn,
						id:         conn.ID,
						userName:   conn.userName,
						hostName:   conn.hostName,
						startTime:  conn.startTime,
					},
				)
			}

			connectionsMutex.Unlock()

			for _, ci := range conns {
				if ci.channel != nil {
					// Don't block on writing to the channel during shutdown
					done := make(chan struct{})

					go func() {
						defer recoverGoroutine("immediateShutdown channel write")
						defer close(done)

						_, _ = ci.channel.Write(
							[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"),
						)
					}()

					select {
					case <-done:
					case <-time.After(100 * time.Millisecond):
					}

					connUptime := time.Since(ci.startTime)
					log.Printf("%sLINKDOWN [%s] %s@%s (link time %s)",
						yellowDotPrefix(), ci.id, ci.userName,
						ci.hostName, connUptime.Round(time.Second))
				}

				if ci.cancelFunc != nil {
					ci.cancelFunc()
				}

				if ci.sshConn != nil {
					err := ci.sshConn.Close()
					if err != nil {
						log.Printf("%sError closing SSH connection for %s: %v",
							alertPrefix(), ci.id, err)
					}
				}
			}

			shutdownOnce.Do(
				func() {
					close(shutdownSignal)
				},
			)

			for i := range 50 {
				connectionsMutex.Lock()

				if len(connections) == 0 {
					connectionsMutex.Unlock()

					break
				}

				if i == 49 {
					ids := make([]string, 0, len(connections))
					for id := range connections {
						ids = append(ids, id)
					}

					log.Printf(
						"%sWarning: immediate shutdown timed out waiting for connections: %v",
						warnPrefix(), ids,
					)
				}

				connectionsMutex.Unlock()

				time.Sleep(100 * time.Millisecond)
			}

			if isConsoleLogQuiet.Load() {
				_, _ = fmt.Fprintf(os.Stdout,
					"%s %sWaiting for logs to flush...\r\n",
					nowStamp(), bellPrefix())
			}

			log.Printf("%sWaiting for logs to flush...",
				bellPrefix())

			loggingWg.Wait()

			closeDB()

			if isConsoleLogQuiet.Load() {
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
		},
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConnections(truncate bool) {
	connectionsMutex.Lock()

	if len(connections) == 0 {
		connectionsMutex.Unlock()

		fmt.Printf("\r%s No active connections.\r\n",
			nowStamp())

		return
	}

	conns := make([]*Connection, 0, len(connections))
	for _, conn := range connections {
		conns = append(conns, conn)
	}

	connectionsMutex.Unlock()

	sort.Slice(
		conns,
		func(i, j int) bool {
			return conns[i].startTime.Before(conns[j].startTime)
		},
	)

	type row struct {
		ID      string
		Details string
		Link    string
		Idle    string
	}

	userTruncat := false
	rows := make([]row, 0, len(conns))

	for _, conn := range conns {
		if conn.sshConn == nil {
			log.Printf("%sError: sshConn is nil for connection %s",
				warnPrefix(), conn.ID)

			continue
		}

		user := conn.userName

		if truncate && len(user) > shareableUsernameLen {
			userTruncat = true
			user = "..." + user[len(user)-shareableUsernameTailLen:]
		}

		var details, idle string

		if conn.monitoring.Load() {
			if conn.monitoredConnection == nil {
				log.Printf("%sInternal error: monitoring enabled but monitoredConnection is nil!",
					warnPrefix())

				return
			}

			details = fmt.Sprintf("%s@%s -> %s",
				user, conn.sshConn.RemoteAddr(), conn.monitoredConnection.ID)
			idle = "---------"
		} else {
			targetInfo := ""

			var targetHost string

			var targetPort int

			if t := conn.target.Load(); t != nil {
				targetHost = t.host
				targetPort = int(t.port)
			}

			if targetHost != "" {
				if targetPort != 0 {
					targetInfo = " -> " + targetHost + ":" + strconv.Itoa(targetPort)
				} else {
					targetInfo = " -> " + targetHost
				}
			}

			details = fmt.Sprintf("%s@%s%s",
				user, conn.sshConn.RemoteAddr(), targetInfo)
			idle = time.Since(
				time.Unix(0, conn.lastActivityTime.Load()),
			).Round(time.Second).String()
		}

		rows = append(
			rows,
			row{
				ID:      conn.ID,
				Details: details,
				Link:    time.Since(conn.startTime).Round(time.Second).String(),
				Idle:    idle,
			},
		)
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

	border := fmt.Sprintf(
		"\r+=%s=+=%s=+=%s=+=%s=+\r\n",
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
			"\r\n* %sSome Connection Details have been truncated, use 'L' for wider output.\r\n",
			alertPrefix(),
		)
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

	s10 := "SSH Certificate Directory: " + certDirStr

	updateMaxLength(s10)

	var gopsStr string

	if enableGops {
		gopsStr = "enabled"
	} else {
		gopsStr = "disabled" //nolint:goconst,nolintlint
	}

	s14 := "Gops diagnostic agent: " + gopsStr

	updateMaxLength(s14)

	var MDNSStr string

	if enableMDNS {
		MDNSStr = "enabled"
	} else {
		MDNSStr = "disabled"
	}

	s13 := "Multicast DNS announcements: " + MDNSStr

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

	if timeDefMax > 0 {
		if timeMax > 0 {
			timeMaxStr += fmt.Sprintf(" (Def. Target: %d seconds)",
				timeDefMax)
		} else {
			timeMaxStr = fmt.Sprintf("disabled (Def. Target: %d seconds)",
				timeDefMax)
		}
	}

	updateMaxLength("Time Max: " + timeMaxStr)

	idleMaxStr := "disabled"

	if idleMax > 0 {
		idleMaxStr = fmt.Sprintf("%d seconds",
			idleMax)
	}

	if idleDefMax > 0 {
		if idleMax > 0 {
			idleMaxStr += fmt.Sprintf(" (Def. Target: %d seconds)",
				idleDefMax)
		} else {
			idleMaxStr = fmt.Sprintf("disabled (Def. Target: %d seconds)",
				idleDefMax)
		}
	}

	updateMaxLength("Idle Max: " + idleMaxStr)

	updateMaxLength("Log Base Directory: " + logDir)

	s4 := fmt.Sprintf("No Session Logging: %t",
		noLog)

	updateMaxLength(s4)

	consoleLogMutex.Lock()
	clName := consoleLog
	consoleLogMutex.Unlock()

	if clName != "" {
		var quietMode string
		if isConsoleLogQuiet.Load() {
			quietMode = "quiet"
		} else {
			quietMode = "noquiet" //nolint:goconst,nolintlint
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

	networksMutex.RLock()

	blacklistLen := len(blacklistedNetworks)
	whitelistLen := len(whitelistedNetworks)

	networksMutex.RUnlock()

	if blacklistFile == "" && blacklistLen == 0 { //nolint:gocritic
		updateMaxLength("Blacklist: 0 entries active")
	} else if whitelistFile != "" && blacklistFile == "" {
		updateMaxLength("Blacklist: Deny all (due to whitelist only)")
	} else {
		s9 := fmt.Sprintf("Blacklist: %d entries active",
			blacklistLen)
		updateMaxLength(s9)
	}

	if whitelistFile == "" {
		updateMaxLength("Whitelist: 0 entries active")
	} else {
		s10 := fmt.Sprintf("Whitelist: %d entries active",
			whitelistLen)
		updateMaxLength(s10)
	}

	uptime := time.Since(startTime)

	uptimeDays := int(uptime.Hours() / 24)
	uptimeHours := int(uptime.Hours()) % 24
	uptimeMinutes := int(uptime.Minutes()) % 60
	uptimeSeconds := int(uptime.Seconds()) % 60

	uptimeString := fmt.Sprintf("%dd%dh%dm%ds (since %s)",
		uptimeDays, uptimeHours, uptimeMinutes, uptimeSeconds,
		startTime.Format("2006-Jan-02 15:04:05"))

	updateMaxLength("Proxy Uptime: " + uptimeString)

	var lifetimeString string

	if !persistedStartTime.IsZero() {
		lifetime := time.Since(persistedStartTime)
		days := int(lifetime.Hours() / 24)
		hours := int(lifetime.Hours()) % 24
		minutes := int(lifetime.Minutes()) % 60
		seconds := int(lifetime.Seconds()) % 60
		lifetimeString = fmt.Sprintf("%dd%dh%dm%ds (created %s)",
			days, hours, minutes, seconds,
			persistedStartTime.Format("2006-Jan-02 15:04:05"))
	}

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

	if lifetimeString != "" {
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

		sort.Slice(
			users,
			func(i, j int) bool {
				return naturalLess(users[i], users[j])
			},
		)

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

	consoleLogMutex.Lock()
	clName = consoleLog
	consoleLogMutex.Unlock()

	if clName != "" {
		var quietMode string

		if isConsoleLogQuiet.Load() {
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

	networksMutex.RLock()

	blacklistLen = len(blacklistedNetworks)
	whitelistLen = len(whitelistedNetworks)

	networksMutex.RUnlock()

	if blacklistFile == "" && blacklistLen == 0 { //nolint:gocritic
		printRow(&b, "Blacklist: 0 entries active")
	} else if whitelistFile != "" && blacklistFile == "" {
		printRow(&b, "Blacklist: Deny all (due to whitelist only)")
	} else {
		printRow(&b, fmt.Sprintf("Blacklist: %d entries active",
			blacklistLen))
	}

	if whitelistFile == "" {
		printRow(&b, "Whitelist: 0 entries active")
	} else {
		printRow(&b, fmt.Sprintf("Whitelist: %d entries active",
			whitelistLen))
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
					err),
			)
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
					err),
			)
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

	networksMutex.Lock()
	defer networksMutex.Unlock()

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

		blacklistedNetworks = []*net.IPNet{ipv4Net, ipv6Net}

		log.Printf("%sBlacklist: Blacklisting all host by default\r\n",
			alertPrefix())
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killConnection(id string) {
	connectionsMutex.Lock()

	conn, ok := connections[id]
	if !ok {
		connectionsMutex.Unlock()

		_, _ = fmt.Fprintf(os.Stdout, //nolint:gosec,nolintlint
			"%s Session ID '%s' not found.\r\n",
			nowStamp(), id)

		return
	}

	if isConsoleLogQuiet.Load() {
		_, err := fmt.Fprintf(os.Stdout, //nolint:gosec,nolintlint
			"%s %sKilling connection %s...\r\n",
			nowStamp(), skullPrefix(), id)
		if err != nil {
			log.Printf("%sError writing to Stdout: %v",
				warnPrefix(), err)
		}
	}

	log.Printf("%sKilling connection %s...\r\n", //nolint:gosec,nolintlint
		skullPrefix(), id)

	connUptime := time.Since(conn.startTime)

	log.Printf("%sTERMKILL [%s] %s@%s (link time %s)",
		yellowDotPrefix(), conn.ID, conn.userName,
		conn.hostName, connUptime.Round(time.Second))

	adminKillsTotal.Add(1)

	channel := conn.channel
	sshConn := conn.sshConn
	connID := conn.ID

	delete(connections, id)
	delete(shareableConnections, conn.shareableUsername)

	connectionsMutex.Unlock()

	if channel != nil {
		done := make(chan struct{})

		go func(ch ssh.Channel) {
			defer recoverGoroutine("killConnection channel write")
			defer close(done)

			_, _ = ch.Write(
				[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"),
			)
		}(channel)

		select {
		case <-done:

		case <-time.After(100 * time.Millisecond):
		}
	}

	if sshConn != nil {
		err := sshConn.Close()
		if err != nil {
			log.Printf("%sError closing SSH connection for %s: %v",
				warnPrefix(), connID, err)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func killAllConnections() {
	connectionsMutex.Lock()

	if len(connections) == 0 {
		connectionsMutex.Unlock()

		fmt.Printf("\r%s No active connections to kill.\r\n",
			nowStamp())

		return
	}

	fmt.Printf("\r%s %sKilling all %d active connections...\r\n",
		nowStamp(), skullPrefix(), len(connections))

	type connToKill struct {
		id                string
		channel           ssh.Channel
		userName          string
		hostName          string
		shareableUsername string
		startTime         time.Time
		sshConn           *ssh.ServerConn
	}

	connsToKill := make([]connToKill, 0, len(connections))

	for id, conn := range connections {
		connsToKill = append(
			connsToKill,
			connToKill{
				id:                id,
				channel:           conn.channel,
				userName:          conn.userName,
				hostName:          conn.hostName,
				shareableUsername: conn.shareableUsername,
				startTime:         conn.startTime,
				sshConn:           conn.sshConn,
			},
		)
	}

	connectionsMutex.Unlock()

	for _, c := range connsToKill {
		if isConsoleLogQuiet.Load() {
			_, err := fmt.Fprintf(os.Stdout,
				"%s %sKilling connection %s...\r\n",
				nowStamp(), skullPrefix(), c.id)
			if err != nil {
				log.Printf("%sError writing to Stdout: %v",
					warnPrefix(), err)
			}
		}

		if c.channel != nil {
			done := make(chan struct{})

			go func(ch ssh.Channel) {
				defer recoverGoroutine("killAllConnections channel write")
				defer close(done)

				_, _ = ch.Write(
					[]byte("\r\n\r\nCONNECTION TERMINATED\r\n\r\n"),
				)
			}(c.channel)

			select {
			case <-done:

			case <-time.After(100 * time.Millisecond):
			}
		}

		connUptime := time.Since(c.startTime)
		log.Printf("%sTERMKILL [%s] %s@%s (link time %s)",
			yellowDotPrefix(), c.id, c.userName,
			c.hostName, connUptime.Round(time.Second))

		adminKillsTotal.Add(1)

		if c.sshConn != nil {
			err := c.sshConn.Close()
			if err != nil {
				log.Printf("%sError closing SSH connection for %s: %v",
					warnPrefix(), c.id, err)
			}
		} else {
			log.Printf("%sError: sshConn is nil for connection %s",
				warnPrefix(), c.id)
		}

		connectionsMutex.Lock()

		delete(connections, c.id)
		delete(shareableConnections, c.shareableUsername)

		connectionsMutex.Unlock()
	}

	fmt.Printf("\r%s %sAll active connections killed.\r\n",
		nowStamp(), alertPrefix())
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendNaws(conn *Connection, width, height uint32) {
	if !conn.nawsActive.Load() || !hasTelnetConn(conn) {
		return
	}

	if width == 0 ||
		width > 65535 {
		width = 1
	}

	if height == 0 ||
		height > 65535 {
		height = 1
	}

	packet := make([]byte, 0, 13)
	packet = append(packet, TelcmdIAC, TelcmdSB, TeloptNAWS)

	for _, b := range []byte{
		byte(width >> 8), byte(width & 0xff),
		byte(height >> 8), byte(height & 0xff),
	} {
		packet = append(packet, b)
		if b == TelcmdIAC {
			packet = append(packet, TelcmdIAC)
		}
	}

	packet = append(packet, TelcmdIAC, TelcmdSE)

	if debugNegotiation {
		log.Printf("%sDEBUG: sending NAWS to TELNET target: %d x %d",
			blueDotPrefix(), width, height)
	}

	_, err := telnetWrite(conn, packet)
	if err != nil {
		log.Printf("%sError sending NAWS to TELNET target for %s: %v",
			warnPrefix(), conn.ID, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func kickNaws(conn *Connection, width, height uint32) {
	conn.nawsPending.Store(&nawsSize{width: width, height: height})

	select {
	case conn.nawsKick <- struct{}{}:

	default:
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func nawsSender(conn *Connection) {
	defer recoverGoroutine("nawsSender")

	for {
		select {
		case <-conn.cancelCtx.Done():
			return

		case <-conn.nawsKick:
			sz := conn.nawsPending.Load()
			if sz == nil {
				continue
			}

			sendNaws(conn, sz.width, sz.height)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func loadOrCreateHostKey(keyPath, keyType string) (ssh.Signer, error) { //nolint:ireturn
	keyData, err := os.ReadFile(keyPath) //nolint:gosec,nolintlint
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w",
				err)
		}

		return signer, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read key: %w",
			err)
	}

	var privateKey any

	var pemBlock *pem.Block

	var keySize int

	switch keyType {
	case "rsa":
		key, err := rsa.GenerateKey(rand.Reader, int(certRSABits)) //nolint:gosec,nolintlint
		if err != nil {
			return nil, fmt.Errorf("failed to generate rsa key: %w",
				err)
		}

		privateKey = key
		keySize = key.N.BitLen()

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
			return nil, fmt.Errorf("failed to generate ed25519 key: %w",
				err)
		}

		privateKey = rawPriv
		keySize = 256

		edKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type %T",
				privateKey)
		}

		derBytes, err := x509.MarshalPKCS8PrivateKey(edKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ed25519 private key: %w",
				err)
		}

		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		}

	case "ecdsa":
		var curve elliptic.Curve

		switch certECDSABits {
		case 256:
			curve = elliptic.P256()

		case 384:
			curve = elliptic.P384()

		case 521:
			curve = elliptic.P521()

		default:
			return nil, fmt.Errorf("unsupported ECDSA curve size: %d",
				certECDSABits)
		}

		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ecdsa key: %w",
				err)
		}

		privateKey = key
		keySize = key.Curve.Params().BitSize

		ecKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type %T",
				key)
		}

		derBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ecdsa private key: %w",
				err)
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

	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock),
		os.FileMode(certPerm)) //nolint:gosec,nolintlint
	if err != nil {
		return nil, fmt.Errorf("failed to write new key: %w",
			err)
	}

	log.Printf("%sNew %s host key (%d-bit) generated at %s",
		keyPrefix(), strings.ToUpper(keyType), keySize, keyPath)

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer from private key: %w",
			err)
	}

	return signer, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConn(rawConn net.Conn, edSigner, rsaSigner, ecdsaSigner ssh.Signer) {
	defer recoverGoroutine("handleConn")

	if rawConn == nil {
		log.Printf("%sError: rawConn is nil in handleConn",
			warnPrefix())

		return
	}

	sid := newSessionID(connections, &connectionsMutex)
	keyLog := []string{}

	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	raddr := rawConn.RemoteAddr()
	if raddr == nil {
		log.Printf("%sError: RemoteAddr() returned nil for rawConn",
			warnPrefix())

		_ = rawConn.Close()

		return
	}

	remoteAddr := raddr.String()

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
				Extensions: map[string]string{
					"auth-method": "password", //nolint:goconst,nolintlint
				},
			}, nil
		},
		PublicKeyCallback: func( //nolint:gosec,nolintlint
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error,
		) {
			line := fmt.Sprintf(
				"VALIDATE [%s] %s@%s %q:%s",
				sid, sanitizeForLog(c.User()), c.RemoteAddr(),
				pubKey.Type(), ssh.FingerprintSHA256(pubKey),
			)

			if !suppressLogs {
				log.Printf("%s%s",
					blueDotPrefix(), line)
			}

			keyLog = append(keyLog, line)

			return &ssh.Permissions{
				Extensions: map[string]string{
					"auth-method": "publickey", //nolint:goconst,nolintlint
				},
			}, errors.New("next key")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error,
		) {
			return &ssh.Permissions{
				Extensions: map[string]string{
					"auth-method": "keyboard-interactive", //nolint:goconst,nolintlint
				},
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

	_ = rawConn.SetDeadline(time.Now().Add(30 * time.Second))

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)

	_ = rawConn.SetDeadline(time.Time{})

	if err != nil {
		sshHandshakeFailedTotal.Add(1)

		log.Printf("%sTEARDOWN [%s] HANDSHAKE FAILED: %v",
			yellowDotPrefix(), sid, err)

		return
	}

	abandonSSH := func() {
		if sshConn == nil {
			return
		}

		go func() {
			defer recoverGoroutine("abandonSSH discard")

			ssh.DiscardRequests(reqs)
		}()

		go func() {
			defer recoverGoroutine("abandonSSH chans drain")

			for newCh := range chans {
				_ = newCh.Reject(ssh.Prohibited, "session not authorized")
			}
		}()

		_ = sshConn.Close()
	}

	teardownInstalled := false

	defer func() {
		if !teardownInstalled {
			abandonSSH()
		}
	}()

	if sshConn.Permissions == nil {
		log.Printf("%sError: sshConn.Permissions [%s] is nil",
			warnPrefix(), sid)

		return
	}

	var authMethod string

	var method string

	if sshConn != nil && sshConn.Permissions != nil && sshConn.Permissions.Extensions != nil {
		method = sshConn.Permissions.Extensions["auth-method"]
	}

	switch method {
	case "password":
		authMethod = "password"

	case "publickey":
		authMethod = "publickey"

	case "keyboard-interactive":
		authMethod = "keyboard-interactive"

	default:
		authMethod = "unknown" //nolint:goconst,nolintlint
	}

	var userName string

	var hostName string

	if sshConn == nil {
		log.Printf("%sError: sshConn nil while building connection for %s",
			warnPrefix(), sid)

		userName = ""
		hostName = ""
	} else {
		userName = sanitizeForLog(sshConn.User())

		addr := sshConn.RemoteAddr()
		if addr == nil {
			log.Printf("%sError: sshConn.RemoteAddr() nil while building connection for %s",
				warnPrefix(), sid)

			hostName = ""
		} else {
			hostName = addr.String()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	conn := &Connection{
		ID:         sid,
		sshConn:    sshConn,
		startTime:  time.Now(),
		cancelCtx:  ctx,
		cancelFunc: cancel,
		userName:   userName,
		hostName:   hostName,
		nawsKick:   make(chan struct{}, 1),
	}

	conn.emacsKeymapEnabled.Store(keymapByDefault)
	conn.lastActivityTime.Store(time.Now().UnixNano())

	if iconv != "" {
		cm := findCharmap(iconv)
		if cm != nil {
			conn.iconvDecoder = cm.NewDecoder()
			conn.iconvEnabled.Store(true)
		}
	}

	defaultHost, defaultPort, err := parseHostPort(telnetHostPort)
	if err != nil {
		log.Printf("%sError parsing default TELNET target: %v",
			warnPrefix(), err)

		return
	}

	conn.target.Store(&targetEndpoint{
		host: defaultHost,
		port: int32(defaultPort), //nolint:gosec
	})

	_, isAltHost := altHosts[conn.userName]
	conn.isDefaultTarget = !isAltHost

	connectionsMutex.Lock()

	conn.shareableUsername = newShareableUsernameLocked()

	existingConn, found := shareableConnections[conn.userName]
	if found {
		conn.monitoring.Store(true)
		conn.monitoredConnection = existingConn
		existingConn.totalMonitors.Add(1)
		existingConn.wasMonitored.Store(true)
	}

	if !found && strings.HasPrefix(conn.userName, "_") &&
		len(conn.userName) == shareableUsernameLen {
		conn.invalidShare = true
	}

	connectionsInFlight.Add(1)

	connections[sid] = conn
	shareableConnections[conn.shareableUsername] = conn

	currentLen := uint64(len(connections))

	connectionsMutex.Unlock()

	defer func() {
		if !teardownInstalled {
			return
		}

		conn.cancelFunc()

		connectionsMutex.Lock()

		sshConnSnapshot := conn.sshConn

		delete(connections, sid)
		delete(shareableConnections, conn.shareableUsername)

		fireShutdown := connectionsInFlight.Add(^uint64(0)) == 0 &&
			gracefulShutdownMode.Load()

		connectionsMutex.Unlock()

		if sshConnSnapshot != nil {
			err := sshConnSnapshot.Close()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Printf("%sError closing SSH connection for %s: %v",
						warnPrefix(), conn.ID, err)
				}
			}
		}

		if fireShutdown {
			shutdownOnce.Do(
				func() {
					close(shutdownSignal)
				},
			)
		}

		const unknownHost = "<UNKNOWN>"

		if !suppressLogs {
			host, _, err := net.SplitHostPort(conn.hostName)
			if err != nil {
				log.Printf(
					"%sTEARDOWN [%s] %s@"+unknownHost,
					yellowDotPrefix(), sid,
					func() string {
						if conn.userName == "" {
							return unknownHost
						}

						return conn.userName
					}(),
				)
			} else {
				log.Printf(
					"%sTEARDOWN [%s] %s@%s",
					yellowDotPrefix(), sid,
					func() string {
						if conn.userName == "" {
							return unknownHost
						}

						return conn.userName
					}(), host,
				)
			}
		}
	}()

	teardownInstalled = true

	for {
		prev := peakUsersTotal.Load()
		if currentLen <= prev {
			break
		}

		if peakUsersTotal.CompareAndSwap(prev, currentLen) {
			break
		}
	}

	if dbEnabled {
		for {
			prev := lifetimePeakUsersTotal.Load()
			if currentLen <= prev {
				break
			}

			if lifetimePeakUsersTotal.CompareAndSwap(prev, currentLen) {
				break
			}
		}
	}

	if !noBanner {
		bannerHost, _, splitErr := net.SplitHostPort(conn.hostName)
		if splitErr != nil {
			bannerHost = conn.hostName
		}

		if bannerHost != "" {
			go func() {
				defer recoverGoroutine("reverse-DNS lookup")

				lookupCtx, lookupCancel := context.WithTimeout(conn.cancelCtx, time.Second)

				defer lookupCancel()

				names, err := net.DefaultResolver.LookupAddr(lookupCtx, bannerHost)
				if err != nil || len(names) == 0 {
					return
				}

				name := strings.TrimSuffix(names[0], ".")
				conn.reverseHost.Store(&name)
			}()
		}
	}

	var addr string

	if sshConn == nil || sshConn.RemoteAddr() == nil {
		log.Printf("%sError: sshConn or its RemoteAddr() is nil",
			warnPrefix())

		addr = ""
	} else {
		addr = sshConn.RemoteAddr().String()
	}

	handshakeLog := fmt.Sprintf(
		"VALIDATE [%s] %s@%s \"ssh\":%s",
		sid,
		func() string {
			if conn.userName == "" {
				return "<UNKNOWN>"
			}

			return conn.userName
		}(), addr, authMethod,
	)

	if !suppressLogs {
		log.Printf("%s%s",
			blueDotPrefix(), handshakeLog)
	}

	keyLog = append(keyLog, handshakeLog)

	go func() {
		defer recoverGoroutine("ssh.DiscardRequests")

		ssh.DiscardRequests(reqs)
	}()

	sessionAccepted := false

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			err := newCh.Reject(
				ssh.UnknownChannelType, "only session allowed",
			)
			if err != nil {
				log.Printf("%sError rejecting channel: %v",
					warnPrefix(), err)
			}

			continue
		}

		if sessionAccepted {
			log.Printf("%sRejecting extra session channel for [%s]",
				warnPrefix(), sid)

			err := newCh.Reject(
				ssh.Prohibited, "only one session per connection",
			)
			if err != nil {
				log.Printf("%sError rejecting extra session channel: %v",
					warnPrefix(), err)
			}

			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}

		sessionAccepted = true

		connectionsMutex.Lock()

		conn.channel = ch

		connectionsMutex.Unlock()

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
		return "", 0, fmt.Errorf("failed to split host port: %w",
			err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %s",
			portStr)
	}

	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range (1-65535): %d",
			port)
	}

	return host, port, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func dialDest(dest string) (net.Conn, error) {
	if isUnixSocket(dest) {
		conn, err := net.Dial("unix", dest)
		if err != nil {
			return nil, fmt.Errorf("failed to dial UNIX domain socket: %w",
				err)
		}

		return conn, nil
	}

	conn, err := net.Dial("tcp", dest)
	if err != nil {
		return nil, fmt.Errorf("failed to dial TCP socket: %w",
			err)
	}

	return conn, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleSession(ctx context.Context, conn *Connection, channel ssh.Channel,
	requests <-chan *ssh.Request, keyLog []string,
) {
	defer recoverGoroutine("handleSession")

	suppressLogs := gracefulShutdownMode.Load() || denyNewConnectionsMode.Load()

	sessionStarted := make(chan bool, 1)

	go func() {
		defer recoverGoroutine("handleSession SSH request loop")

		if debugNegotiation {
			log.Printf("%sDEBUG: starting SSH request loop for %s",
				blueDotPrefix(), conn.ID)
		}

		for req := range requests {
			if debugNegotiation {
				log.Printf("%sDEBUG: SSH request received for %s: %s (want reply: %v)",
					blueDotPrefix(), conn.ID, req.Type, req.WantReply)
			}

			switch req.Type {
			case "pty-req":
				if len(req.Payload) >= 4 {
					termLen := binary.BigEndian.Uint32(req.Payload[0:4])
					payloadLen := uint64(len(req.Payload))

					if payloadLen >= 4+uint64(termLen) {
						termLenInt := int(termLen)
						term := sanitizeForLog(string(req.Payload[4 : 4+termLenInt]))
						conn.termType.Store(&term)

						if payloadLen >= 4+uint64(termLen)+8 {
							off := 4 + termLenInt
							width := binary.BigEndian.Uint32(req.Payload[off : off+4])
							height := binary.BigEndian.Uint32(req.Payload[off+4 : off+8])

							conn.initialWindow.Store(&nawsSize{width: width, height: height})

							if hasTelnetConn(conn) {
								nawsWill := []byte{TelcmdIAC, TelcmdWILL, TeloptNAWS}

								if debugNegotiation {
									log.Printf("%sDEBUG: offering NAWS to TELNET target for %s",
										blueDotPrefix(), conn.ID)
								}

								_, err := telnetWrite(conn, nawsWill)
								if err != nil {
									log.Printf(
										"%sError sending IAC WILL NAWS to TELNET target for %s: %v",
										warnPrefix(), conn.ID, err,
									)
								}
							}
						}
					} else if debugNegotiation {
						log.Printf("%sDEBUG: pty-req payload too short for TERM (%d) for %s: %d",
							warnPrefix(), termLen, conn.ID, len(req.Payload))
					}
				} else if debugNegotiation {
					log.Printf("%sDEBUG: pty-req payload too short for %s: %d < 4",
						warnPrefix(), conn.ID, len(req.Payload))
				}

				err := req.Reply(true, nil)
				if err != nil {
					log.Printf("%sError replying to pty-req for %s: %v",
						warnPrefix(), conn.ID, err)
				}

			case "window-change":
				if debugNegotiation {
					log.Printf("%sDEBUG: window-change received for %s",
						blueDotPrefix(), conn.ID)
				}

				if len(req.Payload) == 16 {
					width := binary.BigEndian.Uint32(req.Payload[:4])
					height := binary.BigEndian.Uint32(req.Payload[4:8])

					if debugNegotiation {
						log.Printf("%sDEBUG: window-change payload for %s: width=%d, height=%d",
							blueDotPrefix(), conn.ID, width, height)
					}

					err := req.Reply(true, nil)
					if err != nil {
						log.Printf("%sError replying to window-change request for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					if hasTelnetConn(conn) {
						kickNaws(conn, width, height)
					}
				} else {
					if debugNegotiation {
						log.Printf("%sDEBUG: window-change payload size mismatch for %s: %d != 16",
							warnPrefix(), conn.ID, len(req.Payload))
					}

					err := req.Reply(false, nil)
					if err != nil {
						log.Printf("%sError replying to window-change request (failure) for %s: %v",
							warnPrefix(), conn.ID, err)
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
					if conn.sshConn == nil {
						log.Printf("%sREJECTED [%s] (Illegal request: exec)",
							redDotPrefix(), conn.ID)
					} else {
						addr := conn.sshConn.RemoteAddr()
						if addr == nil {
							log.Printf("%sREJECTED [%s] (Illegal request: exec)",
								redDotPrefix(), conn.ID)
						} else {
							log.Printf("%sREJECTED [%s] %s (Illegal request: exec)",
								redDotPrefix(), conn.ID, addr.String())
						}
					}
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

				if conn.sshConn == nil {
					log.Printf("%sError: sshConn is nil for connection %s",
						warnPrefix(), conn.ID)
				} else {
					err = conn.sshConn.Close()
					if err != nil {
						log.Printf("%sError closing SSH connection for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}

			case "subsystem":
				if len(req.Payload) >= 4 {
					subsystemLen := binary.BigEndian.Uint32(req.Payload[0:4])
					payloadLen := uint64(len(req.Payload))

					if payloadLen >= 4+uint64(subsystemLen) {
						subsystemLenInt := int(subsystemLen)
						subsystem := string(req.Payload[4 : 4+subsystemLenInt])

						if subsystem == "sftp" {
							if !suppressLogs {
								if conn.sshConn == nil {
									log.Printf("%sREJECTED [%s] (Illegal request: SFTP)",
										redDotPrefix(), conn.ID)
								} else {
									addr := conn.sshConn.RemoteAddr()
									if addr == nil {
										log.Printf("%sREJECTED [%s] (Illegal request: SFTP)",
											redDotPrefix(), conn.ID)
									} else {
										log.Printf("%sREJECTED [%s] %s (Illegal request: SFTP)",
											redDotPrefix(), conn.ID, addr.String())
									}
								}
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

							if conn.sshConn == nil {
								log.Printf("%sError: sshConn is nil for connection %s",
									warnPrefix(), conn.ID)
							} else {
								err = conn.sshConn.Close()
								if err != nil {
									log.Printf("%sError closing SSH connection for %s: %v",
										warnPrefix(), conn.ID, err)
								}
							}

							continue
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
		if debugNegotiation {
			log.Printf("%sDEBUG: session start signal received for %s (proceed=%v)",
				blueDotPrefix(), conn.ID, proceed)
		}

		if !proceed {
			return
		}

	case <-time.After(2 * time.Second):
		sshRequestTimeoutTotal.Add(1)

		if debugNegotiation {
			log.Printf("%sDEBUG: session start timeout for %s",
				warnPrefix(), conn.ID)
		}

		if !suppressLogs {
			remoteAddr := "unknown"

			if conn.sshConn != nil {
				addr := conn.sshConn.RemoteAddr()
				if addr != nil {
					remoteAddr = addr.String()
				}
			}

			log.Printf("%sTEARDOWN [%s] %s (Timeout waiting for session request)",
				yellowDotPrefix(), conn.ID, remoteAddr)
		}

		if conn.sshConn != nil {
			err := conn.sshConn.Close()
			if err != nil {
				log.Printf("%sError closing SSH connection for %s: %v",
					warnPrefix(), conn.ID, err)
			}
		}

		return
	}

	var remoteAddrStr string

	if conn.sshConn != nil {
		addr := conn.sshConn.RemoteAddr()
		if addr != nil {
			remoteAddrStr = addr.String()
		}
	}

	remoteHost, _, err := net.SplitHostPort(remoteAddrStr)
	if err != nil {
		remoteHost = remoteAddrStr
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

		if conn.sshConn != nil {
			err = conn.sshConn.Close()
			if err != nil {
				log.Printf("%sError closing SSH connection for %s: %v",
					warnPrefix(), conn.ID, err)
			}
		}

		return
	}

	networksMutex.RLock()

	blacklistSnapshot := blacklistedNetworks
	whitelistSnapshot := whitelistedNetworks

	networksMutex.RUnlock()

	var rejectedByRule string

	for _, ipNet := range blacklistSnapshot {
		if ipNet.Contains(clientIP) {
			rejectedByRule = ipNet.String()

			break
		}
	}

	if rejectedByRule != "" {
		var exemptedByRule string

		for _, ipNet := range whitelistSnapshot {
			if ipNet.Contains(clientIP) {
				exemptedByRule = ipNet.String()

				break
			}
		}

		if exemptedByRule != "" {
			if !suppressLogs {
				remoteAddrStr := "unknown"

				if conn.sshConn != nil {
					addr := conn.sshConn.RemoteAddr()
					if addr != nil {
						remoteAddrStr = addr.String()
					}
				}

				log.Printf("%sEXEMPTED [%s] %s (matched %s)",
					greenHeartPrefix(), conn.ID,
					remoteAddrStr, exemptedByRule)
			}

			exemptedTotal.Add(1)
		} else {
			if !suppressLogs {
				remoteAddrStr := "unknown"

				if conn.sshConn != nil {
					addr := conn.sshConn.RemoteAddr()
					if addr != nil {
						remoteAddrStr = addr.String()
					}
				}

				log.Printf("%sREJECTED [%s] %s (matched %s)",
					redDotPrefix(), conn.ID,
					remoteAddrStr, rejectedByRule)
			}

			rejectedTotal.Add(1)

			raw, err := getFileContent(blockFile, conn.userName)
			if err == nil {
				blockMessageContent := strings.ReplaceAll(
					strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n",
				)

				_, err := channel.Write(
					[]byte(blockMessageContent + "\r\n"),
				)
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}
			} else {
				_, err := channel.Write(
					[]byte("Connection blocked.\r\n"),
				)
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

			if conn.sshConn != nil {
				err = conn.sshConn.Close()
				if err != nil {
					log.Printf("%sError closing SSH connection for %s: %v",
						warnPrefix(), conn.ID, err)
				}
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

					if conn.sshConn != nil {
						err := conn.sshConn.Close()
						if err != nil {
							if !strings.Contains(err.Error(), "use of closed network connection") {
								log.Printf("%sError closing SSH connection for %s: %v",
									warnPrefix(), conn.ID, err)
							}
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

				if conn.sshConn != nil {
					err := conn.sshConn.Close()
					if err != nil {
						if !strings.Contains(err.Error(), "use of closed network connection") {
							log.Printf("%sError closing SSH connection for %s: %v",
								warnPrefix(), conn.ID, err)
						}
					}
				}

				return
			}

			log.Printf("%sError clearing delay spinner from channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}

	sshSessionsTotal.Add(1)

	if conn.monitoring.Load() {
		monitorSessionsTotal.Add(1)

		if !suppressLogs {
			monitoredConnectionID := ""
			if conn.monitoredConnection != nil {
				monitoredConnectionID = conn.monitoredConnection.ID
			}

			log.Printf("%sUMONITOR [%s] %s -> %s",
				greenDotPrefix(), conn.ID, conn.userName, monitoredConnectionID)
		}

		go func() {
			defer recoverGoroutine("monitor Ctrl-] reader")

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

		var monitoredDone <-chan struct{}

		var ownDone <-chan struct{}

		if conn.monitoredConnection != nil && conn.monitoredConnection.cancelCtx != nil {
			monitoredDone = conn.monitoredConnection.cancelCtx.Done()
		}

		if ctx != nil {
			ownDone = ctx.Done()
		}

		if monitoredDone != nil || ownDone != nil {
			select {
			case <-monitoredDone:

			case <-ownDone:
			}
		}

		dur := time.Since(conn.startTime)

		closingNotice := fmt.Appendf(nil,
			"\r\nMONITORING SESSION CLOSED (monitored for %s)\r\n\r\n",
			dur.Round(time.Second))

		writeDone := make(chan struct{})

		go func(ch ssh.Channel) {
			defer recoverGoroutine("monitor closing notice")
			defer close(writeDone)

			_, _ = ch.Write(closingNotice)
		}(channel)

		select {
		case <-writeDone:

		case <-time.After(time.Second):
			log.Printf(
				"%sMonitor closing notice timed out for %s",
				warnPrefix(), conn.ID,
			)
		}

		err := channel.Close()
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
				strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n",
			)

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
			strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n",
		)

		_, err := channel.Write([]byte(txt + "\r\n"))
		if err != nil {
			log.Printf("%sError writing to channel for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}

	start := time.Now()

	var sshIn, sshOut, telnetIn, telnetOut atomic.Uint64

	var logfile *os.File

	var logwriter io.Writer

	var basePath string

	if !noLog {
		var remoteAddr net.Addr
		if conn.sshConn != nil {
			remoteAddr = conn.sshConn.RemoteAddr()
		}

		logfile, basePath, err = createDatedLog(conn.ID, remoteAddr)
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

		logwriter = logfile

		loggingWg.Add(1)

		defer loggingWg.Done()

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

		_, err := logwriter.Write(
			[]byte(nowStamp() + " Session start\r\n"),
		)
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
	} else {
		logwriter = io.Discard
	}

	var targetDest string

	if conn.isDefaultTarget {
		targetDest = telnetHostPort
	} else {
		targetDest = altHosts[conn.userName]
	}

	targetHost, targetPort, err := parseHostPort(targetDest)
	if err != nil {
		var errMsg string

		sanitizedErrStr := sanitizeNonASCII(err.Error())
		if !conn.isDefaultTarget {
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

	if !conn.isDefaultTarget {
		altHostRoutesTotal.Add(1)

		log.Printf("%sALTROUTE [%s] %s -> %s",
			greenDotPrefix(), conn.ID, conn.userName, targetDest)
	}

	conn.target.Store(&targetEndpoint{
		host: targetHost,
		port: int32(targetPort), //nolint:gosec
	})

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

	conn.telnetWriteMutex.Lock()

	conn.telnetConn = remote

	conn.telnetWriteMutex.Unlock()

	go nawsSender(conn)

	telnetReader := bufio.NewReader(remote)

	go func() {
		defer recoverGoroutine("ctx-watcher")

		if ctx != nil {
			<-ctx.Done()
		}

		_ = remote.Close()
	}()

	defer func() {
		err := remote.Close()
		if err != nil {
			log.Printf("%sError closing remote connection for %s: %v",
				warnPrefix(), conn.ID, err)
		}
	}()

	negotiateTelnet(telnetReader, remote, channel, logwriter, conn)

	var width, height uint32
	if sz := conn.initialWindow.Load(); sz != nil {
		width = sz.width
		height = sz.height
	}

	if conn.nawsActive.Load() && width > 0 && height > 0 {
		conn.nawsPending.CompareAndSwap(nil, &nawsSize{width: width, height: height})

		select {
		case conn.nawsKick <- struct{}{}:

		default:
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer recoverGoroutine("SSH-to-TELNET pump")
		defer conn.cancelFunc()

		var menuMode bool

		var escSequence []byte

		var escTimer <-chan time.Time

		reader := bufio.NewReader(channel)

		byteChan := make(chan byte)
		errorChan := make(chan error)

		go func() {
			defer recoverGoroutine("SSH byte reader")
			defer conn.cancelFunc()

			var done <-chan struct{}
			if ctx != nil {
				done = ctx.Done()
			}

			for {
				b, err := reader.ReadByte()
				if err != nil {
					select {
					case errorChan <- err:

					case <-done:
					}

					return
				}

				select {
				case byteChan <- b:

				case <-done:
					return
				}
			}
		}()

		for {
			select {
			case <-func() <-chan struct{} {
				if ctx == nil {
					return nil
				}

				return ctx.Done()
			}():
				if len(escSequence) > 0 {
					m, err := telnetWrite(conn, escapeIACOutbound(escSequence))
					if err != nil {
						log.Printf("%sError writing to remote for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

					trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

					_, err = logwriter.Write(escSequence)
					if err != nil {
						log.Printf("%sError writing to log for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}

				return

			case <-escTimer:
				m, err := telnetWrite(conn, escapeIACOutbound(escSequence))
				if err != nil {
					log.Printf("%sError writing to remote for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

				trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

				_, err = logwriter.Write(escSequence)
				if err != nil {
					log.Printf("%sError writing to log for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				escSequence = nil
				escTimer = nil

			case b := <-byteChan:
				conn.lastActivityTime.Store(time.Now().UnixNano())

				sshIn.Add(1)

				if menuMode {
					handleMenuSelection(b, conn, channel, logwriter,
						&sshIn, &sshOut, &telnetIn, &telnetOut, start)

					menuMode = false

					continue
				}

				if !noMenu && b == 0x1d { // Ctrl-]
					showMenu(channel)

					menuMode = true
					escSequence = nil
					escTimer = nil

					continue
				}

				if len(escSequence) > 0 { //nolint:gocritic
					escSequence = append(escSequence, b)
					if conn.emacsKeymapEnabled.Load() {
						replacement, ok := emacsKeymap[string(escSequence)]
						if ok {
							m, err := telnetWrite(conn, escapeIACOutbound([]byte(replacement)))
							if err != nil {
								log.Printf("%sError writing to remote for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

							trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

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
							m, err := telnetWrite(conn, escapeIACOutbound(escSequence))
							if err != nil {
								log.Printf("%sError writing to remote for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

							trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

							_, err = logwriter.Write(escSequence)
							if err != nil {
								log.Printf("%sError writing to log for %s: %v",
									warnPrefix(), conn.ID, err)
							}

							escSequence = nil
							escTimer = nil
						}
					} else {
						m, err := telnetWrite(conn, escapeIACOutbound(escSequence))
						if err != nil {
							log.Printf("%sError writing to remote for %s: %v",
								warnPrefix(), conn.ID, err)
						}

						telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

						trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

						_, err = logwriter.Write(escSequence)
						if err != nil {
							log.Printf("%sError writing to log for %s: %v",
								warnPrefix(), conn.ID, err)
						}

						escSequence = nil
						escTimer = nil
					}
				} else if b == 0x1b && conn.emacsKeymapEnabled.Load() {
					escSequence = append(escSequence, b)
					escTimer = time.After(50 * time.Millisecond)
				} else {
					m, err := telnetWrite(conn, escapeIACOutbound([]byte{b}))
					if err != nil {
						log.Printf("%sError writing to remote for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

					trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

					_, err = logwriter.Write([]byte{b})
					if err != nil {
						log.Printf("%sError writing to log for %s: %v",
							warnPrefix(), conn.ID, err)
					}
				}

			case err := <-errorChan:
				if len(escSequence) > 0 {
					m, err := telnetWrite(conn, escapeIACOutbound(escSequence))
					if err != nil {
						log.Printf("%sError writing to remote for %s: %v",
							warnPrefix(), conn.ID, err)
					}

					telnetOut.Add(uint64(m)) //nolint:gosec,nolintlint

					trafficOutTotal.Add(uint64(m)) //nolint:gosec,nolintlint

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
		defer recoverGoroutine("TELNET-to-SSH pump")
		defer conn.cancelFunc()

		buf := make([]byte, 1024)

		for {
			err := remote.SetReadDeadline(
				time.Now().Add(100 * time.Millisecond),
			)
			if err != nil {
				log.Printf("%sError setting read deadline for %s: %v",
					warnPrefix(), conn.ID, err)
			}

			n, err := telnetReader.Read(buf)
			trafficInTotal.Add(uint64(n)) //nolint:gosec,nolintlint

			if err != nil {
				var netErr net.Error

				if errors.As(err, &netErr) && netErr.Timeout() {
					select {
					case <-func() <-chan struct{} {
						if ctx == nil {
							return nil
						}

						return ctx.Done()
					}():
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

				secs := dur.Seconds()

				var inRateSSH, outRateSSH, inRateNVT, outRateNVT uint64

				if secs > 0 {
					inRateSSH = uint64(float64(sshIn.Load()) / secs)
					outRateSSH = uint64(float64(sshOut.Load()) / secs)
					inRateNVT = uint64(float64(telnetIn.Load()) / secs)
					outRateNVT = uint64(float64(telnetOut.Load()) / secs)
				}

				_, err = channel.Write(fmt.Appendf(nil,
					">> SSH - in: %s, out: %s, in-rate: %s/s, out-rate: %s/s\r\n",
					formatBytes(sshIn.Load()),
					formatBytes(sshOut.Load()),
					formatBytes(inRateSSH),
					formatBytes(outRateSSH)))
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				_, err = channel.Write(fmt.Appendf(nil,
					">> NVT - in: %s, out: %s, in-rate: %s/s, out-rate: %s/s\r\n",
					formatBytes(telnetIn.Load()),
					formatBytes(telnetOut.Load()),
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

				return
			}

			if n > 0 {
				telnetIn.Add(uint64(n)) //nolint:gosec,nolintlint

				iconvActive := conn.iconvEnabled.Load() && conn.iconvDecoder != nil
				fwd := buf[:n]

				if !noFilter {
					fwd = bytes.ReplaceAll(fwd, []byte{0}, []byte{})
				}

				if iconvActive {
					fwd = decodeTelnetData(conn.iconvDecoder, fwd)
				}

				sshOut.Add(uint64(len(fwd)))

				_, err := channel.Write(fwd)
				if err != nil {
					log.Printf("%sError writing to channel for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				var monitors []ssh.Channel

				connectionsMutex.Lock()
				for _, c := range connections {
					if c.monitoring.Load() {
						if c.monitoredConnection == nil {
							log.Printf("%sError: monitoredConnection is nil for %s",
								warnPrefix(), c.ID)

							continue
						}

						if c.monitoredConnection.ID == conn.ID {
							monitors = append(monitors, c.channel)
						}
					}
				}
				connectionsMutex.Unlock()

				if len(monitors) > 0 {
					fwdCopy := make([]byte, len(fwd))
					copy(fwdCopy, fwd)

					var mwg sync.WaitGroup

					for _, monCh := range monitors {
						mwg.Add(1)

						go func(ch ssh.Channel) {
							defer mwg.Done()
							defer recoverGoroutine("monitor fan-out")

							writeDone := make(chan error, 1)

							go func() {
								defer close(writeDone)
								defer recoverGoroutine("monitor write")

								_, err := ch.Write(fwdCopy)
								writeDone <- err
							}()

							select {
							case err, ok := <-writeDone:
								if !ok {
									log.Printf(
										"%sMonitor write recovered from panic; closing monitor",
										warnPrefix(),
									)

									_ = ch.Close()
								} else if err != nil {
									log.Printf("%sError writing to monitor channel: %v",
										warnPrefix(), err)
								}

							case <-time.After(time.Second):
								log.Printf(
									"%sMonitor channel write timed out; closing slow monitor",
									warnPrefix(),
								)

								_ = ch.Close()

								<-writeDone
							}
						}(monCh)
					}

					mwg.Wait()
				}

				if iconvActive {
					_, err = logwriter.Write(fwd)
				} else {
					_, err = logwriter.Write(buf[:n])
				}

				if err != nil {
					log.Printf("%sError writing to log for %s: %v",
						warnPrefix(), conn.ID, err)
				}

				conn.lastActivityTime.Store(time.Now().UnixNano())
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

	var addrStr string

	if sshConn != nil {
		a := sshConn.RemoteAddr()
		if a != nil {
			addrStr = a.String()
		}
	}

	host, _, _ := net.SplitHostPort(addrStr)
	if host == "" {
		host = addrStr
	}

	var origin string

	if p := conn.reverseHost.Load(); p != nil && *p != "" {
		origin = fmt.Sprintf("%s [%s]",
			*p, host)
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

	if conn.monitoring.Load() {
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
		_, err := fmt.Fprint(ch,
			"That session-share username is not active.\r\n")
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

func negotiateTelnet(r *bufio.Reader, remote net.Conn, ch ssh.Channel, logw io.Writer,
	conn *Connection,
) {
	type telnetState struct {
		weWill   bool
		theyWill bool
	}

	telnetStates := make(map[byte]*telnetState)

	supportedOptions := map[byte]bool{
		TeloptBinary:          true,
		TeloptEcho:            true,
		TeloptNAWS:            true,
		TeloptSuppressGoAhead: true,
		TeloptTTYPE:           true,
	}

	// Proactively negotiate options we support
	for opt, supported := range supportedOptions {
		if supported {
			if opt == TeloptEcho {
				continue
			}

			state := &telnetState{weWill: true}
			telnetStates[opt] = state

			sendIAC(conn, TelcmdWILL, opt)
			writeNegotiation(ch, logw,
				"[SENT "+cmdName(TelcmdWILL)+" "+optName(opt)+"]",
				conn.userName)

			if opt == TeloptBinary || opt == TeloptSuppressGoAhead {
				state.weWill = true

				sendIAC(conn, TelcmdDO, opt)
				writeNegotiation(ch, logw,
					"[SENT "+cmdName(TelcmdDO)+" "+optName(opt)+"]",
					conn.userName)
			}
		}
	}

	err := remote.SetReadDeadline(time.Now().Add(time.Second))
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

	for {
		b, err := r.ReadByte()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				break
			}

			return
		}

		trafficInTotal.Add(1)

		if b == TelcmdIAC {
			b2, err := r.ReadByte()
			if err != nil {
				return
			}

			trafficInTotal.Add(1)

			switch b2 {
			case TelcmdWILL, TelcmdWONT, TelcmdDO, TelcmdDONT:
				b3, err := r.ReadByte()
				if err != nil {
					return
				}

				trafficInTotal.Add(1)

				cmd, opt := b2, b3
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

							sendIAC(conn, TelcmdDO, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdDO)+" "+optName(opt)+"]",
								conn.userName)
						}
					} else {
						sendIAC(conn, TelcmdDONT, opt)
						writeNegotiation(ch, logw,
							"[SENT "+cmdName(TelcmdDONT)+" "+optName(opt)+"]",
							conn.userName)
					}

				case TelcmdWONT:
					if state.theyWill {
						state.theyWill = false

						sendIAC(conn, TelcmdDONT, opt)
						writeNegotiation(ch, logw,
							"[SENT "+cmdName(TelcmdDONT)+" "+optName(opt)+"]",
							conn.userName)
					}

				case TelcmdDO:
					if opt == TeloptNAWS { //nolint:gocritic
						if !conn.nawsActive.Load() {
							conn.nawsActive.Store(true)

							if debugNegotiation {
								log.Printf("%sDEBUG: NAWS activated for %s",
									blueDotPrefix(), conn.ID)
							}
						}

						sendIAC(conn, TelcmdWILL, opt)
						writeNegotiation(ch, logw,
							"[SENT "+cmdName(TelcmdWILL)+" "+optName(opt)+"]",
							conn.userName)
					} else if supportedOptions[opt] {
						if !state.weWill {
							state.weWill = true

							sendIAC(conn, TelcmdWILL, opt)
							writeNegotiation(ch, logw,
								"[SENT "+cmdName(TelcmdWILL)+" "+optName(opt)+"]",
								conn.userName)
						}
					} else {
						sendIAC(conn, TelcmdWONT, opt)
						writeNegotiation(ch, logw,
							"[SENT "+cmdName(TelcmdWONT)+" "+optName(opt)+"]",
							conn.userName)
					}

				case TelcmdDONT:
					if state.weWill {
						state.weWill = false

						sendIAC(conn, TelcmdWONT, opt)
						writeNegotiation(ch, logw,
							"[SENT "+cmdName(TelcmdWONT)+" "+optName(opt)+"]",
							conn.userName)
					}
				}

			case TelcmdSB:
				opt, err := r.ReadByte()
				if err != nil {
					return
				}

				trafficInTotal.Add(1)

				const subDataMax = 4096

				var subData []byte

				for {
					b4, err := r.ReadByte()
					if err != nil {
						return
					}

					trafficInTotal.Add(1)

					if b4 == TelcmdIAC {
						b5, err := r.ReadByte()
						if err != nil {
							return
						}

						trafficInTotal.Add(1)

						if b5 == TelcmdSE {
							break
						}

						if b5 == TelcmdIAC && len(subData) < subDataMax {
							subData = append(subData, TelcmdIAC)
						}
					} else if len(subData) < subDataMax {
						subData = append(subData, b4)
					}
				}

				writeNegotiation(ch, logw,
					"[RCVD SB "+optName(opt)+" ... IAC SE]", conn.userName)

				if supportedOptions[opt] && opt == TeloptTTYPE &&
					len(subData) > 0 && subData[0] == TelnetSend {
					var termType string
					if p := conn.termType.Load(); p != nil {
						termType = *p
					}

					if termType != "" {
						data := make([]byte, 0, 4+len(termType)+2)
						data = append(data, TelcmdIAC, TelcmdSB, TeloptTTYPE, TelnetIs)
						data = append(data, []byte(termType)...)
						data = append(data, TelcmdIAC, TelcmdSE)

						_, err := telnetWrite(conn, data)
						if err != nil {
							log.Printf("%sError writing TELNET TTYPE response: %v",
								warnPrefix(), err)
						}

						writeNegotiation(ch, logw,
							"[SENT SB "+optName(TeloptTTYPE)+" IS "+
								termType+" IAC SE]", conn.userName)
					} else {
						sendIAC(conn, TelcmdWONT, TeloptTTYPE)
						writeNegotiation(ch, logw,
							"[SENT WONT "+optName(TeloptTTYPE)+"]", conn.userName)
					}
				}

			case TelcmdIAC: // Escaped IAC
				data := []byte{TelcmdIAC}
				if conn.iconvEnabled.Load() && conn.iconvDecoder != nil {
					decoded, _, err := transform.Bytes(conn.iconvDecoder, data)
					if err == nil {
						data = decoded
					}
				}

				_, _ = ch.Write(data)
				_, _ = logw.Write(data)

			default:
				// Skip other IAC commands
			}
		} else {
			data := []byte{b}
			if conn.iconvEnabled.Load() && conn.iconvDecoder != nil {
				decoded, _, err := transform.Bytes(conn.iconvDecoder, data)
				if err == nil {
					data = decoded
				}
			}

			_, _ = ch.Write(data)
			_, _ = logw.Write(data)
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

func telnetWrite(conn *Connection, p []byte) (int, error) {
	conn.telnetWriteMutex.Lock()
	defer conn.telnetWriteMutex.Unlock()

	remote := conn.telnetConn
	if remote == nil {
		return 0, errors.New("telnet connection not established")
	}

	_ = remote.SetWriteDeadline(time.Now().Add(time.Second))

	defer func() {
		_ = remote.SetWriteDeadline(time.Time{})
	}()

	n, err := remote.Write(p)
	if err != nil {
		return n, fmt.Errorf("telnet write failed: %w", err)
	}

	return n, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func hasTelnetConn(conn *Connection) bool {
	conn.telnetWriteMutex.Lock()
	defer conn.telnetWriteMutex.Unlock()

	return conn.telnetConn != nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sendIAC(conn *Connection, cmd byte, opts ...byte) {
	data := make([]byte, 0, 2+len(opts))
	data = append(data, TelcmdIAC, cmd)
	data = append(data, opts...)

	_, err := telnetWrite(conn, data)
	if err != nil {
		log.Printf("%sError writing TELNET IAC command for %s: %v",
			warnPrefix(), conn.ID, err)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func escapeIACOutbound(p []byte) []byte {
	if bytes.IndexByte(p, TelcmdIAC) < 0 {
		return p
	}

	out := make([]byte, 0, len(p)+1)
	for _, b := range p {
		out = append(out, b)
		if b == TelcmdIAC {
			out = append(out, TelcmdIAC)
		}
	}

	return out
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

func subSatU64(a uint64, subs ...uint64) uint64 {
	for _, s := range subs {
		if s >= a {
			return 0
		}

		a -= s
	}

	return a
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
		"\r +=====+=================+ \r\n"

	if iconv != "" {
		menu += "\r |  C  | Toggle Charmap  | \r\n"
	}

	menu += "\r |  K  | Toggle Keymap   | \r\n" +
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

func handleMenuSelection(sel byte, conn *Connection, ch ssh.Channel,
	logw io.Writer, sshIn, sshOut, telnetIn, telnetOut *atomic.Uint64, start time.Time,
) {
	switch sel {
	case '0':
		_, err := telnetWrite(conn, []byte{0})
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
		sendIAC(conn, TelcmdAYT)

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
		sendIAC(conn, TelcmdBreak)

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
		sendIAC(conn, TelcmdIP)

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

	case 'c', 'C':
		if iconv != "" {
			newIconv := atomicToggleBool(&conn.iconvEnabled)

			if newIconv {
				_, err := ch.Write([]byte("\r\n>> Character map conversion ENABLED\r\n"))
				if err != nil {
					log.Printf("%s"+
						"Error writing 'Character map conversion ENABLED' message to channel: %v",
						warnPrefix(), err)
				}
			} else {
				_, err := ch.Write([]byte("\r\n>> Character map conversion DISABLED\r\n"))
				if err != nil {
					log.Printf("%s"+
						"Error writing 'Character map conversion DISABLED' message to channel: %v",
						warnPrefix(), err)
				}
			}

			_, err := ch.Write([]byte("\r\n[BACK TO HOST]\r\n"))
			if err != nil {
				log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
					warnPrefix(), err)
			}
		}

	case 'k', 'K':
		newKeymap := atomicToggleBool(&conn.emacsKeymapEnabled)

		if newKeymap {
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
		sendIAC(conn, TelcmdNOP)

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

		if conn.wasMonitored.Load() {
			connectionsMutex.Lock()

			currentMonitors := 0

			for _, c := range connections {
				if c.monitoring.Load() {
					if c.monitoredConnection == nil {
						log.Printf("%sError: monitoredConnection is nil for %s",
							warnPrefix(), c.ID)

						continue
					}

					if c.monitoredConnection.ID == conn.ID {
						currentMonitors++
					}
				}
			}

			connectionsMutex.Unlock()

			totalMonitors := conn.totalMonitors.Load()

			timesStr := "times"
			if totalMonitors == 1 {
				timesStr = "time"
			}

			userStr := "users"
			if currentMonitors == 1 {
				userStr = "user"
			}

			_, err := ch.Write(fmt.Appendf(nil,
				">> MON - Shared session has been viewed %d %s; %d %s currently online.\r\n",
				totalMonitors, timesStr, currentMonitors, userStr))
			if err != nil {
				log.Printf("%sError writing shared session information to channel: %v",
					warnPrefix(), err)
			}
		}

		inSSH := sshIn.Load()
		outSSH := sshOut.Load()
		inNVT := telnetIn.Load()
		outNVT := telnetOut.Load()

		secs := dur.Seconds()

		var inRateSSH, outRateSSH, inRateNVT, outRateNVT uint64

		if secs > 0 {
			inRateSSH = uint64(float64(sshIn.Load()) / secs)
			outRateSSH = uint64(float64(sshOut.Load()) / secs)
			inRateNVT = uint64(float64(telnetIn.Load()) / secs)
			outRateNVT = uint64(float64(telnetOut.Load()) / secs)
		}

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

		if conn.iconvEnabled.Load() && iconv != "" {
			_, err = ch.Write(fmt.Appendf(nil,
				">> CNV - Character map \"%s\" to UTF-8 conversion enabled.\r\n",
				iconv))
			if err != nil {
				log.Printf("%sError writing character map conversion status to channel: %v",
					warnPrefix(), err)
			}
		}

		keymapStatus := ""

		if conn.emacsKeymapEnabled.Load() {
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
			log.Printf("%sError writing '[BACK TO HOST]' message after link time to channel: %v",
				warnPrefix(), err)
		}

	case 'x', 'X':
		_, err := ch.Write([]byte("\r\n>> DISCONNECTING...\r\n"))
		if err != nil {
			log.Printf("%sError writing 'DISCONNECTING...' message to channel: %v",
				warnPrefix(), err)
		}

		err = ch.Close()
		if err != nil {
			log.Printf("%sError closing channel: %v",
				warnPrefix(), err)
		}

		if conn.cancelFunc != nil {
			conn.cancelFunc()
		}

		if conn.sshConn != nil {
			closeErr := conn.sshConn.Close()
			if closeErr != nil &&
				!strings.Contains(closeErr.Error(), "use of closed network connection") {
				log.Printf("%sError closing SSH connection on disconnect: %v",
					warnPrefix(), closeErr)
			}
		}

	case ']':
		_, err := telnetWrite(conn, []byte{0x1d})
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
			log.Printf("%sError writing '[BACK TO HOST]' message to channel: %v",
				warnPrefix(), err)
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func createDatedLog(sid string, addr net.Addr) (*os.File, string, error) {
	addrStr := "unknown"
	if addr != nil {
		addrStr = addr.String()
	}

	host, _, _ := net.SplitHostPort(addrStr)
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

	err := os.MkdirAll(dir, os.FileMode(logDirPerm)) //nolint:gosec,nolintlint
	if err != nil {
		return nil, "", fmt.Errorf("failed to create log directory: %w",
			err)
	}

	dir = filepath.Join(dir, ipDir)

	err = os.MkdirAll(dir, os.FileMode(logDirPerm)) //nolint:gosec,nolintlint
	if err != nil {
		return nil, "", fmt.Errorf("failed to create log subdirectory: %w",
			err)
	}

	ts := now.Format("150405")

	files, readErr := os.ReadDir(dir)
	if readErr != nil {
		log.Printf("%sWarning: failed to read log directory %q: %v",
			warnPrefix(), dir, readErr)
	}

	maxSeq := 0
	prefix := ts + "_" + sid + "_"

	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			parts := strings.SplitN(f.Name()[len(prefix):], ".", 2)
			if parts == nil {
				if enableGops {
					gopsClose()
				}

				panic("internal error: SplitN returned nil (impossible)")
			}

			n, err := strconv.Atoi(parts[0])
			if err == nil && n > maxSeq {
				maxSeq = n
			}
		}
	}

	seq := maxSeq + 1

	var (
		f        *os.File
		pathBase string
	)

	for range 100 {
		base := fmt.Sprintf("%s_%s_%d",
			ts, sid, seq)
		pathBase = filepath.Join(dir, base)

		flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND | os.O_EXCL

		f, err = os.OpenFile(pathBase+".log", flags, //nolint:gosec,nolintlint
			os.FileMode(logPerm)) //nolint:gosec,nolintlint
		if err == nil {
			break
		}

		if !errors.Is(err, os.ErrExist) {
			return nil, "", fmt.Errorf("failed to open log file: %w",
				err)
		}

		seq++
	}

	if f == nil {
		return nil, "", fmt.Errorf("could not find unique log filename after 100 attempts in %q",
			dir)
	}

	return f, pathBase, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func closeAndCompressLog(logfile *os.File, logFilePath string) {
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
			panic(fmt.Sprintf("rand.Read failed generating session ID: %v",
				err))
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

// newShareableUsernameLocked must be called with connectionsMutex held;
// it returns a unique shareable username that does not collide with any
// existing entry in shareableConnections.
func newShareableUsernameLocked() string {
	const chars = "cdhkmnprswxyzCDFGJKMNPRSTXY57"

	for {
		b := make([]byte, shareableUsernameRandomLen)

		_, err := rand.Read(b)
		if err != nil {
			panic(fmt.Sprintf("rand.Read failed generating shareable username: %v",
				err))
		}

		for i, v := range b {
			b[i] = chars[v%byte(len(chars))]
		}

		username := "_" + string(b)

		if _, found := shareableConnections[username]; !found {
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
	safeUsername := username != ""

	for _, r := range username {
		if r == '/' || r == '\\' || r == ':' || r < 0x20 || r == 0x7f {
			safeUsername = false

			break
		}
	}

	if safeUsername {
		userSpecificFile := fmt.Sprintf(
			"%s-%s.txt", strings.TrimSuffix(baseFilename, ".txt"), username,
		)

		content, err := os.ReadFile(userSpecificFile) //nolint:gosec,nolintlint
		if err == nil {
			return content, nil
		}
	}

	content, err := os.ReadFile(baseFilename) //nolint:gosec,nolintlint
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w",
			err)
	}

	return content, nil
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

	if isConsoleLogQuiet.Load() {
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
	defer func() {
		select {
		case <-shutdownSignal:

		default:
			log.Printf(
				"%sConsole-log rollover has stopped unexpectedly; daily log rotation will not occur.",
				alertPrefix(),
			)
		}
	}()
	defer recoverGoroutine("consoleLogRollover")

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			currentDate := now.Format("2006-01-02")

			consoleLogMutex.Lock()
			lastDate := lastLogDate
			consoleLogMutex.Unlock()

			if lastDate != currentDate {
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
	oldLogFile := func() *os.File {
		consoleLogMutex.Lock()

		defer consoleLogMutex.Unlock()

		logPath := getConsoleLogPath(t)
		logDir := filepath.Dir(logPath)

		err := os.MkdirAll(
			logDir, os.FileMode(logDirPerm), //nolint:gosec,nolintlint
		)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sERROR: Failed to create console log directory: %v\r\n",
				nowStamp(), warnPrefix(), err)

			isConsoleLogQuiet.Store(false)

			consoleLog = ""

			if consoleLogFile != nil {
				_ = consoleLogFile.Close()
			}

			consoleLogFile = nil

			log.SetOutput(os.Stdout)
			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sConsole logging disabled.\r\n",
				nowStamp(), alertPrefix())

			return nil
		}

		file, err := os.OpenFile( //nolint:gosec,nolintlint
			logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND,
			os.FileMode(logPerm), //nolint:gosec,nolintlint
		)
		if err != nil {
			if isConsoleLogQuiet.Load() {
				isConsoleLogQuiet.Store(false)
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

			return nil
		}

		old := consoleLogFile
		consoleLogFile = file
		lastLogDate = t.Format("2006-01-02")

		fileWriter := &emojiStripperWriter{w: consoleLogFile}

		if isConsoleLogQuiet.Load() {
			log.SetOutput(fileWriter)
		} else {
			log.SetOutput(io.MultiWriter(os.Stdout, fileWriter))
		}

		return old
	}()

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

func openUniqueCompressedFile(basePath string) (*os.File, string, error) {
	ext := filepath.Ext(basePath)
	stem := strings.TrimSuffix(basePath, ext)

	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL

	for i := range 100 {
		path := basePath
		if i > 0 {
			path = fmt.Sprintf("%s_%d%s",
				stem, i+1, ext)
		}

		f, err := os.OpenFile(path, flags, os.FileMode(logPerm)) //nolint:gosec,nolintlint
		if err == nil {
			return f, path, nil
		}

		if !errors.Is(err, os.ErrExist) {
			return nil, path, fmt.Errorf("failed to open compressed log file: %w",
				err)
		}
	}

	return nil, basePath, fmt.Errorf(
		"could not find unique compressed log filename after 100 attempts for %q",
		basePath,
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func compressLogFile(logFilePath string) {
	srcInfo, err := os.Lstat(logFilePath) //nolint:gosec,nolintlint
	if os.IsNotExist(err) {
		return
	}

	if err == nil && srcInfo.Mode()&os.ModeSymlink != 0 {
		log.Printf("%sRefusing to compress log %q: source is a symlink",
			warnPrefix(), logFilePath)

		return
	}

	var compressedFilePath string

	var compressedFile *os.File

	var writer io.WriteCloser

	var (
		gzipLevel    int
		zstdLevel    zstd.EncoderLevel
		lzipDictSize uint32
	)

	switch compressLevel {
	case "fast":
		gzipLevel = gzip.BestSpeed
		zstdLevel = zstd.SpeedFastest
		lzipDictSize = 1 << 16 // 64 KiB

	case "normal":
		gzipLevel = gzip.DefaultCompression
		zstdLevel = zstd.SpeedDefault
		lzipDictSize = lzip.DefaultDictSize

	case "high":
		gzipLevel = gzip.BestCompression
		zstdLevel = zstd.SpeedBestCompression
		lzipDictSize = lzip.MaxDictSize

	default:
		log.Printf(
			"%sUnknown compression level %q, falling back to normal",
			warnPrefix(), compressLevel,
		)

		gzipLevel = gzip.DefaultCompression
		zstdLevel = zstd.SpeedDefault
		lzipDictSize = lzip.DefaultDictSize
	}

	switch compressAlgo {
	case "gzip": //nolint:goconst,nolintlint
		compressedFile, compressedFilePath, err = openUniqueCompressedFile(logFilePath + ".gz")
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = gzip.NewWriterLevel(compressedFile, gzipLevel)
		if err != nil {
			log.Printf("%sError creating gzip writer for %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after gzip writer error: %v",
					warnPrefix(), err)
			}

			_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

			return
		}

	case "xz":
		compressedFile, compressedFilePath, err = openUniqueCompressedFile(logFilePath + ".xz")
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = xz.NewWriter(compressedFile)
		if err != nil {
			log.Printf("%sError creating xz writer for %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after xz writer error: %v",
					warnPrefix(), err)
			}

			_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

			return
		}

	case "lzip":
		compressedFile, compressedFilePath, err = openUniqueCompressedFile(logFilePath + ".lz")
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = lzip.NewWriterOptions(
			compressedFile, &lzip.WriterOptions{
				DictSize: lzipDictSize,
			},
		)
		if err != nil {
			log.Printf("%sError creating lzip writer for %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after lzip writer error: %v",
					warnPrefix(), err)
			}

			_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

			return
		}

	case "zstd":
		compressedFile, compressedFilePath, err = openUniqueCompressedFile(logFilePath + ".zst")
		if err != nil {
			log.Printf("%sFailed to create compressed file %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			return
		}

		writer, err = zstd.NewWriter(
			compressedFile, zstd.WithEncoderLevel(zstdLevel),
		)
		if err != nil {
			log.Printf("%sError creating zstd writer for %q: %v", //nolint:gosec,nolintlint
				warnPrefix(), compressedFilePath, err)

			err := compressedFile.Close()
			if err != nil {
				log.Printf("%sError closing compressed file after zstd writer error: %v",
					warnPrefix(), err)
			}

			_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

			return
		}

	default:
		log.Printf("%sUnknown compression algorithm: %s", //nolint:gosec,nolintlint
			warnPrefix(), compressAlgo)

		return
	}

	defer func() {
		err := compressedFile.Close()
		if err != nil && !strings.Contains(err.Error(), "file already closed") {
			log.Printf("%sError closing compressed file: %v",
				warnPrefix(), err)
		}
	}()

	defer func() {
		err := writer.Close()
		if err != nil && !strings.Contains(err.Error(), "writer already closed") {
			log.Printf("%sError closing writer: %v",
				warnPrefix(), err)
		}
	}()

	src, err := os.Open(logFilePath) //nolint:gosec,nolintlint
	if err != nil {
		log.Printf("%sFailed to open log %q for compression: %v", //nolint:gosec,nolintlint
			warnPrefix(), logFilePath, err)

		_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

		return
	}

	_, err = io.Copy(writer, src)

	closeErr := src.Close()
	if closeErr != nil {
		log.Printf("%sError closing log source %q: %v", //nolint:gosec,nolintlint
			warnPrefix(), logFilePath, closeErr)
	}

	if err != nil {
		log.Printf("%sError writing to compressed file %q: %v", //nolint:gosec,nolintlint
			warnPrefix(), compressedFilePath, err)

		_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

		return
	}

	err = writer.Close()
	if err != nil {
		log.Printf("%sError closing writer for %q: %v", //nolint:gosec,nolintlint
			warnPrefix(), compressedFilePath, err)

		_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

		return
	}

	err = compressedFile.Close()
	if err != nil {
		log.Printf("%sError closing compressed file %q: %v", //nolint:gosec,nolintlint
			warnPrefix(), compressedFilePath, err)

		_ = os.Remove(compressedFilePath) //nolint:gosec,nolintlint

		return
	}

	err = os.Remove(logFilePath) //nolint:gosec,nolintlint
	if err != nil {
		log.Printf( //nolint:gosec,nolintlint
			"%sError removing original log %q after compression: %v",
			warnPrefix(), logFilePath, err,
		)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func parseIPListFile(filePath string) ([]*net.IPNet, error) {
	file, err := os.Open(filePath) //nolint:gosec,nolintlint
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
				networks = append(
					networks, &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(32, 32),
					},
				)
			} else {
				networks = append(
					networks, &net.IPNet{
						IP:   ip,
						Mask: net.CIDRMask(128, 128),
					},
				)
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

	for stacklen == len(buf) && len(buf) < 16<<20 {
		buf = make([]byte, 2*len(buf))
		stacklen = runtime.Stack(buf, true)
	}

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

		stateStart := min(len(header[0])+len(id)+2, len(lines[0]))

		state := strings.Trim(lines[0][stateStart:], " :")

		entrypoint := lines[1]
		caller := ""

		if len(lines) > 2 {
			caller = strings.TrimSpace(lines[2])
		}

		goroutines = append(
			goroutines,
			GoroutineInfo{
				ID:         id,
				State:      state,
				Entrypoint: entrypoint,
				Caller:     caller,
			},
		)
	}

	if len(goroutines) == 0 { // Not possible!
		return
	}

	type row struct {
		Name, Value string
	}

	allRows := make([]row, 0, len(goroutines)*4)

	for _, g := range goroutines {
		allRows = append(
			allRows,
			row{"Name", "Goroutine #" + g.ID},
		)
		allRows = append(
			allRows,
			row{"State", g.State},
		)
		allRows = append(
			allRows,
			row{"Entrypoint", g.Entrypoint},
		)
		allRows = append(
			allRows,
			row{"Caller", g.Caller},
		)
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

	border := fmt.Sprintf(
		"+=%s=+=%s=+\n",
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
// Local Variables:
// mode: go
// tab-width: 4
// eval: (setq-local display-fill-column-indicator-column 100)
// eval: (display-fill-column-indicator-mode 1)
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
