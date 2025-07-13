///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy
// Copyright (c) 2025 Jeffrey H. Johnson
// SPDX-License-Identifier: MIT
// vim: set ft=go noexpandtab tabstop=4 :
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
	"encoding/base64"
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
	telnetHost             string
	telnetPort             int
	debugNegotiation       bool
	logDir                 string
	gracefulShutdownMode   atomic.Bool
	denyNewConnectionsMode atomic.Bool
	connections            = make(map[string]*Connection)
	connectionsMutex       sync.Mutex
	shutdownOnce           sync.Once
	consoleInputActive     atomic.Bool
	originalLogOutput      io.Writer
	logBuffer              *strings.Builder
	logBufferMutex         sync.Mutex
	shutdownSignal         chan struct{}
)

type Connection struct {
	ID         string
	sshConn    *ssh.ServerConn
	channel    ssh.Channel
	startTime  time.Time
	logFile    *os.File
	basePath   string
	cancelCtx  context.Context
	cancelFunc context.CancelFunc
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	flag.StringVar(&sshAddr, "ssh-addr", ":2222", "SSH listen address")
	flag.StringVar(&telnetHost, "telnet-host", "127.0.0.1", "TELNET target host")
	flag.IntVar(&telnetPort, "telnet-port", 6180, "TELNET target port")
	flag.BoolVar(&debugNegotiation, "debug", false, "Debug TELNET negotiation")
	flag.StringVar(&logDir, "log-dir", "./log", "Base directory for session logs")
	originalLogOutput = log.Writer()
	logBuffer = &strings.Builder{}
	shutdownSignal = make(chan struct{})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func main() {
	flag.Parse()

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
	log.Printf("Type '?' for help.")

	go handleConsoleInput()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		immediateShutdown()
	}()

	go func() {
		<-shutdownSignal
		log.Println("Received shutdown signal. Exiting.")
		os.Exit(0)
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
		"\r +========= HELP =========+\r\n" +
		"\r | ? - Display This Help  |\r\n" +
		"\r | l - List Connections   |\r\n" +
		"\r | k - Kill Connection    |\r\n" +
		"\r | d - Deny Connections   |\r\n" +
		"\r | q - Graceful Shutdown  |\r\n" +
		"\r | Q - Immediate Shutdown |\r\n" +
		"\r +========================+\r\n\r\n")
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
				conn.channel.Write([]byte("\r\nCONNECTION TERMINATED\r\n"))
			}
			if conn.cancelFunc != nil {
				conn.cancelFunc()
			}
			if conn.sshConn != nil {
				conn.sshConn.Close()
			}
			if conn.logFile != nil {
				conn.logFile.Close()
				os.Rename(conn.basePath+".open.log", conn.basePath+".log")
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
		log.Println("Exiting.")
		os.Exit(0)
	})
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func listConnections() {
	connectionsMutex.Lock()
	defer connectionsMutex.Unlock()
	fmt.Println("\r\nActive Connections")
	fmt.Println("\r\n------------------")
	if len(connections) == 0 {
		fmt.Println("  None")
		return
	}
	for id, conn := range connections {
		fmt.Printf("* ID: %s, Remote: %s, User: %s, Uptime: %s\r\n",
			id, conn.sshConn.RemoteAddr(), conn.sshConn.User(),
			time.Since(conn.startTime).Round(time.Second))
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

	startBufferingLogs()
	defer stopBufferingLogs()

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
	conn.channel.Write([]byte("\r\nCONNECTION TERMINATED\r\n"))
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

	config := &ssh.ServerConfig{
		NoClientAuth: true,
		PublicKeyCallback: func(
			c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			line := fmt.Sprintf(
				"FROM %s@%s [%s] %q:%s",
				c.User(),
				c.RemoteAddr(),
				sid,
				pubKey.Type(),
				ssh.FingerprintSHA256(pubKey),
			)
			log.Print(line)
			keyLog = append(keyLog, line)
			return nil, fmt.Errorf("trying next method")
		},
		KeyboardInteractiveCallback: func(
			conn ssh.ConnMetadata,
			challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(edSigner)
	config.AddHostKey(rsaSigner)

	if tcp, ok := rawConn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		log.Printf("SSH HANDSHAKE FAILED: %v", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	conn := &Connection{
		ID:         sid,
		sshConn:    sshConn,
		startTime:  time.Now(),
		cancelCtx:  ctx,
		cancelFunc: cancel,
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
				// Channel already closed or signal sent, do nothing
			}
		} else {
			connectionsMutex.Unlock()
		}
		log.Printf("DISCONNECT (SSH) [%s]", sid)
	}()

	addr := sshConn.RemoteAddr().String()
	log.Printf("CONNECT %s [%s]", addr, sid)

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

func handleSession(
	conn *Connection,
	channel ssh.Channel,
	requests <-chan *ssh.Request,
	keyLog []string,
	ctx context.Context,
) {
	if gracefulShutdownMode.Load() || denyNewConnectionsMode.Load() {
		if denyMsg, err := ioutil.ReadFile("deny.txt"); err == nil {
			txt := strings.ReplaceAll(strings.ReplaceAll(string(denyMsg), "\r\n", "\n"), "\n", "\r\n")
			channel.Write([]byte("\r\n"))
			channel.Write([]byte(txt))
			channel.Write([]byte("\r\n"))
		}
		channel.Close()
		return
	}

	sendBanner(conn.ID, conn.sshConn, channel)

	if raw, err := ioutil.ReadFile("motd.txt"); err == nil {
		txt := strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
		channel.Write([]byte(txt + "\r\n"))
	}

	start := time.Now()
	var sshIn, sshOut, telnetIn, telnetOut uint64

	logfile, basePath, err := createDatedLog(conn.sshConn.RemoteAddr())
	if err != nil {
		fmt.Fprintf(channel, "log file error: %v\n", err)
		channel.Close()
		return
	}
	conn.logFile = logfile
	conn.basePath = basePath

	logfile.Write([]byte(nowStamp() + " Session start\r\n"))

	for _, line := range keyLog {
		logfile.Write([]byte(nowStamp() + " " + line + "\r\n"))
	}

	defer func() {
		logfile.Close()
		os.Rename(basePath+".open.log", basePath+".log")
	}()

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

	remote, err := net.Dial("tcp", fmt.Sprintf("%s:%d", telnetHost, telnetPort))
	if err != nil {
		fmt.Fprintf(channel, "%v\r\n\r\n", err)
		log.Printf("ERROR: %v", err)
		channel.Close()
		return
	}

	if tcp2, ok := remote.(*net.TCPConn); ok {
		tcp2.SetNoDelay(true)
	}

	defer remote.Close()

	negotiateTelnet(remote, channel, logfile)

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
					showMenu(channel, remote, logfile, &sshIn, &sshOut, &telnetIn, &telnetOut, start)
					continue
				}
				m, err2 := remote.Write(buf[:n])
				atomic.AddUint64(&telnetOut, uint64(m))
				logfile.Write(buf[:n])
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
				logfile.Write(buf[:n])
			}
			if err != nil {
				dur := time.Since(start).Seconds()
				channel.Write([]byte("\r\nCONNECTION CLOSED\r\n\r\n"))
				channel.Write([]byte(fmt.Sprintf(
					">> SSH: in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n",
					sshIn, sshOut,
					float64(sshIn)/dur, float64(sshOut)/dur,
				)))
				channel.Write([]byte(fmt.Sprintf(
					">> NVT: in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n\r\n",
					telnetIn, telnetOut,
					float64(telnetIn)/dur, float64(telnetOut)/dur,
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
	user := sshConn.User()
	host, _, _ := net.SplitHostPort(sshConn.RemoteAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	names, _ := net.DefaultResolver.LookupAddr(ctx, host)
	var origin string
	if len(names) > 0 {
		origin = fmt.Sprintf("%s@%s (%s)", user, strings.TrimSuffix(names[0], "."), host)
	} else if user != "" {
		origin = fmt.Sprintf("%s@%s", user, host)
	} else {
		origin = host
	}
	now := nowStamp()
	fmt.Fprintf(ch, "CONNECT from %s at %s.\r\n", origin, now)
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
	menu := "\r\n\r\n" +
		"+==== MENU =====+\r\n" +
		"| 1) Send Break |\r\n" +
		"| 2) Show Stats |\r\n" +
		"+===============+\r\n"
	ch.Write([]byte(menu))
	sel := make([]byte, 1)

	if _, err := ch.Read(sel); err == nil {
		switch sel[0] {
		case '1':
			remote.Write([]byte{IAC, 243}) // BREAK
			logw.Write([]byte{IAC, 243})
			ch.Write([]byte("\r\n>> Sent BREAK\r\n"))
		case '2':
			dur := time.Since(start).Seconds()
			ch.Write([]byte("\r\n"))
			ch.Write([]byte(fmt.Sprintf(
				">> SSH: in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n",
				atomic.LoadUint64(sshIn),
				atomic.LoadUint64(sshOut),
				float64(atomic.LoadUint64(sshIn))/dur,
				float64(atomic.LoadUint64(sshOut))/dur,
			)))
			ch.Write([]byte(fmt.Sprintf(
				">> NVT: in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n\r\n",
				atomic.LoadUint64(telnetIn),
				atomic.LoadUint64(telnetOut),
				float64(atomic.LoadUint64(telnetIn))/dur,
				float64(atomic.LoadUint64(telnetOut))/dur,
			)))
		default:
			ch.Write([]byte("\r\n>> Unknown option!\r\n"))
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func createDatedLog(addr net.Addr) (*os.File, string, error) {
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
	prefix := ts + "_"
	for _, f := range files {
		if strings.HasPrefix(f.Name(), prefix) {
			parts := strings.SplitN(f.Name()[len(prefix):], ".", 2)
			if n, err := strconv.Atoi(parts[0]); err == nil && n > maxSeq {
				maxSeq = n
			}
		}
	}

	seq := maxSeq + 1
	base := fmt.Sprintf("%s_%d", ts, seq)
	pathBase := filepath.Join(dir, base)
	f, err := os.OpenFile(pathBase+".open.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)

	return f, pathBase, err
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sanitizeIP(s string) string {
	return strings.NewReplacer(":", "_", ".", "_").Replace(s)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func newSessionID() string {
	b := make([]byte, 4)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func nowStamp() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

///////////////////////////////////////////////////////////////////////////////////////////////////
