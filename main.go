///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy
// Copyright (c) 2025 Jeffrey H. Johnson
// SPDX-License-Identifier: MIT
// vim: set ft=go noexpandtab tabstop=4 :
///////////////////////////////////////////////////////////////////////////////////////////////////

package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	sshAddr          string
	telnetHost       string
	telnetPort       int
	debugNegotiation bool
	logDir           string
	usersOnline      int32
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func init() {
	flag.StringVar(&sshAddr, "ssh-addr", ":2222", "SSH listen address")
	flag.StringVar(&telnetHost, "telnet-host", "127.0.0.1", "TELNET target host")
	flag.IntVar(&telnetPort, "telnet-port", 6180, "TELNET target port")
	flag.BoolVar(&debugNegotiation, "debug", false, "Debug TELNET negotiation")
	flag.StringVar(&logDir, "log-dir", "./log", "Base directory for session logs")
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

	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(edSigner)
	config.AddHostKey(rsaSigner)

	listener, err := net.Listen("tcp", sshAddr)
	if err != nil {
		log.Fatalf("LISTEN %s: %v", sshAddr, err)
	}

	log.Printf("SSH LISTEN ON %s", sshAddr)

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			log.Printf("ACCEPT ERROR: %v", err)
			continue
		}
		go handleConn(rawConn, config)
	}
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
		if err := ioutil.WriteFile(path, data, 0600); err != nil {
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
		if err := ioutil.WriteFile(path, data, 0600); err != nil {
			return nil, err
		}

		return ssh.ParsePrivateKey(data)

	default:
		return nil, fmt.Errorf("UNSUPPORTED KEY TYPE %q", keyType)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleConn(rawConn net.Conn, config *ssh.ServerConfig) {
	sid := newSessionID()

	if tcp, ok := rawConn.(*net.TCPConn); ok {
		tcp.SetNoDelay(true)
	} else {
		log.Printf("Failed setting NODELAY")
	}

	sshConn, chans, reqs, err := ssh.NewServerConn(rawConn, config)
	if err != nil {
		log.Printf("SSH HANDSHAKE FAILED: %v", err)
		return
	}
	defer sshConn.Close()

	count := atomic.AddInt32(&usersOnline, 1)
	addr := sshConn.RemoteAddr().String()
	log.Printf("CONNECT %s [%s] (Online: %d)",
		addr, sid, count)

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

		go handleSession(sid, sshConn, ch, requests)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleSession(
	sid string,
	sshConn *ssh.ServerConn,
	channel ssh.Channel,
	requests <-chan *ssh.Request,
) {
	defer atomic.AddInt32(&usersOnline, -1)

	sendBanner(sid, sshConn, channel)

	if raw, err := ioutil.ReadFile("motd.txt"); err == nil {
		txt := strings.ReplaceAll(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n", "\r\n")
		channel.Write([]byte(txt + "\r\n"))
	}

	start := time.Now()
	var sshIn, sshOut, telnetIn, telnetOut uint64

	logfile, basePath, err := createDatedLog(sshConn.RemoteAddr())
	if err != nil {
		fmt.Fprintf(channel, "log file error: %v\n", err)
		channel.Close()
		return
	}

	logfile.Write([]byte(nowStamp() + " Session start\r\n"))

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
		fmt.Fprintf(channel, "telnet connect failed: %v\n", err)
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

	var once sync.Once

	go func() {
		defer wg.Done()
		buf := make([]byte, 1)

		for {
			n, err := channel.Read(buf)
			if n > 0 {
				atomic.AddUint64(&sshIn, uint64(n))
				if buf[0] == 0x1D { // Ctrl-]
					showMenu(channel, remote, logfile)
					continue
				}
				m, err2 := remote.Write(buf[:n])
				atomic.AddUint64(&telnetOut, uint64(m))
				logfile.Write(buf[:n])
				if err2 != nil {
					once.Do(func() {
						log.Printf("DISCONNECT (SSH) [%s] (Online: %d)",
							sid, atomic.LoadInt32(&usersOnline)-1)
					})
					channel.Close()
					return
				}
			}
			if err != nil {
				once.Do(func() {
					ts := nowStamp()
					log.Printf("DISCONNECT (SSH) [%s] (Online: %d)",
						sid, atomic.LoadInt32(&usersOnline)-1)
					logfile.Write([]byte(ts + " DISCONNECT (SSH)\r\n"))
				})
				remote.Close()
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 1024)
		for {
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
					"> SSH: in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n",
					sshIn, sshOut,
					float64(sshIn)/dur, float64(sshOut)/dur,
				)))
				channel.Write([]byte(fmt.Sprintf(
					"> NVT: in: %d bytes, out: %d bytes, in rate: %.2f B/s, out rate: %.2f B/s\r\n\r\n",
					telnetIn, telnetOut,
					float64(telnetIn)/dur, float64(telnetOut)/dur,
				)))
				once.Do(func() {
					ts := nowStamp()
					log.Printf("DISCONNECT (TELNET) [%s] (Online: %d)",
						sid, atomic.LoadInt32(&usersOnline)-1)
					logfile.Write([]byte(ts + " DISCONNECT (TELNET)\r\n"))
				})
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

func showMenu(ch ssh.Channel, remote net.Conn, logw io.Writer) {
	menu := "\r\n" +
		"-===- MENU -===-\r\n" +
		" 1) Send BREAK\r\n" +
		"> "
	ch.Write([]byte(menu))
	sel := make([]byte, 1)

	if _, err := ch.Read(sel); err == nil && sel[0] == '1' {
		remote.Write([]byte{IAC, 243}) // BREAK
		logw.Write([]byte{IAC, 243})
		ch.Write([]byte("\r\n>> Sent BREAK\r\n"))
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
	if err := os.MkdirAll(dir, 0755); err != nil {
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
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

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
