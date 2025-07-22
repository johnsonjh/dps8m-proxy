///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - utf8.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/term"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var (
	utf8SupportOnce sync.Once
	utf8Support     bool
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func haveUTF8support() bool {
	utf8SupportOnce.Do(func() {
		if os.Getenv("PROXY_FORCE_UTF8") == "1" { //nolint:gocritic
			utf8Support = true // Undocumented: for debugging use.
		} else if os.Getenv("PROXY_FORCE_NO_UTF8") == "1" {
			utf8Support = false // Undocumented: for debugging use.
		} else if !term.IsTerminal(int(os.Stdout.Fd())) {
			utf8Support = false
		} else {
			utf8Support = isUTF8plan9() || isUTF8wasi() || isUTF8js() ||
				isUTF8windows() || isUTF8unix() || canOutputUTF8()
		}
	})

	return utf8Support
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func canOutputUTF8() bool {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return false
	}

	testStr := "┌─"
	if !utf8.ValidString(testStr) {
		return false
	}

	fullStr := "\r" + testStr
	n, err := os.Stdout.WriteString(fullStr)

	erase := strings.Repeat("\b", utf8.RuneCountInString(testStr)) +
		strings.Repeat(" ", utf8.RuneCountInString(testStr)) + "\r"
	_, _ = os.Stdout.WriteString(erase)

	return err == nil && n == len(fullStr)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUTF8unix() bool {
	pattern := regexp.MustCompile(`(?i)utf.?8`)
	keys := []string{"LC_ALL", "LC_CTYPE", "LANG", "TERM"}

	for _, key := range keys {
		val := os.Getenv(key)

		if val != "" && pattern.MatchString(val) {
			return true
		}
	}

	return false
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUTF8windows() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	original := os.Stdout

	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return false
	}

	defer func() {
		os.Stdout = original
		if err := null.Close(); err != nil {
			log.Printf("%sError closing null: %v",
				warnPrefix(), err)
		}
	}()

	os.Stdout = null

	out, err := exec.Command("cmd", "/C", "chcp").Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(out), "65001")
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUTF8plan9() bool {
	return runtime.GOOS == "plan9"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUTF8wasi() bool {
	return runtime.GOOS == "wasip1"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isUTF8js() bool {
	return runtime.GOOS == "js"
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func errorPrefix() string {
	if haveUTF8console {
		return "❌ " // Fatal
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func boomPrefix() string {
	if haveUTF8console {
		return "💥 " // Near-fatal
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func warnPrefix() string {
	if haveUTF8console {
		return "⚠️ " // Warning
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func alertPrefix() string {
	if haveUTF8console {
		return "🚨 " // Alert
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func bellPrefix() string {
	if haveUTF8console {
		return "🔔 " // Signal
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func toolPrefix() string {
	if haveUTF8console {
		return "🔧 " // Work
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func thumbsUpPrefix() string {
	if haveUTF8console {
		return "👍 " // Deny cancel
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func greenDotPrefix() string {
	if haveUTF8console {
		return "🟢 " // Good
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func yellowDotPrefix() string {
	if haveUTF8console {
		return "🟡 " // Kill/Teardown/Detach
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func blueDotPrefix() string {
	if haveUTF8console {
		return "🔵 " // Validate
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func redDotPrefix() string {
	if haveUTF8console {
		return "🔴 " // Reject/Deny
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func greenHeartPrefix() string {
	if haveUTF8console {
		return "💚 " // Exempted
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func skullPrefix() string {
	if haveUTF8console {
		return "💀 " // Admin Kill / No new
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func easterEggPrefix() string {
	if haveUTF8console {
		return "🥚 " // Easter egg!
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func byePrefix() string {
	if haveUTF8console {
		return "👋 " // Goodbye
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func relayPrefix() string {
	if haveUTF8console {
		return "📡 " // Startup
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func bugPrefix() string {
	if haveUTF8console {
		return "🐛 " // (De)bug
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

type emojiStripperWriter struct {
	w io.Writer
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func (e *emojiStripperWriter) Write(p []byte) (int, error) {
	stripped := stripEmoji(string(p))

	return e.w.Write([]byte(stripped))
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isEmojiRune(r rune) bool {
	switch {
	case r >= 0x1F600 && r <= 0x1F64F: // Emoticons
		return true

	case r >= 0x1F300 && r <= 0x1F5FF: // Misc symbols
		return true

	case r >= 0x1F680 && r <= 0x1F6FF: // Transport
		return true

	case r >= 0x2600 && r <= 0x26FF: // Misc symbols
		return true

	case r >= 0x2700 && r <= 0x27BF: // Dingbats
		return true

	case r >= 0xFE00 && r <= 0xFE0F: // Selectors
		return true

	case r >= 0x1F900 && r <= 0x1F9FF: // Supplemental
		return true

	case r >= 0x1FA70 && r <= 0x1FAFF: // Extended pictographs
		return true

	case r >= 0x1F7E0 && r <= 0x1F7EB: // Geometric Shapes Extended
		return true

	default:
		return false
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func stripEmoji(s string) string {
	runes := []rune(s)
	var out []rune

	i := 0
	for i < len(runes) {
		r := runes[i]

		if isEmojiRune(r) {
			i++

			if i < len(runes) && runes[i] == ' ' {
				i++
			}

			continue
		}

		out = append(out, r)
		i++
	}

	return string(out)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
