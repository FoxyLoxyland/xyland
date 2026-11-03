// Package browser adalah executor browser nyata xyland (rod + Chromium).
// Dipakai untuk konfirmasi eksekusi DOM (menaikkan verdict XSS dari
// likely -> confirmed) dan mengambil screenshot bukti.
//
// Browser diunduh rod ke cache lokal pada peluncuran pertama (~150 MB).
// Set XYLAND_BROWSER=off untuk menonaktifkan executor ini sepenuhnya.
package browser

import (
	"os"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

var (
	mu   sync.Mutex
	inst *rod.Browser
)

// Enabled melaporkan apakah executor browser boleh dipakai.
func Enabled() bool { return os.Getenv("XYLAND_BROWSER") != "off" }

func get() (*rod.Browser, error) {
	mu.Lock()
	defer mu.Unlock()
	if inst != nil {
		return inst, nil
	}
	u, err := launcher.New().Headless(true).Set("no-sandbox").Launch()
	if err != nil {
		return nil, err
	}
	b := rod.New().ControlURL(u)
	if err := b.Connect(); err != nil {
		return nil, err
	}
	inst = b
	return inst, nil
}

// Close menutup browser bersama (dipanggil di akhir run).
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if inst != nil {
		_ = inst.Close()
		inst = nil
	}
}

// ConfirmSVGOnload membuka testURL (payload sudah tertanam oleh pemanggil)
// dan memeriksa apakah handler onload SVG benar-benar tereksekusi di DOM:
// payload xyland memasang atribut data-xyland="pwned" pada <body>.
// Mengembalikan status eksekusi + screenshot PNG sebagai bukti.
func ConfirmSVGOnload(testURL string) (bool, []byte, error) {
	b, err := get()
	if err != nil {
		return false, nil, err
	}
	page, err := b.Page(proto.TargetCreateTarget{URL: testURL})
	if err != nil {
		return false, nil, err
	}
	defer page.Close()
	_ = page.WaitLoad()
	deadline := time.Now().Add(6 * time.Second)
	executed := false
	for time.Now().Before(deadline) {
		res, err := page.Eval(`() => document.body && document.body.getAttribute('data-xyland')`)
		if err == nil && res.Value.Str() == "pwned" {
			executed = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	var shot []byte
	if executed {
		shot, _ = page.Screenshot(false, &proto.PageCaptureScreenshot{Format: proto.PageCaptureScreenshotFormatPng})
	}
	return executed, shot, nil
}

// ScreenshotURL membuka URL di browser dan mengembalikan screenshot PNG.
func ScreenshotURL(rawurl string) ([]byte, error) {
	b, err := get()
	if err != nil {
		return nil, err
	}
	page, err := b.Page(proto.TargetCreateTarget{URL: rawurl})
	if err != nil {
		return nil, err
	}
	defer page.Close()
	_ = page.WaitLoad()
	return page.Screenshot(false, &proto.PageCaptureScreenshot{Format: proto.PageCaptureScreenshotFormatPng})
}
