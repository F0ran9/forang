package carriers

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 反编译小程序源码 zip：app.json + 一个带 API 域名和硬编码密钥的 js。
func TestParseMiniSourceZip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "decompiled.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	files := map[string]string{
		"app.json":            `{"pages":["pages/index/index"],"entryPagePath":"pages/index/index"}`,
		"utils/request.js":    "const BASE='https://api.demo-university.example.cn/v1/login';\nwx.request({url:BASE,method:'POST'})",
		"utils/config.js":     "module.exports={secret_key:'AbCdEf1234567890abcdef12'}",
		"pages/index/index.js": "Page({data:{}})",
	}
	for name, body := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		fw.Write([]byte(body))
	}
	w.Close()
	f.Close()

	a, err := ParseMiniSourceZip(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.Carrier != "miniprogram" || a.Format != "minisrc-zip" {
		t.Fatalf("carrier/format = %s/%s", a.Carrier, a.Format)
	}
	if a.AppID == "" {
		t.Log("note: no appid in source zip (expected unless appid referenced)")
	}
	if a.Stats.TextFiles != 4 {
		t.Fatalf("text files = %d, want 4", a.Stats.TextFiles)
	}
	foundLogin := false
	for _, e := range a.Endpoints {
		if e.Host == "api.demo-university.example.cn" && strings.Contains(e.Path, "/v1/login") {
			foundLogin = true
		}
	}
	if !foundLogin {
		t.Fatalf("login endpoint not extracted, endpoints=%+v", a.Endpoints)
	}
	if len(a.Secrets) == 0 {
		t.Fatalf("secret_key not extracted")
	}
	foundPage := false
	for _, p := range a.Pages {
		if p == "pages/index/index" {
			foundPage = true
		}
	}
	if !foundPage {
		t.Fatalf("app.json page not extracted, pages=%+v", a.Pages)
	}
}
