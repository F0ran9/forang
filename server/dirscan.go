package server

// dirscan.go — 目录扫描（移植自 AI-PENTEST scan_tools.py 的 dir-scan，Go 原生
// 并发 HTTP 探测）。内置常见路径字典 + 用户自定义字典（textarea 逐行）；
// 非 404 且能建连即命中；301/302 单独标注（可能是目录）。任务落 scan_jobs 表。

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// dirWordlist 内置常见敏感路径（渗透字典精选，~180 条）。
var dirWordlist = []string{
	".env", ".git/config", ".git/HEAD", ".svn/entries", ".DS_Store", ".htaccess",
	"admin", "admin/", "admin/login", "admin.php", "admin.html", "administrator/",
	"api", "api/", "api/v1", "api/v2", "actuator", "actuator/health", "actuator/env",
	"backup", "backup/", "backup.zip", "backup.sql", "back/", "bak/", "bak.zip",
	"bin/", "cache/", "cgi-bin/", "conf/", "config", "config.php", "config.json",
	"config.yml", "console", "core/", "cron/", "data/", "db/", "debug/",
	"doc/", "docs/", "dump.sql", "error/", "files/", "ftp/", "home/",
	"include/", "includes/", "install", "install/", "js/", "lib/", "login",
	"login/", "login.php", "logout", "manager/", "media/", "member/", "misc/",
	"mysql/", "old/", "phpinfo.php", "phpmyadmin/", "private/", "public/",
	"readme.txt", "robots.txt", "root/", "script/", "scripts/", "secret/",
	"server-status", "server-info", "setup/", "shop/", "site/", "source/",
	"sql/", "src/", "static/", "statistics/", "stats/", "swf/", "temp/",
	"template/", "templates/", "test", "test/", "test.php", "tmp/", "tool/",
	"tools/", "upload/", "uploads/", "user/", "users/", "util/", "utils/",
	"web-inf/web.xml", "webadmin/", "wordpress/", "wp-admin/", "wp-login.php",
	"xml/", "zip/", "1.php", "1.jsp", "index.bak", "index.old", "index.txt",
	"WEB-INF/web.xml", "META-INF/", "swagger", "swagger/", "swagger-ui.html",
	"swagger/index.html", "v2/api-docs", "v3/api-docs", "druid/index.html",
	"druid/login.html", "nacos/", "eureka/", "gateway/", "auth/", "oauth/",
	"sso/", "grafana/", "kibana/", "jenkins/", "jenkins/login", "zabbix/",
	"solr/", "es/", "elastic/", "rabbitmq/", "mongo/", "redis/", "minio/",
	"prometheus", "metrics", "health", "info", "trace", "env", "mappings",
	"beans", "configprops", "dump", "heapdump", "threaddump", "logstat",
}

var dirScanMu sync.Mutex // 同时只跑一个目录扫描

// POST /api/tools/dirscan {base_url, wordlist?, extensions?, timeout_sec?}
func (s *Server) dirScanStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		BaseURL     string `json:"base_url"`
		Wordlist    string `json:"wordlist"`
		Extensions  string `json:"extensions"`
		TimeoutSec  int    `json:"timeout_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	base := strings.TrimRight(strings.TrimSpace(b.BaseURL), "/")
	if base == "" || !strings.HasPrefix(base, "http") {
		writeErr(w, 400, "base_url 需以 http(s):// 开头")
		return
	}
	if _, err := url.Parse(base); err != nil {
		writeErr(w, 400, "base_url 不合法")
		return
	}
	if b.TimeoutSec <= 0 || b.TimeoutSec > 1800 {
		b.TimeoutSec = 300
	}
	// 字典：用户自定义（逐行）优先，空则内置；extensions 逐个附加再跑一轮
	words := []string{}
	for _, l := range strings.Split(b.Wordlist, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			words = append(words, strings.Trim(l, "/"))
		}
	}
	custom := len(words) > 0
	if !custom {
		words = dirWordlist
	}
	exts := []string{""}
	if e := strings.TrimSpace(b.Extensions); e != "" {
		exts = []string{""}
		for _, x := range strings.Split(e, ",") {
			x = strings.TrimSpace(x)
			if x != "" {
				if !strings.HasPrefix(x, ".") {
					x = "." + x
				}
				exts = append(exts, x)
			}
		}
	}
	paths := map[string]bool{}
	for _, wd := range words {
		for _, ex := range exts {
			paths[wd+ex] = true
		}
	}
	params, _ := json.Marshal(map[string]any{
		"base_url": base, "word_count": len(paths), "custom_dict": custom,
		"extensions": b.Extensions, "timeout_sec": b.TimeoutSec,
	})
	var jobID int64
	if err := s.m.PG().QueryRow(
		"INSERT INTO scan_jobs (kind, targets, params, status, findings) VALUES ('dir',$1,$2,'pending','{}') RETURNING id",
		truncateStr(base, 500), string(params)).Scan(&jobID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	go s.runDirScan(jobID, base, paths, b.TimeoutSec)
	writeJSON(w, 200, map[string]any{"data": map[string]any{"job_id": jobID, "paths": len(paths)}})
}

func (s *Server) runDirScan(jobID int64, base string, paths map[string]bool, timeoutSec int) {
	dirScanMu.Lock()
	defer dirScanMu.Unlock()
	db := s.m.PG()
	_, _ = db.Exec("UPDATE scan_jobs SET status='running', updated_at=now() WHERE id=$1", jobID)

	type hit struct {
		Path   string `json:"path"`
		Status int    `json:"status"`
		Size   int64  `json:"size"`
		Where  string `json:"location,omitempty"`
	}
	type findingsT struct {
		Hits    []hit `json:"hits"`
		Scanned int   `json:"scanned"`
		Total   int   `json:"total"`
	}
	f := findingsT{Hits: []hit{}, Total: len(paths)}
	save := func() {
		j, _ := json.Marshal(f)
		_, _ = db.Exec("UPDATE scan_jobs SET findings=$1, updated_at=now() WHERE id=$2", string(j), jobID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 渗透目标常见自签
			DisableKeepAlives: false,
			MaxIdleConns:      40,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 不跟随，301/302 即结果
		},
	}
	sem := make(chan struct{}, 25)
	var mu sync.Mutex
	var wg sync.WaitGroup
	lastSave := time.Now()
	for p := range paths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+p, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FORANG-DirScan")
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				f.Scanned++
				mu.Unlock()
				return
			}
			size := resp.ContentLength
			if size < 0 {
				size = 0
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			code := resp.StatusCode
			mu.Lock()
			f.Scanned++
			if code != 404 && code != 0 {
				h := hit{Path: p, Status: code, Size: size}
				if loc := resp.Header.Get("Location"); loc != "" {
					h.Where = truncateStr(loc, 200)
				}
				f.Hits = append(f.Hits, h)
			}
			if time.Since(lastSave) > 2*time.Second {
				lastSave = time.Now()
				save()
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	save()
	_, _ = db.Exec("UPDATE scan_jobs SET status='done', updated_at=now() WHERE id=$1", jobID)
}

// GET /api/tools/dirscan — 最近 20 个任务。
func (s *Server) dirScanList(w http.ResponseWriter, r *http.Request) {
	s.scanJobList(w, "dir")
}

// GET /api/tools/dirscan/{id} — 任务详情。
func (s *Server) dirScanDetail(w http.ResponseWriter, r *http.Request) {
	s.scanJobDetail(w, r, "dir")
}
