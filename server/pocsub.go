package server

// pocsub.go â Nuclei POC è®¢éï¼ç§»æ¤èªå¨åµ poc-subscriptions.tsï¼MITï¼ï¼
// è®¢éæº = ä¸ä¸ª zip URLï¼é»è®¤å®æ¹ nuclei-templates main åæ¯ï¼+ å¯éè®¤è¯å¤´ï¼
// å®æ¶åæ­¥ï¼intervalHoursï¼0=ä»æå¨ï¼ï¼ææ¨¡æ¿ id å»é upsertãåªå¢ä¸å 
// ï¼é²è¢«å«æçæºæ¸ç©ºåºï¼ï¼æ¯æ¬¡åæ­¥ï¼å«å¤±è´¥ï¼çä¸æ¡åå²ã
// VM è®¿é® GitHub å¯è½åéï¼é»è®¤ URL èµ°éååç¼å¯æ¹ã

import (
	"archive/zip"
	"github.com/Autumn-27/artex/db"
	"context"

	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"runtime/debug"
	"time"
)

const (
	pocOfficialSourceID   = "official"
	pocOfficialSourceURL  = "https://github.com/projectdiscovery/nuclei-templates/archive/refs/heads/main.zip"
	pocMaxZipBytes        = 200 << 20
	pocFetchTimeout       = 10 * time.Minute
	pocHistoryLimit       = 5
)

type pocSource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	URL           string `json:"url"`
	AuthHeader    string `json:"auth_header"` // å¯é "Header: value"
	IntervalHours int    `json:"interval_hours"` // 0=ä»æå¨ï¼1-720
	LastSync      time.Time `json:"last_sync"`
}

type pocSyncRecord struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	Added   int       `json:"added"`
	Updated int       `json:"updated"`
}

func (s *Server) loadPocSources() []pocSource {
	var out []pocSource
	if s.m.pg == nil {
		return out
	}
	if v, ok, _ := s.m.pg.GetSetting("poc_sources"); ok && v != "" {
		_ = json.Unmarshal([]byte(v), &out)
	}
	return out
}

func (s *Server) savePocSources(list []pocSource) error {
	b, _ := json.Marshal(list)
	return s.m.pg.SetSetting("poc_sources", string(b))
}

func (s *Server) loadPocHistory() map[string][]pocSyncRecord {
	out := map[string][]pocSyncRecord{}
	if s.m.pg == nil {
		return out
	}
	if v, ok, _ := s.m.pg.GetSetting("poc_sync_history"); ok && v != "" {
		_ = json.Unmarshal([]byte(v), &out)
	}
	return out
}

func (s *Server) appendPocHistory(id string, rec pocSyncRecord) {
	h := s.loadPocHistory()
	h[id] = append(h[id], rec)
	if len(h[id]) > pocHistoryLimit {
		h[id] = h[id][len(h[id])-pocHistoryLimit:]
	}
	b, _ := json.Marshal(h)
	_ = s.m.pg.SetSetting("poc_sync_history", string(b))
}

// startPocSubLoop æ¯åéæ£æ¥å°ææºï¼å¨åµ minute-ticker è¯­ä¹ï¼ã
func (s *Server) startPocSubLoop() {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-t.C:
				for _, src := range s.loadPocSources() {
					if src.IntervalHours <= 0 {
						continue
					}
					if time.Since(src.LastSync) < time.Duration(src.IntervalHours)*time.Hour {
						continue
					}
					s.syncPocSource(src.ID)
				}
			}
		}
	}()
}

var pocIDRe = regexp.MustCompile(`(?m)^id:\s*(\S+)`)
var pocSeverityRe = regexp.MustCompile(`(?m)^\s*severity:\s*(\S+)`)
var pocNameRe = regexp.MustCompile(`(?m)^\s*name:\s*["']?(.+?)["']?\s*$`)
var pocTagRe = regexp.MustCompile(`(?m)^\s*-\s*(\S+)`)

// SyncPocSource åæ­¥ä¸ä¸ªæºï¼ä¸è½½ â è§£æ yaml â ææ¨¡æ¿ id upsertã
func (s *Server) syncPocSource(id string) (pocSyncRecord, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[pocsub] sync %s panic: %v\n%s", id, r, debug.Stack())
		}
	}()
	// 手动与定时可能并发触发同一源：在飞则跳过本轮。
	// Lock/Unlock 紧邻（中间只有 map 读写）：持锁窗口内 panic 会把互斥锁永久
	// 带进坟墓（nil map panic + recover 的组合曾把同步端点整个死锁），锁窗口
	// 内不允许出现任何可 panic 的调用形状。
	s.pocSyncMu.Lock()
	if s.pocSyncInFlight == nil {
		s.pocSyncInFlight = map[string]bool{}
	}
	inFlight := s.pocSyncInFlight[id]
	if !inFlight {
		s.pocSyncInFlight[id] = true
	}
	s.pocSyncMu.Unlock()
	if inFlight {
		return pocSyncRecord{At: time.Now(), Message: "同步已在进行中"}, nil
	}
	defer func() { s.pocSyncMu.Lock(); delete(s.pocSyncInFlight, id); s.pocSyncMu.Unlock() }()
	rec := pocSyncRecord{At: time.Now()}
	var target *pocSource
	for i, src := range s.loadPocSources() {
		if src.ID == id {
			target = &s.loadPocSources()[i]
			break
		}
	}
	if target == nil {
		rec.Message = "源不存在"
		return rec, fmt.Errorf("源不存在")
	}
	log.Printf("[pocsub] %s: 开始下载 %s", id, target.URL)
	body, err := pocFetch(target)
	if err != nil {
		rec.Message = "下载失败: " + err.Error()
		s.appendPocHistory(id, rec)
		return rec, err
	}
	log.Printf("[pocsub] %s: 下载完成 %dKB，开始解析导入", id, len(body)/1024)
	added, updated, cerr := s.pocImportZip(body)
	if cerr != nil {
		rec.Message = "å¯¼å¥å¤±è´¥: " + cerr.Error()
		s.appendPocHistory(id, rec)
		return rec, cerr
	}
	rec.OK, rec.Added, rec.Updated = true, added, updated
	rec.Message = fmt.Sprintf("æ°å¢ %dï¼æ´æ° %d", added, updated)
	s.appendPocHistory(id, rec)
	list := s.loadPocSources()
	for i := range list {
		if list[i].ID == id {
			list[i].LastSync = time.Now()
		}
	}
	_ = s.savePocSources(list)
	log.Printf("[pocsub] %s: %s", id, rec.Message)
	return rec, nil
}

func pocFetch(src *pocSource) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pocFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", src.URL, nil)
	if err != nil {
		return nil, err
	}
	if src.AuthHeader != "" {
		if i := strings.Index(src.AuthHeader, ":"); i > 0 {
			req.Header.Set(strings.TrimSpace(src.AuthHeader[:i]), strings.TrimSpace(src.AuthHeader[i+1:]))
		}
	}
	client := &http.Client{Timeout: 8 * time.Minute} // 审计修复：无超时会把慢速流挂到 ctx 上限
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, pocMaxZipBytes+1))
		if err != nil {
			lastErr = err
			continue
		}
		if len(b) > pocMaxZipBytes {
			return nil, fmt.Errorf("åç¼©åè¶è¿ %d MB ä¸é", pocMaxZipBytes>>20)
		}
		return b, nil
	}
	return nil, lastErr
}

// pocImportZip 解析 zip 内全部 .yaml/.yml，按模板 id upsert 进 pocs 表。
// component 用 tags 首个；只增不删（哨兵语义）。
// 限额（审计修复：zip 炸弹面）：最多 60000 条、累计 1GB 模板字节。
const pocImportMaxEntries = 60000
const pocImportMaxBytes = 1 << 30

func (s *Server) pocImportZip(body []byte) (added, updated int, err error) {
	var entries, totalBytes int
	zr, err := zip.NewReader(bytesReaderAt(body), int64(len(body)))
	if err != nil {
		return 0, 0, err
	}
	// 先收集、后 BulkUpsertTx 单事务落库：逐条 autocommit 曾是同步分钟级主因。
	var rows []db.PocUpsertRow
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || (!strings.HasSuffix(f.Name, ".yaml") && !strings.HasSuffix(f.Name, ".yml")) {
			continue
		}
		entries++
		if entries > pocImportMaxEntries {
			return added, updated, fmt.Errorf("zip 条目超过 %d 上限（疑似压缩炸弹），已中止", pocImportMaxEntries)
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		content, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		totalBytes += len(content)
		if totalBytes > pocImportMaxBytes {
			return added, updated, fmt.Errorf("解包总量超过 1GB 上限，已中止")
		}
		tpl := ensureNucleiAuthorLocal(string(content))
		id := firstMatch(pocIDRe, tpl)
		if id == "" {
			continue
		}
		name := firstMatch(pocNameRe, tpl)
		if name == "" {
			name = id
		}
		rows = append(rows, db.PocUpsertRow{
			TemplateID: id, Title: name,
			Component: firstMatch(pocTagRe, tpl), Severity: firstMatch(pocSeverityRe, tpl),
			Template: tpl, Source: "subscription",
		})
	}
	return s.m.pg.Pocs().BulkUpsertTx(rows)
}

func firstMatch(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); len(m) > 1 {
		return strings.Trim(m[1], `"'`)
	}
	return ""
}

// ensureNucleiAuthorLocal ä¸ server.ensureNucleiAuthor åä¹ï¼æ¬å°å¤ç¨ï¼ã
var pocAuthorRe = regexp.MustCompile(`(?m)^author:`)

func ensureNucleiAuthorLocal(tpl string) string {
	if pocAuthorRe.MatchString(tpl) {
		return tpl
	}
	i := strings.Index(tpl, "info:")
	if i < 0 {
		return tpl
	}
	rest := tpl[i+len("info:"):]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		return tpl + "\n  author: artex\n"
	}
	return tpl[:i+len("info:")+nl+1] + "  author: artex\n" + rest[nl+1:]
}

// ---------- HTTP ----------

func (s *Server) registerPocSubRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/pocs/sources", s.pocSourcesGet)
	mux.HandleFunc("PUT /api/pocs/sources", s.pocSourcesSet)
	mux.HandleFunc("POST /api/pocs/sources/{id}/sync", s.pocSourcesSync)
}

func (s *Server) pocSourcesGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"sources": s.loadPocSources(), "history": s.loadPocHistory()})
}

func (s *Server) pocSourcesSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Sources []pocSource `json:"sources"`
		EnsureOfficial bool `json:"ensure_official"` // ä¸é®åå»ºå®æ¹æº
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "è¯·æ±ä½æ æ")
		return
	}
	if body.EnsureOfficial {
		found := false
		for _, src := range body.Sources {
			if src.ID == pocOfficialSourceID {
				found = true
			}
		}
		if !found {
			body.Sources = append(body.Sources, pocSource{ID: pocOfficialSourceID, Name: "å®æ¹ NucleiPOC", URL: pocOfficialSourceURL, IntervalHours: 168})
		}
	}
	if err := s.savePocSources(body.Sources); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"sources": s.loadPocSources()})
}

func (s *Server) pocSourcesSync(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, err := s.syncPocSource(id)
	if err != nil {
		writeJSON(w, 500, map[string]any{"record": rec, "error": err.Error()})
		return
	}
	writeJSON(w, 200, rec)
}

type bytesReader struct{ b []byte }

func (r *bytesReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	return n, nil
}

var _ = context.Background

func bytesReaderAt(b []byte) *bytesReader { return &bytesReader{b} }
