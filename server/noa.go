package server

// noa.go — 实验功能「noa 上下文压缩」的落盘观测与清理。
// 归档集中在 <data>/noa/<session>/ 下（agent/noa.go），此前平台对它零可见性：
// 跑了多久、攒了多少会话、占多少盘、能否安全清理，都只能上机器翻目录。
// status 给出清单，cleanup 一键清空（实验性数据，删除即放弃回溯能力——前端需确认）。

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type noaSessionStat struct {
	SessionID string `json:"session_id"`
	Files     int    `json:"files"`
	Bytes     int64  `json:"bytes"`
	Modified  string `json:"modified,omitempty"` // RFC3339，该会话最近一次落盘
}

func (s *Server) noaArchiveRoot() string { return filepath.Join(s.m.dir, "noa") }

// GET /api/noa/status
func (s *Server) noaStatus(w http.ResponseWriter, r *http.Request) {
	root := s.noaArchiveRoot()
	resp := map[string]any{
		"enabled":     s.m.NoaCompactionEnabled(),
		"archive_dir": root,
		"sessions":    []noaSessionStat{},
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		// 目录不存在 = 从未启用过，属正常状态而非错误。
		writeJSON(w, 200, resp)
		return
	}
	var sessions []noaSessionStat
	var totalFiles int
	var totalBytes int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		st := noaSessionStat{SessionID: e.Name()}
		dir := filepath.Join(root, e.Name())
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil //nolint:nilerr // 单个不可读文件跳过，不影响整体清点
			}
			st.Files++
			st.Bytes += info.Size()
			if mt := info.ModTime(); mt.After(mustParseRFC3339(st.Modified)) {
				st.Modified = mt.Format(time.RFC3339)
			}
			return nil
		})
		if st.Files > 0 {
			sessions = append(sessions, st)
			totalFiles += st.Files
			totalBytes += st.Bytes
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].SessionID < sessions[j].SessionID })
	resp["sessions"] = sessions
	resp["total_sessions"] = len(sessions)
	resp["total_files"] = totalFiles
	resp["total_bytes"] = totalBytes
	writeJSON(w, 200, resp)
}

// POST /api/noa/cleanup — 清空归档根目录。只在根存在时动作；返回释放的字节数。
func (s *Server) noaCleanup(w http.ResponseWriter, r *http.Request) {
	root := s.noaArchiveRoot()
	var freed int64
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			_ = filepath.Walk(filepath.Join(root, e.Name()), func(_ string, info os.FileInfo, err error) error {
				if err == nil && info != nil && !info.IsDir() {
					freed += info.Size()
				}
				return nil
			})
		}
	}
	if err := os.RemoveAll(root); err != nil {
		writeErr(w, 500, "清理失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "freed_bytes": freed})
}

func mustParseRFC3339(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// noaRoutes 注册在 server.go。
func (s *Server) registerNoaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/noa/status", s.noaStatus)
	mux.HandleFunc("POST /api/noa/cleanup", s.noaCleanup)
}
