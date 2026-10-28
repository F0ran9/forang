package server

// plugins.go — 插件中心（移植自哨兵 plugin-center 的可移植子集，MIT）。
// 哨兵完整版含 Docker 镜像交付 + VPS plugin-host + iframe 前端；本版面向内网
// 单机部署裁剪为：插件 = zip（plugin.json manifest + 任意文件），上传解包到
// <data>/plugins/<id>/，manifest 声明 capabilities 与 mcp servers；启用时把
// mcp servers 以 plugin-<id>-<name> 写入 mcp_servers 表（stdio 相对命令解析为
// 插件目录内绝对路径），停用/删除时移除——工具经既有 MCP 通路挂给 agent。
// 不做（如实记录）：VPS 远端宿主、Docker 镜像构建、插件自带 iframe UI。

import (
	"github.com/Autumn-27/artex/db"
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type pluginManifest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Capabilities []string `json:"capabilities"`
	MCP         []struct {
		Name      string            `json:"name"`
		Transport string            `json:"transport"` // stdio / http / sse
		Command   string            `json:"command"`
		Args      []string          `json:"args"`
		Env       map[string]string `json:"env"`
		URL       string            `json:"url"`
		Insecure  bool              `json:"insecure"`
	} `json:"mcp"`
}

type pluginEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Capabilities []string `json:"capabilities"`
	Enabled     bool     `json:"enabled"`
	Dir         string   `json:"dir"`
}

func (s *Server) pluginsRoot() string { return filepath.Join(s.m.dir, "plugins") }

func (s *Server) loadPlugins() []pluginEntry {
	var out []pluginEntry
	if s.m.pg == nil {
		return out
	}
	if v, ok, _ := s.m.pg.GetSetting("plugins"); ok && v != "" {
		_ = json.Unmarshal([]byte(v), &out)
	}
	return out
}

func (s *Server) savePlugins(list []pluginEntry) error {
	b, _ := json.Marshal(list)
	return s.m.pg.SetSetting("plugins", string(b))
}

func (s *Server) registerPluginRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins", s.pluginsList)
	mux.HandleFunc("POST /api/plugins", s.pluginsUpload)
	mux.HandleFunc("PUT /api/plugins/{id}", s.pluginsToggle)
	mux.HandleFunc("DELETE /api/plugins/{id}", s.pluginsDelete)
}

func (s *Server) pluginsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"items": s.loadPlugins(), "root": s.pluginsRoot()})
}

// pluginsUpload 接收 zip：根目录或单层子目录里有 plugin.json。
func (s *Server) pluginsUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "上传解析失败: "+err.Error())
		return
	}
	f, hdr, err := r.FormFile("package")
	if err != nil {
		writeErr(w, 400, "缺少 package 文件域")
		return
	}
	defer f.Close()
	zr, err := zip.NewReader(&readerAt{r: f}, hdr.Size)
	if err != nil {
		writeErr(w, 400, "不是合法 zip")
		return
	}
	// 找 manifest 前缀（根 or 一层子目录）
	var prefix string
	var manifest *pluginManifest
	for _, zf := range zr.File {
		name := zf.Name
		if base := filepath.Base(name); base == "plugin.json" {
			depth := strings.Count(strings.TrimSuffix(name, "/"), "/")
			if depth <= 1 {
				prefix = strings.TrimSuffix(strings.TrimSuffix(name, "plugin.json"), "/")
				prefix = strings.TrimSuffix(prefix, "/") + "/"
				rc, oerr := zf.Open()
				if oerr != nil {
					continue
				}
				b, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
				rc.Close()
				var m pluginManifest
				if json.Unmarshal(b, &m) == nil {
					manifest = &m
				}
			}
		}
	}
	if manifest == nil || strings.TrimSpace(manifest.Name) == "" {
		writeErr(w, 400, "压缩包内未找到含 name 的 plugin.json（根目录或一层子目录）")
		return
	}
	id := slugDoctrine(manifest.Name)
	list := s.loadPlugins()
	for _, p := range list {
		if p.ID == id {
			writeErr(w, 409, "同名插件已存在："+id)
			return
		}
	}
	dir := filepath.Join(s.pluginsRoot(), id)
	_ = os.RemoveAll(dir)
	if err := extractZip(zr, dir, prefix); err != nil {
		writeErr(w, 500, "解包失败: "+err.Error())
		return
	}
	entry := pluginEntry{
		ID: id, Name: manifest.Name, Description: manifest.Description,
		Capabilities: manifest.Capabilities, Enabled: false, Dir: dir,
	}
	list = append(list, entry)
	if err := s.savePlugins(list); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, entry)
}

// pluginsToggle 启停：启用=按 manifest 同步 mcp_servers 行；停用=移除对应行。
func (s *Server) pluginsToggle(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct{ Enabled bool }
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求体无效")
		return
	}
	list := s.loadPlugins()
	idx := -1
	for i, p := range list {
		if p.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		writeErr(w, 404, "插件不存在")
		return
	}
	if body.Enabled {
		if err := s.syncPluginMCP(list[idx]); err != nil {
			writeErr(w, 500, "注册 MCP 失败: "+err.Error())
			return
		}
	} else {
		s.removePluginMCP(id)
	}
	list[idx].Enabled = body.Enabled
	_ = s.savePlugins(list)
	writeJSON(w, 200, list[idx])
}

func (s *Server) pluginsDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	list := s.loadPlugins()
	var out []pluginEntry
	for _, p := range list {
		if p.ID == id {
			s.removePluginMCP(id)
			_ = os.RemoveAll(p.Dir)
			continue
		}
		out = append(out, p)
	}
	if len(out) == len(list) {
		writeErr(w, 404, "插件不存在")
		return
	}
	_ = s.savePlugins(out)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// syncPluginMCP 按 manifest 写入 mcp_servers（name=plugin-<id>-<srv>，幂等 upsert）。
func (s *Server) syncPluginMCP(p pluginEntry) error {
	mf, err := readPluginManifest(p.Dir)
	if err != nil {
		return err
	}
	existing, _ := s.m.pg.ListMCP()
	byName := map[string]int64{}
	for _, m := range existing {
		byName[m.Name] = m.ID
	}
	for _, srv := range mf.MCP {
		if srv.Name == "" {
			continue
		}
		name := fmt.Sprintf("plugin-%s-%s", p.ID, srv.Name)
		cmd := srv.Command
		if srv.Transport == "stdio" && cmd != "" && !filepath.IsAbs(cmd) {
			cmd = filepath.Join(p.Dir, cmd)
		}
		args, _ := json.Marshal(srv.Args)
		env, _ := json.Marshal(srv.Env)
		row := db.MCPServer{
			Name: name, Transport: srv.Transport, Command: cmd,
			Args: args, Env: env, URL: srv.URL, Enabled: true, Insecure: srv.Insecure,
		}
		if id, ok := byName[name]; ok {
			row.ID = id
		}
		if _, err := s.m.pg.SaveMCP(&row); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) removePluginMCP(id string) {
	existing, _ := s.m.pg.ListMCP()
	prefix := fmt.Sprintf("plugin-%s-", id)
	for _, m := range existing {
		if strings.HasPrefix(m.Name, prefix) {
			_ = s.m.pg.DeleteMCP(m.ID)
		}
	}
}

func readPluginManifest(dir string) (*pluginManifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "plugin.json"))
	if err != nil {
		return nil, fmt.Errorf("插件目录缺少 plugin.json")
	}
	var m pluginManifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("plugin.json 解析失败: %v", err)
	}
	return &m, nil
}


func extractZip(zr *zip.Reader, dest, prefix string) error {
	for _, zf := range zr.File {
		name := strings.TrimPrefix(zf.Name, prefix)
		if name == "" {
			continue
		}
		if strings.Contains(name, "..") {
			continue // 防穿越
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		if zf.FileInfo().IsDir() {
			_ = os.MkdirAll(target, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, io.LimitReader(rc, 100<<20))
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

type readerAt struct {
	r   io.Reader
	buf []byte
	done bool
}

func (ra *readerAt) ReadAt(p []byte, off int64) (int, error) {
	// multipart 文件不支持随机访问；首次调用读全量并缓存（zip.NewReader 会多次 ReadAt）。
	if !ra.done {
		b, err := io.ReadAll(ra.r)
		if err != nil && err != io.EOF {
			return 0, err
		}
		ra.buf, ra.done = b, true
	}
	if off >= int64(len(ra.buf)) {
		return 0, io.EOF
	}
	n := copy(p, ra.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
