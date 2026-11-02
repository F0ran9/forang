package server

// codeaudit.go — 源码审计（移植自 CodeScan-Artex 的上传与解压安全设计）：
//   POST /api/codeaudit/upload        上传源码 zip（流式落盘 + 安全解压到 staging）
//   GET  /api/codeaudit/uploads       未使用的上传列表（刷新不丢）
//   DELETE /api/codeaudit/uploads/{id} 放弃上传
//   POST /api/codeaudit/task          消费上传 → 创建审计任务（audit_mode + 源码目录迁移）
//
// 大包考虑：multipart 流式接收（MaxBytesReader 上限 2GiB），边收边写不进内存；
// 解压防 zip bomb（总数 6GiB/30 万文件上限）+ 防路径穿越 + 跳过符号链接/设备文件。
// 上传先落 data/code_uploads/<id>/{orig.zip,source/}，建任务时整体搬进
// data/tasks/<taskID>/source——未消费的上传不污染任何任务，重启后仍可用。

import (
	"archive/zip"

	"github.com/Autumn-27/artex/db"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

)

const (
	caMaxUploadBytes  = 2 << 30    // 2 GiB：上传 zip 上限（大仓库源码包）
	caMaxExtractBytes = 6 << 30    // 6 GiB：解压后总量上限（zip bomb 兜底）
	caMaxExtractFiles = 300000     // 解压文件条数上限
	caUploadDir       = "code_uploads"
)

// ensureCodeAuditTables 幂等建表（uploads 台账 + tasks 审计标记列）。
func (s *Server) ensureCodeAuditTables() {
	_, _ = s.m.PG().Exec(`CREATE TABLE IF NOT EXISTS code_uploads (
		id TEXT PRIMARY KEY,
		filename TEXT NOT NULL,
		zip_path TEXT NOT NULL,
		source_path TEXT NOT NULL,
		file_count BIGINT NOT NULL DEFAULT 0,
		total_bytes BIGINT NOT NULL DEFAULT 0,
		consumed_by BIGINT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	_, _ = s.m.PG().Exec(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS audit_mode BOOLEAN NOT NULL DEFAULT false`)
	_, _ = s.m.PG().Exec(`ALTER TABLE tasks ADD COLUMN IF NOT EXISTS source_path TEXT NOT NULL DEFAULT ''`)
}

func newUploadID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return time.Now().Format("20060102150405") + hex.EncodeToString(b)
}

// caSanitizeName 清洗上传文件名（只留安全字符，防路径注入）。
func caSanitizeName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '-' || r == '_' || r == '(' || r == ')' {
			return r
		}
		return '_'
	}, name)
	if len(name) > 120 {
		name = name[len(name)-120:]
	}
	return name
}

// caSafeZipPath 校验 zip 条目名：拒绝绝对路径/../ 穿越，返回清理后的相对路径。
func caSafeZipPath(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "/")
	if name == "" || strings.Contains(name, "..") {
		return "", false
	}
	cleaned := filepath.ToSlash(filepath.Clean(name))
	if strings.HasPrefix(cleaned, "../") || cleaned == ".." || strings.HasPrefix(cleaned, "/") {
		return "", false
	}
	return cleaned, true
}

// caExtractZip 安全解压：防穿越/符号链接/超限，返回 (文件数, 总字节, 顶层条目)。
func caExtractZip(src, dest string) (files, total int64, entries []string, err error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("不是合法的 zip 文件（%v）", err)
	}
	defer zr.Close()
	if len(zr.File) > caMaxExtractFiles {
		return 0, 0, nil, fmt.Errorf("压缩包内文件数超过 %d", caMaxExtractFiles)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, 0, nil, err
	}
	top := map[string]bool{}
	for _, f := range zr.File {
		rel, ok := caSafeZipPath(f.Name)
		if !ok || rel == "" {
			continue
		}
		if i := strings.IndexByte(rel, '/'); i > 0 {
			top[rel[:i]] = true
		} else {
			top[rel] = true
		}
		if f.FileInfo().IsDir() {
			_ = os.MkdirAll(filepath.Join(dest, filepath.FromSlash(rel)), 0o755)
			continue
		}
		// 符号链接/设备/管道一律跳过：源码审计用不到，解出来只有风险。
		if f.Mode()&os.ModeSymlink != 0 || f.Mode()&os.ModeDevice != 0 || f.Mode()&os.ModeNamedPipe != 0 {
			continue
		}
		if total+int64(f.UncompressedSize64) > caMaxExtractBytes {
			return 0, 0, nil, fmt.Errorf("解压后总大小超过上限（%d GiB）", caMaxExtractBytes>>30)
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return 0, 0, nil, err
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		out, oerr := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if oerr != nil {
			_ = rc.Close()
			continue
		}
		n, cperr := io.Copy(out, io.LimitReader(rc, caMaxExtractBytes))
		_ = rc.Close()
		_ = out.Close()
		if cperr == nil {
			files++
			total += n
		}
	}
	for k := range top {
		if len(entries) < 20 {
			entries = append(entries, k)
		}
	}
	return files, total, entries, nil
}

// caUploadDTO 上传视图（不泄露服务端绝对路径）。
type caUploadDTO struct {
	ID         string   `json:"id"`
	Filename   string   `json:"filename"`
	FileCount  int64    `json:"file_count"`
	TotalBytes int64    `json:"total_bytes"`
	Entries    []string `json:"entries,omitempty"`
	CreatedAt  string   `json:"created_at"`
	TaskID     *int64   `json:"task_id,omitempty"` // 已消费时指向审计任务
	TaskStatus string   `json:"task_status,omitempty"` // 该任务当前状态（done/running/…）
}

// POST /api/codeaudit/upload — multipart 字段 file，.zip 源码包，流式接收。
func (s *Server) caUpload(w http.ResponseWriter, r *http.Request) {
	s.ensureCodeAuditTables()
	r.Body = http.MaxBytesReader(w, r.Body, caMaxUploadBytes+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		writeErr(w, 400, "请求不是合法的文件上传")
		return
	}
	id := newUploadID()
	dir := filepath.Join(s.m.dir, caUploadDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "创建上传目录失败: "+err.Error())
		return
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	var savedName string
	for {
		part, perr := mr.NextPart()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			cleanup()
			writeErr(w, 400, "读取上传内容失败（文件过大或网络中断）: "+perr.Error())
			return
		}
		if part.FormName() != "file" || part.FileName() == "" {
			_ = part.Close()
			continue
		}
		savedName = caSanitizeName(part.FileName())
		if !strings.HasSuffix(strings.ToLower(savedName), ".zip") {
			_ = part.Close()
			cleanup()
			writeErr(w, 400, "只支持 .zip 源码压缩包")
			return
		}
		zipPath := filepath.Join(dir, savedName)
		f, ferr := os.Create(zipPath)
		if ferr != nil {
			_ = part.Close()
			cleanup()
			writeErr(w, 500, "保存上传文件失败: "+ferr.Error())
			return
		}
		_, cerr := io.Copy(f, part) // 流式落盘，大包不占内存
		_ = f.Close()
		_ = part.Close()
		if cerr != nil {
			cleanup()
			writeErr(w, 400, "保存上传文件失败（可能超过大小上限）: "+cerr.Error())
			return
		}
		break
	}
	if savedName == "" {
		cleanup()
		writeErr(w, 400, "未收到文件（表单字段名应为 file）")
		return
	}

	sourceDir := filepath.Join(dir, "source")
	files, total, entries, xerr := caExtractZip(filepath.Join(dir, savedName), sourceDir)
	if xerr != nil {
		cleanup()
		writeErr(w, 400, "解压失败: "+xerr.Error())
		return
	}
	if files == 0 {
		cleanup()
		writeErr(w, 400, "压缩包内没有可解压的文件")
		return
	}
	_, _ = s.m.PG().Exec(
		`INSERT INTO code_uploads (id, filename, zip_path, source_path, file_count, total_bytes)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, savedName, filepath.Join(dir, savedName), sourceDir, files, total)
	log.Printf("[codeaudit] 上传 %s ← %s（%d 文件 / %.1f MB）", id, savedName, files, float64(total)/(1<<20))
	writeJSON(w, 201, caUploadDTO{ID: id, Filename: savedName, FileCount: files, TotalBytes: total,
		Entries: entries, CreatedAt: time.Now().Format("01-02 15:04")})
}

// GET /api/codeaudit/uploads — 最近 50 个未消费上传。
func (s *Server) caUploadsList(w http.ResponseWriter, r *http.Request) {
	s.ensureCodeAuditTables()
	rows, err := s.m.PG().Query(
		`SELECT u.id, u.filename, u.file_count, u.total_bytes, to_char(u.created_at,'MM-DD HH24:MI'),
		        u.consumed_by, COALESCE(t.status,'')
		 FROM code_uploads u LEFT JOIN tasks t ON t.id = u.consumed_by
		 ORDER BY u.created_at DESC LIMIT 50`)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	out := []caUploadDTO{}
	for rows.Next() {
		var d caUploadDTO
		var consumed sql.NullInt64
		var taskStatus string
		if err := rows.Scan(&d.ID, &d.Filename, &d.FileCount, &d.TotalBytes, &d.CreatedAt, &consumed, &taskStatus); err == nil {
			if consumed.Valid {
				d.TaskID = &consumed.Int64
				d.TaskStatus = taskStatus
			}
			out = append(out, d)
		}
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

// DELETE /api/codeaudit/uploads/{id} — 放弃未消费的上传。
func (s *Server) caUploadDelete(w http.ResponseWriter, r *http.Request) {
	s.ensureCodeAuditTables()
	id := strings.TrimSpace(r.PathValue("id"))
	var consumed sql.NullInt64
	err := s.m.PG().QueryRow(`SELECT consumed_by FROM code_uploads WHERE id=$1`, id).Scan(&consumed)
	if err == sql.ErrNoRows {
		writeErr(w, 404, "上传不存在")
		return
	}
	if consumed.Valid {
		writeErr(w, 400, "该上传已被任务使用")
		return
	}
	_, _ = s.m.PG().Exec(`DELETE FROM code_uploads WHERE id=$1`, id)
	_ = os.RemoveAll(filepath.Join(s.m.dir, caUploadDir, id))
	writeJSON(w, 200, map[string]any{"deleted": id})
}

// caAuditGoal 审计任务的目标模板（聚焦可选）。
const caAuditGoal = `对已解压在 tasks/%s/source 的源码做静态代码审计（只读，不出网不执行）。
按序推进：
1) 摸结构：LS/Glob 看清目录与构建文件（pom.xml/package.json/requirements.txt/go.mod 等），确定语言与框架；
2) 入口清点：找全部对外入口（Controller/Router/API），用 insert_assets 登记为 endpoint 资产（url/method/params/permission，permission 按鉴权注解>拦截器>路由分组判定）；
3) 高危面审计：优先查 SQL 注入、命令执行、未授权访问（permission=内部接口/公开但涉敏）、路径穿越、SSRF、反序列化、硬编码凭据；
4) 数据流确认：每个疑似缺陷走三步（入口参数可控→校验确实缺失→到达 Sink），给 文件:行号+代码片段，report_finding 提交；
5) 对抗自检：每条漏洞换一条证据链复核一次再提交；存疑的记 fact 不报漏洞；
6) 收尾：record_fact 总结审计范围与结论。%s`

// POST /api/codeaudit/task — {upload_id, focus?} 消费上传并创建审计任务。
func (s *Server) caCreateTask(w http.ResponseWriter, r *http.Request) {
	s.ensureCodeAuditTables()
	var b struct {
		UploadID string `json:"upload_id"`
		Focus    string `json:"focus"`
	}
	if err := decodeJSONBody(r, &b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	var filename, sourcePath string
	var consumed sql.NullInt64
	err := s.m.PG().QueryRow(
		`SELECT filename, source_path, consumed_by FROM code_uploads WHERE id=$1`, b.UploadID).
		Scan(&filename, &sourcePath, &consumed)
	if err == sql.ErrNoRows {
		writeErr(w, 404, "上传不存在或已过期，请重新上传")
		return
	}
	if consumed.Valid {
		writeErr(w, 400, fmt.Sprintf("该上传已被任务 #%d 使用", consumed.Int64))
		return
	}
	fi, serr := os.Stat(sourcePath)
	if serr != nil || !fi.IsDir() {
		writeErr(w, 400, "上传的源码目录已丢失，请重新上传")
		return
	}

	focus := strings.TrimSpace(b.Focus)
	focusBlock := ""
	if focus != "" {
		focusBlock = "\n重点关注：" + focus
	}
	goal := fmt.Sprintf(caAuditGoal, "%s", focusBlock) // 占位在创建后补任务 id
	taskName := "源码审计：" + filename
	if focus != "" {
		taskName += "（" + truncateStr(focus, 20) + "）"
	}

	t, terr := s.m.CreateTaskWithOptions(filename, goal, db.TaskCreateOptions{Name: taskName})
	if terr != nil {
		writeErr(w, 500, "创建任务失败: "+terr.Error())
		return
	}
	// 补全 goal 里的任务 id 占位（source 路径依赖任务 id）。
	goal = fmt.Sprintf(caAuditGoal, t.ID, focusBlock)
	_, _ = s.m.PG().Exec(`UPDATE tasks SET goal=$2 WHERE id=$1`, mustInt64(t.ID), goal)
	// 源码目录迁移：staging → data/tasks/<id>/source。
	dest := filepath.Join(s.m.dir, "tasks", t.ID, "source")
	_ = os.MkdirAll(filepath.Dir(dest), 0o755)
	if rerr := os.Rename(sourcePath, dest); rerr != nil {
		// 跨盘退化为复制
		if cerr := caCopyDir(sourcePath, dest); cerr != nil {
			writeErr(w, 500, "源码迁移失败: "+cerr.Error())
			return
		}
		_ = os.RemoveAll(sourcePath)
	}
	rel := "tasks/" + t.ID + "/source"
	if _, err := s.m.PG().Exec(
		`UPDATE tasks SET audit_mode=true, source_path=$2 WHERE id=$1`, mustInt64(t.ID), rel); err != nil {
		writeErr(w, 500, "标记审计任务失败: "+err.Error())
		return
	}
	// 消费标记（原子抢占：防两个请求同时用同一上传）。
	res, _ := s.m.PG().Exec(
		`UPDATE code_uploads SET consumed_by=$2 WHERE id=$1 AND consumed_by IS NULL`, b.UploadID, mustInt64(t.ID))
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, 409, "该上传已被其他任务使用")
		return
	}
	log.Printf("[codeaudit] 上传 %s → 审计任务 #%s（源码 %s）", b.UploadID, t.ID, rel)
	s.launchTask(t, goal, false)
	writeJSON(w, 201, map[string]any{"task_id": t.ID, "name": taskName, "source": rel})
}

// mustInt64 任务 id 转 int64（创建路径里必然合法）。
func mustInt64(s string) int64 {
	var n int64
	fmt.Sscan(s, &n)
	return n
}

// caCopyDir 递归复制目录（Rename 跨盘兜底）。
func caCopyDir(src, dst string) error {
	return filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, ierr := os.Open(p)
		if ierr != nil {
			return ierr
		}
		defer in.Close()
		out, oerr := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if oerr != nil {
			return oerr
		}
		defer out.Close()
		_, oerr = io.Copy(out, in)
		return oerr
	})
}
