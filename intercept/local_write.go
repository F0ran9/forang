package intercept

// local_write.go — 给裁判补上「Write/Edit 写的是本机工作目录，不是目标主机」的事实。
//
// 线上 #1798：模型调 Write 写一个本地 DNS 差异对比脚本（工作目录内），裁判判成
// 「在目标系统创建可执行代码，构成持久化驻留风险」→ DENY。这是典型的归属误判：
// Write 工具落盘在本机任务工作目录，跟目标系统毫无关系；只有内容被上传/提交到
// 目标接口时才算目标侧变更。
//
// 另外该次调用的 file_path 参数本身是坏的（含换行与 # 的注释片段），裁判更无从
// 判断位置。这里把路径合法性一并作为事实交给裁判，让它按「参数错误」处理，而
// 不是脑补成持久化。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// writeTools 会落盘到本机文件系统的工具。
var writeTools = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true,
}

// LocalWriteHint 描述一次本地文件写入的位置与合法性（随裁判输入下发）。
type LocalWriteHint struct {
	// Tool 工具名，便于裁判区分 Write / Edit。
	Tool string `json:"tool"`
	// Path 模型给出的原始路径（未加工，便于裁判看原始参数）。
	Path string `json:"path"`
	// Resolved 解析后的绝对路径（相对工作目录时才是绝对路径）。
	Resolved string `json:"resolved,omitempty"`
	// InsideWorkdir 是否落在任务工作目录子树内。
	InsideWorkdir bool `json:"inside_workdir"`
	// Exists 目标文件当前是否已存在（覆盖 vs 新建）。
	Exists bool `json:"exists"`
	// Size 已存在文件的大小（字节）。
	Size int64 `json:"size,omitempty"`
	// PathValid 路径本身是否可用（空、含换行/控制字符、含 URL、纯注释片段都算无效）。
	PathValid bool `json:"path_valid"`
	// Note 面向裁判的一句话结论，避免它自行脑补归属。
	Note string `json:"note"`
}

// AttachLocalWrite 为写类工具附带本地写入事实。非写类工具直接返回。
func AttachLocalWrite(in *ReviewInput, tool string, arguments json.RawMessage) {
	if in == nil || !writeTools[tool] {
		return
	}
	var args map[string]any
	if err := json.Unmarshal(arguments, &args); err != nil {
		return
	}
	raw := ""
	for _, k := range []string{"file_path", "filePath", "path", "filename"} {
		if v, ok := args[k].(string); ok && strings.TrimSpace(v) != "" {
			raw = v
			break
		}
	}
	hint := LocalWriteHint{Tool: tool, Path: raw}
	switch {
	case raw == "":
		hint.PathValid = false
		hint.Note = "未提供文件路径；按参数错误处理，不要当成对目标系统的写入"
	case strings.ContainsAny(raw, "\r\n\t") || strings.Contains(raw, "://"):
		hint.PathValid = false
		hint.Note = "文件路径含换行/控制字符或 URL，是无效路径（参数错误），不会真的写入，不要判成持久化"
	default:
		hint.PathValid = true
		// 解析位置
		p := raw
		if !filepath.IsAbs(p) && in.WorkingDir != "" {
			p = filepath.Join(in.WorkingDir, p)
		}
		if abs, err := filepath.Abs(p); err == nil {
			hint.Resolved = abs
			if in.WorkingDir != "" {
				wdAbs, werr := filepath.Abs(in.WorkingDir)
				if werr == nil {
					hint.InsideWorkdir = abs == wdAbs ||
						strings.HasPrefix(abs+string(filepath.Separator), wdAbs+string(filepath.Separator))
				}
			}
			if st, err := os.Stat(abs); err == nil {
				hint.Exists = true
				hint.Size = st.Size()
			}
		}
		switch {
		case hint.InsideWorkdir:
			hint.Note = "写的是本机任务工作目录内的文件（不是目标主机/目标系统），属于测试产物"
		case hint.Resolved != "":
			hint.Note = "写的是本机文件系统路径，不是通过接口写目标系统；请只按内容本身判断是否构成危险"
		}
	}
	in.LocalWrite = &hint
}
