package intercept

// 线上 #1798 回归：写本地分析脚本被裁判判成「目标系统持久化」。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAttachLocalWriteInsideWorkdir(t *testing.T) {
	dir := t.TempDir()
	in := &ReviewInput{Tool: "Write", WorkingDir: dir}
	args, _ := json.Marshal(map[string]string{
		"file_path": filepath.Join(dir, "diffcheck.py"),
		"content":   "import re\nprint('ok')\n",
	})
	AttachLocalWrite(in, "Write", args)
	if in.LocalWrite == nil {
		t.Fatal("未附带 local_write")
	}
	w := in.LocalWrite
	if !w.PathValid || !w.InsideWorkdir || w.Exists {
		t.Fatalf("事实不对: %+v", w)
	}
	if w.Note == "" {
		t.Fatal("应给出结论 note")
	}
}

func TestAttachLocalWriteInvalidPath(t *testing.T) {
	in := &ReviewInput{Tool: "Write", WorkingDir: t.TempDir()}
	// #1798 的真实形态：file_path 是一段带换行的注释片段
	args, _ := json.Marshal(map[string]string{
		"file_path": "自動化代碼# 调用它解析每个文件:\n# python3 diffcheck.py\n",
		"content":   "import re\n",
	})
	AttachLocalWrite(in, "Write", args)
	if in.LocalWrite == nil || in.LocalWrite.PathValid {
		t.Fatalf("应标记为无效路径: %+v", in.LocalWrite)
	}
	if in.LocalWrite.Note == "" {
		t.Fatal("无效路径也要给结论")
	}
}

func TestAttachLocalWriteExistingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := &ReviewInput{Tool: "Edit", WorkingDir: dir}
	args, _ := json.Marshal(map[string]string{"file_path": "a.txt"})
	AttachLocalWrite(in, "Edit", args)
	if in.LocalWrite == nil || !in.LocalWrite.Exists || in.LocalWrite.Size != 5 {
		t.Fatalf("应识别已存在文件: %+v", in.LocalWrite)
	}
}

func TestAttachLocalWriteIgnoresBash(t *testing.T) {
	in := &ReviewInput{Tool: "Bash", WorkingDir: t.TempDir()}
	args, _ := json.Marshal(map[string]string{"command": "echo hi > x"})
	AttachLocalWrite(in, "Bash", args)
	if in.LocalWrite != nil {
		t.Fatal("Bash 不应产生 local_write")
	}
}
