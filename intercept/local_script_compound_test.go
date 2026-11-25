package intercept

// 线上反馈回归：真实命令形态下裁判看不到脚本内容。
// 覆盖 ①复合命令 ②sh -c 包装 ③heredoc 现场生成（文件尚未落盘）。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractScriptPathsCompound(t *testing.T) {
	cases := map[string]string{
		"cd /w/i1 && bash probe.sh | tee round1.log": "probe.sh",
		"cd /w && chmod +x p.sh && bash p.sh":        "p.sh",
		"sh -c 'bash ./x.sh'":                        "./x.sh",
		"timeout 30s python3 -u fetch.py --all":      "fetch.py",
		"env FOO=1 bash run.sh":                      "run.sh",
		"nmap -p 80,443 10.0.0.1":                    "", // 不是脚本
		"python3 -m http.server 8000":                "", // -m 是模块
	}
	for cmd, want := range cases {
		got := ExtractScriptPath(cmd)
		if got != want {
			t.Errorf("ExtractScriptPath(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestAttachLocalScriptFromDisk(t *testing.T) {
	dir := t.TempDir()
	body := "#!/bin/bash\necho hello\n"
	if err := os.WriteFile(filepath.Join(dir, "probe.sh"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	in := &ReviewInput{Tool: "Bash", WorkingDir: dir}
	args, _ := json.Marshal(map[string]string{"command": "cd " + dir + " && bash probe.sh | tee r.log"})
	AttachLocalScript(in, args)
	if in.LocalScript == nil {
		t.Fatal("未附带脚本")
	}
	if in.LocalScript.Path != "probe.sh" || !strings.Contains(in.LocalScript.Content, "echo hello") {
		t.Fatalf("内容不对: %+v", in.LocalScript)
	}
	if in.LocalScript.Source != "file" {
		t.Fatalf("Source=%q, want file", in.LocalScript.Source)
	}
}

// heredoc 现场生成：审批时文件还不存在，必须从命令里抽正文。
func TestAttachLocalScriptFromHeredoc(t *testing.T) {
	dir := t.TempDir()
	cmd := "cd " + dir + " && cat > probe.sh <<'EOF'\n#!/bin/bash\nfor p in 80 443; do\n  timeout 3 bash -c \"exec 3<>/dev/tcp/1.2.3.4/$p\" && echo OPEN $p\ndone\nEOF\nchmod +x probe.sh && bash probe.sh | tee out.log"
	in := &ReviewInput{Tool: "Bash", WorkingDir: dir}
	args, _ := json.Marshal(map[string]string{"command": cmd})
	AttachLocalScript(in, args)
	if in.LocalScript == nil {
		t.Fatal("未附带脚本")
	}
	ref := in.LocalScript
	if ref.Source != "command-inline" {
		t.Fatalf("Source=%q, want command-inline", ref.Source)
	}
	if !strings.Contains(ref.Content, "exec 3<>/dev/tcp") || strings.Contains(ref.Content, "EOF") {
		t.Fatalf("heredoc 抽取不对: %q", ref.Content)
	}
}

// 越界仍必须拦住（审查通道不能变成任意文件读取口）。
func TestAttachLocalScriptOutOfWorkdir(t *testing.T) {
	dir := t.TempDir()
	in := &ReviewInput{Tool: "Bash", WorkingDir: dir}
	args, _ := json.Marshal(map[string]string{"command": "bash /etc/profile.d/x.sh"})
	AttachLocalScript(in, args)
	if in.LocalScript == nil || in.LocalScript.ReadError == "" {
		t.Fatalf("越界应记 ReadError，实际 %+v", in.LocalScript)
	}
	if in.LocalScript.Content != "" {
		t.Fatal("越界不应附带内容")
	}
}

// 人工审批说明里要能看见脚本体（否则人也没法判断）。
func TestScriptExcerptFor(t *testing.T) {
	cmd := "cd /w && cat > probe.sh <<'EOF'\necho probing 1.2.3.4\nEOF\nbash probe.sh"
	args, _ := json.Marshal(map[string]string{"command": cmd})
	got := ScriptExcerptFor("Bash", args)
	if !strings.Contains(got, "probe.sh") || !strings.Contains(got, "echo probing") {
		t.Fatalf("摘要不含脚本内容: %q", got)
	}
	if !strings.Contains(got, "命令内联") {
		t.Fatalf("摘要未标注来源: %q", got)
	}
	// 非脚本命令不应产生摘要
	args2, _ := json.Marshal(map[string]string{"command": "curl -I https://x.test"})
	if ScriptExcerptFor("Bash", args2) != "" {
		t.Fatal("普通命令不应产生脚本摘要")
	}
}
