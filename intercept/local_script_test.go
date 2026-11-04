package intercept

// local_script_test.go — 脚本源码附带：路径提取 + BuildReviewInput 挂接 + 越界/截断。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractScriptPath(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		{"python3 fetch_pages.py", "fetch_pages.py"},
		{"python3 -u scripts/scan.py --threads 4", "scripts/scan.py"},
		{"bash ./run.sh arg1", "./run.sh"},
		{"sh /tmp/x.sh", "/tmp/x.sh"},
		{"node --experimental-modules tool.js", "tool.js"},
		{"env API=1 python3 a.py", "a.py"},
		{"sudo python3 a.py", "a.py"},
		{"python3 -c 'print(1)'", ""},                    // -c 内联代码不是文件
		{"curl -s http://x/ | bash", ""},                 // 管道不算
		{"python3", ""},                                  // 无脚本参数
		{"echo python3 a.py", ""},                        // runner 不在首位
		{"python3 -m http.server 8000", ""},            // -m 模块名不是文件
		{"./custom-runner a.py", ""},                     // 自定义 runner 不识别
		{"python3 'my script.py' --flag", "my script.py"}, // 引号包裹带空格
	}
	for _, c := range cases {
		if got := ExtractScriptPath(c.cmd); got != c.want {
			t.Errorf("ExtractScriptPath(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

func TestAttachLocalScriptReadsContent(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fetch_pages.py")
	body := "#!/usr/bin/env python3\nimport urllib.request\nfor u in URLS:\n    print(urllib.request.urlopen(u).read()[:100])\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := WithReviewContext(context.Background(), dir, ReviewBackground{})
	args, _ := json.Marshal(map[string]any{"command": "python3 fetch_pages.py"})
	in, err := BuildReviewInput(ctx, "Bash", args)
	if err != nil {
		t.Fatal(err)
	}
	if in.LocalScript == nil {
		t.Fatal("LocalScript 未附带")
	}
	if in.LocalScript.ReadError != "" {
		t.Fatalf("ReadError 应为空: %s", in.LocalScript.ReadError)
	}
	if !strings.Contains(in.LocalScript.Content, "urllib.request.urlopen") {
		t.Errorf("脚本正文缺失: %q", in.LocalScript.Content)
	}
	// 输入 JSON 里字段可见（裁判侧数据流）
	raw, _ := json.Marshal(in)
	if !strings.Contains(string(raw), "local_script") {
		t.Error("local_script 未进入序列化输入")
	}
}

func TestAttachLocalScriptOutsideWorkdir(t *testing.T) {
	dir := t.TempDir()
	ctx := WithReviewContext(context.Background(), dir, ReviewBackground{})
	abs := filepath.Join(t.TempDir(), "evil.py") // 工作目录外
	args, _ := json.Marshal(map[string]any{"command": "python3 " + abs})
	in, err := BuildReviewInput(ctx, "Bash", args)
	if err != nil {
		t.Fatal(err)
	}
	if in.LocalScript == nil || in.LocalScript.ReadError == "" {
		t.Fatalf("越界路径应带 ReadError，got %+v", in.LocalScript)
	}
	if !strings.Contains(in.LocalScript.ReadError, "工作目录") {
		t.Errorf("ReadError 应说明越界: %s", in.LocalScript.ReadError)
	}
}

func TestAttachLocalScriptTruncatesHugeScript(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", 16<<10) + "os.system('rm -rf /')" // 关键破坏在尾部
	if err := os.WriteFile(filepath.Join(dir, "big.py"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := WithReviewContext(context.Background(), dir, ReviewBackground{})
	args, _ := json.Marshal(map[string]any{"command": "python3 big.py"})
	in, err := BuildReviewInput(ctx, "Bash", args)
	if err != nil {
		t.Fatal(err)
	}
	if in.LocalScript == nil || !in.LocalScript.Truncated {
		t.Fatalf("超长脚本应标记截断，got %+v", in.LocalScript)
	}
	if !strings.Contains(in.LocalScript.Content, "rm -rf") {
		t.Error("截断预览应保留尾部（头8K+尾4K），破坏语句在尾部却丢失")
	}
}

func TestAttachLocalScriptNonBashIgnored(t *testing.T) {
	dir := t.TempDir()
	ctx := WithReviewContext(context.Background(), dir, ReviewBackground{})
	args, _ := json.Marshal(map[string]any{"raw": "GET / HTTP/1.1"})
	in, err := BuildReviewInput(ctx, "repeater_send", args)
	if err != nil {
		t.Fatal(err)
	}
	if in.LocalScript != nil {
		t.Error("非 Bash 工具不应附带 local_script")
	}
}
