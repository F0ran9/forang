package intercept

// 只读预筛：认得出必须放行的，也必须挡住一切可能写盘的。

import (
	"context"
	"encoding/json"
	"testing"
)

func TestPrefilterReadOnly(t *testing.T) {
	allow := []string{
		"echo hello",
		"sleep 30",
		"cat a.txt | head -5",
		"grep -n TODO src/*.go",
		"dig +short A www.zjmiit.com @223.5.5.5",
		"curl -s -I https://x.test",
		"curl -s 'https://x.test/a?b=1' | jq -r .name",
		"nslookup mail.wzgroup.cn 8.8.8.8",
		"ls -la /tmp 2>/dev/null",
		"awk '{print $1}' file.txt | sort | uniq -c",
		"ping -c 2 1.1.1.1",
		"/bin/cat /etc/hostname",
		"cd /opt/x && curl -sk -o /dev/null -w 'code=%{http_code}' https://y.test",
		"cd /tmp && echo '=== A ===' ; curl -s -I https://y.test",
		"curl -s -o /dev/null -m 15 -w 'HTTP %{http_code}' https://y.test/x",
	}
	deny := []string{
		"echo x > out.txt",
		"cat a >> b",
		"curl -o /tmp/x https://y.test",
		"curl -O https://y.test/a.zip",
		"curl -s https://y.test | tee out.txt",
		"curl -X POST -d 'a=1' https://y.test",
		"wget -O /tmp/x https://y.test",
		"sed -i 's/a/b/' f.txt",
		"find . -name '*.sh' -delete",
		"rm -rf /tmp/x",
		"echo $(id) ",
		"echo hi | sh",
		"python3 x.py",
		"bash probe.sh",
		"cp a b",
		"chmod +x x",
		"nmap -p 80 1.2.3.4",
		"echo `whoami`",
		"",
	}
	for _, c := range allow {
		args, _ := json.Marshal(map[string]string{"command": c})
		if ok, _ := PrefilterReadOnly("Bash", args); !ok {
			t.Errorf("应放行但被拦: %q", c)
		}
	}
	for _, c := range deny {
		args, _ := json.Marshal(map[string]string{"command": c})
		if ok, why := PrefilterReadOnly("Bash", args); ok {
			t.Errorf("应交给裁判但被预筛放行: %q (%s)", c, why)
		}
	}
	// 非 Bash 工具不预筛
	args, _ := json.Marshal(map[string]string{"file_path": "a.txt"})
	if ok, _ := PrefilterReadOnly("Write", args); ok {
		t.Error("Write 不应被预筛放行")
	}
}

// 工作目录内的本地产物写入（A2）也应预筛；目录外写入必须交给裁判。
func TestPrefilterLocalArtifacts(t *testing.T) {
	wd := t.TempDir()
	ctx := WithReviewContext(context.Background(), wd, ReviewBackground{})
	ok := []string{
		"cd " + wd + " && curl -sk -D f1.txt -o f1.html https://x.test",
		"cd " + wd + " && for u in a b c; do echo $u; done",
		"mkdir -p " + wd + "/sub",
		"echo hi > " + wd + "/a.log",
		"tee " + wd + "/round1.log",
	}
	no := []string{
		"curl -o /etc/passwd.bak https://x.test",
		"echo hi > /etc/motd",
		"mkdir -p /etc/evil",
		"cp /etc/shadow /tmp/x",
	}
	for _, c := range ok {
		args, _ := json.Marshal(map[string]string{"command": c})
		if got, why := PrefilterDecision(ctx, "Bash", args); !got {
			t.Errorf("工作目录内应放行: %q (%s)", c, why)
		}
	}
	for _, c := range no {
		args, _ := json.Marshal(map[string]string{"command": c})
		if got, _ := PrefilterDecision(ctx, "Bash", args); got {
			t.Errorf("目录外写入不应预筛: %q", c)
		}
	}
}
