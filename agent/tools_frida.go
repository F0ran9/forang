package agent

// tools_frida.go — Android frida 动态调试工具集（移植自全链哨兵 frida-tool.ts，MIT）。
// 脚本原文内嵌于 frida_scripts/*.js（哨兵原版 JS，未改动）。
// 通道：宿主机 adb forward tcp:27042 → 设备 frida-server；frida CLI 在宿主机跑。
// 输出机制照抄：每个内建脚本注入 prelude 参数 + ===== sentinel: name ===== banner，
// 工具按 banner 分节，每脚本输出预算 6000 字符。

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

//go:embed frida_scripts/okhttp_log.js
var fsOkhttp string

//go:embed frida_scripts/ssl_pinning_bypass.js
var fsSslPinning string

//go:embed frida_scripts/root_detection_bypass.js
var fsRootBypass string

//go:embed frida_scripts/crypto_log.js
var fsCryptoLog string

//go:embed frida_scripts/native_ssl_bypass.js
var fsNativeSsl string

//go:embed frida_scripts/flutter_bypass.js
var fsFlutter string

//go:embed frida_scripts/anti_frida_bypass.js
var fsAntiFrida string

//go:embed frida_scripts/dex_dump.js
var fsDexDump string

//go:embed frida_scripts/summaries.json
var fridaSummariesRaw string

var fridaSources = map[string]string{
	"okhttp_log":         fsOkhttp,
	"ssl_pinning_bypass": fsSslPinning,
	"root_detection_bypass": fsRootBypass,
	"crypto_log":         fsCryptoLog,
	"native_ssl_bypass":  fsNativeSsl,
	"flutter_bypass":     fsFlutter,
	"anti_frida_bypass":  fsAntiFrida,
	"dex_dump":           fsDexDump,
}

var fridaSummaries map[string]string

func init() {
	_ = json.Unmarshal([]byte(fridaSummariesRaw), &fridaSummaries)
}

// FridaScriptCatalog 内建脚本清单（给模型看）。
func FridaScriptCatalog() string {
	var sb strings.Builder
	names := []string{"anti_frida_bypass", "root_detection_bypass", "ssl_pinning_bypass", "native_ssl_bypass",
		"flutter_bypass", "okhttp_log", "crypto_log", "dex_dump"}
	for _, n := range names {
		fmt.Fprintf(&sb, "- %s：%s\n", n, fridaSummaries[n])
	}
	return sb.String()
}

const fridaHost = "127.0.0.1:27042"

// fridaParseSpec 解析 name / name?key=value&…（哨兵 parseScriptSpec）。
func fridaParseSpec(spec string) (name string, params map[string]string) {
	i := strings.Index(spec, "?")
	if i < 0 {
		return spec, nil
	}
	name = spec[:i]
	params = map[string]string{}
	for _, pair := range strings.Split(spec[i+1:], "&") {
		eq := strings.Index(pair, "=")
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(pair[:eq])
		v, err := url.QueryUnescape(strings.TrimSpace(pair[eq+1:]))
		if err != nil {
			v = pair[eq+1:]
		}
		params[k] = v
	}
	return name, params
}

// fridaResolveScript 内建名 → prelude+banner+源码；其余视为工作目录路径。
func (t *ToolSet) fridaResolveScript(dir, spec string) (string, string, error) {
	name, params := fridaParseSpec(spec)
	src, ok := fridaSources[name]
	if !ok {
		if strings.Contains(spec, "?") {
			return "", "", fmt.Errorf("未知内建脚本: %s（可用: %s）", name, strings.Join(fridaNames(), ", "))
		}
		p := spec
		if strings.Contains(p, "..") {
			return "", "", fmt.Errorf("自定义脚本路径不允许包含 ..: %s", p)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		if _, err := os.Stat(p); err != nil {
			return "", "", fmt.Errorf("脚本既不是内建名也不是工作目录内文件: %s", spec)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", "", err
		}
		return name, string(b), nil
	}
	pj, _ := json.Marshal(params)
	prelude := "var SENTINEL_PARAMS = " + string(pj) + ";\nfunction sp(k, d) { return SENTINEL_PARAMS[k] !== undefined ? SENTINEL_PARAMS[k] : d; }\n"
	return name, prelude + "console.log(\"\\n===== sentinel: " + name + " =====\");\n" + src, nil
}

func fridaNames() []string {
	return []string{"anti_frida_bypass", "root_detection_bypass", "ssl_pinning_bypass", "native_ssl_bypass",
		"flutter_bypass", "okhttp_log", "crypto_log", "dex_dump"}
}

// fridaForward adb forward 27042（幂等）。
func fridaForward(device string) error {
	pre, err := droidSerial(device)
	if err != nil {
		return err
	}
	out, err := droidRun(context.Background(), 15, append(append([]string{}, pre...), "forward", "tcp:27042", "tcp:27042")...)
	if err != nil {
		return fmt.Errorf("adb forward 失败: %v %s", err, strings.TrimSpace(out))
	}
	return nil
}

// frida-server 17.x 注入即崩，16.7.19 实测可用；CLI 与 server 版本必须配对）。
func fridaBin() string {
	for _, p := range []string{os.Getenv("ARTEX_FRIDA_BIN"), "/opt/frida16/bin/frida", "frida"} {
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			if _, err := os.Stat(p); err == nil {
				return p
			}
			continue
		}
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return ""
}

// fridaRun 在宿主机跑 frida CLI（timeout 兜底收尾，组合输出）。
func fridaRun(secs int, args ...string) (string, error) {
	bin := fridaBin()
	if bin == "" {
		return "", fmt.Errorf("宿主机未安装 frida CLI（模拟器场景建议 /opt/frida16 配 frida-server 16.x）")
	}
	if secs < 5 {
		secs = 5
	}
	// stdin 用 sleeper 撑住：-q 模式下 stdin EOF 会让 REPL 立即退出（resume 后脚本
	// 定时器全部落空、spawn 子进程被连带杀掉），睡满时长后送 exit 正常收尾。
	cmd := exec.Command("sh", "-c", fmt.Sprintf("(sleep %d; echo exit) | timeout %d '%s' %s 2>&1", secs, secs+5, bin, shellJoin(args)))
	out, _ := cmd.CombinedOutput() // timeout 到点被杀是正常收尾，不算错误
	return string(out), nil
}

func shellJoin(args []string) string {
	var parts []string
	for _, a := range args {
		if strings.ContainsAny(a, " '\"") {
			parts = append(parts, "'"+strings.ReplaceAll(a, "'", "'\\''")+"'")
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}

// fridaSectionOutput 按 banner 分节裁剪（哨兵 sectionOutput：每节 6000，节前噪声 2000，总 12000）。
func fridaSectionOutput(output string) string {
	bannerRe := regexp.MustCompile(`(?m)^===== sentinel: (\S+) =====`)
	locs := bannerRe.FindAllStringSubmatchIndex(output, -1)
	if len(locs) == 0 {
		return vulnPreview(output, 12000)
	}
	var sb strings.Builder
	if locs[0][0] > 200 {
		sb.WriteString(vulnPreview(output[:locs[0][0]], 2000) + "\n")
	}
	for i, loc := range locs {
		name := output[loc[2]:loc[3]]
		end := len(output)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		section := strings.TrimSpace(output[loc[0]:end])
		fmt.Fprintf(&sb, "── %s ──\n%s\n\n", name, vulnPreview(section, 6000))
	}
	return vulnPreview(sb.String(), 12000)
}

func (t *ToolSet) fridaTools() []actool.CoreTool {
	return []actool.CoreTool{t.fridaSetupTool(), t.fridaPsTool(), t.fridaRunTool(), t.fridaUnpackTool()}
}

func (t *ToolSet) fridaSetupTool() actool.CoreTool {
	return writeTool("droid_frida_setup",
		"初始化设备 frida 环境：adb forward 27042 → 检查/启动设备上的 frida-server → 用 frida-ps 验证连通。local_path 可选（工作目录内 frida-server 二进制，将 push 到 /data/local/tmp/ 并以 root 启动）；设备上已有 server 时直接复用。",
		obj(map[string]any{
			"device":     str("可选，设备 serial"),
			"local_path": str("可选，宿主工作目录内 frida-server 文件路径（root 设备用它推送）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			device := droidString(in, "device")
			if err := fridaForward(device); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			pre, err := droidSerial(device)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			local := droidString(in, "local_path")
			if local != "" {
				if !filepath.IsAbs(local) {
					local = filepath.Join(t.droidDir, local)
				}
				if _, err := os.Stat(local); err != nil {
					return actool.Errorf("local_path 文件不存在: " + local), nil
				}
				if out, err := droidRun(ctx, 300, append(append([]string{}, pre...), "push", local, "/data/local/tmp/frida-server")...); err != nil {
					return actool.Errorf("push 失败: " + strings.TrimSpace(out)), nil
				}
				_, _ = droidRun(ctx, 30, append(append([]string{}, pre...), "shell", "su", "-c", "chmod 755 /data/local/tmp/frida-server")...)
			}
			// 已在跑？
			out, _ := droidRun(ctx, 20, append(append([]string{}, pre...), "shell", "su", "-c", "pgrep -l frida-server | head -2")...)
			if !strings.Contains(out, "frida-server") {
				if local == "" {
					if out2, _ := droidRun(ctx, 20, append(append([]string{}, pre...), "shell", "su", "-c", "ls /data/local/tmp/frida-server")...); strings.Contains(out2, "No such") {
						return actool.Errorf("设备上没有 frida-server：请把对应架构的 frida-server 放到工作目录后传 local_path（下载地址 https://github.com/frida/frida/releases，选 android-arm64），或自行推到 /data/local/tmp/frida-server"), nil
					}
				}
				_, _ = droidRun(ctx, 30, append(append([]string{}, pre...), "shell", "su", "-c", "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &")...)
				time.Sleep(2 * time.Second)
			}
			ps, err := fridaRun(20, "-H", fridaHost)
			if err != nil {
				return actool.Errorf("frida CLI 不可用: " + err.Error()), nil
			}
			if strings.Contains(ps, "Failed to connect") || strings.Contains(ps, "unable to connect") {
				return actool.Errorf("frida-server 未监听（root 是否可用？）: " + vulnPreview(ps, 400)), nil
			}
			return actool.Text("✅ frida 环境就绪（forward 27042 + server 在跑 + frida-ps 连通）。可用内建脚本：\n" + FridaScriptCatalog()), nil
		})
}

func (t *ToolSet) fridaPsTool() actool.CoreTool {
	return readTool("droid_frida_ps",
		"列出设备上的进程（frida-ps -H）。applications=true 时列出可 spawn 的应用包名。",
		obj(map[string]any{"device": str("可选"), "applications": str("可选，true=列应用（-ai）")}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if err := fridaForward(droidString(in, "device")); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			args := []string{"-H", fridaHost}
			if strings.EqualFold(droidString(in, "applications"), "true") {
				args = append(args, "-ai")
			}
			out, err := fridaRun(30, args...)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text(vulnPreview(out, 8000)), nil
		})
}

func (t *ToolSet) fridaRunTool() actool.CoreTool {
	return writeTool("droid_frida",
		"对目标 app 注入 frida 脚本运行。scripts 每项是 name 或 name?key=value（内建脚本可带参数）或工作目录内自定义 .js 路径，1-4 个按序注入。app 传包名（spawn 默认，可 mode=attach 按进程名附加）或纯数字 PID。app 有反调试/检测 frida 时把 anti_frida_bypass 放第一个。\n内建脚本：\n"+FridaScriptCatalog(),
		obj(map[string]any{
			"app":     str("目标：包名（spawn）/进程名（mode=attach）/纯数字 PID"),
			"scripts": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "1-4 个脚本 spec"},
			"mode":    str("可选：spawn（默认）/ attach"),
			"seconds": intp("可选，运行秒数，默认 20，5-300"),
			"device":  str("可选"),
		}, "app", "scripts"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var a struct {
				App     string   `json:"app"`
				Scripts []string `json:"scripts"`
				Mode    string   `json:"mode"`
				Seconds int      `json:"seconds"`
				Device  string   `json:"device"`
			}
			if err := json.Unmarshal(in, &a); err != nil || a.App == "" || len(a.Scripts) == 0 {
				return actool.Errorf("app 与 scripts 必填"), nil
			}
			if len(a.Scripts) > 4 {
				a.Scripts = a.Scripts[:4]
			}
			if a.Seconds < 5 {
				a.Seconds = 20
			}
			if a.Seconds > 300 {
				a.Seconds = 300
			}
			if err := fridaForward(a.Device); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			scriptDir := filepath.Join(dir, "frida")
			if err := os.MkdirAll(scriptDir, 0o755); err != nil {
				return actool.Errorf("建脚本目录失败: " + err.Error()), nil
			}
			var args []string
			for i, spec := range a.Scripts {
				name, src, rerr := t.fridaResolveScript(dir, spec)
				if rerr != nil {
					return actool.Errorf(rerr.Error()), nil
				}
				p := filepath.Join(scriptDir, fmt.Sprintf("%s-%d.js", name, i))
				if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
					return actool.Errorf("写脚本失败: " + err.Error()), nil
				}
				args = append(args, "-l", p)
			}
			// 目标形态：纯数字=PID；mode=attach=-n；默认 spawn=-f。
			if regexp.MustCompile(`^\d+$`).MatchString(a.App) {
				args = append(args, "--pid", a.App)
			} else if a.Mode == "attach" {
				args = append(args, "-n", strings.Trim(a.App, `"'`))
			} else {
				args = append(args, "-f", a.App)
			}
			args = append(args, "-q")
			out, _ := fridaRun(a.Seconds+5, append([]string{"-H", fridaHost}, args...)...)
			return actool.Text(fridaSectionOutput(out)), nil
		})
}

func (t *ToolSet) fridaUnpackTool() actool.CoreTool {
	return writeTool("droid_unpack",
		"内存脱壳：spawn 目标 app 注入 dex_dump 扫描内存中的 DEX 并落盘，随后把 /data/local/tmp/sentinel-unpack 打包拉回工作目录（droid/unpack/<包名>.tar 并解开）。适合加固壳（爱加密/360/腾讯乐固等）；抽取壳 dump 出的方法体可能仍是 nop。app 有反 frida 时建议先 droid_frida 带 anti_frida_bypass 试探。",
		obj(map[string]any{
			"app":     str("目标 app 包名"),
			"seconds": intp("可选，注入运行秒数，默认 30，10-120"),
			"device":  str("可选"),
		}, "app"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			app := droidString(in, "app")
			if app == "" {
				return actool.Errorf("app 必填"), nil
			}
			secs := droidInt(in, "seconds", 30)
			if secs < 10 {
				secs = 10
			}
			if secs > 120 {
				secs = 120
			}
			device := droidString(in, "device")
			if err := fridaForward(device); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			pre, err := droidSerial(device)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			// 1) 清旧产物 + spawn 注入 dex_dump
			_, _ = droidRun(ctx, 20, append(append([]string{}, pre...), "shell", "su", "-c", "rm -rf /data/local/tmp/sentinel-unpack")...)
			_, src, _ := t.fridaResolveScript(dir, "dex_dump")
			scriptDir := filepath.Join(dir, "frida")
			_ = os.MkdirAll(scriptDir, 0o755)
			p := filepath.Join(scriptDir, "dex_dump-run.js")
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				return actool.Errorf("写脚本失败: " + err.Error()), nil
			}
			out, _ := fridaRun(secs+10, "-H", fridaHost, "-f", app, "-l", p, "-q")
			// 2) 打包拉回
			_, _ = droidRun(ctx, 60, append(append([]string{}, pre...), "shell", "su", "-c",
				"cd /data/local/tmp && tar cf unpack.tar sentinel-unpack 2>/dev/null; chmod 644 unpack.tar; ls sentinel-unpack | wc -l")...)
			dst := filepath.Join(dir, "droid", "unpack")
			_ = os.MkdirAll(dst, 0o755)
			tarPath := filepath.Join(dst, app+".tar")
			if pout, err := droidRun(ctx, 300, append(append([]string{}, pre...), "pull", "/data/local/tmp/unpack.tar", tarPath)...); err != nil {
				return actool.Errorf("脱壳产物拉取失败（设备上是否生成了 sentinel-unpack？）: " + vulnPreview(pout, 300) + "\nfrida 输出:\n" + fridaSectionOutput(out)), nil
			}
			_ = exec.Command("tar", "-xf", tarPath, "-C", dst).Run()
			entries, _ := os.ReadDir(filepath.Join(dst, "sentinel-unpack"))
			return actool.Text(fmt.Sprintf("脱壳完成：%d 个 dex 已落到 %s（tar: %s）。\nfrida 输出节选：\n%s",
				len(entries), filepath.Join(dst, "sentinel-unpack"), tarPath, fridaSectionOutput(out))), nil
		})
}
