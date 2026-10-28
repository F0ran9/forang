package agent

// tools_droid.go — 移动设备动态测试工具集（APP 渗透预设的执行层）。
//
// 工具面对标全链哨兵的 DroidBridge（exec/pull/push/screencap/logcat/packages），
// 但载体从「桥接 APK 反连 WebSocket」改为 adb 直连：平台宿主机装 adb，
// `droid_connect` 到模拟器（MuMu 默认 127.0.0.1:16384，雷电 5555，真机走 USB/
// wireless）后即可驱动，无需在设备上装任何东西。
//
// 串口选择：所有工具接受可选 device 参数；不传时若恰好一台在线设备则自动选中，
// 多台时报错列出清单让模型指名。连接状态由宿主机 adb server 持有，connect 一次
// 后续工具即可复用。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

const (
	droidAdbBin     = "adb"
	droidMaxOut     = 64 << 10  // shell/logcat/packages 输出上限
	droidMaxFile    = 200 << 20 // pull/截图 落盘大小上限
	droidTimeoutMax = 600       // shell 超时上限（秒）
)

// SetDroidDir wires the local scratch dir for screencap/pull/push/install
// (usually the agent workDir). Empty = those file tools report unavailable.
func (t *ToolSet) SetDroidDir(dir string) { t.droidDir = dir }

func (t *ToolSet) needDroidDir() (string, error) {
	if t.droidDir == "" {
		return "", fmt.Errorf("文件类 droid 工具不可用（本 agent 未接通工作目录）")
	}
	return t.droidDir, nil
}

// droidSerial resolves the target device to an explicit ["-s", serial] prefix.
func droidSerial(device string) ([]string, error) {
	if device != "" {
		return []string{"-s", device}, nil
	}
	out, err := exec.Command(droidAdbBin, "devices").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("宿主机 adb 不可用（请安装 android platform-tools）: %v", err)
	}
	var online []string
	for _, ln := range strings.Split(string(out), "\n")[1:] {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) >= 2 && parts[1] == "device" {
			online = append(online, parts[0])
		}
	}
	switch len(online) {
	case 1:
		return []string{"-s", online[0]}, nil
	case 0:
		return nil, fmt.Errorf("没有在线设备，请先 droid_connect（MuMu 默认 127.0.0.1:16384）")
	default:
		return nil, fmt.Errorf("多台设备在线，请用 device 参数指名: %s", strings.Join(online, ", "))
	}
}

// droidRun runs adb with a per-call timeout and bounded output.
func droidRun(ctx context.Context, secs int, args ...string) (string, error) {
	if secs <= 0 {
		secs = 30
	}
	if secs > droidTimeoutMax {
		secs = droidTimeoutMax
	}
	c, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, droidAdbBin, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if len(out) > droidMaxOut {
		out = out[:droidMaxOut] + "\n…(输出截断)"
	}
	if err != nil {
		if c.Err() == context.DeadlineExceeded {
			return out, fmt.Errorf("adb 超时(%ds)", secs)
		}
		return out, err
	}
	return out, nil
}

func droidString(in json.RawMessage, key string) string {
	var a map[string]any
	if err := json.Unmarshal(in, &a); err != nil {
		return ""
	}
	s, _ := a[key].(string)
	return strings.TrimSpace(s)
}

func droidInt(in json.RawMessage, key string, def int) int {
	var a map[string]any
	if err := json.Unmarshal(in, &a); err != nil {
		return def
	}
	if v, ok := a[key].(float64); ok && v > 0 {
		return int(v)
	}
	return def
}

// ---------- 工具集 ----------

// droidTools 被装配进 Worker / MainAgent 工具清单（tools_insert.go）。
func (t *ToolSet) droidTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.droidDevicesTool(),
		t.droidConnectTool(),
		t.droidShellTool(),
		t.droidListPackagesTool(),
		t.droidScreencapTool(),
		t.droidUiautomatorTool(),
		t.droidPullTool(),
		t.droidPushTool(),
		t.droidInstallTool(),
		t.droidLogcatTool(),
		t.droidProxyTool(),
	}
}

func (t *ToolSet) droidDevicesTool() actool.CoreTool {
	return readTool("droid_devices",
		"列出 adb 已知设备与在线状态（device=在线/offline/unauthorized）。APP 动态测试前先调本工具确认设备；没有在线设备时用 droid_connect 连接。",
		obj(map[string]any{}),
		func(_ context.Context, _ json.RawMessage) (actool.Result, error) {
			out, err := exec.Command(droidAdbBin, "devices", "-l").CombinedOutput()
			if err != nil {
				return actool.Errorf(fmt.Sprintf("宿主机 adb 不可用: %v", err)), nil
			}
			return actool.Text(strings.TrimSpace(string(out))), nil
		})
}

func (t *ToolSet) droidConnectTool() actool.CoreTool {
	return writeTool("droid_connect",
		"连接一台模拟器/真机（adb connect host:port）。MuMu 默认 127.0.0.1:16384，雷电默认 127.0.0.1:5555，网络调试真机为 IP:5555。连接成功后其他 droid 工具即可使用。",
		obj(map[string]any{"addr": str("设备地址 host:port，如 127.0.0.1:16384")}, "addr"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			addr := droidString(in, "addr")
			if addr == "" {
				return actool.Errorf("addr 必填"), nil
			}
			out, err := droidRun(ctx, 20, "connect", addr)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("连接失败: %v\n%s", err, out)), nil
			}
			return actool.Text("连接结果: " + strings.TrimSpace(out)), nil
		})
}

func (t *ToolSet) droidShellTool() actool.CoreTool {
	return writeTool("droid_shell",
		"在设备上执行一条 shell 命令（如 dumpsys activity top、input tap x y、settings get global http_proxy、dumpsys package <pkg>、su -c id）。输出上限 64KB，超时默认 30s 上限 600s。",
		obj(map[string]any{
			"cmd":         str("要执行的 shell 命令"),
			"device":      str("可选，设备 serial；只有一台在线时可省略"),
			"timeoutSecs": intp("可选，默认 30，上限 600"),
		}, "cmd"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			cmd := droidString(in, "cmd")
			if cmd == "" {
				return actool.Errorf("cmd 必填"), nil
			}
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := droidRun(ctx, droidInt(in, "timeoutSecs", 30),
				append(pre, "shell", cmd)...)
			if err != nil && out == "" {
				return actool.Errorf(fmt.Sprintf("执行失败: %v", err)), nil
			}
			text := strings.TrimRight(out, "\n")
			if err != nil {
				text += "\n(adb 报错: " + err.Error() + ")"
			}
			return actool.Text(text), nil
		})
}

func (t *ToolSet) droidListPackagesTool() actool.CoreTool {
	return readTool("droid_list_packages",
		"列出设备上已安装的包名。默认只列第三方应用（-3）；filter 按子串过滤（如 filter=bank 或 com.tencent）。APP 测试的起点：先列包再挑目标。",
		obj(map[string]any{
			"device": str("可选，设备 serial"),
			"filter": str("可选，包名子串过滤"),
			"system": intp("可选，1=连系统包一起列（默认仅第三方）"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			args := append(append([]string{}, pre...), "shell", "pm", "list", "packages")
			if droidInt(in, "system", 0) != 1 {
				args = append(args, "-3")
			}
			out, err := droidRun(ctx, 30, args...)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("列出包失败: %v", err)), nil
			}
			filter := droidString(in, "filter")
			lines := []string{}
			for _, ln := range strings.Split(out, "\n") {
				ln = strings.TrimSpace(strings.TrimPrefix(ln, "package:"))
				if ln == "" {
					continue
				}
				if filter == "" || strings.Contains(strings.ToLower(ln), strings.ToLower(filter)) {
					lines = append(lines, ln)
				}
			}
			sort.Strings(lines)
			if len(lines) == 0 {
				return actool.Text("（没有匹配的包）"), nil
			}
			return actool.Text(fmt.Sprintf("共 %d 个包:\n%s", len(lines), strings.Join(lines, "\n"))), nil
		})
}

func (t *ToolSet) droidScreencapTool() actool.CoreTool {
	return readTool("droid_screencap",
		"截取设备当前屏幕为 PNG，保存到平台工作目录（droid/ 下）并返回路径。配合 droid_uiautomator 看清界面状态。",
		obj(map[string]any{"device": str("可选，设备 serial")}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			c, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			var buf bytes.Buffer
			cmd := exec.CommandContext(c, droidAdbBin, append(append([]string{}, pre...), "exec-out", "screencap", "-p")...)
			cmd.Stdout = &buf
			if err := cmd.Run(); err != nil {
				return actool.Errorf(fmt.Sprintf("截图失败: %v", err)), nil
			}
			if buf.Len() == 0 || buf.Len() > droidMaxFile {
				return actool.Errorf(fmt.Sprintf("截图异常（%d 字节）", buf.Len())), nil
			}
			if err := os.MkdirAll(filepath.Join(dir, "droid"), 0o755); err != nil {
				return actool.Errorf(fmt.Sprintf("建目录失败: %v", err)), nil
			}
			name := "droid/scr-" + time.Now().Format("0102-150405") + ".png"
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
				return actool.Errorf(fmt.Sprintf("保存失败: %v", err)), nil
			}
			return actool.Text(fmt.Sprintf("截图已保存: %s（%d KB）", path, buf.Len()/1024)), nil
		})
}

var (
	droidNodeRe  = regexp.MustCompile(`<node[^>]*>`)
	droidAttrRe  = regexp.MustCompile(`(\w+)="([^"]*)"`)
	droidBoundRe = regexp.MustCompile(`\[(-?\d+),(-?\d+)\]\[(-?\d+),(-?\d+)\]`)
)

func (t *ToolSet) droidUiautomatorTool() actool.CoreTool {
	return readTool("droid_uiautomator",
		"抓取当前界面的控件树（uiautomator dump），返回可点控件的文本/ID/类名/中心坐标。用坐标配合 droid_shell 的 input tap 完成 UI 驱动；界面看不清时补 droid_screencap。",
		obj(map[string]any{"device": str("可选，设备 serial")}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := droidRun(ctx, 45, append(append([]string{}, pre...),
				"shell", "uiautomator dump /sdcard/artex_ui.xml")...)
			if err != nil || !strings.Contains(out, "dumped") {
				out2, _ := droidRun(ctx, 45, append(append([]string{}, pre...),
					"shell", "uiautomator dump /sdcard/artex_ui.xml")...)
				if !strings.Contains(out2, "dumped") {
					return actool.Errorf(fmt.Sprintf("uiautomator dump 失败（界面可能禁止无障碍转储，可改用 droid_screencap）: %s %s", strings.TrimSpace(out), strings.TrimSpace(out2))), nil
				}
				out = out2
			}
			xml, err := droidRun(ctx, 30, append(append([]string{}, pre...), "shell", "cat", "/sdcard/artex_ui.xml")...)
			_, _ = droidRun(ctx, 15, append(append([]string{}, pre...), "shell", "rm", "-f", "/sdcard/artex_ui.xml")...)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("读取控件树失败: %v", err)), nil
			}
			var lines []string
			for _, node := range droidNodeRe.FindAllString(xml, -1) {
				attrs := map[string]string{}
				for _, m := range droidAttrRe.FindAllStringSubmatch(node, -1) {
					attrs[m[1]] = m[2]
				}
				clickable := attrs["clickable"] == "true"
				text, id := attrs["text"], attrs["resource-id"]
				if !clickable && text == "" {
					continue
				}
				b := droidBoundRe.FindStringSubmatch(attrs["bounds"])
				if len(b) != 5 {
					continue
				}
				x1, _ := strconv.Atoi(b[1])
				y1, _ := strconv.Atoi(b[2])
				x2, _ := strconv.Atoi(b[3])
				y2, _ := strconv.Atoi(b[4])
				mark := " "
				if clickable {
					mark = "*"
				}
				lines = append(lines, fmt.Sprintf("%s text=%q id=%s class=%s center=(%d,%d)",
					mark, text, id, attrs["class"], (x1+x2)/2, (y1+y2)/2))
				if len(lines) >= 80 {
					lines = append(lines, "…(截断，共 80 条)")
					break
				}
			}
			if len(lines) == 0 {
				return actool.Text("（界面无可交互控件转储，建议 droid_screencap 看实际画面）"), nil
			}
			return actool.Text("当前界面控件（* = 可点击，center 即 input tap 坐标）:\n" + strings.Join(lines, "\n")), nil
		})
}

func (t *ToolSet) droidPullTool() actool.CoreTool {
	return writeTool("droid_file_pull",
		"从设备拉取文件到平台工作目录（droid/ 下），如 /data/app/…/base.apk（拉回来可交三端载体解析/静态审计）。上限 200MB。",
		obj(map[string]any{
			"device_path": str("设备上的绝对路径"),
			"device":      str("可选，设备 serial"),
		}, "device_path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			dp := droidString(in, "device_path")
			if dp == "" || !strings.HasPrefix(dp, "/") {
				return actool.Errorf("device_path 必须是设备上的绝对路径"), nil
			}
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if err := os.MkdirAll(filepath.Join(dir, "droid"), 0o755); err != nil {
				return actool.Errorf(fmt.Sprintf("建目录失败: %v", err)), nil
			}
			name := filepath.Base(dp)
			if name == "" || name == "/" || name == "." {
				return actool.Errorf("device_path 需指向具体文件"), nil
			}
			local := filepath.Join(dir, "droid", name)
			out, err := droidRun(ctx, 300, append(append([]string{}, pre...), "pull", dp, local)...)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("拉取失败: %v\n%s", err, strings.TrimSpace(out))), nil
			}
			st, serr := os.Stat(local)
			if serr != nil || st.Size() > droidMaxFile {
				os.Remove(local)
				return actool.Errorf("拉取结果异常（不存在或超过 200MB 上限）"), nil
			}
			return actool.Text(fmt.Sprintf("已拉取: %s（%d KB）", local, st.Size()/1024)), nil
		})
}

func (t *ToolSet) droidPushTool() actool.CoreTool {
	return writeTool("droid_file_push",
		"把平台工作目录里的文件推到设备（如修改过的配置/测试数据），落点一般用 /data/local/tmp/。",
		obj(map[string]any{
			"local_path":  str("平台工作目录内的相对路径（droid/…）或绝对路径"),
			"device_path": str("设备上的目标绝对路径"),
			"device":      str("可选，设备 serial"),
		}, "local_path", "device_path"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			lp := droidString(in, "local_path")
			dp := droidString(in, "device_path")
			if lp == "" || dp == "" || !strings.HasPrefix(dp, "/") {
				return actool.Errorf("local_path 与 device_path（设备绝对路径）必填"), nil
			}
			if !filepath.IsAbs(lp) {
				lp = filepath.Join(dir, lp)
			}
			st, err := os.Stat(lp)
			if err != nil || st.IsDir() {
				return actool.Errorf("本地文件不存在: " + lp), nil
			}
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := droidRun(ctx, 300, append(append([]string{}, pre...), "push", lp, dp)...)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("推送失败: %v\n%s", err, strings.TrimSpace(out))), nil
			}
			return actool.Text("推送完成: " + strings.TrimSpace(out)), nil
		})
}

func (t *ToolSet) droidInstallTool() actool.CoreTool {
	return writeTool("droid_install",
		"安装 APK 到设备（adb install -r）。apk 为平台工作目录内的路径（通常是三端载体上传或 droid_file_pull 下来的 base.apk）。",
		obj(map[string]any{
			"apk":    str("APK 在平台工作目录内的路径"),
			"device": str("可选，设备 serial"),
		}, "apk"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			dir, err := t.needDroidDir()
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			apk := droidString(in, "apk")
			if apk == "" {
				return actool.Errorf("apk 必填"), nil
			}
			if !filepath.IsAbs(apk) {
				apk = filepath.Join(dir, apk)
			}
			if st, serr := os.Stat(apk); serr != nil || st.IsDir() {
				return actool.Errorf("APK 文件不存在: " + apk), nil
			}
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			out, err := droidRun(ctx, 300, append(append([]string{}, pre...), "install", "-r", apk)...)
			if err != nil || strings.Contains(out, "Failure") {
				return actool.Errorf(fmt.Sprintf("安装失败: %s", strings.TrimSpace(out))), nil
			}
			return actool.Text("安装结果: " + strings.TrimSpace(out)), nil
		})
}

func (t *ToolSet) droidLogcatTool() actool.CoreTool {
	return readTool("droid_logcat",
		"读取设备日志缓冲（logcat -d -t N），filter 按子串过滤（包名/tag）。常用于找崩溃栈、泄露的敏感日志、接口报错。",
		obj(map[string]any{
			"device": str("可选，设备 serial"),
			"lines":  intp("可选，默认 200，上限 2000"),
			"filter": str("可选，子串过滤"),
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			n := droidInt(in, "lines", 200)
			if n > 2000 {
				n = 2000
			}
			out, err := droidRun(ctx, 60, append(append([]string{}, pre...),
				"logcat", "-d", "-t", strconv.Itoa(n))...)
			if err != nil && out == "" {
				return actool.Errorf(fmt.Sprintf("读取日志失败: %v", err)), nil
			}
			filter := droidString(in, "filter")
			if filter != "" {
				var kept []string
				for _, ln := range strings.Split(out, "\n") {
					if strings.Contains(strings.ToLower(ln), strings.ToLower(filter)) {
						kept = append(kept, ln)
					}
				}
				out = strings.Join(kept, "\n")
			}
			if strings.TrimSpace(out) == "" {
				return actool.Text("（无匹配日志）"), nil
			}
			return actool.Text(strings.TrimRight(out, "\n")), nil
		})
}

func (t *ToolSet) droidProxyTool() actool.CoreTool {
	return writeTool("droid_proxy",
		"设备全局 HTTP 代理管理：action=set 时 addr 必填（如 <platform-host>:8788，指向平台流量代理做抓包）；action=clear 恢复直连；action=status 查询当前代理。HTTPS 抓包需设备安装并信任代理 CA。",
		obj(map[string]any{
			"action": str("set / clear / status"),
			"addr":   str("action=set 时必填，host:port"),
			"device": str("可选，设备 serial"),
		}, "action"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			action := droidString(in, "action")
			pre, err := droidSerial(droidString(in, "device"))
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			switch action {
			case "set":
				addr := droidString(in, "addr")
				if addr == "" {
					return actool.Errorf("action=set 时 addr 必填"), nil
				}
				out, err := droidRun(ctx, 30, append(append([]string{}, pre...),
					"shell", "settings", "put", "global", "http_proxy", addr)...)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("设置代理失败: %v\n%s", err, strings.TrimSpace(out))), nil
				}
				return actool.Text("已设置设备全局 HTTP 代理 → " + addr), nil
			case "clear":
				out, _ := droidRun(ctx, 30, append(append([]string{}, pre...),
					"shell", "settings", "put", "global", "http_proxy", ":0")...)
				return actool.Text("已清除设备全局 HTTP 代理\n" + strings.TrimSpace(out)), nil
			case "status":
				out, err := droidRun(ctx, 30, append(append([]string{}, pre...),
					"shell", "settings", "get", "global", "http_proxy")...)
				if err != nil {
					return actool.Errorf(fmt.Sprintf("查询失败: %v", err)), nil
				}
				v := strings.TrimSpace(out)
				if v == "" || v == "null" || v == ":0" {
					v = "（未设置）"
				}
				return actool.Text("当前设备全局 HTTP 代理: " + v), nil
			default:
				return actool.Errorf("action 仅支持 set/clear/status"), nil
			}
		})
}
