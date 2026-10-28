package server

// replayd.go — FORANG 内嵌的发包留证服务客户端（移植自全链哨兵 MITM_Fuzz_Render
// replayd，MIT）。架构差异：FORANG 直接跑在宿主 VM 上（无每项目容器），所以
// replayd 作为宿主进程运行在 127.0.0.1:18901，数据目录 <data>/replayd/。
// 链路：replay_capture 工具 → POST /api/capture（发报文 + 渲染 Repeater 三栏留证页
// + 浏览器截图）→ screenshots.viewport.artifactId → GET /api/artifacts/{id} 取 PNG
// → 落 <data>/evidence/replay/ → 可绑进 findings 证据（kind=screenshot）。
// 鉴权：replayd 未显式给 -token 时在数据目录生成 token 文件（0600），客户端每次
// 请求读该文件带 Bearer。/api/health 公开，用于就绪等待。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
)

const (
	replaydPort    = 18901
	replaydBinName = "replayd"
	replaydLogName = "replayd.log"
)

type replaydProcess struct {
	mu    sync.Mutex
	start sync.Once
}

// ReplaydStart 启动（或确认已在跑）replayd 服务进程。
func (s *Server) ReplaydStart() error {
	s.replayd.mu.Lock()
	defer s.replayd.mu.Unlock()
	s.replayd.start.Do(func() {
		bin := filepath.Join(s.m.dir, replaydBinName)
		if _, err := os.Stat(bin); err != nil {
			// 工作目录没有就找可执行文件旁
			exe, _ := os.Executable()
			alt := filepath.Join(filepath.Dir(exe), replaydBinName)
			if _, err2 := os.Stat(alt); err2 == nil {
				bin = alt
			}
		}
		// 数据目录与二进制错开：m.dir=replayd 是二进制（文件），replayd-data 才是
		// replayd 的工作目录（token/replayd.log/flows 都在这里）。
		dataDir := filepath.Join(s.m.dir, "replayd-data")
		_ = os.MkdirAll(dataDir, 0o755)
		logf := filepath.Join(dataDir, replaydLogName)
		cmd := exec.Command(bin, "-data-dir", dataDir, "-listen", fmt.Sprintf("127.0.0.1:%d", replaydPort))
		lf, err := os.OpenFile(logf, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			cmd.Stdout, cmd.Stderr = lf, lf
		}
		if err := cmd.Start(); err != nil {
			fmt.Printf("[replayd] 启动失败: %v\n", err)
			return
		}
		go cmd.Wait() // 回收
		fmt.Printf("[replayd] 已启动 pid=%d data=%s\n", cmd.Process.Pid, dataDir)
	})
	return nil
}

// replaydToken 读 replayd 数据目录下的 token 文件（首次启动时生成）。
func (s *Server) replaydToken() string {
	b, err := os.ReadFile(filepath.Join(s.m.dir, "replayd-data", "token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// replaydRequest 调 replayd 的 REST API（自动带 Bearer token）。
func (s *Server) replaydRequest(ctx context.Context, method, path string, body io.Reader) ([]byte, error) {
	u := fmt.Sprintf("http://127.0.0.1:%d%s", replaydPort, path)
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if tok := s.replaydToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// replaydEnsureOnce 启动时拉起 replayd（容错：失败不影响平台其他功能）。
func (s *Server) replaydEnsureOnce() {
	if _, err := os.Stat(filepath.Join(s.m.dir, replaydBinName)); err == nil {
		_ = s.ReplaydStart()
	}
}

// replayCaptureFn 把 replayd 客户端包成 agent 工具回调（任务/对话/自定义 agent 共用）。
func (s *Server) replayCaptureFn() agent.ReplayCaptureFunc {
	return func(ctx context.Context, r agent.ReplayCaptureReq) (string, string, error) {
		path, text, err := s.ReplayCapture(ctx, ReplayCapturePayload{
			Raw:               r.Raw,
			Host:              r.Host,
			Port:              r.Port,
			Scheme:            r.Scheme,
			Purpose:           r.Purpose,
			HighlightRequest:  r.HighlightRequest,
			HighlightResponse: r.HighlightResponse,
		})
		return path, text, err
	}
}

// ReplayCapturePayload 一次留证截图的入参（purpose 只在 agent 侧审计展示，不发给 replayd）。
type ReplayCapturePayload struct {
	Raw               string   `json:"raw"`
	Host              string   `json:"host,omitempty"`
	Port              int      `json:"port,omitempty"`
	Scheme            string   `json:"scheme,omitempty"`
	Purpose           string   `json:"purpose,omitempty"`
	HighlightRequest  []string `json:"highlight_request,omitempty"`
	HighlightResponse []string `json:"highlight_response,omitempty"`
}

// ReplayCapture 发送报文并截取 Repeater 三栏留证页，返回 (PNG 路径, 响应摘要, 错误)。
func (s *Server) ReplayCapture(ctx context.Context, p ReplayCapturePayload) (string, string, error) {
	if strings.TrimSpace(p.Raw) == "" {
		return "", "", fmt.Errorf("raw 为空")
	}
	if err := s.ReplaydStart(); err != nil {
		return "", "", err
	}
	// 等就绪（/api/health 公开）
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := s.replaydRequest(ctx, "GET", "/api/health", nil); err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	// POST /api/capture：一次完成 发送 + 渲染 + 截图（replayd captureRequest 形状）。
	payload, _ := json.Marshal(map[string]any{
		"raw":         p.Raw,
		"scheme":      p.Scheme,
		"host":        p.Host,
		"port":        p.Port,
		"insecureTLS": true,
		"highlight": map[string]any{
			"request":  p.HighlightRequest,
			"response": p.HighlightResponse,
			"color":    "yellow",
		},
		"waitTimeoutMs": 30000,
	})
	cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	respBody, err := s.replaydRequest(cctx, "POST", "/api/capture", bytes.NewReader(payload))
	if err != nil {
		return "", "", err
	}
	var result struct {
		Status            string `json:"status"`
		StatusLine        string `json:"statusLine"`
		ResponsePreview   string `json:"responsePreview"`
		EvidenceWatermark string `json:"evidenceWatermark"`
		SendError         string `json:"sendError"`
		Screenshots       map[string]struct {
			ArtifactID string `json:"artifactId"`
		} `json:"screenshots"`
		FlowID string `json:"flowId"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("replayd 响应解析失败: %w（%s）", err, previewBytes(respBody, 300))
	}
	if result.Error != nil {
		return "", "", fmt.Errorf("replayd %s: %s", result.Error.Code, result.Error.Message)
	}
	// 优先三栏 viewport 截图
	shot, ok := result.Screenshots["viewport"]
	if !ok {
		for _, v := range result.Screenshots {
			shot = v
			break
		}
	}
	if shot.ArtifactID == "" {
		if result.SendError != "" {
			return "", "", fmt.Errorf("发送失败: %s", result.SendError)
		}
		return "", "", fmt.Errorf("replayd 未返回截图")
	}
	img, err := s.replaydRequest(cctx, "GET", "/api/artifacts/"+shot.ArtifactID, nil)
	if err != nil {
		return "", "", err
	}
	if len(img) < 1000 {
		return "", "", fmt.Errorf("截图产物异常（%d 字节）", len(img))
	}
	outDir := filepath.Join(s.m.dir, "evidence", "replay")
	_ = os.MkdirAll(outDir, 0o755)
	name := fmt.Sprintf("capture-%s.png", time.Now().Format("0102-150405"))
	outPath := filepath.Join(outDir, name)
	if err := os.WriteFile(outPath, img, 0o644); err != nil {
		return "", "", err
	}
	// 响应摘要给 agent 确认漏洞现象（留证页本身已含完整请求/响应）。
	text := strings.TrimSpace(result.StatusLine)
	if result.ResponsePreview != "" {
		if text != "" {
			text += "\n"
		}
		text += result.ResponsePreview
	}
	return outPath, text, nil
}

// previewBytes 截断二进制响应体用于错误信息。
func previewBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return strings.ToValidUTF8(string(b), "?")
}

// replayEvidenceFile 服务 replay 留证截图：GET /api/evidence/replay/{name}。
// 供聊天/任务流内联渲染 <img>（登录 cookie 随同源请求自动带上，过 requireAuth）。
// 文件名白名单校验，杜绝路径穿越。
func (s *Server) replayEvidenceFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !strings.HasPrefix(name, "capture-") || !strings.HasSuffix(name, ".png") || strings.ContainsAny(name, "/\\") {
		writeErr(w, 400, "invalid evidence file name")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.m.dir, "evidence", "replay", name))
	if os.IsNotExist(err) {
		writeErr(w, 404, "evidence file not found")
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Disposition", "inline; filename=\""+name+"\"")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(data)
}
