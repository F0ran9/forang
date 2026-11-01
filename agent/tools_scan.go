package agent

// tools_scan.go — 侦察扫描工具（对接工具箱扫描引擎，与指纹工具同一平台 API 模式）：
//   port_scan  端口扫描（原生并发 TCP dial，top100/自定义端口/区间/CIDR）
//   dir_scan   目录扫描（内置敏感路径字典 + 知识库路径联用，命中回灌字典）
// 两者都是「POST 启动任务 → 轮询 scan_jobs 到终态」，执行结果自动作为 action
// 节点写入探索链路图（recordAction），与 webshell/C2 动作同一套留痕体系。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// platformCall 调平台工具箱 API（127.0.0.1:8787，FORANG_TOKEN 认证），
// 返回 data 段原始 JSON。fingerprintTool 同款约定。
func platformCall(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	token := os.Getenv("FORANG_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("平台 token 未设置（FORANG_TOKEN）")
	}
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:8787"+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	var out struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// pollScanJob 轮询扫描任务到终态（done/failed），间隔 2s，受 ctx 与 waitSec 约束。
// 返回任务详情 data（含 status/params/findings）。
func pollScanJob(ctx context.Context, detailPath string, waitSec int) (json.RawMessage, string, error) {
	if waitSec <= 0 {
		waitSec = 120
	}
	if waitSec > 600 {
		waitSec = 600
	}
	deadline := time.Now().Add(time.Duration(waitSec) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
		data, err := platformCall(ctx, http.MethodGet, detailPath, nil)
		if err != nil {
			continue // 轮询抖动不致命
		}
		var d struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(data, &d) == nil && (d.Status == "done" || d.Status == "failed") {
			return data, d.Status, nil
		}
	}
	return nil, "timeout", nil
}

// portScanTool port_scan：启动端口扫描并等结果。
func (t *ToolSet) portScanTool() actool.CoreTool {
	return writeTool("port_scan",
		"端口扫描（工具箱扫描引擎，原生并发 TCP dial）。targets 支持逗号分隔 host / a.b.c.d-e 区间 / CIDR(/20 内)；ports 支持 top100（默认）/逗号列表/区间 8000-8100。阻塞等结果（默认 120 秒），返回开放端口列表。授权测试场景专用。",
		obj(map[string]any{
			"targets":  str("目标：逗号分隔 host / a.b.c.d-e / CIDR（如 192.168.1.10 或 192.168.1.1-254 或 10.0.0.0/24）"),
			"ports":    str("可选：top100（默认）/ 80,443,8080 / 8000-8100"),
			"timeout_sec": intp("可选：扫描超时秒数，默认 600"),
			"wait_sec": intp("可选：等待结果秒数，默认 120（超时未完可稍后重查，任务仍在跑）"),
		}, "targets"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				Targets    string `json:"targets"`
				Ports      string `json:"ports"`
				TimeoutSec int    `json:"timeout_sec"`
				WaitSec    int    `json:"wait_sec"`
			}
			if err := json.Unmarshal(in, &a); err != nil || strings.TrimSpace(a.Targets) == "" {
				return actool.Errorf("targets 必填"), nil
			}
			start, err := platformCall(ctx, http.MethodPost, "/api/tools/portscan", map[string]any{
				"targets": a.Targets, "ports": a.Ports, "timeout_sec": a.TimeoutSec,
			})
			if err != nil {
				t.recordAction("port_scan", "端口扫描启动失败", map[string]any{
					"target": a.Targets, "result": "fail", "error": truncateStr(err.Error(), 200),
				})
				return actool.Errorf("扫描启动失败: " + err.Error()), nil
			}
			var st struct {
				JobID int64 `json:"job_id"`
				Hosts int   `json:"hosts"`
				Ports int   `json:"ports"`
			}
			_ = json.Unmarshal(start, &st)
			if st.JobID == 0 {
				return actool.Errorf("服务端未返回 job_id"), nil
			}
			detail, status, err := pollScanJob(ctx, "/api/tools/portscan/"+strconv.FormatInt(st.JobID, 10), a.WaitSec)
			if err != nil {
				return actool.Errorf("轮询失败: " + err.Error()), nil
			}
			if status == "timeout" {
				t.recordAction("port_scan", fmt.Sprintf("端口扫描进行中（%d 主机×%d 端口，job #%d）", st.Hosts, st.Ports, st.JobID), map[string]any{
					"target": a.Targets, "job_id": st.JobID, "result": "pending",
				})
				return actool.Text(fmt.Sprintf("⏳ 扫描仍在跑（job #%d，%d 主机）。稍后可用 repeater_send 或再跑一次查看。", st.JobID, st.Hosts)), nil
			}
			var d struct {
				Status string `json:"status"`
				Findings struct {
					Hosts []struct {
						Host  string `json:"host"`
						Ports []int  `json:"ports"`
					} `json:"hosts"`
					Scanned   int `json:"scanned"`
					Total     int `json:"total"`
					OpenTotal int `json:"open_total"`
				} `json:"findings"`
			}
			_ = json.Unmarshal(detail, &d)
			if status != "done" {
				t.recordAction("port_scan", "端口扫描失败/中断", map[string]any{
					"target": a.Targets, "job_id": st.JobID, "result": "fail",
				})
				return actool.Text(fmt.Sprintf("❌ 扫描任务 %s（job #%d）", status, st.JobID)), nil
			}
			// 动作入图 + 摘要
			openSum := strings.Builder{}
			for i, h := range d.Findings.Hosts {
				if i >= 10 {
					fmt.Fprintf(&openSum, "…共 %d 主机有开放端口", len(d.Findings.Hosts))
					break
				}
				ps := make([]string, len(h.Ports))
				for j, p := range h.Ports {
					ps[j] = strconv.Itoa(p)
				}
				fmt.Fprintf(&openSum, "%s: %s\n", h.Host, strings.Join(ps, ","))
			}
			t.recordAction("port_scan", fmt.Sprintf("端口扫描 %s：%d/%d 主机，%d 个开放端口", truncateStr(a.Targets, 40), d.Findings.Scanned, d.Findings.Total, d.Findings.OpenTotal), map[string]any{
				"target": a.Targets, "job_id": st.JobID, "result": "ok",
				"open_total": d.Findings.OpenTotal, "hosts_hit": len(d.Findings.Hosts),
			})
			var b strings.Builder
			fmt.Fprintf(&b, "✅ 端口扫描完成（%d/%d 主机，%d 开放端口）\n", d.Findings.Scanned, d.Findings.Total, d.Findings.OpenTotal)
			b.WriteString(strings.TrimRight(openSum.String(), "\n"))
			return actool.Text(b.String()), nil
		})
}

// dirScanTool dir_scan：目录/路径扫描。
func (t *ToolSet) dirScanTool() actool.CoreTool {
	return writeTool("dir_scan",
		"目录与敏感路径扫描（工具箱扫描引擎，内置 ~180 条敏感路径字典 + 知识库路径联用，命中自动回灌字典库）。非 404 即命中，301/302 标注跳转。阻塞等结果。授权测试场景专用。",
		obj(map[string]any{
			"base_url":    str("目标基址（http://target:port）"),
			"wordlist":    str("可选：自定义字典（逐行）；缺省用内置+知识库沉淀"),
			"extensions":  str("可选：附加扩展名，逗号分隔（如 php,jsp,html）"),
			"wait_sec":    intp("可选：等待结果秒数，默认 120"),
		}, "base_url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				BaseURL    string `json:"base_url"`
				Wordlist   string `json:"wordlist"`
				Extensions string `json:"extensions"`
				WaitSec    int    `json:"wait_sec"`
			}
			if err := json.Unmarshal(in, &a); err != nil || strings.TrimSpace(a.BaseURL) == "" {
				return actool.Errorf("base_url 必填"), nil
			}
			start, err := platformCall(ctx, http.MethodPost, "/api/tools/dirscan", map[string]any{
				"base_url": a.BaseURL, "wordlist": a.Wordlist, "extensions": a.Extensions,
			})
			if err != nil {
				t.recordAction("dir_scan", "目录扫描启动失败", map[string]any{
					"target": a.BaseURL, "result": "fail", "error": truncateStr(err.Error(), 200),
				})
				return actool.Errorf("扫描启动失败: " + err.Error()), nil
			}
			var st struct {
				JobID int64 `json:"job_id"`
				Paths int   `json:"paths"`
			}
			_ = json.Unmarshal(start, &st)
			if st.JobID == 0 {
				return actool.Errorf("服务端未返回 job_id"), nil
			}
			detail, status, err := pollScanJob(ctx, "/api/tools/dirscan/"+strconv.FormatInt(st.JobID, 10), a.WaitSec)
			if err != nil {
				return actool.Errorf("轮询失败: " + err.Error()), nil
			}
			if status == "timeout" {
				t.recordAction("dir_scan", fmt.Sprintf("目录扫描进行中（%d 路径，job #%d）", st.Paths, st.JobID), map[string]any{
					"target": a.BaseURL, "job_id": st.JobID, "result": "pending",
				})
				return actool.Text(fmt.Sprintf("⏳ 扫描仍在跑（job #%d，%d 路径）。", st.JobID, st.Paths)), nil
			}
			var d struct {
				Status   string `json:"status"`
				Findings struct {
					Hits []struct {
						Path   string `json:"path"`
						Status int    `json:"status"`
						Size   int64  `json:"size"`
						Where  string `json:"where"`
					} `json:"hits"`
					Scanned int `json:"scanned"`
					Total   int `json:"total"`
				} `json:"findings"`
			}
			_ = json.Unmarshal(detail, &d)
			if status != "done" {
				t.recordAction("dir_scan", "目录扫描失败/中断", map[string]any{
					"target": a.BaseURL, "job_id": st.JobID, "result": "fail",
				})
				return actool.Text(fmt.Sprintf("❌ 扫描任务 %s（job #%d）", status, st.JobID)), nil
			}
			// 摘要：高价值命中（200/301/302/401/403）优先
			var b strings.Builder
			hits := d.Findings.Hits
			fmt.Fprintf(&b, "✅ 目录扫描完成（%d/%d 路径，命中 %d）\n", d.Findings.Scanned, d.Findings.Total, len(hits))
			for i, h := range hits {
				if i >= 30 {
					fmt.Fprintf(&b, "…共 %d 命中\n", len(hits))
					break
				}
				line := fmt.Sprintf("  [%d] /%s", h.Status, h.Path)
				if h.Where != "" {
					line += " → " + truncateStr(h.Where, 60)
				}
				b.WriteString(line + "\n")
			}
			t.recordAction("dir_scan", fmt.Sprintf("目录扫描 %s：命中 %d 条路径", truncateStr(a.BaseURL, 40), len(hits)), map[string]any{
				"target": a.BaseURL, "job_id": st.JobID, "result": "ok",
				"hits": len(hits), "scanned": d.Findings.Scanned,
			})
			return actool.Text(strings.TrimRight(b.String(), "\n")), nil
		})
}

// scanTools 汇出扫描工具集。
func (t *ToolSet) scanTools() []actool.CoreTool {
	return []actool.CoreTool{t.portScanTool(), t.dirScanTool()}
}
