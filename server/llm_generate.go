package server

// llm_generate.go — 平台内 AI 生成入口（免杀变形 / webshell 生成）。
// 复用平台 LLM 配置链：ActiveProfile → providerForProfile → 流式补全。

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// llmGenProfileID 取用于生成的 LLM profile（可显式指定，缺省激活配置）。
func (s *Server) llmGenProfileID(requested int64) int64 {
	if requested > 0 {
		return requested
	}
	if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
		return p.ID
	}
	return 0
}

// llmGenerate 一次性生成（带代码围栏剥离）。maxTokens 按产物体积给足。
func (s *Server) llmGenerate(ctx context.Context, profileID int64, system, user string, maxTokens int) (string, error) {
	pid := s.llmGenProfileID(profileID)
	if pid == 0 {
		return "", fmt.Errorf("未配置可用的生成模型（平台设置里激活一个 LLM 配置）")
	}
	prov, _, ok := s.providerForProfile(pid)
	if !ok {
		return "", fmt.Errorf("生成模型 profile %d 不可用", pid)
	}
	c, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	req := llm.CompletionRequest{
		System:    []string{system},
		Messages:  []llm.Message{llm.UserText(user)},
		MaxTokens: maxTokens,
	}
	var sb strings.Builder
	for ev, err := range prov.Stream(c, req) {
		if err != nil {
			return "", err
		}
		if ev.Type == llm.SETextDelta {
			sb.WriteString(ev.Text)
		}
	}
	return strings.TrimSpace(stripCodeFence(sb.String())), nil
}

// stripCodeFence 剥 ```go / ```php 等围栏。
func stripCodeFence(text string) string {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "```") {
		return t
	}
	if i := strings.Index(t, "\\n"); i > 0 {
		t = t[i+1:]
	} else {
		return t
	}
	if j := strings.LastIndex(t, "```"); j >= 0 {
		t = t[:j]
	}
	return strings.TrimSpace(t)
}
