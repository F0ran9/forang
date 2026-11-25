package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 回归：gate 开启后，agent 的环回工具调用曾被裸 404（"扫描启动失败: HTTP 404"）。
func TestGateInternalRequest(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name   string
		remote string
		path   string
		hdrs   map[string]string
		want   bool
	}{
		{"本机直连工具接口", "127.0.0.1:5555", "/api/tools/portscan", nil, true},
		{"本机 IPv6 回环", "[::1]:5555", "/api/tools/portscan/1", nil, true},
		{"本机但非工具接口", "127.0.0.1:5555", "/api/tasks", nil, false},
		{"经过 nginx（带 XFF）", "127.0.0.1:5555", "/api/tools/portscan", map[string]string{"X-Forwarded-For": "1.2.3.4"}, false},
		{"经过 nginx（X-Real-IP）", "127.0.0.1:5555", "/api/tools/portscan", map[string]string{"X-Real-IP": "1.2.3.4"}, false},
		{"经过 Cloudflare", "127.0.0.1:5555", "/api/tools/portscan", map[string]string{"CF-Connecting-IP": "1.2.3.4"}, false},
		{"外部来源", "8.8.8.8:5555", "/api/tools/portscan", nil, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", c.path, nil)
		r.RemoteAddr = c.remote
		for k, v := range c.hdrs {
			r.Header.Set(k, v)
		}
		if got := s.gateInternalRequest(r); got != c.want {
			t.Errorf("%s: gateInternalRequest=%v want %v", c.name, got, c.want)
		}
	}
	_ = http.StatusOK
}
