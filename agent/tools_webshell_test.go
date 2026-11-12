package agent

// tools_webshell_test.go — webshell 工具的入参绑定。
//
// webshell_plugin 的入参是「wsConn 内嵌 + 插件字段」：内嵌类型未导出，靠
// encoding/json 把提升字段摊平来解析。这个行为一旦失效（换成非 struct 内嵌、
// 或加了 json:"-"），表现是所有连接参数变成空串，工具只报「url 与 password 必填」，
// 从错误信息完全看不出根因，所以单独钉一条测试。

import (
	"encoding/json"
	"testing"
)

func TestWSConnEmbeddedUnmarshal(t *testing.T) {
	var in struct {
		wsConn
		Op         string `json:"op"`
		Filter     string `json:"filter"`
		ScanPorts  string `json:"scan_ports"`
		FilterName string `json:"filter_name"`
	}
	raw := `{"url":"http://t/a.jsp","password":"k","script_type":"jsp","carrier":"java",
		"op":"proc_list","filter":"1234","scan_ports":"80,443","filter_name":"fs"}`
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		t.Fatal(err)
	}
	if in.URL != "http://t/a.jsp" || in.Password != "k" || in.Carrier != "java" || in.ScriptType != "jsp" {
		t.Fatalf("内嵌连接字段未解析：%+v", in.wsConn)
	}
	if in.Op != "proc_list" || in.Filter != "1234" || in.ScanPorts != "80,443" || in.FilterName != "fs" {
		t.Fatalf("插件字段未解析：op=%q filter=%q ports=%q name=%q", in.Op, in.Filter, in.ScanPorts, in.FilterName)
	}

	// 缺省值：encoder/script_type 未给时按 raw/php 兜底（与 webshell_exec 一致）
	var bare struct{ wsConn }
	if err := json.Unmarshal([]byte(`{"url":"u","password":"p"}`), &bare); err != nil {
		t.Fatal(err)
	}
	bare.normalize()
	if bare.Encoder != "raw" || bare.ScriptType != "php" {
		t.Fatalf("缺省值不对：encoder=%q script_type=%q", bare.Encoder, bare.ScriptType)
	}
}
