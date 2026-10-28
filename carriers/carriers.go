// Package carriers implements pure-Go analysis of multi-carrier artifacts
// (WeChat mini-program wxapkg / Android APK / iOS IPA / HAR traffic).
//
// 移植自 AI-PENTEST 平台的 carrier_parsers.py：载体只是入口，真正要打的
// 是它背后的后端。解析不执行任何上传内容、不发起网络请求；产物是
// 结构化的域名 / API 端点 / 硬编码凭据 / 风险提示，供资产图与 agent 探索复用。
package carriers

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxArtifactBytes caps any single artifact (300MB, mirrors AI-PENTEST).
	MaxArtifactBytes = 300 << 20
	maxTextFile      = 2 << 20   // per-file text cap fed into regex pass
	maxTextTotal     = 24 << 20  // total text budget per artifact
	maxFiles         = 3000      // file listing cap
	maxEndpoints     = 5000      // endpoint cap
	maxSecrets       = 200       // secret cap
)

// Endpoint is one normalized backend API call.
type Endpoint struct {
	Method        string   `json:"method"`
	Scheme        string   `json:"scheme"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	QueryKeys     []string `json:"query_keys,omitempty"`
	BodyKeys      []string `json:"body_keys,omitempty"`
	AuthHeaders   []string `json:"auth_headers,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	SampleRequest string   `json:"sample_request,omitempty"`
	SampleResponse string  `json:"sample_response,omitempty"`
	Source        string   `json:"source,omitempty"`
	HitCount      int      `json:"hit_count"`
}

// Analysis is the structured result of parsing one artifact.
type Analysis struct {
	Carrier    string   `json:"carrier"`
	Format     string   `json:"format"`
	AppID      string   `json:"appid,omitempty"`
	Package    string   `json:"package,omitempty"`
	BundleID   string   `json:"bundle_id,omitempty"`
	VersionName string  `json:"versionName,omitempty"`
	Pages      []string `json:"pages,omitempty"`
	Subpackages []string `json:"subpackages,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Domains    []string `json:"domains"`
	Endpoints  []Endpoint `json:"endpoints"`
	Secrets    []Secret `json:"secrets"`
	RiskHints  []string `json:"risk_hints"`
	Files      []FileInfo `json:"files,omitempty"`
	Stats      Stats    `json:"stats"`
}

// Secret is one hardcoded credential hit.
type Secret struct {
	Kind   string `json:"kind"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

// FileInfo is one entry of the artifact file listing.
type FileInfo struct {
	Name string `json:"name"`
	Size int    `json:"size"`
}

// Stats summarizes the analysis counts.
type Stats struct {
	FileCount     int `json:"file_count"`
	TextFiles     int `json:"text_files"`
	EndpointCount int `json:"endpoint_count"`
	DomainCount   int `json:"domain_count"`
	SecretCount   int `json:"secret_count"`
	PackageSize   int `json:"package_size"`
}

// ---- shared text extraction (ported regexes from carrier_parsers.py) ----

var (
	reURL      = regexp.MustCompile(`https?://[A-Za-z0-9._~:\/?#\[\]@!$&'()*+,;=%-]+`)
	reDomain   = regexp.MustCompile(`(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,12}`)
	reWXAppID  = regexp.MustCompile(`\bwx[0-9a-f]{16}\b`)
	reWXCall   = regexp.MustCompile(`wx\.(request|uploadFile|downloadFile|connectSocket)\s*\(\s*\{(.{0,1000}?)\}\s*\)`)
	reURLField = regexp.MustCompile(`url\s*:\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	reMethod   = regexp.MustCompile(`method\s*:\s*["'` + "`" + `]([A-Za-z]+)["'` + "`" + `]`)
	reDataBlk  = regexp.MustCompile(`data\s*:\s*\{([^}]{0,800})\}`)
	reJSONKey  = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*:`)

	reAKID  = regexp.MustCompile(`\b(LTAI[0-9A-Za-z]{12,24})\b`)
	reAKSK  = regexp.MustCompile(`(?i)\b(access[_-]?key[_-]?secret|secret[_-]?key|sk-[A-Za-z0-9]{20,})\b['"]?\s*[:=]\s*['"]([A-Za-z0-9/+=_-]{16,64})['"]`)
	reJWTS  = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`)
	rePGSQL = regexp.MustCompile(`(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s'"<>]{6,}`)
	reAPIKey= regexp.MustCompile(`(?i)\b(api[_-]?key|app[_-]?secret|appkey)\b['"]?\s*[:=]\s*['"]([A-Za-z0-9_-]{16,64})['"]`)
)

func isTextName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".js", ".json", ".html", ".htm", ".css", ".txt", ".xml", ".ts", ".jsx", ".tsx", ".wxml", ".wxss", ".properties", ".yml", ".yaml", ".env", ".md", ".plist", ".sql", ".ini", ".conf", ".config", ".lua", ".php", ".py", ".java", ".kt":
		return true
	}
	return false
}

type epKey struct{ method, host, path string }

func normalizeEndpoint(rawURL, method, source string) *Endpoint {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return nil
	}
	scheme, rest := "https", u
	if i := strings.Index(u, "://"); i > 0 {
		scheme, rest = strings.ToLower(u[:i]), u[i+3:]
	}
	if scheme != "http" && scheme != "https" {
		return nil
	}
	rest = strings.SplitN(strings.SplitN(rest, "?", 2)[0], "#", 2)[0]
	if rest == "" {
		return nil
	}
	host, path := rest, "/"
	if i := strings.Index(rest, "/"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	host = strings.ToLower(host)
	if host == "" || !strings.Contains(host, ".") {
		return nil
	}
	if method == "" {
		method = "GET"
	}
	return &Endpoint{Method: strings.ToUpper(method), Scheme: scheme, Host: host, Path: path, Source: source, HitCount: 1}
}

// extractFromText pulls domains / endpoints / secrets from one text blob.
func extractFromText(text, source string) (domains []string, eps []Endpoint, secrets []Secret) {
	seenDom := map[string]bool{}
	for _, m := range reURL.FindAllString(text, -1) {
		u := strings.TrimRight(m, ".,;:!?)\"]}")
		if e := normalizeEndpoint(u, "", source); e != nil {
			eps = append(eps, *e)
			if !seenDom[e.Host] {
				seenDom[e.Host] = true
				domains = append(domains, e.Host)
			}
		}
	}
	// bare domains next to code identifiers (api.example.com patterns)
	for _, m := range reDomain.FindAllString(text, -1) {
		if strings.HasSuffix(m, ".png") || strings.HasSuffix(m, ".jpg") || strings.HasSuffix(m, ".gif") {
			continue
		}
		if !seenDom[m] && strings.Contains(text, `"`+m+`"`) || strings.Contains(text, "'"+m+"'") {
			seenDom[m] = true
			domains = append(domains, m)
		}
	}
	for _, m := range reAKID.FindAllStringSubmatch(text, -1) {
		secrets = append(secrets, Secret{Kind: "aliyun_ak_id", Value: m[1], Source: source})
	}
	for _, m := range reAKSK.FindAllStringSubmatch(text, -1) {
		if len(m) > 2 && len(m[2]) >= 16 {
			secrets = append(secrets, Secret{Kind: "secret_key", Value: m[2], Source: source})
		}
	}
	for _, m := range reJWTS.FindAllString(text, -1) {
		secrets = append(secrets, Secret{Kind: "jwt_token", Value: m, Source: source})
	}
	for _, m := range rePGSQL.FindAllString(text, -1) {
		secrets = append(secrets, Secret{Kind: "db_connection", Value: m, Source: source})
	}
	for _, m := range reAPIKey.FindAllStringSubmatch(text, -1) {
		if len(m) > 2 && len(m[2]) >= 16 {
			secrets = append(secrets, Secret{Kind: strings.ToLower(m[1]), Value: m[2], Source: source})
		}
	}
	return
}

func dedupeEndpoints(eps []Endpoint) []Endpoint {
	byKey := map[epKey]*Endpoint{}
	out := make([]Endpoint, 0, len(eps))
	for i := range eps {
		e := eps[i]
		if e.Host == "" {
			continue
		}
		k := epKey{e.Method, e.Host, e.Path}
		if ex, ok := byKey[k]; ok {
			ex.HitCount += e.HitCount
			if len(ex.QueryKeys) == 0 {
				ex.QueryKeys = e.QueryKeys
			}
			if len(ex.BodyKeys) == 0 {
				ex.BodyKeys = e.BodyKeys
			}
			if ex.SampleRequest == "" {
				ex.SampleRequest = e.SampleRequest
			}
			if ex.SampleResponse == "" {
				ex.SampleResponse = e.SampleResponse
			}
			continue
		}
		byKey[k] = &eps[i]
		out = append(out, eps[i])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	if len(out) > maxEndpoints {
		out = out[:maxEndpoints]
	}
	return out
}

func dedupeStrings(in []string, limit int) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// ---- wxapkg ----

// ParseWxapkg unpacks a WeChat mini-program package and analyzes its text files.
func ParseWxapkg(path string) (*Analysis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxArtifactBytes {
		return nil, fmt.Errorf("小程序包超过 %dMB 上限", MaxArtifactBytes>>20)
	}
	if len(data) < 18 {
		return nil, fmt.Errorf("文件过小，不是有效 wxapkg")
	}
	if bytes.HasPrefix(data, []byte("V1MMWX")) || bytes.HasPrefix(data, []byte("v1mmwx")) {
		return nil, fmt.Errorf("检测到加密的 wxapkg（V1MMWX），需运行时抓包(HAR)或先解密")
	}
	if data[0] != 0xBE {
		return nil, fmt.Errorf("wxapkg 头标记错误: 0x%02x", data[0])
	}
	count := int(binary.BigEndian.Uint32(data[14:18]))
	if count <= 0 || count > 200000 {
		return nil, fmt.Errorf("wxapkg 文件数异常: %d", count)
	}
	a := &Analysis{Carrier: "miniprogram", Format: "wxapkg",
		Domains: []string{}, Endpoints: []Endpoint{}, Secrets: []Secret{}, RiskHints: []string{}}
	pos := 18
	var text bytes.Buffer
	for i := 0; i < count && pos+4 <= len(data); i++ {
		nameLen := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if nameLen <= 0 || nameLen > 4096 || pos+nameLen+8 > len(data) {
			break
		}
		name := string(data[pos : pos+nameLen])
		pos += nameLen
		off := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		size := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if off < 0 || size < 0 || off+size > len(data) {
			continue
		}
		a.Files = append(a.Files, FileInfo{Name: name, Size: size})
		if !isTextName(name) || size > maxTextFile || text.Len() >= maxTextTotal {
			continue
		}
		text.Write(data[off : off+size])
		text.WriteByte('\n')
		a.Stats.TextFiles++
	}
	a.analyzeMiniText(text.String())
	a.finish(len(data))
	return a, nil
}

// ParseMiniSourceZip 分析反编译后的小程序源码包（unveilr / wxappUnpacker 等工具
// 的产物，zip 内是 app.json/pages/*.js/.wxml 等明文源码）。逐文件走与 wxapkg
// 相同的文本分析管线（domains/endpoints/secrets/app.json 页面）。
func ParseMiniSourceZip(path string) (*Analysis, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("不是合法的 zip 包: %w", err)
	}
	defer zr.Close()
	a := &Analysis{Carrier: "miniprogram", Format: "minisrc-zip",
		Domains: []string{}, Endpoints: []Endpoint{}, Secrets: []Secret{}, RiskHints: []string{}}
	var text bytes.Buffer
	var total int
	for _, f := range zr.File {
		name := strings.TrimPrefix(f.Name, "./")
		if f.FileInfo().IsDir() || strings.Contains(name, "__MACOSX") {
			continue
		}
		if !isTextName(name) {
			continue
		}
		if f.UncompressedSize64 > uint64(maxTextFile) || total >= maxTextTotal {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxTextFile+1))
		rc.Close()
		if err != nil || len(data) > maxTextFile {
			continue
		}
		total += len(data)
		a.Files = append(a.Files, FileInfo{Name: name, Size: len(data)})
		text.Write(data)
		text.WriteByte('\n')
		a.Stats.TextFiles++
	}
	if a.Stats.TextFiles == 0 {
		return nil, fmt.Errorf("zip 里没有可分析的小程序源码文本文件（需要 .js/.json/.wxml 等）")
	}
	a.analyzeMiniText(text.String())
	a.finish(int(total))
	return a, nil
}

func (a *Analysis) analyzeMiniText(text string) {
	if m := reWXAppID.FindString(text); m != "" {
		a.AppID = m
	}
	// app-config.json / app.json pages
	var cfg struct {
		Entry   string   `json:"entryPagePath"`
		Pages   []string `json:"pages"`
		SubPkgs []struct {
			Root  string   `json:"root"`
			Pages []string `json:"pages"`
		} `json:"subPackages"`
	}
	// best-effort: find the largest JSON object with "pages"
	if idx := strings.Index(text, `"entryPagePath`); idx >= 0 {
		start := strings.LastIndex(text[:idx], "{")
		if start >= 0 {
			dec := json.NewDecoder(bytes.NewReader([]byte(text[start:])))
			if err := dec.Decode(&cfg); err != nil {
				cfg = struct {
					Entry   string   `json:"entryPagePath"`
					Pages   []string `json:"pages"`
					SubPkgs []struct {
						Root  string   `json:"root"`
						Pages []string `json:"pages"`
					} `json:"subPackages"`
				}{}
				// fallback: pages-only
				var only struct {
					Pages []string `json:"pages"`
				}
				if err2 := json.NewDecoder(bytes.NewReader([]byte(text[start:]))).Decode(&only); err2 == nil {
					cfg.Pages = only.Pages
				}
			}
		}
	}
	a.Pages = dedupeStrings(cfg.Pages, 500)
	if cfg.Entry != "" {
		a.Pages = append([]string{cfg.Entry}, a.Pages...)
	}
	for _, sp := range cfg.SubPkgs {
		for _, p := range sp.Pages {
			a.Subpackages = append(a.Subpackages, strings.TrimPrefix(sp.Root+"/"+p, "/"))
		}
	}
	a.Subpackages = dedupeStrings(a.Subpackages, 500)

	domains, eps, secrets := extractFromText(text, "wxapkg")
	// wx.request / uploadFile / downloadFile / connectSocket structured calls
	for _, m := range reWXCall.FindAllStringSubmatch(text, -1) {
		kind, block := m[1], m[2]
		um := reURLField.FindStringSubmatch(block)
		if um == nil {
			continue
		}
		method := "GET"
		if mm := reMethod.FindStringSubmatch(block); mm != nil {
			method = strings.ToUpper(mm[1])
		} else if kind == "uploadFile" {
			method = "POST"
		}
		e := normalizeEndpoint(um[1], method, "wx."+kind)
		if e == nil {
			continue
		}
		if dm := reDataBlk.FindStringSubmatch(block); dm != nil {
			keys := reJSONKey.FindAllStringSubmatch(dm[1], -1)
			for _, k := range keys {
				e.BodyKeys = append(e.BodyKeys, k[1])
			}
		}
		eps = append(eps, *e)
	}
	a.Domains = append(a.Domains, domains...)
	a.Endpoints = append(a.Endpoints, eps...)
	a.Secrets = append(a.Secrets, secrets...)
	a.RiskHints = append(a.RiskHints, "已识别 appid，可进一步核对 appsecret 泄露")
}

// ---- APK ----

// ParseAPK analyzes an Android package: binary manifest, permissions, dex strings.
func ParseAPK(path string) (*Analysis, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	a := &Analysis{Carrier: "app", Format: "apk",
		Domains: []string{}, Endpoints: []Endpoint{}, Secrets: []Secret{}, RiskHints: []string{}}
	var text bytes.Buffer
	manifestIdx, dexCount := -1, 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(a.Files) < maxFiles {
			a.Files = append(a.Files, FileInfo{Name: f.Name, Size: int(f.UncompressedSize64)})
		}
		base := strings.ToLower(f.Name)
		switch {
		case base == "androidmanifest.xml":
			manifestIdx = len(a.Files) - 1
		case strings.HasSuffix(base, ".dex"):
			dexCount++
		}
		if manifestIdx == len(a.Files)-1 {
			rc, err := f.Open()
			if err == nil {
				mx, _ := io.ReadAll(io.LimitReader(rc, maxTextFile))
				rc.Close()
				a.parseBinaryManifest(mx)
			}
			manifestIdx = -1 // consumed
			continue
		}
		if !isTextName(f.Name) || f.UncompressedSize64 > maxTextFile || text.Len() >= maxTextTotal {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, maxTextFile))
		rc.Close()
		text.Write(b)
		text.WriteByte('\n')
		a.Stats.TextFiles++
	}
	// dex strings: scan every .dex for printable runs (domains, urls, secrets)
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".dex") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, maxTextFile*8))
		rc.Close()
		text.Write(dexStrings(b))
		text.WriteByte('\n')
	}
	_ = dexCount
	domains, eps, secrets := extractFromText(text.String(), "apk")
	a.Domains = append(a.Domains, domains...)
	a.Endpoints = append(a.Endpoints, eps...)
	a.Secrets = append(a.Secrets, secrets...)
	if a.Package != "" {
		a.RiskHints = append(a.RiskHints, "包名 "+a.Package)
	}
	for _, p := range a.Permissions {
		if strings.HasPrefix(p, "android.permission.") {
			switch p {
			case "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
				"android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO",
				"android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
				"android.permission.READ_PHONE_STATE", "android.permission.WRITE_EXTERNAL_STORAGE":
				a.RiskHints = append(a.RiskHints, "敏感权限: "+strings.TrimPrefix(p, "android.permission."))
			}
		}
	}
	a.finish(fileSizeOf(path))
	return a, nil
}

var reManifestStr = regexp.MustCompile(`[\x20-\x7e\x{4e00}-\x{9fff}]{4,}`)

func (a *Analysis) parseBinaryManifest(data []byte) {
	// AndroidManifest.xml is Android binary XML; the string pool holds readable
	// tokens. Extract package / permissions / exported components heuristically.
	strs := reManifestStr.FindAllString(string(data), -1)
	seen := map[string]bool{}
	uniq := make([]string, 0, len(strs))
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			uniq = append(uniq, s)
		}
	}
	for _, s := range uniq {
		switch {
		case strings.HasPrefix(s, "android.permission."):
			a.Permissions = append(a.Permissions, s)
		case strings.HasSuffix(s, ".MainActivity") ||
			(strings.Contains(s, ".activity") && strings.Contains(s, ".")):
			// component names surface in the string pool
		}
	}
	// package: first token that looks like com.xxx.yyy and is not a permission
	for _, s := range uniq {
		if strings.HasPrefix(s, "android.") || strings.HasPrefix(s, "com.android.") {
			continue
		}
		if len(strings.Split(s, ".")) >= 3 && !strings.Contains(s, " ") && !strings.Contains(s, "http") {
			a.Package = s
			break
		}
	}
	a.Permissions = dedupeStrings(a.Permissions, 100)
}

// dexStrings extracts printable ASCII runs (len>=6) from dex bytecode — good
// enough to surface hardcoded URLs, hosts, and credential material.
func dexStrings(b []byte) []byte {
	var out bytes.Buffer
	start := -1
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 6 {
			out.Write(b[start:i])
			out.WriteByte('\n')
		}
		start = -1
	}
	return out.Bytes()
}

// ---- IPA ----

// ParseIPA analyzes an iOS package: Info.plist identity + text scan.
func ParseIPA(path string) (*Analysis, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	a := &Analysis{Carrier: "app", Format: "ipa",
		Domains: []string{}, Endpoints: []Endpoint{}, Secrets: []Secret{}, RiskHints: []string{}}
	var text bytes.Buffer
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if len(a.Files) < maxFiles {
			a.Files = append(a.Files, FileInfo{Name: f.Name, Size: int(f.UncompressedSize64)})
		}
		base := f.Name
		if strings.HasSuffix(base, "Info.plist") && a.BundleID == "" {
			rc, err := f.Open()
			if err == nil {
				b, _ := io.ReadAll(io.LimitReader(rc, maxTextFile))
				rc.Close()
				a.parseInfoPlist(b)
			}
			continue
		}
		if !isTextName(base) && !strings.HasSuffix(base, ".strings") {
			continue
		}
		if f.UncompressedSize64 > maxTextFile || text.Len() >= maxTextTotal {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, maxTextFile))
		rc.Close()
		text.Write(b)
		text.WriteByte('\n')
		a.Stats.TextFiles++
	}
	domains, eps, secrets := extractFromText(text.String(), "ipa")
	a.Domains = append(a.Domains, domains...)
	a.Endpoints = append(a.Endpoints, eps...)
	a.Secrets = append(a.Secrets, secrets...)
	if a.BundleID != "" {
		a.RiskHints = append(a.RiskHints, "Bundle ID "+a.BundleID)
	}
	a.RiskHints = append(a.RiskHints, "IPA 未检查 ATS/URL Scheme（需进一步逆向）")
	a.finish(fileSizeOf(path))
	return a, nil
}

func (a *Analysis) parseInfoPlist(b []byte) {
	s := string(b)
	// XML plist
	if m := regexp.MustCompile(`<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(s); m != nil {
		a.BundleID = m[1]
	}
	if m := regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(s); m != nil {
		a.VersionName = m[1]
	}
	// binary plist: CFBundleIdentifier appears as raw ASCII near its value
	if a.BundleID == "" {
		strs := reManifestStr.FindAllString(s, -1)
		for i, tok := range strs {
			if tok == "CFBundleIdentifier" && i+1 < len(strs) {
				a.BundleID = strs[i+1]
				break
			}
		}
	}
}

// ---- HAR ----

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				URL     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				PostData *struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Params   []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"params"`
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Status    int    `json:"status"`
				Content   struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

// ParseHAR converts recorded HTTP traffic into normalized endpoints.
func ParseHAR(path string) (*Analysis, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxArtifactBytes {
		return nil, fmt.Errorf("HAR 超过 %dMB 上限", MaxArtifactBytes>>20)
	}
	var h harFile
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("HAR 解析失败: %w", err)
	}
	a := &Analysis{Carrier: "web", Format: "har",
		Domains: []string{}, Endpoints: []Endpoint{}, Secrets: []Secret{}, RiskHints: []string{}}
	for _, e := range h.Log.Entries {
		e0 := normalizeEndpoint(e.Request.URL, e.Request.Method, "har")
		if e0 == nil {
			continue
		}
		for _, hd := range e.Request.Headers {
			n := strings.ToLower(hd.Name)
			if n == "authorization" || n == "cookie" || strings.HasSuffix(n, "token") {
				e0.AuthHeaders = append(e0.AuthHeaders, hd.Name)
			}
		}
		if e.Request.PostData != nil {
			e0.ContentType = e.Request.PostData.MimeType
			if len(e.Request.PostData.Params) > 0 {
				for _, p := range e.Request.PostData.Params {
					e0.BodyKeys = append(e0.BodyKeys, p.Name)
				}
			} else if e.Request.PostData.Text != "" {
				if strings.Contains(e0.ContentType, "json") {
					var obj map[string]any
					if json.Unmarshal([]byte(e.Request.PostData.Text), &obj) == nil {
						for k := range obj {
							e0.BodyKeys = append(e0.BodyKeys, k)
						}
					}
				}
			}
			if len(e0.BodyKeys) > 50 {
				e0.BodyKeys = e0.BodyKeys[:50]
			}
		}
		u := e0.Scheme + "://" + e0.Host + e0.Path
		var req bytes.Buffer
		fmt.Fprintf(&req, "%s %s HTTP/1.1\nHost: %s\n", e0.Method, e0.Path, e0.Host)
		for _, hd := range e.Request.Headers {
			if strings.ToLower(hd.Name) == "host" {
				continue
			}
			fmt.Fprintf(&req, "%s: %s\n", hd.Name, hd.Value)
		}
		e0.SampleRequest = req.String()
		if e.Response.Content.Text != "" {
			e0.SampleResponse = fmt.Sprintf("HTTP/1.1 %d\n%s", e.Response.Status, truncate(e.Response.Content.Text, 4000))
		}
		_ = u
		a.Endpoints = append(a.Endpoints, *e0)
		a.Domains = append(a.Domains, e0.Host)
	}
	a.finish(fileSizeOf(path))
	return a, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func fileSizeOf(path string) int {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return int(st.Size())
}

func (a *Analysis) finish(size int) {
	a.Domains = dedupeStrings(a.Domains, 500)
	a.Endpoints = dedupeEndpoints(a.Endpoints)
	a.Secrets = a.Secrets[:min(len(a.Secrets), maxSecrets)]
	a.Files = a.Files[:min(len(a.Files), maxFiles)]
	a.RiskHints = dedupeStrings(a.RiskHints, 30)
	a.Permissions = dedupeStrings(a.Permissions, 100)
	a.Stats.FileCount = len(a.Files)
	a.Stats.EndpointCount = len(a.Endpoints)
	a.Stats.DomainCount = len(a.Domains)
	a.Stats.SecretCount = len(a.Secrets)
	a.Stats.PackageSize = size
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DetectKind maps a filename to an artifact kind.
func DetectKind(filename string) string {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".wxapkg":
		return "wxapkg"
	case ".apk":
		return "apk"
	case ".ipa":
		return "ipa"
	case ".har":
		return "har"
	case ".json", ".ndjson":
		return "har" // mitmproxy JSON dump treated as HAR-shaped
	case ".js":
		return "jsbundle"
	}
	return "other"
}

// KindFromForm 校验上传表单显式选择的产物类型；空串=按扩展名识别。
func KindFromForm(v string) string {
	switch v {
	case "wxapkg", "minisrc", "apk", "ipa", "har", "jsbundle", "text":
		return v
	}
	return ""
}

// Analyze dispatches to the right parser by kind.
func Analyze(path, kind string) (*Analysis, error) {
	switch kind {
	case "wxapkg":
		return ParseWxapkg(path)
	case "minisrc":
		return ParseMiniSourceZip(path)
	case "apk":
		return ParseAPK(path)
	case "ipa":
		return ParseIPA(path)
	case "har":
		// mitmproxy JSON may not be HAR; try HAR first, fall back to text scan
		a, err := ParseHAR(path)
		if err == nil {
			return a, nil
		}
		return parseTextDump(path)
	case "jsbundle":
		return parseTextDump(path)
	}
	return nil, fmt.Errorf("不支持的产物类型: %s", kind)
}

// parseTextDump scans an arbitrary text/JSON dump the same way as jsbundle.
func parseTextDump(path string) (*Analysis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > maxTextTotal {
		data = data[:maxTextTotal]
	}
	a := &Analysis{Carrier: "web", Format: "text",
		Domains: []string{}, Endpoints: []Endpoint{}, Secrets: []Secret{}, RiskHints: []string{}}
	domains, eps, secrets := extractFromText(string(data), "text")
	a.Domains, a.Endpoints, a.Secrets = domains, eps, secrets
	a.finish(fileSizeOf(path))
	return a, nil
}
