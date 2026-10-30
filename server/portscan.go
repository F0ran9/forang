package server

// portscan.go — 端口扫描（移植自 AI-PENTEST scan_tools.py 的端口扫描，Go 原生
// 并发 TCP dial，无 nmap/masscan 外部依赖）。任务落 scan_jobs 表，前端轮询进度。
// targets 支持：逗号分隔 host / a.b.c.d-e / CIDR(/24 内)。ports 支持：top100 /
// 逗号列表 / 区间 8000-8100 组合。

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// top100Ports 常见 TCP 端口（nmap top100 子集，渗透够用）。
var top100Ports = []int{
	21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 443, 445, 465, 500, 514, 543,
	548, 554, 587, 631, 646, 873, 990, 993, 995, 1080, 1099, 1194, 1433, 1434, 1521,
	1723, 1883, 2049, 2082, 2083, 2181, 2375, 2376, 2379, 2601, 2604, 3000, 3128, 3260,
	3306, 3389, 3690, 4369, 4443, 4848, 5000, 5432, 5555, 5601, 5672, 5900, 5901, 5984,
	6379, 6443, 6660, 6666, 7000, 7001, 7002, 7077, 7100, 7180, 7474, 7547, 7777, 8000,
	8001, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080, 8081, 8086, 8088, 8090, 8091,
	8161, 8180, 8200, 8222, 8243, 8280, 8333, 8334, 8443, 8500, 8649, 8686, 8800, 8848,
	8868, 8888, 8889, 8920, 9000, 9001, 9002, 9008, 9042, 9043, 9060, 9080, 9090, 9091,
	9092, 9100, 9200, 9256, 9300, 9418, 9443, 9495, 9527, 9600, 9711, 9800, 9869, 9981,
	9990, 9999, 10000, 10001, 10010, 10250, 11211, 11883, 12201, 12443, 13000, 13306,
	15000, 15672, 16080, 18080, 18083, 19000, 19071, 20000, 20720, 21025, 28017, 30865,
	32400, 33060, 50000, 50070, 50090, 61616, 63791,
}

var portScanMu sync.Mutex // 同一时刻只跑一个端口扫描（资源保护）

// POST /api/tools/portscan {targets, ports?, timeout_sec?} → {data:{job_id, hosts, ports}}
func (s *Server) portScanStart(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Targets    string `json:"targets"`
		Ports      string `json:"ports"`
		TimeoutSec int    `json:"timeout_sec"`
		Concurrency int   `json:"concurrency"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	targets := strings.TrimSpace(b.Targets)
	if targets == "" {
		writeErr(w, 400, "targets 不能为空")
		return
	}
	if b.TimeoutSec <= 0 || b.TimeoutSec > 3600 {
		b.TimeoutSec = 600
	}
	if b.Concurrency <= 0 || b.Concurrency > 1000 {
		b.Concurrency = 300
	}
	portsSpec := strings.TrimSpace(b.Ports)
	if portsSpec == "" {
		portsSpec = "top100"
	}
	hosts, err := expandScanTargets(targets)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(hosts) > 512 {
		writeErr(w, 400, fmt.Sprintf("展开后主机数 %d 超上限 512", len(hosts)))
		return
	}
	ports, err := resolveScanPorts(portsSpec)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	params, _ := json.Marshal(map[string]any{
		"ports": portsSpec, "timeout_sec": b.TimeoutSec, "concurrency": b.Concurrency,
		"host_count": len(hosts), "port_count": len(ports),
	})
	var jobID int64
	if err := s.m.PG().QueryRow(
		"INSERT INTO scan_jobs (kind, targets, params, status, findings) VALUES ('port',$1,$2,'pending','{}') RETURNING id",
		truncateStr(targets, 2000), string(params)).Scan(&jobID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	go s.runPortScan(jobID, hosts, ports, b.TimeoutSec, b.Concurrency)
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"job_id": jobID, "hosts": len(hosts), "ports": len(ports)}})
}

func (s *Server) runPortScan(jobID int64, hosts []string, ports []int, timeoutSec, concurrency int) {
	portScanMu.Lock()
	defer portScanMu.Unlock()
	db := s.m.PG()
	_, _ = db.Exec("UPDATE scan_jobs SET status='running', updated_at=now() WHERE id=$1", jobID)

	type hostResult struct {
		Host  string `json:"host"`
		Ports []int  `json:"ports"`
	}
	type findingsT struct {
		Hosts    []hostResult `json:"hosts"`
		Scanned  int          `json:"scanned"`
		Total    int          `json:"total"`
		OpenTotal int         `json:"open_total"`
	}
	f := findingsT{Hosts: []hostResult{}, Total: len(hosts), Scanned: 0}
	save := func() {
		j, _ := json.Marshal(f)
		_, _ = db.Exec("UPDATE scan_jobs SET findings=$1, updated_at=now() WHERE id=$2", string(j), jobID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	lastSave := time.Now()

	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			open := []int{}
			var hostWG sync.WaitGroup
			for _, p := range ports {
				hostWG.Add(1)
				go func(p int) {
					defer hostWG.Done()
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						return
					}
					defer func() { <-sem }()
					addr := net.JoinHostPort(h, strconv.Itoa(p))
					d := net.Dialer{Timeout: 2500 * time.Millisecond}
					c, err := d.DialContext(ctx, "tcp", addr)
					if err == nil {
						c.Close()
						mu.Lock()
						open = append(open, p)
						mu.Unlock()
					}
				}(p)
			}
			hostWG.Wait()
			sort.Ints(open)
			mu.Lock()
			if len(open) > 0 {
				f.Hosts = append(f.Hosts, hostResult{Host: h, Ports: open})
				f.OpenTotal += len(open)
			}
			f.Scanned++
			if time.Since(lastSave) > 2*time.Second { // 节流写进度
				lastSave = time.Now()
				save()
			}
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	save()
	_, _ = db.Exec("UPDATE scan_jobs SET status='done', updated_at=now() WHERE id=$1", jobID)
}

// GET /api/tools/portscan — 最近 20 个任务。
func (s *Server) portScanList(w http.ResponseWriter, r *http.Request) {
	s.scanJobList(w, "port")
}

// GET /api/tools/portscan/{id} — 任务详情（含 findings）。
func (s *Server) portScanDetail(w http.ResponseWriter, r *http.Request) {
	s.scanJobDetail(w, r, "port")
}

func (s *Server) scanJobList(w http.ResponseWriter, kind string) {
	rows, err := s.m.PG().Query(
		"SELECT id, targets, params, status, findings, created_at FROM scan_jobs WHERE kind=$1 ORDER BY id DESC LIMIT 20", kind)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type job struct {
		ID        int64           `json:"id"`
		Targets   string          `json:"targets"`
		Params    json.RawMessage `json:"params"`
		Status    string          `json:"status"`
		Findings  json.RawMessage `json:"findings"`
		CreatedAt string          `json:"created_at"`
	}
	out := []job{}
	for rows.Next() {
		var j job
		var ct sql.NullTime
		var params, findings []byte
		if err := rows.Scan(&j.ID, &j.Targets, &params, &j.Status, &findings, &ct); err != nil {
			continue
		}
		j.Params, j.Findings = json.RawMessage(params), json.RawMessage(findings)
		if ct.Valid {
			j.CreatedAt = ct.Time.Format("2006-01-02 15:04")
		}
		out = append(out, j)
	}
	writeJSON(w, 200, map[string]any{"data": out})
}

func (s *Server) scanJobDetail(w http.ResponseWriter, r *http.Request, kind string) {
	id := parseID(r.PathValue("id"))
	if id <= 0 {
		writeErr(w, 400, "bad id")
		return
	}
	var targets, status string
	var params, findings []byte
	var ct sql.NullTime
	err := s.m.PG().QueryRow(
		"SELECT targets, status, params, findings, created_at FROM scan_jobs WHERE id=$1 AND kind=$2", id, kind).
		Scan(&targets, &status, &params, &findings, &ct)
	if err != nil {
		writeErr(w, 404, "job 不存在")
		return
	}
	created := ""
	if ct.Valid {
		created = ct.Time.Format("2006-01-02 15:04")
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{
		"id": id, "targets": targets, "status": status,
		"params": json.RawMessage(params), "findings": json.RawMessage(findings),
		"created_at": created,
	}})
}

// expandScanTargets 展开：逗号分隔、a-b 区间、CIDR（/24 内）。
func expandScanTargets(spec string) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// CIDR
		if strings.Contains(part, "/") {
			ip, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("CIDR 不合法: %s", part)
			}
			ones, bits := ipnet.Mask.Size()
			if bits-ones > 12 {
				return nil, fmt.Errorf("CIDR %s 网段过大（最多 /20）", part)
			}
			for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
				if !seen[cur.String()] {
					seen[cur.String()] = true
					out = append(out, cur.String())
				}
				if len(out) > 512 {
					return nil, fmt.Errorf("展开主机数超上限 512")
				}
			}
			continue
		}
		// a-b 区间（仅 IPv4 末段）
		if i := strings.Index(part, "-"); i > 0 {
			lo := net.ParseIP(strings.TrimSpace(part[:i]))
			if lo != nil && lo.To4() != nil {
				base := lo.To4()[:3]
				hiN, err2 := strconv.Atoi(strings.TrimSpace(part[i+1:]))
				loN := int(lo.To4()[3])
				if err2 == nil && hiN >= loN && hiN <= 255 && hiN-loN <= 255 {
					for n := loN; n <= hiN; n++ {
						ip := net.IPv4(base[0], base[1], base[2], byte(n)).String()
						if !seen[ip] {
							seen[ip] = true
							out = append(out, ip)
						}
					}
					continue
				}
			}
			return nil, fmt.Errorf("区间不合法: %s", part)
		}
		// 单 host：域名原样保留（dial 时解析）
		if !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无有效目标")
	}
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// resolveScanPorts 端口规格：top100 / 80,443 / 8000-8100 组合。
func resolveScanPorts(spec string) ([]int, error) {
	spec = strings.ToLower(strings.TrimSpace(spec))
	if spec == "" || spec == "top100" {
		return top100Ports, nil
	}
	seen := map[int]bool{}
	out := []int{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if e1 != nil || e2 != nil || lo < 1 || hi < lo || hi > 65535 || hi-lo > 20000 {
				return nil, fmt.Errorf("端口区间不合法: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("端口不合法: %s", part)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("无有效端口")
	}
	sort.Ints(out)
	return out, nil
}
