package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ScanOptions 扫描配置
type ScanOptions struct {
	Targets     []string      // IP 列表
	Ports       []int         // 端口列表
	Concurrency int           // 并发数
	Timeout     time.Duration // 单个连接超时
}

// ScanResult 单个扫描结果
type ScanResult struct {
	IP    string
	Port  int
	Open  bool
	Error error
}

// ProgressCallback 进度回调函数
type ProgressCallback func(completed, total int)

// Scanner 通用端口扫描器
type Scanner struct {
	opts     ScanOptions
	progress ProgressCallback
}

// NewScanner 创建扫描器
func NewScanner(opts ScanOptions) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 100
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	return &Scanner{opts: opts}
}

// WithProgress 设置进度回调
func (s *Scanner) WithProgress(fn ProgressCallback) *Scanner {
	s.progress = fn
	return s
}

// Scan 执行扫描，返回结果 channel
func (s *Scanner) Scan(ctx context.Context) <-chan ScanResult {
	results := make(chan ScanResult, s.opts.Concurrency)

	go func() {
		defer close(results)

		// 构建所有扫描任务
		type task struct {
			ip   string
			port int
		}
		var tasks []task
		for _, ip := range s.opts.Targets {
			for _, port := range s.opts.Ports {
				tasks = append(tasks, task{ip: ip, port: port})
			}
		}

		total := len(tasks)
		if total == 0 {
			return
		}

		// 并发控制
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, s.opts.Concurrency)
		var completed int
		var mu sync.Mutex

		for _, t := range tasks {
			select {
			case <-ctx.Done():
				return
			default:
			}

			wg.Add(1)
			semaphore <- struct{}{}

			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-semaphore }()

				result := s.probePort(ctx, ip, port)

				select {
				case results <- result:
				case <-ctx.Done():
					return
				}

				// 更新进度
				if s.progress != nil {
					mu.Lock()
					completed++
					s.progress(completed, total)
					mu.Unlock()
				}
			}(t.ip, t.port)
		}

		wg.Wait()
	}()

	return results
}

// probePort 探测单个端口
func (s *Scanner) probePort(ctx context.Context, ip string, port int) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: port,
	}

	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))

	// 使用带超时的 Dialer
	dialer := &net.Dialer{Timeout: s.opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		result.Open = false
		result.Error = err
		return result
	}
	_ = conn.Close()

	result.Open = true
	return result
}

// ParseTargets 解析目标字符串为 IP 列表
// 支持格式:
//   - 单个 IP: 192.168.1.1
//   - CIDR: 192.168.1.0/24
//   - IP 范围: 192.168.1.1-100 或 192.168.1.1-192.168.1.100
func ParseTargets(target string) ([]string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("目标不能为空")
	}

	// CIDR 格式
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}

	// IP 范围格式
	if strings.Contains(target, "-") {
		return parseIPRange(target)
	}

	// 单个 IP
	if ip := net.ParseIP(target); ip != nil {
		return []string{target}, nil
	}

	return nil, fmt.Errorf("无效的目标格式: %s", target)
}

// parseCIDR 解析 CIDR 格式
func parseCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无效的 CIDR: %s", cidr)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		// 跳过网络地址和广播地址
		if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
			continue
		}
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// parseIPRange 解析 IP 范围格式
// 支持: 192.168.1.1-100 或 192.168.1.1-192.168.1.100
func parseIPRange(rangeStr string) ([]string, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的 IP 范围格式: %s", rangeStr)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return nil, fmt.Errorf("无效的起始 IP: %s", parts[0])
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("仅支持 IPv4: %s", parts[0])
	}

	endPart := strings.TrimSpace(parts[1])

	// 检查是否是完整 IP 还是只是最后一段
	var endIP net.IP
	if strings.Contains(endPart, ".") {
		// 完整 IP: 192.168.1.1-192.168.1.100
		endIP = net.ParseIP(endPart)
		if endIP == nil {
			return nil, fmt.Errorf("无效的结束 IP: %s", endPart)
		}
		endIP = endIP.To4()
	} else {
		// 只有最后一段: 192.168.1.1-100
		endNum, err := strconv.Atoi(endPart)
		if err != nil || endNum < 0 || endNum > 255 {
			return nil, fmt.Errorf("无效的结束值: %s", endPart)
		}
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(endNum)
	}

	// 生成 IP 列表
	var ips []string
	for ip := copyIP(startIP); compareIP(ip, endIP) <= 0; incrementIP(ip) {
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// ParsePorts 解析端口字符串
// 支持格式:
//   - 单个端口: 10250
//   - 端口列表: 10250,10255,6443
//   - 端口范围: 10250-10260
func ParsePorts(portStr string) ([]int, error) {
	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return nil, fmt.Errorf("端口不能为空")
	}

	var ports []int
	seen := make(map[int]bool)

	// 按逗号分割
	parts := strings.Split(portStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否是范围
		if strings.Contains(part, "-") {
			rangePorts, err := parsePortRange(part)
			if err != nil {
				return nil, err
			}
			for _, p := range rangePorts {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			// 单个端口
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("无效的端口: %s", part)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("没有有效的端口")
	}

	return ports, nil
}

// parsePortRange 解析端口范围
func parsePortRange(rangeStr string) ([]int, error) {
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的端口范围: %s", rangeStr)
	}

	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || start < 1 || start > 65535 {
		return nil, fmt.Errorf("无效的起始端口: %s", parts[0])
	}

	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || end < 1 || end > 65535 {
		return nil, fmt.Errorf("无效的结束端口: %s", parts[1])
	}

	if start > end {
		return nil, fmt.Errorf("起始端口不能大于结束端口: %d > %d", start, end)
	}

	var ports []int
	for p := start; p <= end; p++ {
		ports = append(ports, p)
	}

	return ports, nil
}

// incrementIP 递增 IP 地址
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// copyIP 复制 IP 地址
func copyIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// compareIP 比较两个 IP 地址
func compareIP(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
