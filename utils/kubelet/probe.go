package kubelet

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ProbeResult 表示端口探测结果
type ProbeResult struct {
	IP         string
	Port       int
	Reachable  bool
	IsKubelet  bool
	HealthPath string
	Error      error
}

// ProbePort 测试指定 IP:Port 的 TCP 连通性
func ProbePort(ip string, port int, timeout time.Duration) *ProbeResult {
	result := &ProbeResult{
		IP:   ip,
		Port: port,
	}

	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Reachable = false
		result.Error = err
		return result
	}
	defer func() { _ = conn.Close() }()

	result.Reachable = true
	return result
}

// ValidateKubeletPort 验证指定端口是否为有效的 Kubelet 端口
// 通过访问 /healthz 或 /pods 端点来验证
func ValidateKubeletPort(ip string, port int, token string, timeout time.Duration) *ProbeResult {
	result := &ProbeResult{
		IP:   ip,
		Port: port,
	}

	// 首先测试 TCP 连通性
	address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Reachable = false
		result.Error = fmt.Errorf("TCP 连接失败: %w", err)
		return result
	}
	_ = conn.Close()
	result.Reachable = true

	// 创建 HTTP 客户端（跳过 TLS 验证）
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 尝试访问 /healthz 端点（通常不需要认证）
	healthzURL := fmt.Sprintf("https://%s:%d/healthz", ip, port)
	req, err := http.NewRequest("GET", healthzURL, nil)
	if err != nil {
		result.IsKubelet = false
		result.Error = fmt.Errorf("创建请求失败: %w", err)
		return result
	}

	resp, err := client.Do(req)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		// /healthz 返回 200 或 401（需要认证）都说明是 Kubelet
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
			result.IsKubelet = true
			result.HealthPath = "/healthz"
			return result
		}
	}

	// 尝试使用 Token 访问 /pods 端点
	if token != "" {
		podsURL := fmt.Sprintf("https://%s:%d/pods", ip, port)
		req, err = http.NewRequest("GET", podsURL, nil)
		if err != nil {
			result.IsKubelet = false
			result.Error = fmt.Errorf("创建请求失败: %w", err)
			return result
		}

		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

		resp, err = client.Do(req)
		if err == nil {
			defer func() { _ = resp.Body.Close() }()
			// 200, 401, 403 都说明是 Kubelet 端点
			if resp.StatusCode == http.StatusOK ||
				resp.StatusCode == http.StatusUnauthorized ||
				resp.StatusCode == http.StatusForbidden {
				result.IsKubelet = true
				result.HealthPath = "/pods"
				return result
			}
		}
	}

	// 无法确认是 Kubelet
	result.IsKubelet = false
	if err != nil {
		result.Error = fmt.Errorf("无法验证 Kubelet: %w", err)
	} else {
		result.Error = fmt.Errorf("端口响应不像是 Kubelet")
	}

	return result
}

// DefaultProbeTimeout 默认探测超时时间
const DefaultProbeTimeout = 5 * time.Second
