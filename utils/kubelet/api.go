package kubelet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// PodInfo 表示从 Kubelet API 获取的 Pod 基本信息
type PodInfo struct {
	Name      string
	Namespace string
	Status    string
	PodIP     string
	NodeName  string
}

// SecurityContext 容器安全上下文
type SecurityContext struct {
	Privileged               *bool `json:"privileged"`
	AllowPrivilegeEscalation *bool `json:"allowPrivilegeEscalation"`
	RunAsRoot                bool  `json:"runAsNonRoot"` // 注意：这是 runAsNonRoot，取反表示可能以 root 运行
}

// VolumeMount 卷挂载信息
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}

// Volume Pod 卷定义
type Volume struct {
	Name     string `json:"name"`
	HostPath *struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"hostPath"`
	Secret *struct {
		SecretName string `json:"secretName"`
	} `json:"secret"`
}

// KubeletPodsResponse 表示 Kubelet /pods API 的响应结构
type KubeletPodsResponse struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Items      []struct {
		Metadata struct {
			Name              string `json:"name"`
			Namespace         string `json:"namespace"`
			UID               string `json:"uid"`
			CreationTimestamp string `json:"creationTimestamp"`
		} `json:"metadata"`
		Spec struct {
			NodeName       string `json:"nodeName"`
			ServiceAccount string `json:"serviceAccountName"`
			Containers     []struct {
				Name            string           `json:"name"`
				Image           string           `json:"image"`
				SecurityContext *SecurityContext `json:"securityContext"`
				VolumeMounts    []VolumeMount    `json:"volumeMounts"`
			} `json:"containers"`
			Volumes []Volume `json:"volumes"`
		} `json:"spec"`
		Status struct {
			Phase             string `json:"phase"`
			PodIP             string `json:"podIP"`
			HostIP            string `json:"hostIP"`
			ContainerStatuses []struct {
				Name  string `json:"name"`
				Ready bool   `json:"ready"`
				State struct {
					Running *struct {
						StartedAt string `json:"startedAt"`
					} `json:"running"`
					Waiting *struct {
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"waiting"`
					Terminated *struct {
						Reason   string `json:"reason"`
						ExitCode int    `json:"exitCode"`
					} `json:"terminated"`
				} `json:"state"`
			} `json:"containerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// FetchPods 从 Kubelet API 获取 Pod 列表
func FetchPods(ip string, port int, token string) ([]PodInfo, error) {
	url := fmt.Sprintf("https://%s:%d/pods", ip, port)

	// 创建 HTTP 客户端（跳过 TLS 验证）
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Kubelet API 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("认证失败：Token 无效或无权限访问 Kubelet API")
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("权限被拒绝：Token 无权访问 /pods 端点")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kubelet API 返回错误 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var response KubeletPodsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析 API 响应失败: %w", err)
	}

	var pods []PodInfo
	for _, item := range response.Items {
		pods = append(pods, PodInfo{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Status:    item.Status.Phase,
			PodIP:     item.Status.PodIP,
			NodeName:  item.Spec.NodeName,
		})
	}

	return pods, nil
}

// FetchPodsRaw 获取原始 JSON 响应
func FetchPodsRaw(ip string, port int, token string) ([]byte, error) {
	url := fmt.Sprintf("https://%s:%d/pods", ip, port)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Kubelet API 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kubelet API 返回错误 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// FetchPodsWithProxy 通过 SOCKS5 代理从 Kubelet API 获取 Pod 列表
func FetchPodsWithProxy(ip string, port int, token string, proxyURL string) ([]PodInfo, error) {
	client, err := createProxyClient(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("创建代理客户端失败: %w", err)
	}

	return fetchPodsClient(client, ip, port, token)
}

// FetchPodsRawWithProxy 通过 SOCKS5 代理获取原始 JSON 响应
func FetchPodsRawWithProxy(ip string, port int, token string, proxyURL string) ([]byte, error) {
	client, err := createProxyClient(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("创建代理客户端失败: %w", err)
	}

	return fetchPodsRawClient(client, ip, port, token)
}

// createProxyClient 创建支持代理的 HTTP 客户端
func createProxyClient(proxyURL string) (*http.Client, error) {
	if proxyURL == "" {
		// 没有配置代理，使用默认客户端
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}, nil
	}

	// 解析代理 URL
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("解析代理 URL 失败: %w", err)
	}

	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("不支持的代理协议: %s，仅支持 socks5 或 socks5h", u.Scheme)
	}

	// 创建 SOCKS5 代理
	dialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 代理失败: %w", err)
	}

	// 创建自定义 Transport
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// fetchPodsClient 使用指定的客户端获取 Pod 列表
func fetchPodsClient(client *http.Client, ip string, port int, token string) ([]PodInfo, error) {
	url := fmt.Sprintf("https://%s:%d/pods", ip, port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Kubelet API 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("认证失败：Token 无效或无权限访问 Kubelet API")
	}

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("权限被拒绝：Token 无权访问 /pods 端点")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kubelet API 返回错误 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var response KubeletPodsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析 API 响应失败: %w", err)
	}

	var pods []PodInfo
	for _, item := range response.Items {
		pods = append(pods, PodInfo{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Status:    item.Status.Phase,
			PodIP:     item.Status.PodIP,
			NodeName:  item.Spec.NodeName,
		})
	}

	return pods, nil
}

// fetchPodsRawClient 使用指定的客户端获取原始 JSON 响应
func fetchPodsRawClient(client *http.Client, ip string, port int, token string) ([]byte, error) {
	url := fmt.Sprintf("https://%s:%d/pods", ip, port)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Kubelet API 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("kubelet API 返回错误 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}
