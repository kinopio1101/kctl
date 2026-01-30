package kubelet

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"kctl/utils/Print"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

// ExecStatus 表示 Kubernetes exec API 的状态响应
type ExecStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// ExecOptions 定义 exec 执行选项
type ExecOptions struct {
	IP        string
	Port      int
	Token     string
	Namespace string
	Pod       string
	Container string
	Command   []string
	Stdin     bool
	Stdout    bool
	Stderr    bool
	TTY       bool
}

// K8s WebSocket 子协议通道编号
const (
	StreamStdin  = 0 // stdin 通道
	StreamStdout = 1 // stdout 通道
	StreamStderr = 2 // stderr 通道
	StreamError  = 3 // error 通道
	StreamResize = 4 // resize 通道 (TTY)
)

// ExecResult 表示 exec 执行结果
type ExecResult struct {
	Stdout string
	Stderr string
	Error  string
}

// SecurityFlags 安全标识
type SecurityFlags struct {
	Privileged               bool // 特权容器
	AllowPrivilegeEscalation bool // 允许权限提升
	HasHostPath              bool // 挂载了 HostPath
	HasSecretMount           bool // 挂载了 Secret
	HasSATokenMount          bool // 挂载了 ServiceAccount Token (/var/run/secrets/kubernetes.io/serviceaccount)
}

// PodContainerInfo 表示 Pod 和容器信息，用于交互式选择
type PodContainerInfo struct {
	Namespace     string
	PodName       string
	Containers    []string
	Status        string
	PodIP         string
	SecurityFlags SecurityFlags // 安全标识
}

// FetchPodsWithContainers 获取 Pod 列表及其容器信息
func FetchPodsWithContainers(ip string, port int, token string) ([]PodContainerInfo, error) {
	apiURL := fmt.Sprintf("https://%s:%d/pods", ip, port)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", apiURL, nil)
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
		return nil, fmt.Errorf("kubelet API 返回错误 (HTTP %d)", resp.StatusCode)
	}

	var response KubeletPodsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	var result []PodContainerInfo
	for _, item := range response.Items {
		info := PodContainerInfo{
			Namespace: item.Metadata.Namespace,
			PodName:   item.Metadata.Name,
			Status:    item.Status.Phase,
			PodIP:     item.Status.PodIP,
		}

		// 解析容器信息和安全上下文
		for _, c := range item.Spec.Containers {
			info.Containers = append(info.Containers, c.Name)

			// 检查安全上下文
			if c.SecurityContext != nil {
				if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					info.SecurityFlags.Privileged = true
				}
				if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
					info.SecurityFlags.AllowPrivilegeEscalation = true
				}
			}

			// 检查 Volume 挂载
			for _, vm := range c.VolumeMounts {
				// 检查是否挂载了 SA Token 路径
				if strings.HasPrefix(vm.MountPath, "/var/run/secrets/kubernetes.io/serviceaccount") {
					info.SecurityFlags.HasSATokenMount = true
				}

				// 查找对应的 Volume 定义
				for _, vol := range item.Spec.Volumes {
					if vol.Name == vm.Name {
						if vol.HostPath != nil {
							info.SecurityFlags.HasHostPath = true
						}
						if vol.Secret != nil {
							info.SecurityFlags.HasSecretMount = true
						}
					}
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// ExecInPod 在 Pod 中执行命令（非交互式）
func ExecInPod(opts *ExecOptions) (*ExecResult, error) {
	// 构建 exec URL
	execURL := buildExecURL(opts)

	// 创建 WebSocket dialer
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Subprotocols:    []string{"v4.channel.k8s.io"},
	}

	// 设置请求头
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Bearer %s", opts.Token))

	// 建立 WebSocket 连接
	conn, resp, err := dialer.Dial(execURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("WebSocket 连接失败 (HTTP %d): %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("WebSocket 连接失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	result := &ExecResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 读取 WebSocket 消息
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					mu.Lock()
					if result.Error == "" && !strings.Contains(err.Error(), "close") {
						result.Error = err.Error()
					}
					mu.Unlock()
				}
				return
			}

			if len(message) < 1 {
				continue
			}

			// 第一个字节是通道编号
			channel := message[0]
			data := string(message[1:])

			mu.Lock()
			switch channel {
			case StreamStdout:
				result.Stdout += data
			case StreamStderr:
				result.Stderr += data
			case StreamError:
				// 解析 exec 状态响应
				var execStatus ExecStatus
				if err := json.Unmarshal([]byte(data), &execStatus); err == nil {
					// 只有当 status 不是 Success 时才认为是错误
					if execStatus.Status != "Success" {
						result.Error = execStatus.Message
						if result.Error == "" {
							result.Error = data
						}
					}
					// status == "Success" 时不设置错误
				} else {
					// 无法解析为 JSON，作为原始错误处理
					result.Error = data
				}
			}
			mu.Unlock()
		}
	}()

	wg.Wait()
	return result, nil
}

// ExecInPodInteractive 在 Pod 中交互式执行命令
func ExecInPodInteractive(opts *ExecOptions) error {
	// 构建 exec URL
	execURL := buildExecURL(opts)

	// 创建 WebSocket dialer
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Subprotocols:    []string{"v4.channel.k8s.io"},
	}

	// 设置请求头
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Bearer %s", opts.Token))

	// 建立 WebSocket 连接
	conn, resp, err := dialer.Dial(execURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("WebSocket 连接失败 (HTTP %d): %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("WebSocket 连接失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// 如果启用了 TTY，将终端设置为 raw 模式
	// 这样可以正确处理控制字符和转义序列
	if opts.TTY {
		fd := int(os.Stdin.Fd())
		if term.IsTerminal(fd) {
			oldState, err := term.MakeRaw(fd)
			if err != nil {
				return fmt.Errorf("设置终端 raw 模式失败: %w", err)
			}
			defer func() { _ = term.Restore(fd, oldState) }()
		}
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// 读取输出
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				_, message, err := conn.ReadMessage()
				if err != nil {
					return
				}

				if len(message) < 1 {
					continue
				}

				channel := message[0]
				data := message[1:]

				switch channel {
				case StreamStdout:
					_, _ = os.Stdout.Write(data)
				case StreamStderr:
					_, _ = os.Stderr.Write(data)
				case StreamError:
					fmt.Fprintf(os.Stderr, "\n[Error] %s\n", string(data))
				}
			}
		}
	}()

	// 如果启用了 stdin，从标准输入读取
	if opts.Stdin {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1024)
			for {
				select {
				case <-done:
					return
				default:
					n, err := os.Stdin.Read(buf)
					if err != nil {
						if err != io.EOF {
							return
						}
						return
					}
					if n > 0 {
						// 发送数据，第一个字节是通道编号 (stdin = 0)
						msg := append([]byte{StreamStdin}, buf[:n]...)
						if err := conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
							return
						}
					}
				}
			}
		}()
	}

	wg.Wait()
	return nil
}

// buildExecURL 构建 exec WebSocket URL
func buildExecURL(opts *ExecOptions) string {
	// 基础 URL
	baseURL := fmt.Sprintf("wss://%s:%d/exec/%s/%s/%s",
		opts.IP, opts.Port, opts.Namespace, opts.Pod, opts.Container)

	// 构建查询参数
	// 注意: Kubelet API 使用 input/output/error 而不是 stdin/stdout/stderr
	params := url.Values{}

	if opts.Stdin {
		params.Add("input", "1")
	}
	if opts.Stdout {
		params.Add("output", "1")
	}
	if opts.Stderr {
		params.Add("error", "1")
	}
	if opts.TTY {
		params.Add("tty", "1")
	}

	// 添加命令参数
	for _, cmd := range opts.Command {
		params.Add("command", cmd)
	}

	return baseURL + "?" + params.Encode()
}

// SelectPodInteractive 交互式选择 Pod
func SelectPodInteractive(pods []PodContainerInfo, reader *bufio.Reader) (*PodContainerInfo, error) {
	if len(pods) == 0 {
		return nil, fmt.Errorf("没有可用的 Pod")
	}

	Print.PrintSection("可用的 Pod 列表")

	for i, pod := range pods {
		details := map[string]string{
			"Containers": strings.Join(pod.Containers, ", "),
		}
		if pod.PodIP != "" {
			details["PodIP"] = pod.PodIP
		}

		Print.PrintListItem(Print.ListItem{
			Index:    i + 1,
			Status:   pod.Status,
			Title:    pod.PodName,
			Subtitle: pod.Namespace,
			Details:  details,
		})
	}
	Print.PrintSeparator()

	Print.PrintPrompt("\n请选择 Pod (输入编号): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	input = strings.TrimSpace(input)
	var idx int
	if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > len(pods) {
		return nil, fmt.Errorf("无效的选择: %s", input)
	}

	return &pods[idx-1], nil
}

// SelectContainerInteractive 交互式选择容器
func SelectContainerInteractive(pod *PodContainerInfo, reader *bufio.Reader) (string, error) {
	if len(pod.Containers) == 0 {
		return "", fmt.Errorf("pod %s 没有容器", pod.PodName)
	}

	// 如果只有一个容器，直接返回
	if len(pod.Containers) == 1 {
		Print.PrintSuccess(fmt.Sprintf("自动选择唯一容器: %s", pod.Containers[0]))
		return pod.Containers[0], nil
	}

	Print.PrintSubSection(fmt.Sprintf("Pod %s/%s 的容器列表", pod.Namespace, pod.PodName))
	for i, c := range pod.Containers {
		fmt.Printf("  %d. %s\n", i+1, c)
	}

	Print.PrintPrompt("\n请选择容器 (输入编号): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	input = strings.TrimSpace(input)
	var idx int
	if _, err := fmt.Sscanf(input, "%d", &idx); err != nil || idx < 1 || idx > len(pod.Containers) {
		return "", fmt.Errorf("无效的选择: %s", input)
	}

	return pod.Containers[idx-1], nil
}

// FetchPodsWithContainersProxy 通过 SOCKS5 代理获取 Pod 列表及其容器信息
func FetchPodsWithContainersProxy(ip string, port int, token string, proxyURL string) ([]PodContainerInfo, error) {
	client, err := createProxyHTTPClient(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("创建代理客户端失败: %w", err)
	}

	return fetchPodsWithContainersClient(client, ip, port, token)
}

// ExecInPodProxy 通过 SOCKS5 代理在 Pod 中执行命令
func ExecInPodProxy(opts *ExecOptions, proxyURL string) (*ExecResult, error) {
	// 构建 exec URL
	execURL := buildExecURL(opts)

	// 创建 WebSocket dialer
	dialer, err := createProxyWebSocketDialer(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("创建代理 WebSocket dialer 失败: %w", err)
	}

	// 设置请求头
	headers := http.Header{}
	headers.Set("Authorization", fmt.Sprintf("Bearer %s", opts.Token))

	// 建立 WebSocket 连接
	conn, resp, err := dialer.Dial(execURL, headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("WebSocket 连接失败 (HTTP %d): %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("WebSocket 连接失败: %w", err)
	}
	defer func() { _ = conn.Close() }()

	result := &ExecResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 读取 WebSocket 消息
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					mu.Lock()
					if result.Error == "" && !strings.Contains(err.Error(), "close") {
						result.Error = err.Error()
					}
					mu.Unlock()
				}
				return
			}

			if len(message) < 1 {
				continue
			}

			// 第一个字节是通道编号
			channel := message[0]
			data := string(message[1:])

			mu.Lock()
			switch channel {
			case StreamStdout:
				result.Stdout += data
			case StreamStderr:
				result.Stderr += data
			case StreamError:
				// 解析 exec 状态响应
				var execStatus ExecStatus
				if err := json.Unmarshal([]byte(data), &execStatus); err == nil {
					// 只有当 status 不是 Success 时才认为是错误
					if execStatus.Status != "Success" {
						result.Error = execStatus.Message
						if result.Error == "" {
							result.Error = data
						}
					}
					// status == "Success" 时不设置错误
				} else {
					// 无法解析为 JSON，作为原始错误处理
					result.Error = data
				}
			}
			mu.Unlock()
		}
	}()

	wg.Wait()
	return result, nil
}

// createProxyHTTPClient 创建支持代理的 HTTP 客户端
func createProxyHTTPClient(proxyURL string) (*http.Client, error) {
	if proxyURL == "" {
		// 没有配置代理，使用默认客户端
		return &http.Client{
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
	socksDialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 代理失败: %w", err)
	}

	// 创建自定义 Transport
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

// createProxyWebSocketDialer 创建支持代理的 WebSocket dialer
func createProxyWebSocketDialer(proxyURL string) (*websocket.Dialer, error) {
	if proxyURL == "" {
		// 没有配置代理，使用默认 dialer
		return &websocket.Dialer{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Subprotocols:    []string{"v4.channel.k8s.io"},
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
	socksDialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 代理失败: %w", err)
	}

	// 创建自定义 WebSocket dialer
	return &websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Subprotocols:    []string{"v4.channel.k8s.io"},
		NetDial: func(network, addr string) (net.Conn, error) {
			return socksDialer.Dial(network, addr)
		},
		HandshakeTimeout: 30 * time.Second,
	}, nil
}

// fetchPodsWithContainersClient 使用指定的客户端获取 Pod 列表及其容器信息
func fetchPodsWithContainersClient(client *http.Client, ip string, port int, token string) ([]PodContainerInfo, error) {
	apiURL := fmt.Sprintf("https://%s:%d/pods", ip, port)

	req, err := http.NewRequest("GET", apiURL, nil)
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
		return nil, fmt.Errorf("kubelet API 返回错误 (HTTP %d)", resp.StatusCode)
	}

	var response KubeletPodsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	var result []PodContainerInfo
	for _, item := range response.Items {
		info := PodContainerInfo{
			Namespace: item.Metadata.Namespace,
			PodName:   item.Metadata.Name,
			Status:    item.Status.Phase,
			PodIP:     item.Status.PodIP,
		}

		// 解析容器信息和安全上下文
		for _, c := range item.Spec.Containers {
			info.Containers = append(info.Containers, c.Name)

			// 检查安全上下文
			if c.SecurityContext != nil {
				if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					info.SecurityFlags.Privileged = true
				}
				if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
					info.SecurityFlags.AllowPrivilegeEscalation = true
				}
			}

			// 检查 Volume 挂载
			for _, vm := range c.VolumeMounts {
				// 检查是否挂载了 SA Token 路径
				if strings.HasPrefix(vm.MountPath, "/var/run/secrets/kubernetes.io/serviceaccount") {
					info.SecurityFlags.HasSATokenMount = true
				}

				// 查找对应的 Volume 定义
				for _, vol := range item.Spec.Volumes {
					if vol.Name == vm.Name {
						if vol.HostPath != nil {
							info.SecurityFlags.HasHostPath = true
						}
						if vol.Secret != nil {
							info.SecurityFlags.HasSecretMount = true
						}
					}
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}
