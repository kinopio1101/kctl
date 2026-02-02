package kubelet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"kctl/internal/client"
	"kctl/pkg/types"
)

// Client Kubelet API 客户端接口
type Client interface {
	// Pod 操作
	GetPods(ctx context.Context) (*types.KubeletPodsResponse, error)
	GetPodsRaw(ctx context.Context) ([]byte, error)
	GetPodsWithContainers(ctx context.Context) ([]types.PodContainerInfo, error)

	// 命令执行
	Exec(ctx context.Context, opts *types.ExecOptions) (*types.ExecResult, error)
	ExecInteractive(ctx context.Context, opts *types.ExecOptions) error
	Run(ctx context.Context, opts *types.RunOptions) (*types.RunResult, error)

	// 端口转发
	PortForward(ctx context.Context, opts *types.PortForwardOptions, stopChan <-chan struct{}) error

	// 健康检查
	ValidatePort(ctx context.Context) (*types.ProbeResult, error)
}

// kubeletClient Kubelet 客户端实现
type kubeletClient struct {
	ip         string
	port       int
	token      string
	httpClient *http.Client
	wsDialer   *websocket.Dialer
	config     *client.Config
}

// NewClient 创建 Kubelet 客户端
func NewClient(ip string, port int, token string, cfg *client.Config) (Client, error) {
	if cfg == nil {
		cfg = client.DefaultConfig()
	}

	httpClient, err := client.NewHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 HTTP 客户端失败: %w", err)
	}

	wsDialer, err := client.NewWebSocketDialer(cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 WebSocket 拨号器失败: %w", err)
	}

	return &kubeletClient{
		ip:         ip,
		port:       port,
		token:      token,
		httpClient: httpClient,
		wsDialer:   wsDialer,
		config:     cfg,
	}, nil
}

// baseURL 返回基础 URL
func (c *kubeletClient) baseURL() string {
	return fmt.Sprintf("https://%s:%d", c.ip, c.port)
}

// authHeader 返回认证头
func (c *kubeletClient) authHeader() string {
	return fmt.Sprintf("Bearer %s", c.token)
}

// GetPods 获取 Pod 列表
func (c *kubeletClient) GetPods(ctx context.Context) (*types.KubeletPodsResponse, error) {
	raw, err := c.GetPodsRaw(ctx)
	if err != nil {
		return nil, err
	}

	var response types.KubeletPodsResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	return &response, nil
}

// GetPodsRaw 获取原始 Pod 数据
func (c *kubeletClient) GetPodsRaw(ctx context.Context) ([]byte, error) {
	url := c.baseURL() + "/pods"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", c.authHeader())

	resp, err := c.httpClient.Do(req)
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

	return io.ReadAll(resp.Body)
}

// GetPodsWithContainers 获取 Pod 及容器信息
func (c *kubeletClient) GetPodsWithContainers(ctx context.Context) ([]types.PodContainerInfo, error) {
	response, err := c.GetPods(ctx)
	if err != nil {
		return nil, err
	}

	var result []types.PodContainerInfo
	for _, item := range response.Items {
		info := types.PodContainerInfo{
			Namespace:      item.Metadata.Namespace,
			PodName:        item.Metadata.Name,
			UID:            item.Metadata.UID,
			Status:         item.Status.Phase,
			PodIP:          item.Status.PodIP,
			HostIP:         item.Status.HostIP,
			NodeName:       item.Spec.NodeName,
			ServiceAccount: item.Spec.ServiceAccount,
			CreatedAt:      item.Metadata.CreationTimestamp,
		}

		// 构建 Volume 映射表（用于查找挂载源）
		volumeMap := make(map[string]types.VolumeDetail)
		for _, vol := range item.Spec.Volumes {
			vd := types.VolumeDetail{Name: vol.Name}
			if vol.HostPath != nil {
				vd.Type = "hostPath"
				vd.Source = vol.HostPath.Path
				info.SecurityFlags.HasHostPath = true
			} else if vol.Secret != nil {
				vd.Type = "secret"
				vd.Source = vol.Secret.SecretName
				info.SecurityFlags.HasSecretMount = true
			} else {
				vd.Type = "other"
			}
			volumeMap[vol.Name] = vd
			info.Volumes = append(info.Volumes, vd)
		}

		// 构建容器状态映射
		containerStatusMap := make(map[string]struct {
			Ready     bool
			State     string
			StartedAt string
		})
		for _, cs := range item.Status.ContainerStatuses {
			status := struct {
				Ready     bool
				State     string
				StartedAt string
			}{Ready: cs.Ready}
			if cs.State.Running != nil {
				status.State = "Running"
				status.StartedAt = cs.State.Running.StartedAt
			} else if cs.State.Waiting != nil {
				status.State = "Waiting: " + cs.State.Waiting.Reason
			} else if cs.State.Terminated != nil {
				status.State = "Terminated: " + cs.State.Terminated.Reason
			}
			containerStatusMap[cs.Name] = status
		}

		// 解析容器信息
		for _, container := range item.Spec.Containers {
			cd := types.ContainerDetail{
				Name:  container.Name,
				Image: container.Image,
			}

			// 获取容器状态
			if cs, ok := containerStatusMap[container.Name]; ok {
				cd.Ready = cs.Ready
				cd.State = cs.State
				cd.StartedAt = cs.StartedAt
			}

			// 检查安全上下文
			if container.SecurityContext != nil {
				if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
					cd.Privileged = true
					info.SecurityFlags.Privileged = true
				}
				if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
					cd.AllowPE = true
					info.SecurityFlags.AllowPrivilegeEscalation = true
				}
			}

			// 解析 Volume 挂载
			for _, vm := range container.VolumeMounts {
				vmd := types.VolumeMountDetail{
					Name:      vm.Name,
					MountPath: vm.MountPath,
					ReadOnly:  vm.ReadOnly,
				}

				// 查找对应的 Volume 定义
				if vd, ok := volumeMap[vm.Name]; ok {
					vmd.Type = vd.Type
					vmd.Source = vd.Source
				}

				cd.VolumeMounts = append(cd.VolumeMounts, vmd)

				// 检查是否挂载了 SA Token 路径
				if strings.HasPrefix(vm.MountPath, "/var/run/secrets/kubernetes.io/serviceaccount") {
					info.SecurityFlags.HasSATokenMount = true
				}
			}

			info.Containers = append(info.Containers, cd)
		}

		result = append(result, info)
	}

	return result, nil
}

// ValidatePort 验证 Kubelet 端口
func (c *kubeletClient) ValidatePort(ctx context.Context) (*types.ProbeResult, error) {
	result := &types.ProbeResult{
		IP:   c.ip,
		Port: c.port,
	}

	// 尝试访问 /healthz 端点
	healthzURL := c.baseURL() + "/healthz"
	req, err := http.NewRequestWithContext(ctx, "GET", healthzURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("创建请求失败: %w", err)
		return result, nil
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		result.Reachable = false
		result.Error = err
		return result, nil
	}
	defer func() { _ = resp.Body.Close() }()

	result.Reachable = true

	// /healthz 返回 200 或 401 都说明是 Kubelet
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized {
		result.IsKubelet = true
		result.HealthPath = "/healthz"
		return result, nil
	}

	// 尝试使用 Token 访问 /pods 端点
	podsURL := c.baseURL() + "/pods"
	req, err = http.NewRequestWithContext(ctx, "GET", podsURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("创建请求失败: %w", err)
		return result, nil
	}

	req.Header.Set("Authorization", c.authHeader())

	resp, err = c.httpClient.Do(req)
	if err != nil {
		result.Error = err
		return result, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// 200, 401, 403 都说明是 Kubelet 端点
	if resp.StatusCode == http.StatusOK ||
		resp.StatusCode == http.StatusUnauthorized ||
		resp.StatusCode == http.StatusForbidden {
		result.IsKubelet = true
		result.HealthPath = "/pods"
		return result, nil
	}

	result.IsKubelet = false
	result.Error = fmt.Errorf("端口响应不像是 Kubelet")
	return result, nil
}
