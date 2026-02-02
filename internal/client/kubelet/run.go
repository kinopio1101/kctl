package kubelet

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"kctl/pkg/types"
)

// Run 通过 /run API 在 Pod 中执行命令
func (c *kubeletClient) Run(ctx context.Context, opts *types.RunOptions) (*types.RunResult, error) {
	// 构建 run URL
	runURL := c.buildRunURL(opts)

	// 构建请求体
	data := url.Values{}
	data.Set("cmd", opts.Command)

	// 创建 POST 请求
	req, err := http.NewRequestWithContext(ctx, "POST", runURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置请求头
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 发送请求
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求 Kubelet /run API 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	result := &types.RunResult{}

	// 检查响应状态
	switch resp.StatusCode {
	case http.StatusOK:
		result.Output = string(body)
	case http.StatusUnauthorized:
		result.Error = "认证失败：Token 无效或无权限访问 Kubelet API"
	case http.StatusForbidden:
		result.Error = "权限被拒绝：Token 无权访问 /run 端点"
	case http.StatusNotFound:
		result.Error = fmt.Sprintf("Pod 或容器不存在: %s/%s/%s", opts.Namespace, opts.Pod, opts.Container)
	default:
		result.Error = fmt.Sprintf("Kubelet API 返回错误 (HTTP %d): %s", resp.StatusCode, string(body))
	}

	return result, nil
}

// buildRunURL 构建 /run API URL
func (c *kubeletClient) buildRunURL(opts *types.RunOptions) string {
	return fmt.Sprintf("%s/run/%s/%s/%s",
		c.baseURL(), opts.Namespace, opts.Pod, opts.Container)
}
