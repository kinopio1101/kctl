package kubelet

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// 默认 Token 文件路径
const DefaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// 默认 K8s API Server 地址
const DefaultK8sAPIServer = "https://kubernetes.default.svc"

// TokenInfo 表示解析后的 Token 信息
type TokenInfo struct {
	ServiceAccount string
	Namespace      string
	Issuer         string
	Expiration     time.Time
	IsExpired      bool
}

// PermissionCheck 表示权限检查结果
type PermissionCheck struct {
	Resource    string
	Verb        string
	Allowed     bool
	Group       string // API Group (e.g., "", "apps", "rbac.authorization.k8s.io")
	Subresource string // 子资源 (e.g., "proxy", "exec", "log")
}

// GetDefaultTokenPath 返回默认的 Token 文件路径
func GetDefaultTokenPath() string {
	return DefaultTokenPath
}

// ReadToken 从指定路径读取 Token
func ReadToken(path string) (string, error) {
	if path == "" {
		path = DefaultTokenPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取 Token 文件失败: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token 文件为空")
	}

	return token, nil
}

// ParseTokenInfo 解析 JWT Token 获取基本信息
func ParseTokenInfo(token string) (*TokenInfo, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("无效的 JWT Token 格式")
	}

	// 解码 payload（第二部分）
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// 尝试标准 base64 解码
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, fmt.Errorf("解码 Token payload 失败: %w", err)
		}
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("解析 Token claims 失败: %w", err)
	}

	info := &TokenInfo{}

	// 提取 issuer
	if iss, ok := claims["iss"].(string); ok {
		info.Issuer = iss
	}

	// 提取过期时间
	if exp, ok := claims["exp"].(float64); ok {
		info.Expiration = time.Unix(int64(exp), 0)
		info.IsExpired = time.Now().After(info.Expiration)
	}

	// 提取 Kubernetes ServiceAccount 信息
	// 格式可能是 kubernetes.io 的标准格式
	if k8s, ok := claims["kubernetes.io"].(map[string]interface{}); ok {
		if ns, ok := k8s["namespace"].(string); ok {
			info.Namespace = ns
		}
		if sa, ok := k8s["serviceaccount"].(map[string]interface{}); ok {
			if name, ok := sa["name"].(string); ok {
				info.ServiceAccount = name
			}
		}
	}

	// 备用：从 sub 字段提取
	if info.ServiceAccount == "" {
		if sub, ok := claims["sub"].(string); ok {
			// 格式: system:serviceaccount:namespace:name
			parts := strings.Split(sub, ":")
			if len(parts) >= 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
				info.Namespace = parts[2]
				info.ServiceAccount = parts[3]
			}
		}
	}

	return info, nil
}

// SelfSubjectAccessReview 请求结构
type SelfSubjectAccessReviewRequest struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       string                  `json:"kind"`
	Spec       AccessReviewRequestSpec `json:"spec"`
}

type AccessReviewRequestSpec struct {
	ResourceAttributes *ResourceAttributes `json:"resourceAttributes,omitempty"`
}

type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	Verb        string `json:"verb"`
	Group       string `json:"group,omitempty"`
	Resource    string `json:"resource"`
	Subresource string `json:"subresource,omitempty"`
}

// SelfSubjectAccessReview 响应结构
type SelfSubjectAccessReviewResponse struct {
	Status AccessReviewStatus `json:"status"`
}

type AccessReviewStatus struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// CheckPermission 通过 K8s API Server 检查单个权限
func CheckPermission(token, apiServer, resource, verb, namespace, group, subresource string) (bool, error) {
	if apiServer == "" {
		apiServer = DefaultK8sAPIServer
	}

	// 构建请求
	request := SelfSubjectAccessReviewRequest{
		APIVersion: "authorization.k8s.io/v1",
		Kind:       "SelfSubjectAccessReview",
		Spec: AccessReviewRequestSpec{
			ResourceAttributes: &ResourceAttributes{
				Namespace:   namespace,
				Verb:        verb,
				Group:       group,
				Resource:    resource,
				Subresource: subresource,
			},
		},
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return false, fmt.Errorf("序列化请求失败: %w", err)
	}

	// 创建 HTTP 客户端（跳过 TLS 验证）
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// 发送请求
	url := fmt.Sprintf("%s/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", apiServer)
	req, err := http.NewRequest("POST", url, bytes.NewReader(requestBody))
	if err != nil {
		return false, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("请求 K8s API Server 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("K8s API Server 返回错误状态: %d", resp.StatusCode)
	}

	var response SelfSubjectAccessReviewResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return false, fmt.Errorf("解析响应失败: %w", err)
	}

	return response.Status.Allowed, nil
}

// CheckCommonPermissions 检查常用资源的权限
// 权限列表从 permissions.go 中的 PermissionsToCheck 加载
func CheckCommonPermissions(token, apiServer, namespace string) ([]PermissionCheck, error) {
	var results []PermissionCheck

	for _, check := range PermissionsToCheck {
		allowed, err := CheckPermission(token, apiServer, check.Resource, check.Verb, namespace, check.Group, check.Subresource)
		if err != nil {
			// 记录错误但继续检查其他权限
			results = append(results, PermissionCheck{
				Resource:    check.Resource,
				Verb:        check.Verb,
				Group:       check.Group,
				Subresource: check.Subresource,
				Allowed:     false,
			})
			continue
		}

		results = append(results, PermissionCheck{
			Resource:    check.Resource,
			Verb:        check.Verb,
			Group:       check.Group,
			Subresource: check.Subresource,
			Allowed:     allowed,
		})
	}

	return results, nil
}

// TruncateToken 截断 Token 用于显示
func TruncateToken(token string, maxLen int) string {
	if len(token) <= maxLen {
		return token
	}
	return token[:maxLen] + "..."
}
