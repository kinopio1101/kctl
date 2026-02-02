package session

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"kctl/config"
	"kctl/internal/client"
	k8sclient "kctl/internal/client/k8s"
	kubeletclient "kctl/internal/client/kubelet"
	"kctl/internal/db"
	"kctl/internal/output"
	"kctl/internal/rbac"
	"kctl/internal/runtime"
	"kctl/pkg/network"
	"kctl/pkg/token"
	"kctl/pkg/types"
)

// SessionConfig 会话配置
type SessionConfig struct {
	// Kubelet 配置
	KubeletIP   string
	KubeletPort int

	// Token 配置
	Token     string
	TokenFile string

	// API Server 配置
	APIServer     string
	APIServerPort int

	// 代理配置
	ProxyURL string

	// 并发配置
	Concurrency int
}

// Session 会话状态
type Session struct {
	// 配置
	Config SessionConfig

	// 客户端（延迟初始化）
	kubeletClient kubeletclient.Client
	k8sClients    map[string]k8sclient.Client // token -> client 缓存
	clientConfig  *client.Config
	mu            sync.RWMutex

	// 内存数据库
	DB    *db.DB
	PodDB *db.PodRepository
	SADB  *db.ServiceAccountRepository

	// 当前选中的 SA
	CurrentSA *types.ServiceAccountRecord

	// 扫描结果缓存
	PodCache     []types.PodContainerInfo
	KubeletCache []types.KubeletNode // 发现的 Kubelet 节点缓存

	// 状态
	IsConnected  bool
	IsScanned    bool
	LastScanTime time.Time
	InPod        bool

	// 输出
	Printer output.Printer
}

// NewSession 创建新会话
func NewSession() (*Session, error) {
	// 打开内存数据库
	database, err := db.OpenMemory()
	if err != nil {
		return nil, fmt.Errorf("创建内存数据库失败: %w", err)
	}

	s := &Session{
		Config: SessionConfig{
			KubeletPort:   config.DefaultKubeletPort,
			APIServerPort: 443,
			Concurrency:   config.DefaultScanConcurrency,
		},
		k8sClients: make(map[string]k8sclient.Client),
		DB:         database,
		PodDB:      db.NewPodRepository(database),
		SADB:       db.NewServiceAccountRepository(database),
		InPod:      runtime.IsInPod(),
		Printer:    output.NewPrinter(),
	}

	// 从环境加载默认值
	s.loadFromEnv()

	return s, nil
}

// loadFromEnv 从 Pod 环境加载默认值
func (s *Session) loadFromEnv() {
	if s.InPod {
		// 自动获取 Kubelet IP（默认网关）
		if gw, err := network.GetDefaultGateway(); err == nil {
			s.Config.KubeletIP = gw
		}

		// 自动获取 Token
		if tokenStr, err := token.Read(config.DefaultTokenPath); err == nil {
			s.Config.Token = tokenStr
			s.Config.TokenFile = config.DefaultTokenPath
		}

		// API Server 配置
		if host := runtime.GetKubernetesServiceHost(); host != "" {
			s.Config.APIServer = host
		} else {
			s.Config.APIServer = "kubernetes.default.svc"
		}
	}
}

// Connect 连接到 Kubelet
func (s *Session) Connect() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.Config.KubeletIP == "" {
		return fmt.Errorf("未设置 Kubelet IP，请使用 'set target <ip>' 设置")
	}

	if s.Config.Token == "" {
		return fmt.Errorf("未设置 Token，请使用 'set token <token>' 或 'set token-file <path>' 设置")
	}

	// 创建客户端配置
	cfg := client.DefaultConfig()
	if s.Config.ProxyURL != "" {
		cfg = cfg.WithProxy(s.Config.ProxyURL)
	}
	s.clientConfig = cfg

	// 创建 Kubelet 客户端
	kubelet, err := kubeletclient.NewClient(
		s.Config.KubeletIP,
		s.Config.KubeletPort,
		s.Config.Token,
		cfg,
	)
	if err != nil {
		return fmt.Errorf("创建 Kubelet 客户端失败: %w", err)
	}

	s.kubeletClient = kubelet
	s.IsConnected = true

	return nil
}

// Disconnect 断开连接
func (s *Session) Disconnect() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.kubeletClient = nil
	s.IsConnected = false
}

// GetKubeletClient 获取 Kubelet 客户端（懒加载）
func (s *Session) GetKubeletClient() (kubeletclient.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果已连接，直接返回
	if s.IsConnected && s.kubeletClient != nil {
		return s.kubeletClient, nil
	}

	// 懒加载：自动连接
	if s.Config.KubeletIP == "" {
		return nil, fmt.Errorf("未设置 Kubelet IP，请使用 'set target <ip>' 设置")
	}

	if s.Config.Token == "" {
		return nil, fmt.Errorf("未设置 Token，请使用 'set token <token>' 或 'set token-file <path>' 设置")
	}

	// 创建客户端配置
	cfg := client.DefaultConfig()
	if s.Config.ProxyURL != "" {
		cfg = cfg.WithProxy(s.Config.ProxyURL)
	}
	s.clientConfig = cfg

	// 创建 Kubelet 客户端
	kubelet, err := kubeletclient.NewClient(
		s.Config.KubeletIP,
		s.Config.KubeletPort,
		s.Config.Token,
		cfg,
	)
	if err != nil {
		return nil, fmt.Errorf("创建 Kubelet 客户端失败: %w", err)
	}

	s.kubeletClient = kubelet
	s.IsConnected = true

	return s.kubeletClient, nil
}

// GetK8sClient 获取 K8s API 客户端（带缓存）
func (s *Session) GetK8sClient(tokenStr string) (k8sclient.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 检查缓存
	if client, ok := s.k8sClients[tokenStr]; ok {
		return client, nil
	}

	// 创建新客户端
	cfg := s.clientConfig
	if cfg == nil {
		cfg = client.DefaultConfig()
		if s.Config.ProxyURL != "" {
			cfg = cfg.WithProxy(s.Config.ProxyURL)
		}
	}

	k8s, err := k8sclient.NewClient("", tokenStr, cfg)
	if err != nil {
		return nil, fmt.Errorf("创建 K8s 客户端失败: %w", err)
	}

	// 缓存
	s.k8sClients[tokenStr] = k8s

	return k8s, nil
}

// GetClientConfig 获取客户端配置
func (s *Session) GetClientConfig() *client.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.clientConfig == nil {
		cfg := client.DefaultConfig()
		if s.Config.ProxyURL != "" {
			cfg = cfg.WithProxy(s.Config.ProxyURL)
		}
		return cfg
	}
	return s.clientConfig
}

// SetCurrentSA 设置当前选中的 SA
func (s *Session) SetCurrentSA(sa *types.ServiceAccountRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.CurrentSA = sa
}

// GetCurrentSA 获取当前选中的 SA
func (s *Session) GetCurrentSA() *types.ServiceAccountRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.CurrentSA
}

// GetPromptDisplay 返回提示符显示的内容
func (s *Session) GetPromptDisplay() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.CurrentSA == nil {
		return "default"
	}

	// 格式: namespace/name RISK
	display := fmt.Sprintf("%s/%s", s.CurrentSA.Namespace, s.CurrentSA.Name)

	risk := s.CurrentSA.RiskLevel
	if risk != "" && risk != string(config.RiskNone) {
		display = fmt.Sprintf("%s %s", display, risk)
	}

	return display
}

// CachePods 缓存 Pod 列表
func (s *Session) CachePods(pods []types.PodContainerInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PodCache = pods
}

// GetCachedPods 获取缓存的 Pod 列表
func (s *Session) GetCachedPods() []types.PodContainerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PodCache
}

// CacheKubelets 缓存发现的 Kubelet 节点
func (s *Session) CacheKubelets(nodes []types.KubeletNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.KubeletCache = nodes
}

// GetCachedKubelets 获取缓存的 Kubelet 节点
func (s *Session) GetCachedKubelets() []types.KubeletNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.KubeletCache
}

// MarkScanned 标记已扫描
func (s *Session) MarkScanned() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.IsScanned = true
	s.LastScanTime = time.Now()
}

// ClearCache 清除缓存
func (s *Session) ClearCache() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.PodCache = nil
	s.KubeletCache = nil
	s.CurrentSA = nil
	s.IsScanned = false
	s.k8sClients = make(map[string]k8sclient.Client)
}

// Close 关闭会话，清理资源
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 清理客户端缓存
	s.k8sClients = nil
	s.kubeletClient = nil

	// 关闭数据库
	if s.DB != nil {
		return s.DB.Close()
	}

	return nil
}

// GetModeString 获取运行模式字符串
func (s *Session) GetModeString() string {
	if s.InPod {
		return "In-Pod (Memory Database)"
	}
	return "Local (Memory Database)"
}

// SetupCurrentSA 解析当前 Token 并设置为当前 SA
func (s *Session) SetupCurrentSA() error {
	p := s.Printer
	ctx := context.Background()

	// 解析 Token 获取 SA 信息
	tokenInfo, err := token.Parse(s.Config.Token)
	if err != nil {
		return fmt.Errorf("无法解析 Token: %w", err)
	}

	if tokenInfo.ServiceAccount == "" || tokenInfo.Namespace == "" {
		return fmt.Errorf("Token 中未包含 ServiceAccount 信息")
	}

	// 创建 ServiceAccountRecord
	sa := &types.ServiceAccountRecord{
		Name:        tokenInfo.ServiceAccount,
		Namespace:   tokenInfo.Namespace,
		Token:       s.Config.Token,
		IsExpired:   tokenInfo.IsExpired,
		RiskLevel:   string(config.RiskNone),
		CollectedAt: time.Now(),
		KubeletIP:   s.Config.KubeletIP,
	}

	// 设置过期时间
	if !tokenInfo.Expiration.IsZero() {
		sa.TokenExpiration = tokenInfo.Expiration.Format(time.RFC3339)
	}

	p.Printf("%s Using ServiceAccount: %s/%s\n",
		p.Colored(config.ColorGreen, "[+]"),
		sa.Namespace, sa.Name)

	// 检查当前 SA 的权限
	p.Printf("%s Checking permissions...\n",
		p.Colored(config.ColorBlue, "[*]"))

	k8s, err := s.GetK8sClient(s.Config.Token)
	if err != nil {
		p.Warning(fmt.Sprintf("创建 K8s 客户端失败: %v", err))
		s.SetCurrentSA(sa)
		return nil
	}

	permissions, err := k8s.CheckCommonPermissions(ctx, tokenInfo.Namespace)
	if err != nil {
		p.Warning(fmt.Sprintf("检查权限失败: %v", err))
		s.SetCurrentSA(sa)
		return nil
	}

	// 检查是否是集群管理员
	isClusterAdmin := rbac.IsClusterAdmin(permissions)
	sa.IsClusterAdmin = isClusterAdmin

	// 计算风险等级
	if isClusterAdmin {
		sa.RiskLevel = string(config.RiskAdmin)
	} else {
		sa.RiskLevel = string(rbac.CalculateRiskLevel(permissions))
	}

	// 保存权限信息
	var permList []types.SAPermission
	for _, perm := range permissions {
		if perm.Allowed {
			permList = append(permList, types.SAPermission{
				Resource:    perm.Resource,
				Verb:        perm.Verb,
				Group:       perm.Group,
				Subresource: perm.Subresource,
				Allowed:     perm.Allowed,
			})
		}
	}
	permJSON, _ := json.Marshal(permList)
	sa.Permissions = string(permJSON)

	// 设置为当前 SA
	s.SetCurrentSA(sa)

	// 显示风险等级
	if isClusterAdmin {
		p.Printf("%s Risk Level: %s\n",
			p.Colored(config.ColorRed, "[!]"),
			p.Colored(config.ColorRed, "ADMIN (cluster-admin)"))
	} else {
		riskLevel := config.RiskLevel(sa.RiskLevel)
		display := config.RiskLevelDisplayConfig[riskLevel]
		p.Printf("%s Risk Level: %s\n",
			p.Colored(config.ColorGreen, "[+]"),
			p.Colored(display.Color, display.Label))
	}

	return nil
}
