package types

import "time"

// ==================== Pod 相关类型 ====================

// PodRecord Pod 数据库记录
type PodRecord struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	UID               string    `json:"uid"`
	NodeName          string    `json:"nodeName"`
	PodIP             string    `json:"podIP"`
	HostIP            string    `json:"hostIP"`
	Phase             string    `json:"phase"`
	ServiceAccount    string    `json:"serviceAccount"`
	CreationTimestamp string    `json:"creationTimestamp"`
	Containers        string    `json:"containers"`      // JSON 格式的容器信息
	Volumes           string    `json:"volumes"`         // JSON 格式的敏感挂载信息
	SecurityContext   string    `json:"securityContext"` // JSON 格式的安全上下文
	CollectedAt       time.Time `json:"collectedAt"`     // 收集时间
	KubeletIP         string    `json:"kubeletIP"`       // 收集来源 Kubelet IP
}

// PodContainerInfo Pod 和容器信息，用于交互式选择
type PodContainerInfo struct {
	Namespace      string
	PodName        string
	UID            string
	Status         string
	PodIP          string
	HostIP         string
	NodeName       string
	ServiceAccount string
	CreatedAt      string
	Containers     []ContainerDetail
	Volumes        []VolumeDetail
	SecurityFlags  SecurityFlags
}

// ContainerDetail 容器详细信息
type ContainerDetail struct {
	Name         string
	ContainerID  string // 容器 ID（短格式）
	Image        string
	Ready        bool
	State        string // Running, Waiting, Terminated
	StartedAt    string
	VolumeMounts []VolumeMountDetail
	Privileged   bool
	AllowPE      bool // AllowPrivilegeEscalation
}

// VolumeMountDetail 卷挂载详情
type VolumeMountDetail struct {
	Name      string
	MountPath string
	ReadOnly  bool
	Type      string // hostPath, secret, configMap, emptyDir, projected, etc.
	Source    string // 源路径或名称
}

// VolumeDetail 卷详情
type VolumeDetail struct {
	Name   string
	Type   string // hostPath, secret, configMap, emptyDir, projected
	Source string // hostPath 路径或 secret/configMap 名称
}

// PodInfo 表示从 Kubelet API 获取的 Pod 基本信息
type PodInfo struct {
	Name      string
	Namespace string
	Status    string
	PodIP     string
	NodeName  string
}

// ==================== 容器相关类型 ====================

// ContainerInfo 存储容器的安全相关信息
type ContainerInfo struct {
	Name                     string   `json:"name"`
	Image                    string   `json:"image"`
	RunAsUser                *int64   `json:"runAsUser,omitempty"`
	RunAsGroup               *int64   `json:"runAsGroup,omitempty"`
	Privileged               bool     `json:"privileged"`
	AllowPrivilegeEscalation bool     `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool     `json:"readOnlyRootFilesystem"`
	VolumeMounts             []string `json:"volumeMounts"` // 挂载路径列表
}

// ContainerSecurityInfo 容器安全信息（详细）
type ContainerSecurityInfo struct {
	Name                     string
	Image                    string
	Privileged               bool
	AllowPrivilegeEscalation bool
	ReadOnlyRootFilesystem   bool
	RunAsUser                *int64
	RunAsGroup               *int64
	RunAsRoot                bool
	VolumeMounts             []string
	SensitiveMounts          []string
}

// ==================== 卷相关类型 ====================

// SensitiveVolume 存储敏感卷信息
type SensitiveVolume struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // secret, configMap, hostPath, projected, emptyDir
	SecretName string `json:"secretName,omitempty"`
	HostPath   string `json:"hostPath,omitempty"`
	MountPath  string `json:"mountPath,omitempty"` // 挂载到容器的路径
}

// VolumeClassification 分类卷信息
type VolumeClassification struct {
	Secrets    []SensitiveVolume
	HostPaths  []SensitiveVolume
	ConfigMaps []SensitiveVolume
	SATokens   []SensitiveVolume
	EmptyDirs  []SensitiveVolume
	Others     []SensitiveVolume
}

// ==================== 安全标识类型 ====================

// SecurityFlags 安全标识
type SecurityFlags struct {
	Privileged               bool `json:"privileged"`               // 特权容器
	AllowPrivilegeEscalation bool `json:"allowPrivilegeEscalation"` // 允许权限提升
	HasHostPath              bool `json:"hasHostPath"`              // 挂载了 HostPath
	HasSecretMount           bool `json:"hasSecretMount"`           // 挂载了 Secret
	HasSATokenMount          bool `json:"hasSATokenMount"`          // 挂载了 ServiceAccount Token
}

// ==================== Pod 安全摘要 ====================

// PodSecuritySummary Pod 安全摘要
type PodSecuritySummary struct {
	TotalPods       int
	NamespaceCount  int
	SACount         int
	PrivilegedCount int
	SecretsCount    int
	HostPathCount   int
	RiskyPodCount   int
	Namespaces      map[string]int
	ServiceAccounts map[string]int
}
