package types

import "time"

// ==================== Kubelet API 响应类型 ====================

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

// ==================== 完整 Pod 响应结构（用于解析）====================

// KubeletPodsFullResponse 完整的 Pod 响应结构
type KubeletPodsFullResponse struct {
	Items []PodItem `json:"items"`
}

// PodItem 表示单个 Pod
type PodItem struct {
	Metadata PodMetadata `json:"metadata"`
	Spec     PodSpec     `json:"spec"`
	Status   PodStatus   `json:"status"`
}

// PodMetadata Pod 元数据
type PodMetadata struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	UID               string `json:"uid"`
	CreationTimestamp string `json:"creationTimestamp"`
}

// PodSpec Pod 规格
type PodSpec struct {
	NodeName           string              `json:"nodeName"`
	ServiceAccountName string              `json:"serviceAccountName"`
	Containers         []ContainerSpec     `json:"containers"`
	Volumes            []VolumeSpec        `json:"volumes"`
	SecurityContext    *PodSecurityContext `json:"securityContext,omitempty"`
}

// ContainerSpec 容器规格
type ContainerSpec struct {
	Name            string                    `json:"name"`
	Image           string                    `json:"image"`
	VolumeMounts    []VolumeMountSpec         `json:"volumeMounts"`
	SecurityContext *ContainerSecurityContext `json:"securityContext,omitempty"`
}

// VolumeMountSpec 卷挂载规格
type VolumeMountSpec struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}

// VolumeSpec 卷规格
type VolumeSpec struct {
	Name      string        `json:"name"`
	Secret    *SecretVol    `json:"secret,omitempty"`
	ConfigMap *ConfigMapVol `json:"configMap,omitempty"`
	HostPath  *HostPathVol  `json:"hostPath,omitempty"`
	EmptyDir  *EmptyDirVol  `json:"emptyDir,omitempty"`
	Projected *ProjectedVol `json:"projected,omitempty"`
}

// SecretVol Secret 卷
type SecretVol struct {
	SecretName string `json:"secretName"`
}

// ConfigMapVol ConfigMap 卷
type ConfigMapVol struct {
	Name string `json:"name"`
}

// HostPathVol HostPath 卷
type HostPathVol struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
}

// EmptyDirVol EmptyDir 卷
type EmptyDirVol struct {
	Medium string `json:"medium,omitempty"`
}

// ProjectedVol Projected 卷
type ProjectedVol struct {
	Sources []ProjectedSource `json:"sources"`
}

// ProjectedSource Projected 源
type ProjectedSource struct {
	ServiceAccountToken *SATokenSource `json:"serviceAccountToken,omitempty"`
	Secret              *SecretVol     `json:"secret,omitempty"`
	ConfigMap           *ConfigMapVol  `json:"configMap,omitempty"`
}

// SATokenSource ServiceAccount Token 源
type SATokenSource struct {
	Path              string `json:"path"`
	ExpirationSeconds int64  `json:"expirationSeconds,omitempty"`
}

// PodSecurityContext Pod 安全上下文
type PodSecurityContext struct {
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
	RunAsGroup   *int64 `json:"runAsGroup,omitempty"`
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
}

// ContainerSecurityContext 容器安全上下文
type ContainerSecurityContext struct {
	RunAsUser                *int64 `json:"runAsUser,omitempty"`
	RunAsGroup               *int64 `json:"runAsGroup,omitempty"`
	Privileged               *bool  `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation,omitempty"`
	ReadOnlyRootFilesystem   *bool  `json:"readOnlyRootFilesystem,omitempty"`
	RunAsNonRoot             *bool  `json:"runAsNonRoot,omitempty"`
}

// PodStatus Pod 状态
type PodStatus struct {
	Phase  string `json:"phase"`
	PodIP  string `json:"podIP"`
	HostIP string `json:"hostIP"`
}

// ==================== Exec 相关类型 ====================

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

// ExecResult 表示 exec 执行结果
type ExecResult struct {
	Stdout string
	Stderr string
	Error  string
}

// ExecStatus 表示 Kubernetes exec API 的状态响应
type ExecStatus struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Reason  string `json:"reason"`
	Code    int    `json:"code"`
}

// ==================== 探测相关类型 ====================

// ProbeResult 表示端口探测结果
type ProbeResult struct {
	IP         string
	Port       int
	Reachable  bool
	IsKubelet  bool
	HealthPath string
	Error      error
}

// ==================== Kubelet 节点类型 ====================

// KubeletNode 表示发现的 Kubelet 节点
type KubeletNode struct {
	IP           string
	Port         int
	Reachable    bool
	IsKubelet    bool
	HealthPath   string // /healthz 或 /pods
	DiscoveredAt time.Time
}

// ==================== 路由相关类型 ====================

// RouteEntry 表示路由表中的一条记录
type RouteEntry struct {
	Interface   string
	Destination string
	Gateway     string
	Flags       string
	Mask        string
}
