package kubelet

import (
	"encoding/json"
	"strings"
)

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

// SensitivePaths 敏感路径列表
var SensitivePaths = []string{
	"secret",
	"token",
	"serviceaccount",
	"/etc/",
	"/var/run/",
	"/root",
	"/host",
	"/proc",
	"/sys",
}

// CheckPrivileged 检查是否有特权容器
func CheckPrivileged(containersJSON string) bool {
	return strings.Contains(containersJSON, `"privileged":true`)
}

// CheckAllowPrivilegeEscalation 检查是否允许权限提升
func CheckAllowPrivilegeEscalation(containersJSON string) bool {
	return strings.Contains(containersJSON, `"allowPrivilegeEscalation":true`)
}

// CheckHostPath 检查是否挂载 HostPath
func CheckHostPath(volumesJSON string) bool {
	return strings.Contains(volumesJSON, `"type":"hostPath"`)
}

// CheckSecretMount 检查是否挂载 Secret
func CheckSecretMount(volumesJSON string) bool {
	return strings.Contains(volumesJSON, `"type":"secret"`) ||
		strings.Contains(volumesJSON, `"type":"projected-secret"`)
}

// CheckRunAsRoot 检查容器是否以 root 用户运行
func CheckRunAsRoot(containersJSON string) bool {
	var containers []ContainerInfo
	if err := json.Unmarshal([]byte(containersJSON), &containers); err != nil {
		return false
	}
	for _, c := range containers {
		if c.RunAsUser != nil && *c.RunAsUser == 0 {
			return true
		}
	}
	return false
}

// IsSensitivePath 检查路径是否敏感
func IsSensitivePath(path string) bool {
	pathLower := strings.ToLower(path)
	for _, sensitive := range SensitivePaths {
		if strings.Contains(pathLower, sensitive) {
			return true
		}
	}
	return false
}

// GetPodSecurityFlags 获取 Pod 的安全风险标记
func GetPodSecurityFlags(record *PodRecord) SecurityFlags {
	return SecurityFlags{
		Privileged:               CheckPrivileged(record.Containers),
		AllowPrivilegeEscalation: CheckAllowPrivilegeEscalation(record.Containers),
		HasHostPath:              CheckHostPath(record.Volumes),
		HasSecretMount:           CheckSecretMount(record.Volumes),
	}
}

// CheckSensitivePathsInRecord 检查记录中是否有敏感路径
func CheckSensitivePathsInRecord(record *PodRecord) bool {
	var containers []ContainerInfo
	if err := json.Unmarshal([]byte(record.Containers), &containers); err != nil {
		return false
	}
	for _, c := range containers {
		for _, mp := range c.VolumeMounts {
			if IsSensitivePath(mp) {
				return true
			}
		}
	}
	return false
}

// GetRiskFlags 获取风险标记字符串列表
func GetRiskFlags(record *PodRecord) []string {
	var flags []string

	if CheckPrivileged(record.Containers) {
		flags = append(flags, "PRIV")
	}
	if CheckAllowPrivilegeEscalation(record.Containers) {
		flags = append(flags, "PE")
	}
	if CheckHostPath(record.Volumes) {
		flags = append(flags, "HP")
	}
	if CheckSecretMount(record.Volumes) {
		flags = append(flags, "SEC")
	}
	if CheckRunAsRoot(record.Containers) {
		flags = append(flags, "ROOT")
	}

	return flags
}

// IsPodRisky 检查 Pod 是否有风险
func IsPodRisky(record *PodRecord) bool {
	return CheckPrivileged(record.Containers) ||
		CheckAllowPrivilegeEscalation(record.Containers) ||
		CheckHostPath(record.Volumes) ||
		CheckSecretMount(record.Volumes) ||
		CheckRunAsRoot(record.Containers)
}

// CalculatePodSecuritySummary 计算 Pod 安全摘要
func CalculatePodSecuritySummary(records []*PodRecord) *PodSecuritySummary {
	summary := &PodSecuritySummary{
		TotalPods:       len(records),
		Namespaces:      make(map[string]int),
		ServiceAccounts: make(map[string]int),
	}

	for _, r := range records {
		// 统计命名空间
		summary.Namespaces[r.Namespace]++

		// 统计 ServiceAccount
		if r.ServiceAccount != "" {
			summary.ServiceAccounts[r.ServiceAccount]++
		}

		// 检查安全风险
		if CheckPrivileged(r.Containers) || CheckAllowPrivilegeEscalation(r.Containers) {
			summary.PrivilegedCount++
		}
		if CheckSecretMount(r.Volumes) {
			summary.SecretsCount++
		}
		if CheckHostPath(r.Volumes) {
			summary.HostPathCount++
		}
		if IsPodRisky(r) {
			summary.RiskyPodCount++
		}
	}

	summary.NamespaceCount = len(summary.Namespaces)
	summary.SACount = len(summary.ServiceAccounts)

	return summary
}

// GetContainerSecurityContext 解析容器安全上下文
func GetContainerSecurityContext(containersJSON string) []ContainerSecurityInfo {
	var containers []ContainerInfo
	if err := json.Unmarshal([]byte(containersJSON), &containers); err != nil {
		return nil
	}

	var result []ContainerSecurityInfo
	for _, c := range containers {
		info := ContainerSecurityInfo{
			Name:                     c.Name,
			Image:                    c.Image,
			Privileged:               c.Privileged,
			AllowPrivilegeEscalation: c.AllowPrivilegeEscalation,
			ReadOnlyRootFilesystem:   c.ReadOnlyRootFilesystem,
			VolumeMounts:             c.VolumeMounts,
		}
		if c.RunAsUser != nil {
			info.RunAsUser = c.RunAsUser
			info.RunAsRoot = *c.RunAsUser == 0
		}
		if c.RunAsGroup != nil {
			info.RunAsGroup = c.RunAsGroup
		}

		// 检查敏感挂载路径
		for _, mp := range c.VolumeMounts {
			if IsSensitivePath(mp) {
				info.SensitiveMounts = append(info.SensitiveMounts, mp)
			}
		}

		result = append(result, info)
	}
	return result
}

// ContainerSecurityInfo 容器安全信息
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

// GetSensitiveVolumes 解析敏感卷信息
func GetSensitiveVolumes(volumesJSON string) []SensitiveVolume {
	var volumes []SensitiveVolume
	if err := json.Unmarshal([]byte(volumesJSON), &volumes); err != nil {
		return nil
	}
	return volumes
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

// ClassifyVolumes 对卷进行分类
func ClassifyVolumes(volumesJSON string) *VolumeClassification {
	volumes := GetSensitiveVolumes(volumesJSON)
	if volumes == nil {
		return nil
	}

	classification := &VolumeClassification{}
	for _, v := range volumes {
		switch v.Type {
		case "secret", "projected-secret":
			classification.Secrets = append(classification.Secrets, v)
		case "hostPath":
			classification.HostPaths = append(classification.HostPaths, v)
		case "configMap":
			classification.ConfigMaps = append(classification.ConfigMaps, v)
		case "projected-sa-token":
			classification.SATokens = append(classification.SATokens, v)
		case "emptyDir":
			classification.EmptyDirs = append(classification.EmptyDirs, v)
		default:
			classification.Others = append(classification.Others, v)
		}
	}
	return classification
}

// AggregateSecrets 聚合所有 Pod 的 Secret 挂载信息
// 返回 map[secretName][]podFullName
func AggregateSecrets(records []*PodRecord) map[string][]string {
	secretMap := make(map[string][]string)

	for _, r := range records {
		podFullName := r.Namespace + "/" + r.Name
		volumes := GetSensitiveVolumes(r.Volumes)

		for _, v := range volumes {
			if v.Type == "secret" || v.Type == "projected-secret" {
				if v.SecretName != "" {
					secretMap[v.SecretName] = append(secretMap[v.SecretName], podFullName)
				}
			}
		}
	}
	return secretMap
}

// AggregateHostPaths 聚合所有 Pod 的 HostPath 挂载信息
// 返回 map[hostPath][]podFullName
func AggregateHostPaths(records []*PodRecord) map[string][]string {
	hostPathMap := make(map[string][]string)

	for _, r := range records {
		podFullName := r.Namespace + "/" + r.Name
		volumes := GetSensitiveVolumes(r.Volumes)

		for _, v := range volumes {
			if v.Type == "hostPath" && v.HostPath != "" {
				hostPathMap[v.HostPath] = append(hostPathMap[v.HostPath], podFullName)
			}
		}
	}
	return hostPathMap
}
