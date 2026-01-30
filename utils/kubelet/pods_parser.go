package kubelet

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// KubeletPodsFullResponse 完整的 Pod 响应结构（用于提取安全相关信息）
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
	NodeName           string          `json:"nodeName"`
	ServiceAccountName string          `json:"serviceAccountName"`
	Containers         []ContainerSpec `json:"containers"`
	Volumes            []VolumeSpec    `json:"volumes"`
	SecurityContext    *PodSecContext  `json:"securityContext,omitempty"`
}

// ContainerSpec 容器规格
type ContainerSpec struct {
	Name            string               `json:"name"`
	Image           string               `json:"image"`
	VolumeMounts    []VolumeMountSpec    `json:"volumeMounts"`
	SecurityContext *ContainerSecContext `json:"securityContext,omitempty"`
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

// PodSecContext Pod 安全上下文
type PodSecContext struct {
	RunAsUser    *int64 `json:"runAsUser,omitempty"`
	RunAsGroup   *int64 `json:"runAsGroup,omitempty"`
	RunAsNonRoot *bool  `json:"runAsNonRoot,omitempty"`
}

// ContainerSecContext 容器安全上下文
type ContainerSecContext struct {
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

// FetchPodsRawData 获取原始 Pod 数据
func FetchPodsRawData(ip string, port int, token string) ([]byte, error) {
	url := fmt.Sprintf("https://%s:%d/pods", ip, port)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// ExtractPodRecords 从原始数据中提取有安全价值的信息
func ExtractPodRecords(rawData []byte, kubeletIP string) ([]*PodRecord, error) {
	var response KubeletPodsFullResponse
	if err := json.Unmarshal(rawData, &response); err != nil {
		return nil, fmt.Errorf("JSON 解析失败: %w", err)
	}

	var records []*PodRecord
	now := time.Now()

	for _, item := range response.Items {
		record := &PodRecord{
			Name:              item.Metadata.Name,
			Namespace:         item.Metadata.Namespace,
			UID:               item.Metadata.UID,
			NodeName:          item.Spec.NodeName,
			PodIP:             item.Status.PodIP,
			HostIP:            item.Status.HostIP,
			Phase:             item.Status.Phase,
			ServiceAccount:    item.Spec.ServiceAccountName,
			CreationTimestamp: item.Metadata.CreationTimestamp,
			CollectedAt:       now,
			KubeletIP:         kubeletIP,
		}

		// 提取容器安全信息
		containers := ExtractContainerInfo(item.Spec.Containers)
		if len(containers) > 0 {
			containersJSON, _ := json.Marshal(containers)
			record.Containers = string(containersJSON)
		}

		// 提取敏感卷信息
		volumes := ExtractSensitiveVolumes(item.Spec.Volumes, item.Spec.Containers)
		if len(volumes) > 0 {
			volumesJSON, _ := json.Marshal(volumes)
			record.Volumes = string(volumesJSON)
		}

		// 提取 Pod 级安全上下文
		if item.Spec.SecurityContext != nil {
			secCtxJSON, _ := json.Marshal(item.Spec.SecurityContext)
			record.SecurityContext = string(secCtxJSON)
		}

		records = append(records, record)
	}

	return records, nil
}

// ExtractContainerInfo 提取容器安全信息
func ExtractContainerInfo(containers []ContainerSpec) []ContainerInfo {
	var infos []ContainerInfo

	for _, c := range containers {
		info := ContainerInfo{
			Name:  c.Name,
			Image: c.Image,
		}

		// 提取挂载路径
		for _, vm := range c.VolumeMounts {
			info.VolumeMounts = append(info.VolumeMounts, vm.MountPath)
		}

		// 提取安全上下文
		if c.SecurityContext != nil {
			info.RunAsUser = c.SecurityContext.RunAsUser
			info.RunAsGroup = c.SecurityContext.RunAsGroup

			if c.SecurityContext.Privileged != nil {
				info.Privileged = *c.SecurityContext.Privileged
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil {
				info.AllowPrivilegeEscalation = *c.SecurityContext.AllowPrivilegeEscalation
			}
			if c.SecurityContext.ReadOnlyRootFilesystem != nil {
				info.ReadOnlyRootFilesystem = *c.SecurityContext.ReadOnlyRootFilesystem
			}
		}

		infos = append(infos, info)
	}

	return infos
}

// ExtractSensitiveVolumes 提取敏感卷信息
func ExtractSensitiveVolumes(volumes []VolumeSpec, containers []ContainerSpec) []SensitiveVolume {
	var sensitiveVols []SensitiveVolume

	// 构建卷名到挂载路径的映射
	mountPaths := make(map[string]string)
	for _, c := range containers {
		for _, vm := range c.VolumeMounts {
			mountPaths[vm.Name] = vm.MountPath
		}
	}

	for _, v := range volumes {
		var sv *SensitiveVolume

		if v.Secret != nil {
			sv = &SensitiveVolume{
				Name:       v.Name,
				Type:       "secret",
				SecretName: v.Secret.SecretName,
			}
		} else if v.HostPath != nil {
			sv = &SensitiveVolume{
				Name:     v.Name,
				Type:     "hostPath",
				HostPath: v.HostPath.Path,
			}
		} else if v.Projected != nil {
			// 检查 projected 卷是否包含 ServiceAccount Token
			for _, src := range v.Projected.Sources {
				if src.ServiceAccountToken != nil {
					sv = &SensitiveVolume{
						Name: v.Name,
						Type: "projected-sa-token",
					}
					break
				}
				if src.Secret != nil {
					sv = &SensitiveVolume{
						Name:       v.Name,
						Type:       "projected-secret",
						SecretName: src.Secret.SecretName,
					}
					break
				}
			}
		}

		if sv != nil {
			if mp, ok := mountPaths[v.Name]; ok {
				sv.MountPath = mp
			}
			sensitiveVols = append(sensitiveVols, *sv)
		}
	}

	return sensitiveVols
}
