package proc

import (
	"fmt"
	"os"
	"strings"
)

// ContainerInfo 容器信息
type ContainerInfo struct {
	ContainerID string // 容器 ID（短格式，12 字符）
	PodUID      string // Pod UID
	Runtime     string // 容器运行时 (docker, containerd, cri-o)
}

// GetContainerInfo 从 /proc/<pid>/cgroup 获取容器信息
// 仅支持 cgroup v1
func GetContainerInfo(pid int) (*ContainerInfo, error) {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return nil, fmt.Errorf("读取 cgroup 文件失败: %w", err)
	}

	return parseCgroupV1(string(data))
}

// parseCgroupV1 解析 cgroup v1 格式
// 格式示例:
// 12:memory:/kubepods/burstable/pod<pod-uid>/<container-id>
// 11:devices:/kubepods/besteffort/pod<pod-uid>/<container-id>
// 或 Docker 格式:
// 12:memory:/docker/<container-id>
func parseCgroupV1(content string) (*ContainerInfo, error) {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}

		// 格式: hierarchy-ID:controller-list:cgroup-path
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}

		cgroupPath := parts[2]

		// 检查是否是 Kubernetes Pod
		if strings.Contains(cgroupPath, "kubepods") {
			return parseKubepodsCgroup(cgroupPath)
		}

		// 检查是否是 Docker 容器
		if strings.Contains(cgroupPath, "/docker/") {
			return parseDockerCgroup(cgroupPath)
		}

		// 检查是否是 containerd 容器
		if strings.Contains(cgroupPath, "/containerd/") {
			return parseContainerdCgroup(cgroupPath)
		}
	}

	return nil, nil // 非容器进程
}

// parseKubepodsCgroup 解析 Kubernetes cgroup 路径
// 格式: /kubepods/burstable/pod<pod-uid>/<container-id>
// 或: /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<pod-uid>.slice/docker-<container-id>.scope
func parseKubepodsCgroup(cgroupPath string) (*ContainerInfo, error) {
	info := &ContainerInfo{}

	// 按 / 分割路径
	parts := strings.Split(cgroupPath, "/")

	for i, part := range parts {
		// 查找 pod UID
		if strings.HasPrefix(part, "pod") {
			// 格式: pod<uid> 或 kubepods-burstable-pod<uid>.slice
			uid := strings.TrimPrefix(part, "pod")
			uid = strings.TrimSuffix(uid, ".slice")
			// 移除可能的 QoS 前缀
			if idx := strings.LastIndex(uid, "-pod"); idx != -1 {
				uid = uid[idx+4:]
			}
			info.PodUID = uid
		}

		// 容器 ID 通常是最后一个非空部分
		if i == len(parts)-1 && part != "" {
			containerID := part

			// 处理 systemd slice 格式
			// docker-<container-id>.scope 或 cri-containerd-<container-id>.scope
			if strings.HasSuffix(containerID, ".scope") {
				containerID = strings.TrimSuffix(containerID, ".scope")
				if strings.HasPrefix(containerID, "docker-") {
					containerID = strings.TrimPrefix(containerID, "docker-")
					info.Runtime = "docker"
				} else if strings.HasPrefix(containerID, "cri-containerd-") {
					containerID = strings.TrimPrefix(containerID, "cri-containerd-")
					info.Runtime = "containerd"
				} else if strings.HasPrefix(containerID, "crio-") {
					containerID = strings.TrimPrefix(containerID, "crio-")
					info.Runtime = "cri-o"
				}
			}

			// 取前 12 个字符作为短 ID
			if len(containerID) >= 12 {
				info.ContainerID = containerID[:12]
			} else if len(containerID) > 0 {
				info.ContainerID = containerID
			}
		}
	}

	if info.ContainerID == "" {
		return nil, nil
	}

	return info, nil
}

// parseDockerCgroup 解析 Docker cgroup 路径
// 格式: /docker/<container-id>
func parseDockerCgroup(cgroupPath string) (*ContainerInfo, error) {
	parts := strings.Split(cgroupPath, "/")
	for i, part := range parts {
		if part == "docker" && i+1 < len(parts) {
			containerID := parts[i+1]
			if len(containerID) >= 12 {
				return &ContainerInfo{
					ContainerID: containerID[:12],
					Runtime:     "docker",
				}, nil
			}
		}
	}
	return nil, nil
}

// parseContainerdCgroup 解析 containerd cgroup 路径
func parseContainerdCgroup(cgroupPath string) (*ContainerInfo, error) {
	parts := strings.Split(cgroupPath, "/")
	for i, part := range parts {
		if part == "containerd" && i+1 < len(parts) {
			containerID := parts[i+1]
			if len(containerID) >= 12 {
				return &ContainerInfo{
					ContainerID: containerID[:12],
					Runtime:     "containerd",
				}, nil
			}
		}
	}
	return nil, nil
}

// IsContainerProcess 检查进程是否是容器进程
func IsContainerProcess(pid int) bool {
	info, err := GetContainerInfo(pid)
	if err != nil {
		return false
	}
	return info != nil && info.ContainerID != ""
}
