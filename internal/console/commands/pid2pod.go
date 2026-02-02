package commands

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mitchellh/go-ps"

	"kctl/config"
	"kctl/internal/session"
	"kctl/pkg/proc"
	"kctl/pkg/types"
)

// Pid2PodCmd pid2pod 命令
type Pid2PodCmd struct{}

func init() {
	Register(&Pid2PodCmd{})
}

func (c *Pid2PodCmd) Name() string {
	return "pid2pod"
}

func (c *Pid2PodCmd) Aliases() []string {
	return []string{"p2p"}
}

func (c *Pid2PodCmd) Description() string {
	return "将 PID 映射到 Pod"
}

func (c *Pid2PodCmd) Usage() string {
	return `pid2pod [options]

将 Linux 进程 ID (PID) 映射到 Kubernetes Pod 元数据

注意：此功能仅在 Pod 内可用（需要访问 /proc 文件系统）

选项：
  --pid <pid>         只查看指定 PID
  --all               显示所有进程（包括非容器进程）

示例：
  pid2pod                    显示所有容器进程
  pid2pod --pid 1234         查看指定 PID
  pid2pod --all              显示所有进程`
}

// podProcessInfo 进程与 Pod 的映射信息
type podProcessInfo struct {
	PID         int
	ProcessName string
	Namespace   string
	PodName     string
	Container   string
	ContainerID string
}

func (c *Pid2PodCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer
	ctx := context.Background()

	// 检查是否在 Pod 内
	if !sess.InPod {
		return fmt.Errorf("此功能仅在 Pod 内可用（需要访问 /proc 文件系统）")
	}

	// 解析参数
	targetPID := 0
	showAll := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pid":
			if i+1 < len(args) {
				if pid, err := strconv.Atoi(args[i+1]); err == nil {
					targetPID = pid
				}
				i++
			}
		case "--all":
			showAll = true
		}
	}

	// 获取 Kubelet 客户端
	kubelet, err := sess.GetKubeletClient()
	if err != nil {
		return err
	}

	// 获取 Pod 列表
	p.Printf("%s Fetching pods from Kubelet...\n", p.Colored(config.ColorBlue, "[*]"))
	pods, err := kubelet.GetPodsWithContainers(ctx)
	if err != nil {
		return fmt.Errorf("获取 Pod 列表失败: %w", err)
	}

	// 构建 containerID -> Pod 映射
	containerMap := buildContainerPodMap(pods)

	// 获取所有进程
	p.Printf("%s Scanning processes...\n", p.Colored(config.ColorBlue, "[*]"))
	processes, err := ps.Processes()
	if err != nil {
		return fmt.Errorf("获取进程列表失败: %w", err)
	}

	// 匹配进程与 Pod
	var results []podProcessInfo
	var nonContainerCount int

	for _, process := range processes {
		pid := process.Pid()

		// 如果指定了 PID，只处理该 PID
		if targetPID != 0 && pid != targetPID {
			continue
		}

		// 获取容器信息
		containerInfo, err := proc.GetContainerInfo(pid)
		if err != nil || containerInfo == nil || containerInfo.ContainerID == "" {
			// 非容器进程
			if showAll {
				results = append(results, podProcessInfo{
					PID:         pid,
					ProcessName: process.Executable(),
					Namespace:   "-",
					PodName:     "-",
					Container:   "-",
					ContainerID: "-",
				})
			}
			nonContainerCount++
			continue
		}

		// 查找对应的 Pod
		if podInfo, ok := containerMap[containerInfo.ContainerID]; ok {
			results = append(results, podProcessInfo{
				PID:         pid,
				ProcessName: process.Executable(),
				Namespace:   podInfo.Namespace,
				PodName:     podInfo.PodName,
				Container:   podInfo.Container,
				ContainerID: containerInfo.ContainerID,
			})
		} else {
			// 有容器 ID 但找不到对应的 Pod（可能是其他节点的容器）
			results = append(results, podProcessInfo{
				PID:         pid,
				ProcessName: process.Executable(),
				Namespace:   "?",
				PodName:     "?",
				Container:   "?",
				ContainerID: containerInfo.ContainerID,
			})
		}
	}

	// 按 PID 排序
	sort.Slice(results, func(i, j int) bool {
		return results[i].PID < results[j].PID
	})

	// 输出结果
	p.Println()
	if len(results) == 0 {
		if targetPID != 0 {
			p.Warning(fmt.Sprintf("未找到 PID %d 或该进程不是容器进程", targetPID))
		} else {
			p.Warning("未找到容器进程")
		}
		return nil
	}

	// 计算列宽
	pidWidth := 6
	procWidth := 15
	nsWidth := 12
	podWidth := 30
	containerWidth := 15

	for _, r := range results {
		if len(fmt.Sprintf("%d", r.PID)) > pidWidth {
			pidWidth = len(fmt.Sprintf("%d", r.PID))
		}
		if len(r.ProcessName) > procWidth {
			procWidth = len(r.ProcessName)
		}
		if len(r.Namespace) > nsWidth {
			nsWidth = len(r.Namespace)
		}
		if len(r.PodName) > podWidth {
			podWidth = len(r.PodName)
		}
		if len(r.Container) > containerWidth {
			containerWidth = len(r.Container)
		}
	}

	// 限制最大宽度
	if procWidth > 20 {
		procWidth = 20
	}
	if podWidth > 40 {
		podWidth = 40
	}

	// 打印表头
	headerFmt := fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds  %%-%ds  %%-%ds\n",
		pidWidth, procWidth, nsWidth, podWidth, containerWidth)
	rowFmt := fmt.Sprintf("%%-%dd  %%-%ds  %%-%ds  %%-%ds  %%-%ds\n",
		pidWidth, procWidth, nsWidth, podWidth, containerWidth)

	p.Printf(headerFmt, "PID", "PROCESS", "NAMESPACE", "POD", "CONTAINER")
	p.Printf("%s\n", strings.Repeat("-", pidWidth+procWidth+nsWidth+podWidth+containerWidth+8))

	for _, r := range results {
		procName := r.ProcessName
		if len(procName) > procWidth {
			procName = procName[:procWidth-3] + "..."
		}
		podName := r.PodName
		if len(podName) > podWidth {
			podName = podName[:podWidth-3] + "..."
		}

		p.Printf(rowFmt, r.PID, procName, r.Namespace, podName, r.Container)
	}

	// 统计信息
	containerProcessCount := 0
	for _, r := range results {
		if r.Namespace != "-" {
			containerProcessCount++
		}
	}

	p.Println()
	p.Printf("%s Found %d container processes",
		p.Colored(config.ColorGreen, "[+]"),
		containerProcessCount)
	if showAll {
		p.Printf(", %d non-container processes", nonContainerCount)
	}
	p.Println()

	return nil
}

// containerPodMapInfo 容器与 Pod 的映射信息
type containerPodMapInfo struct {
	Namespace string
	PodName   string
	Container string
}

// buildContainerPodMap 构建 containerID -> Pod 映射
func buildContainerPodMap(pods []types.PodContainerInfo) map[string]containerPodMapInfo {
	result := make(map[string]containerPodMapInfo)

	for _, pod := range pods {
		for _, container := range pod.Containers {
			if container.ContainerID != "" {
				result[container.ContainerID] = containerPodMapInfo{
					Namespace: pod.Namespace,
					PodName:   pod.PodName,
					Container: container.Name,
				}
			}
		}
	}

	return result
}
