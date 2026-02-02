package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"kctl/config"
	"kctl/internal/session"
	"kctl/pkg/types"
)

// RunCmd run 命令
type RunCmd struct{}

func init() {
	Register(&RunCmd{})
}

func (c *RunCmd) Name() string {
	return "run"
}

func (c *RunCmd) Aliases() []string {
	return nil
}

func (c *RunCmd) Description() string {
	return "通过 /run API 执行命令"
}

func (c *RunCmd) Usage() string {
	return `run [options] [pod]

通过 Kubelet /run API 执行命令（HTTP POST 方式）

选项：
  -n <namespace>      指定命名空间
  -c <container>      指定容器
  --cmd <command>     要执行的命令（必需）
  --all-pods          在所有 Pod 中执行命令
  --filter <pods>     排除指定 Pod（逗号分隔）
  --filter-ns <ns>    排除指定命名空间（逗号分隔）
  --concurrency <n>   并发数（默认: 10）

示例：
  run nginx --cmd "id"                              在指定 Pod 中执行
  run -n kube-system nginx --cmd "whoami"           指定命名空间
  run nginx -c nginx --cmd "cat /etc/passwd"        指定容器
  run --all-pods --cmd "id"                         在所有 Pod 中执行
  run --all-pods --filter-ns kube-system --cmd "hostname"  排除命名空间

与 exec 命令的区别：
  - run 使用 HTTP POST 请求，更简单直接
  - exec 使用 WebSocket，支持交互式 shell
  - run 适合快速执行简单命令`
}

func (c *RunCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer
	ctx := context.Background()

	// 检查连接
	kubelet, err := sess.GetKubeletClient()
	if err != nil {
		return err
	}

	// 解析参数
	namespace := ""
	container := ""
	podName := ""
	command := ""
	allPods := false
	filterPods := ""
	filterNs := ""
	concurrency := 10

	// 解析选项
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n":
			if i+1 < len(args) {
				namespace = args[i+1]
				i++
			}
		case "-c":
			if i+1 < len(args) {
				container = args[i+1]
				i++
			}
		case "--cmd":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case "--all-pods":
			allPods = true
		case "--filter":
			if i+1 < len(args) {
				filterPods = args[i+1]
				i++
			}
		case "--filter-ns":
			if i+1 < len(args) {
				filterNs = args[i+1]
				i++
			}
		case "--concurrency":
			if i+1 < len(args) {
				if n, err := strconv.Atoi(args[i+1]); err == nil && n > 0 {
					concurrency = n
				}
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") && podName == "" {
				podName = args[i]
			}
		}
	}

	// 检查命令参数
	if command == "" {
		return fmt.Errorf("必须指定 --cmd 参数")
	}

	// 多 Pod 执行模式
	if allPods {
		return c.runAllPods(ctx, sess, kubelet, namespace, filterPods, filterNs, concurrency, command)
	}

	// 如果没有指定 Pod，尝试使用当前 SA 的 Pod
	if podName == "" {
		sa := sess.GetCurrentSA()
		if sa != nil && sa.Pods != "" && sa.Pods != "[]" {
			var pods []types.SAPodInfo
			if err := json.Unmarshal([]byte(sa.Pods), &pods); err == nil && len(pods) > 0 {
				podName = pods[0].Name
				if namespace == "" {
					namespace = pods[0].Namespace
				}
				if container == "" && pods[0].Container != "" {
					container = pods[0].Container
				}
				p.Printf("%s Using pod: %s/%s (from current SA)\n",
					p.Colored(config.ColorBlue, "[*]"),
					namespace, podName)
			}
		}
	}

	if podName == "" {
		return fmt.Errorf("请指定 Pod 名称或先使用 'use' 选择一个 SA")
	}

	// 如果没有指定命名空间，尝试从缓存中查找
	if namespace == "" {
		pods := sess.GetCachedPods()
		for _, pod := range pods {
			if pod.PodName == podName {
				namespace = pod.Namespace
				if container == "" && len(pod.Containers) > 0 {
					container = pod.Containers[0].Name
				}
				break
			}
		}
	}

	if namespace == "" {
		namespace = "default"
	}

	// 如果没有指定容器，获取第一个容器
	if container == "" {
		pods := sess.GetCachedPods()
		for _, pod := range pods {
			if pod.PodName == podName && pod.Namespace == namespace {
				if len(pod.Containers) > 0 {
					container = pod.Containers[0].Name
				}
				break
			}
		}
	}

	if container == "" {
		return fmt.Errorf("无法确定容器名称，请使用 -c 指定")
	}

	// 执行命令
	return c.runCommand(ctx, sess, kubelet, namespace, podName, container, command)
}

// runCommand 执行单条命令
func (c *RunCmd) runCommand(ctx context.Context, sess *session.Session, kubelet interface {
	Run(ctx context.Context, opts *types.RunOptions) (*types.RunResult, error)
}, namespace, podName, container, command string) error {
	p := sess.Printer

	opts := &types.RunOptions{
		Namespace: namespace,
		Pod:       podName,
		Container: container,
		Command:   command,
	}

	result, err := kubelet.Run(ctx, opts)
	if err != nil {
		return fmt.Errorf("执行命令失败: %w", err)
	}

	if result.Error != "" {
		return fmt.Errorf("%s", result.Error)
	}

	if result.Output != "" {
		p.Print(result.Output)
		if !strings.HasSuffix(result.Output, "\n") {
			p.Println()
		}
	}

	return nil
}

// runAllPods 在多个 Pod 中并发执行命令
func (c *RunCmd) runAllPods(ctx context.Context, sess *session.Session, kubelet interface {
	Run(ctx context.Context, opts *types.RunOptions) (*types.RunResult, error)
}, namespace, filterPods, filterNs string, concurrency int, command string) error {
	p := sess.Printer

	// 获取缓存的 Pod
	pods := sess.GetCachedPods()
	if len(pods) == 0 {
		return fmt.Errorf("没有缓存的 Pod，请先执行 'pods' 命令")
	}

	// 解析 filter 列表
	podFilterList := parseFilterList(filterPods)
	nsFilterList := parseFilterList(filterNs)

	// 过滤 Pod
	var targetPods []types.PodContainerInfo
	for _, pod := range pods {
		// 按命名空间过滤（-n 参数，只保留指定命名空间）
		if namespace != "" && pod.Namespace != namespace {
			continue
		}
		// 按 --filter-ns 排除命名空间
		if matchFilterList(pod.Namespace, nsFilterList) {
			continue
		}
		// 按 --filter 排除 Pod 名称
		if matchFilterList(pod.PodName, podFilterList) {
			continue
		}
		// 只选择 Running 状态
		if pod.Status != "Running" {
			continue
		}
		targetPods = append(targetPods, pod)
	}

	if len(targetPods) == 0 {
		return fmt.Errorf("没有匹配的 Pod")
	}

	p.Printf("%s Executing on %d pods (concurrency: %d)...\n\n",
		p.Colored(config.ColorBlue, "[*]"),
		len(targetPods), concurrency)

	// 执行结果
	type runResultItem struct {
		Namespace string
		Pod       string
		Container string
		Output    string
		Error     string
		Success   bool
	}

	var results []runResultItem
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, pod := range targetPods {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(pod types.PodContainerInfo) {
			defer wg.Done()
			defer func() { <-semaphore }()

			container := ""
			if len(pod.Containers) > 0 {
				container = pod.Containers[0].Name
			}

			opts := &types.RunOptions{
				Namespace: pod.Namespace,
				Pod:       pod.PodName,
				Container: container,
				Command:   command,
			}

			result, err := kubelet.Run(ctx, opts)

			item := runResultItem{
				Namespace: pod.Namespace,
				Pod:       pod.PodName,
				Container: container,
				Success:   true,
			}

			if err != nil {
				item.Success = false
				item.Error = err.Error()
			} else if result.Error != "" {
				item.Success = false
				item.Error = result.Error
			} else {
				item.Output = result.Output
			}

			mu.Lock()
			results = append(results, item)
			mu.Unlock()
		}(pod)
	}

	wg.Wait()

	// 统计结果
	successCount := 0
	failCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failCount++
		}
	}

	// 打印结果
	for _, r := range results {
		if r.Success {
			p.Printf("%s %s/%s\n",
				p.Colored(config.ColorGreen, "[+]"),
				r.Namespace, r.Pod)
			if r.Output != "" {
				// 缩进输出
				lines := strings.Split(strings.TrimRight(r.Output, "\n"), "\n")
				for _, line := range lines {
					p.Printf("    %s\n", line)
				}
			}
		} else {
			p.Printf("%s %s/%s\n",
				p.Colored(config.ColorRed, "[-]"),
				r.Namespace, r.Pod)
			p.Printf("    %s\n", p.Colored(config.ColorRed, r.Error))
		}
		p.Println()
	}

	// 打印统计
	p.Printf("%s Completed: %s, %s\n",
		p.Colored(config.ColorBlue, "[*]"),
		p.Colored(config.ColorGreen, fmt.Sprintf("%d success", successCount)),
		p.Colored(config.ColorRed, fmt.Sprintf("%d failed", failCount)))

	return nil
}
