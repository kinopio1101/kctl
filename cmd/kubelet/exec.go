package kubelet

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	Error "kctl/utils/Error"
	"kctl/utils/Print"
	kubeletutil "kctl/utils/kubelet"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// exec 子命令的 flags
var (
	flagExecNamespace string // 命名空间
	flagExecPod       string // Pod 名称
	flagExecContainer string // 容器名称
	flagExecStdin     bool   // 是否启用 stdin
	flagExecTTY       bool   // 是否启用 TTY
	flagExecList      bool   // 列出所有可用 Pod
	flagExecAllPods   bool   // 在所有 Pod 中执行
	flagExecFilter    string // 过滤 Pod（排除匹配的 Pod）
)

// execCmd 是 exec 子命令
var execCmd = &cobra.Command{
	Use:   "exec [flags] -- [command...]",
	Short: "在 Pod 容器中执行命令",
	Long: `通过 Kubelet API 在 Pod 容器中执行命令

此命令使用 WebSocket 连接 Kubelet 的 /exec 端点，支持：
  - 交互式选择 Pod 和容器
  - 直接指定 namespace/pod/container 执行命令
  - 读取敏感文件（如 /etc/shadow）
  - 交互式 shell（使用 -it 参数）
  - 批量在所有 Pod 中执行命令（使用 --all-pods）

示例：
  # 交互式选择 Pod 并执行命令
  kubelet exec -- cat /etc/passwd

  # 列出所有可用的 Pod
  kubelet exec --list

  # 指定 Pod 执行命令
  kubelet exec -n default -p nginx -c nginx -- cat /etc/shadow

  # 获取交互式 shell
  kubelet exec -n default -p nginx -c nginx -it -- /bin/sh

  # 在所有 Pod 中执行命令
  kubelet exec --all-pods -- whoami

  # 在所有 Pod 中执行命令，排除 kube-system 命名空间的 Pod
  kubelet exec --all-pods --filter "kube-system" -- cat /etc/passwd

  # 使用正则表达式过滤（排除包含 coredns 或 etcd 的 Pod）
  kubelet exec --all-pods --filter "coredns|etcd" -- id

  # 使用自定义 Kubelet 地址
  kubelet --ip 10.0.0.1 --port 10250 exec -- whoami
`,
	Run: runExec,
}

func init() {
	KubeletCmd.AddCommand(execCmd)

	execCmd.Flags().StringVarP(&flagExecNamespace, "namespace", "n", "", "Pod 所在的命名空间")
	execCmd.Flags().StringVarP(&flagExecPod, "pod", "p", "", "Pod 名称")
	execCmd.Flags().StringVarP(&flagExecContainer, "container", "c", "", "容器名称")
	execCmd.Flags().BoolVarP(&flagExecStdin, "stdin", "i", false, "启用 stdin 输入")
	execCmd.Flags().BoolVarP(&flagExecTTY, "tty", "t", false, "启用 TTY")
	execCmd.Flags().BoolVar(&flagExecList, "list", false, "列出所有可用的 Pod")
	execCmd.Flags().BoolVarP(&flagExecAllPods, "all-pods", "A", false, "在所有 Running 状态的 Pod 中执行命令")
	execCmd.Flags().StringVarP(&flagExecFilter, "filter", "f", "", "过滤 Pod（排除匹配的 Pod），支持正则表达式，匹配 namespace/podname")
}

func runExec(cmd *cobra.Command, args []string) {
	// 获取 Token
	tokenPath := FlagTokenFile
	if tokenPath == "" {
		tokenPath = kubeletutil.GetDefaultTokenPath()
	}

	token, err := kubeletutil.ReadToken(tokenPath)
	if err != nil {
		log.Errorf("读取 Token 失败: %v", err)
		Error.HandleFatal(err)
	}

	// 获取 Kubelet IP
	var ip string
	if FlagIP != "" {
		ip = FlagIP
	} else {
		ip, err = kubeletutil.GetDefaultGateway()
		if err != nil {
			log.Errorf("获取默认网关失败: %v", err)
			Error.HandleFatal(err)
		}
	}

	port := FlagPort

	// 如果是列表模式
	if flagExecList {
		listAvailablePods(ip, port, token)
		return
	}

	// 解析命令
	command := args
	if len(command) == 0 {
		// 如果没有指定命令，默认使用 /bin/sh
		if flagExecStdin && flagExecTTY {
			command = []string{"/bin/sh"}
		} else {
			log.Error("请指定要执行的命令，使用 -- 分隔，例如: kubelet exec -- cat /etc/passwd")
			Error.HandleFatal(fmt.Errorf("缺少命令参数"))
		}
	}

	// 如果是 all-pods 模式
	if flagExecAllPods {
		execInAllPods(ip, port, token, command)
		return
	}

	// 获取 namespace, pod, container
	namespace := flagExecNamespace
	pod := flagExecPod
	container := flagExecContainer

	// 如果没有指定完整信息，进入交互式选择模式
	if namespace == "" || pod == "" {
		selectedPod, selectedContainer, err := selectPodAndContainer(ip, port, token)
		if err != nil {
			log.Errorf("选择 Pod 失败: %v", err)
			Error.HandleFatal(err)
		}
		namespace = selectedPod.Namespace
		pod = selectedPod.PodName
		if container == "" {
			container = selectedContainer
		}
	}

	// 如果还没有容器，尝试获取第一个容器
	if container == "" {
		pods, err := kubeletutil.FetchPodsWithContainersProxy(ip, port, token, ProxyURL)
		if err != nil {
			log.Errorf("获取 Pod 列表失败: %v", err)
			Error.HandleFatal(err)
		}
		for _, p := range pods {
			if p.Namespace == namespace && p.PodName == pod {
				if len(p.Containers) > 0 {
					container = p.Containers[0]
					break
				}
			}
		}
	}

	// 打印执行信息
	Print.PrintExecInfo(Print.ExecInfo{
		Target:   fmt.Sprintf("%s/%s/%s", namespace, pod, container),
		Command:  strings.Join(command, " "),
		Endpoint: fmt.Sprintf("%s:%d", ip, port),
	})

	// 构建 exec 选项
	opts := &kubeletutil.ExecOptions{
		IP:        ip,
		Port:      port,
		Token:     token,
		Namespace: namespace,
		Pod:       pod,
		Container: container,
		Command:   command,
		Stdin:     flagExecStdin,
		Stdout:    true,
		Stderr:    true,
		TTY:       flagExecTTY,
	}

	// 执行命令
	if flagExecStdin && flagExecTTY {
		// 交互式模式
		Print.PrintInteractiveHint("进入交互式模式，按 Ctrl+D 退出...")
		if err := kubeletutil.ExecInPodInteractive(opts); err != nil {
			log.Errorf("执行命令失败: %v", err)
			Error.HandleFatal(err)
		}
	} else {
		// 非交互式模式
		result, err := kubeletutil.ExecInPodProxy(opts, ProxyURL)
		if err != nil {
			log.Errorf("执行命令失败: %v", err)
			Error.HandleFatal(err)
		}

		// 输出结果
		if result.Stdout != "" {
			fmt.Print(result.Stdout)
		}
		if result.Stderr != "" {
			fmt.Fprint(os.Stderr, result.Stderr)
		}
		if result.Error != "" {
			fmt.Fprintf(os.Stderr, "\n%s %s\n", Print.Red("[Error]"), result.Error)
		}
	}
}

// execInAllPods 在所有 Pod 中执行命令
func execInAllPods(ip string, port int, token string, command []string) {
	log.Infof("从 Kubelet %s:%d 获取 Pod 列表...", ip, port)

	pods, err := kubeletutil.FetchPodsWithContainersProxy(ip, port, token, ProxyURL)
	if err != nil {
		log.Errorf("获取 Pod 列表失败: %v", err)
		Error.HandleFatal(err)
	}

	// 过滤 Running 状态的 Pod
	var runningPods []kubeletutil.PodContainerInfo
	for _, p := range pods {
		if p.Status == "Running" {
			runningPods = append(runningPods, p)
		}
	}

	if len(runningPods) == 0 {
		log.Warn("没有找到 Running 状态的 Pod")
		return
	}

	// 如果有过滤条件，编译正则表达式并过滤
	var filteredPods []kubeletutil.PodContainerInfo
	if flagExecFilter != "" {
		filterRegex, err := regexp.Compile(flagExecFilter)
		if err != nil {
			log.Errorf("无效的过滤正则表达式: %v", err)
			Error.HandleFatal(err)
		}

		for _, p := range runningPods {
			// 匹配 namespace/podname 或单独的 namespace 或 podname
			fullName := fmt.Sprintf("%s/%s", p.Namespace, p.PodName)
			if !filterRegex.MatchString(fullName) && !filterRegex.MatchString(p.Namespace) && !filterRegex.MatchString(p.PodName) {
				filteredPods = append(filteredPods, p)
			}
		}

		excluded := len(runningPods) - len(filteredPods)
		if excluded > 0 {
			log.Infof("已排除 %d 个匹配过滤条件的 Pod", excluded)
		}
	} else {
		filteredPods = runningPods
	}

	if len(filteredPods) == 0 {
		log.Warn("过滤后没有剩余的 Pod")
		return
	}

	// 打印批量执行信息
	Print.PrintTitleWide(fmt.Sprintf("批量执行命令: %s", strings.Join(command, " ")))
	fmt.Printf("  目标 Pod 数量: %d\n", len(filteredPods))
	fmt.Printf("  Kubelet: %s:%d\n\n", ip, port)

	// 统计结果
	successCount := 0
	failCount := 0

	// 在每个 Pod 的每个容器中执行命令
	for _, pod := range filteredPods {
		for _, container := range pod.Containers {
			target := fmt.Sprintf("%s/%s/%s", pod.Namespace, pod.PodName, container)

			// 打印目标
			Print.PrintSubSection(target)

			opts := &kubeletutil.ExecOptions{
				IP:        ip,
				Port:      port,
				Token:     token,
				Namespace: pod.Namespace,
				Pod:       pod.PodName,
				Container: container,
				Command:   command,
				Stdin:     false,
				Stdout:    true,
				Stderr:    true,
				TTY:       false,
			}

			result, err := kubeletutil.ExecInPodProxy(opts, ProxyURL)
			if err != nil {
				fmt.Printf("  %s 执行失败: %v\n", Print.Red("✗"), err)
				failCount++
				continue
			}

			// 输出结果
			if result.Stdout != "" {
				// 缩进输出
				lines := strings.Split(strings.TrimRight(result.Stdout, "\n"), "\n")
				for _, line := range lines {
					fmt.Printf("  %s\n", line)
				}
			}
			if result.Stderr != "" {
				lines := strings.Split(strings.TrimRight(result.Stderr, "\n"), "\n")
				for _, line := range lines {
					fmt.Fprintf(os.Stderr, "  %s %s\n", Print.Yellow("[stderr]"), line)
				}
			}
			if result.Error != "" {
				fmt.Fprintf(os.Stderr, "  %s %s\n", Print.Red("[error]"), result.Error)
				failCount++
			} else {
				successCount++
			}
		}
	}

	// 打印统计
	fmt.Println()
	Print.PrintSeparatorWide()
	fmt.Printf("执行完成: %s 成功, %s 失败\n",
		Print.Green(fmt.Sprintf("%d", successCount)),
		Print.Red(fmt.Sprintf("%d", failCount)))
}

// listAvailablePods 列出所有可用的 Pod
func listAvailablePods(ip string, port int, token string) {
	log.Infof("从 Kubelet %s:%d 获取 Pod 列表...", ip, port)

	pods, err := kubeletutil.FetchPodsWithContainersProxy(ip, port, token, ProxyURL)
	if err != nil {
		log.Errorf("获取 Pod 列表失败: %v", err)
		Error.HandleFatal(err)
	}

	if len(pods) == 0 {
		log.Warn("没有找到可用的 Pod")
		return
	}

	// 使用统一格式打印标题
	Print.PrintTitleWide("可用的 Pod 列表")

	// 转换为统一的列表项格式
	for i, pod := range pods {
		details := map[string]string{
			"Containers": strings.Join(pod.Containers, ", "),
		}
		if pod.PodIP != "" {
			details["PodIP"] = pod.PodIP
		}

		// 添加安全标识
		secFlags := Print.SecurityFlags{
			Privileged:               pod.SecurityFlags.Privileged,
			AllowPrivilegeEscalation: pod.SecurityFlags.AllowPrivilegeEscalation,
			HasHostPath:              pod.SecurityFlags.HasHostPath,
			HasSecretMount:           pod.SecurityFlags.HasSecretMount,
		}
		secTags := Print.FormatSecurityFlags(secFlags)
		if secTags != "" {
			details["Security"] = secTags
		}

		Print.PrintListItem(Print.ListItem{
			Index:    i + 1,
			Status:   pod.Status,
			Title:    pod.PodName,
			Subtitle: pod.Namespace,
			Details:  details,
		})
	}

	Print.PrintTotalWide("Total", len(pods))

	// 打印安全标识图例
	Print.PrintSecurityLegend()

	// 打印使用提示
	if len(pods) > 0 {
		p := pods[0]
		c := "container"
		if len(p.Containers) > 0 {
			c = p.Containers[0]
		}
		Print.PrintUsageExample("使用示例", []string{
			fmt.Sprintf("kubelet exec -n %s -p %s -c %s -- cat /etc/passwd", p.Namespace, p.PodName, c),
			fmt.Sprintf("kubelet exec -n %s -p %s -c %s -it -- /bin/sh", p.Namespace, p.PodName, c),
		})
	}
}

// selectPodAndContainer 交互式选择 Pod 和容器
func selectPodAndContainer(ip string, port int, token string) (*kubeletutil.PodContainerInfo, string, error) {
	log.Info("获取 Pod 列表...")

	pods, err := kubeletutil.FetchPodsWithContainersProxy(ip, port, token, ProxyURL)
	if err != nil {
		return nil, "", fmt.Errorf("获取 Pod 列表失败: %w", err)
	}

	// 过滤只保留 Running 状态的 Pod
	var runningPods []kubeletutil.PodContainerInfo
	for _, p := range pods {
		if p.Status == "Running" {
			runningPods = append(runningPods, p)
		}
	}

	if len(runningPods) == 0 {
		return nil, "", fmt.Errorf("没有处于 Running 状态的 Pod")
	}

	reader := bufio.NewReader(os.Stdin)

	// 选择 Pod
	selectedPod, err := kubeletutil.SelectPodInteractive(runningPods, reader)
	if err != nil {
		return nil, "", err
	}

	// 选择容器
	selectedContainer, err := kubeletutil.SelectContainerInteractive(selectedPod, reader)
	if err != nil {
		return nil, "", err
	}

	return selectedPod, selectedContainer, nil
}
