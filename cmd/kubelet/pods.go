package kubelet

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	Error "kctl/utils/Error"
	"kctl/utils/Print"
	kubeletutil "kctl/utils/kubelet"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// pods 子命令的 flags
var (
	flagDBPath      string // 数据库文件路径
	flagListMode    string // 列表模式: all, privileged, secrets, hostpath, mounts
	flagFilterNS    string // 过滤命名空间
	flagFilterSA    string // 过滤 ServiceAccount
	flagShowDetails bool   // 显示详细信息
	flagClearDB     bool   // 清空数据库
	flagNoSave      bool   // 不保存到数据库，仅显示
)

// podsCmd 是 pods 子命令
var podsCmd = &cobra.Command{
	Use:   "pods",
	Short: "收集并管理 Kubelet Pod 信息",
	Long: `从 Kubelet API 收集 Pod 信息并保存到本地 SQLite 数据库

此命令会提取 Pod 中有安全利用价值的信息：
  - 基本信息: 名称、命名空间、节点、IP
  - ServiceAccount: 可用于权限提升分析
  - 容器安全上下文: 特权模式、用户权限等
  - 敏感挂载: Secrets、HostPath 等

示例：
  # 收集 Pod 信息并保存
  kubelet pods

  # 指定数据库路径
  kubelet pods --db /tmp/pods.db

  # 只显示不保存
  kubelet pods --no-save

  # 列出已保存的特权 Pod
  kubelet pods --list privileged

  # 按命名空间过滤
  kubelet pods --list all --namespace kube-system

  # 显示挂载了 Secret 的 Pod
  kubelet pods --list secrets
  
  # 展示所有挂载和 Secret 汇总
  kubelet pods --list mounts
  
  # 显示详细信息（含挂载路径）
  kubelet pods --list all --details`,
	Run: runPods,
}

func init() {
	KubeletCmd.AddCommand(podsCmd)

	podsCmd.Flags().StringVar(&flagDBPath, "db", "", "数据库文件路径 (默认: kubelet_pods.db)")
	podsCmd.Flags().StringVar(&flagListMode, "list", "", "列表模式: all, privileged, secrets, hostpath, mounts, sa, ns")
	podsCmd.Flags().StringVar(&flagFilterNS, "namespace", "", "过滤命名空间")
	podsCmd.Flags().StringVar(&flagFilterSA, "sa", "", "过滤 ServiceAccount")
	podsCmd.Flags().BoolVar(&flagShowDetails, "details", false, "显示详细信息（含挂载路径）")
	podsCmd.Flags().BoolVar(&flagClearDB, "clear", false, "清空数据库")
	podsCmd.Flags().BoolVar(&flagNoSave, "no-save", false, "不保存到数据库")
}

func runPods(cmd *cobra.Command, args []string) {
	// 如果是列表模式，直接从数据库读取
	if flagListMode != "" {
		listFromDB()
		return
	}

	// 如果是清空数据库
	if flagClearDB {
		clearDatabase()
		return
	}

	// 收集模式：从 Kubelet API 获取数据
	collectPods()
}

// collectPods 从 Kubelet API 收集 Pod 信息
func collectPods() {
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
	log.Infof("从 Kubelet %s:%d 收集 Pod 信息...", ip, port)

	// 调用 API 获取原始数据
	rawData, err := kubeletutil.FetchPodsRawWithProxy(ip, port, token, ProxyURL)
	if err != nil {
		log.Errorf("获取 Pod 数据失败: %v", err)
		Error.HandleFatal(err)
	}

	// 解析并提取有价值的信息
	records, err := kubeletutil.ExtractPodRecords(rawData, ip)
	if err != nil {
		log.Errorf("解析 Pod 数据失败: %v", err)
		Error.HandleFatal(err)
	}

	log.Infof("解析到 %d 个 Pod", len(records))

	// 显示摘要
	printPodSummary(records)

	// 保存到数据库
	if !flagNoSave {
		db, err := kubeletutil.NewPodDB(flagDBPath)
		if err != nil {
			log.Errorf("打开数据库失败: %v", err)
			Error.HandleFatal(err)
		}
		defer func() { _ = db.Close() }()

		saved, err := db.SavePods(records)
		if err != nil {
			log.Errorf("保存失败: %v", err)
			Error.HandleError(err)
		} else {
			green := color.New(color.FgGreen).SprintFunc()
			fmt.Printf("\n%s 已保存 %d 个 Pod 到数据库\n", green("✓"), saved)
		}
	}
}

// printPodSummary 打印 Pod 摘要
func printPodSummary(records []*kubeletutil.PodRecord) {
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	// 使用工具函数计算安全摘要
	summary := kubeletutil.CalculatePodSecuritySummary(records)

	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│                    %s                              │\n", cyan("Pod 收集摘要"))
	fmt.Println("├─────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ 总计 Pod 数量: %-47d │\n", summary.TotalPods)
	fmt.Printf("│ 命名空间数量: %-48d │\n", summary.NamespaceCount)
	fmt.Printf("│ ServiceAccount 数量: %-41d │\n", summary.SACount)
	fmt.Println("├─────────────────────────────────────────────────────────────────┤")
	fmt.Printf("│ %s                                                 │\n", yellow("安全关注点:"))

	if summary.PrivilegedCount > 0 {
		fmt.Printf("│   %s 特权/可提权容器: %-38d │\n", red("★"), summary.PrivilegedCount)
	}
	if summary.SecretsCount > 0 {
		fmt.Printf("│   %s 挂载 Secret 的 Pod: %-36d │\n", yellow("◆"), summary.SecretsCount)
	}
	if summary.HostPathCount > 0 {
		fmt.Printf("│   %s 挂载 HostPath 的 Pod: %-34d │\n", red("◆"), summary.HostPathCount)
	}
	if summary.PrivilegedCount == 0 && summary.SecretsCount == 0 && summary.HostPathCount == 0 {
		fmt.Printf("│   %s 未发现明显安全风险点                               │\n", green("✓"))
	}
	fmt.Println("└─────────────────────────────────────────────────────────────────┘")

	// 打印每个 Pod 的完整信息
	for i, r := range records {
		fmt.Printf("\n%s [%d/%d] %s\n", cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"), i+1, len(records), cyan(r.Name))

		// 基本信息
		fmt.Printf("  %-20s %s\n", "Namespace:", r.Namespace)
		fmt.Printf("  %-20s %s\n", "UID:", r.UID)
		fmt.Printf("  %-20s %s\n", "Node:", r.NodeName)
		fmt.Printf("  %-20s %s (Host: %s)\n", "Pod IP:", r.PodIP, r.HostIP)
		fmt.Printf("  %-20s %s\n", "ServiceAccount:", yellow(r.ServiceAccount))
		fmt.Printf("  %-20s %s\n", "Status:", r.Phase)
		fmt.Printf("  %-20s %s\n", "Created:", r.CreationTimestamp)

		// 解析容器信息并输出
		if r.Containers != "" {
			var containers []kubeletutil.ContainerInfo
			if err := json.Unmarshal([]byte(r.Containers), &containers); err == nil {
				fmt.Printf("\n  %s\n", cyan("容器列表:"))
				for _, c := range containers {
					fmt.Printf("  ├─ %s\n", magenta(c.Name))
					fmt.Printf("  │  %-16s %s\n", "Image:", c.Image)

					// 安全上下文 - 全部输出，关键项标注
					fmt.Printf("  │  %s\n", "Security Context:")
					if c.Privileged {
						fmt.Printf("  │    %s privileged: %s\n", red("★"), red("true [特权容器]"))
					} else {
						fmt.Printf("  │    privileged: false\n")
					}
					if c.AllowPrivilegeEscalation {
						fmt.Printf("  │    %s allowPrivilegeEscalation: %s\n", yellow("★"), yellow("true [可提权]"))
					} else {
						fmt.Printf("  │    allowPrivilegeEscalation: false\n")
					}
					if c.RunAsUser != nil {
						if *c.RunAsUser == 0 {
							fmt.Printf("  │    %s runAsUser: %s\n", red("★"), red("0 [root]"))
						} else {
							fmt.Printf("  │    runAsUser: %d\n", *c.RunAsUser)
						}
					}
					if c.RunAsGroup != nil {
						fmt.Printf("  │    runAsGroup: %d\n", *c.RunAsGroup)
					}
					if c.ReadOnlyRootFilesystem {
						fmt.Printf("  │    readOnlyRootFilesystem: %s\n", green("true"))
					} else {
						fmt.Printf("  │    readOnlyRootFilesystem: false\n")
					}

					// 挂载点 - 全部输出，敏感路径标注
					if len(c.VolumeMounts) > 0 {
						fmt.Printf("  │  %s\n", "Volume Mounts:")
						for _, mp := range c.VolumeMounts {
							// 使用工具函数检查敏感路径
							if kubeletutil.IsSensitivePath(mp) {
								fmt.Printf("  │    %s %s\n", yellow("→"), yellow(mp+" [敏感路径]"))
							} else {
								fmt.Printf("  │    → %s\n", mp)
							}
						}
					}
				}
			}
		}

		// 解析卷信息并输出
		if r.Volumes != "" {
			var volumes []kubeletutil.SensitiveVolume
			if err := json.Unmarshal([]byte(r.Volumes), &volumes); err == nil && len(volumes) > 0 {
				fmt.Printf("\n  %s\n", cyan("敏感卷详情:"))
				for _, v := range volumes {
					switch v.Type {
					case "secret":
						fmt.Printf("  │ %s [Secret] %s\n", yellow("★"), yellow(v.SecretName))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "projected-secret":
						fmt.Printf("  │ %s [Projected Secret] %s\n", yellow("★"), yellow(v.SecretName))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "hostPath":
						fmt.Printf("  │ %s [HostPath] %s\n", red("★"), red(v.HostPath+" [主机目录]"))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "projected-sa-token":
						fmt.Printf("  │ %s [SA Token]\n", green("◆"))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "configMap":
						fmt.Printf("  │ ◇ [ConfigMap] %s\n", v.Name)
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "emptyDir":
						fmt.Printf("  │ ○ [EmptyDir] %s\n", v.Name)
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					default:
						fmt.Printf("  │ [%s] %s\n", v.Type, v.Name)
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					}
				}
			}
		}

		// 安全风险标记汇总 - 使用工具函数
		riskFlags := kubeletutil.GetRiskFlags(r)
		var coloredFlags []string
		for _, flag := range riskFlags {
			switch flag {
			case "PRIV", "HP", "ROOT":
				coloredFlags = append(coloredFlags, red(flag))
			case "PE", "SEC":
				coloredFlags = append(coloredFlags, yellow(flag))
			default:
				coloredFlags = append(coloredFlags, flag)
			}
		}

		if len(coloredFlags) > 0 {
			fmt.Printf("\n  %s %s\n", red("安全风险标记:"), strings.Join(coloredFlags, " "))
		}
	}

	// 输出图例说明
	fmt.Printf("\n%s\n", cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
	fmt.Printf("%s\n", "标记说明:")
	fmt.Printf("  %s PRIV  - 特权容器    %s PE   - 允许权限提升\n", red("★"), yellow("★"))
	fmt.Printf("  %s HP    - HostPath   %s SEC  - Secret 挂载\n", red("★"), yellow("★"))
	fmt.Printf("  %s 敏感路径            %s 安全配置\n", yellow("→"), green("✓"))
}

// listFromDB 从数据库列出 Pod
func listFromDB() {
	db, err := kubeletutil.NewPodDB(flagDBPath)
	if err != nil {
		log.Errorf("打开数据库失败: %v", err)
		Error.HandleFatal(err)
	}
	defer func() { _ = db.Close() }()

	var records []*kubeletutil.PodRecord

	switch flagListMode {
	case "all":
		if flagFilterNS != "" {
			records, err = db.GetPodsByNamespace(flagFilterNS)
		} else if flagFilterSA != "" {
			records, err = db.GetPodsByServiceAccount(flagFilterSA)
		} else {
			records, err = db.GetAllPods()
		}
	case "privileged":
		records, err = db.GetPrivilegedPods()
	case "secrets":
		records, err = db.GetPodsWithSecrets()
	case "hostpath":
		records, err = db.GetPodsWithHostPath()
	case "mounts":
		// 获取所有 Pod 然后展示挂载汇总
		records, err = db.GetAllPods()
		if err != nil {
			log.Errorf("查询数据库失败: %v", err)
			Error.HandleFatal(err)
		}
		printMountsView(records)
		return
	case "sa":
		listServiceAccounts(db)
		return
	case "ns":
		listNamespaces(db)
		return
	default:
		log.Errorf("未知的列表模式: %s", flagListMode)
		log.Info("可用模式: all, privileged, secrets, hostpath, mounts, sa, ns")
		Error.HandleFatal(fmt.Errorf("未知的列表模式: %s", flagListMode))
	}

	if err != nil {
		log.Errorf("查询数据库失败: %v", err)
		Error.HandleFatal(err)
	}

	if len(records) == 0 {
		log.Info("未找到匹配的 Pod")
		return
	}

	if flagShowDetails {
		printPodDetails(records)
	} else {
		printPodList(records)
	}
}

// printPodList 打印 Pod 列表
func printPodList(records []*kubeletutil.PodRecord) {
	red := color.New(color.FgRed).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	var data [][]string
	for _, r := range records {
		// 使用工具函数获取风险标记
		riskFlags := kubeletutil.GetRiskFlags(r)
		var coloredFlags []string
		for _, flag := range riskFlags {
			switch flag {
			case "PRIV", "HP", "ROOT":
				coloredFlags = append(coloredFlags, red(flag))
			case "PE", "SEC":
				coloredFlags = append(coloredFlags, yellow(flag))
			default:
				coloredFlags = append(coloredFlags, flag)
			}
		}
		flagStr := strings.Join(coloredFlags, ",")

		data = append(data, []string{
			r.Name,
			r.Namespace,
			r.ServiceAccount,
			r.PodIP,
			r.NodeName,
			flagStr,
		})
	}

	header := []string{"NAME", "NAMESPACE", "SERVICE ACCOUNT", "POD IP", "NODE", "FLAGS"}
	table := Print.Table{
		Header: header,
		Body:   data,
	}
	table.Print("")
	fmt.Printf("\nTotal: %d pods\n", len(records))
}

// printPodDetails 打印 Pod 详细信息
func printPodDetails(records []*kubeletutil.PodRecord) {
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	magenta := color.New(color.FgMagenta).SprintFunc()

	for i, r := range records {
		fmt.Printf("\n%s [%d/%d] %s/%s\n", cyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"), i+1, len(records), cyan(r.Namespace), cyan(r.Name))
		fmt.Printf("  %-18s %s\n", "UID:", r.UID)
		fmt.Printf("  %-18s %s\n", "Node:", r.NodeName)
		fmt.Printf("  %-18s %s (Host: %s)\n", "Pod IP:", r.PodIP, r.HostIP)
		fmt.Printf("  %-18s %s\n", "ServiceAccount:", yellow(r.ServiceAccount))
		fmt.Printf("  %-18s %s\n", "Status:", r.Phase)
		fmt.Printf("  %-18s %s\n", "Created:", r.CreationTimestamp)

		// 解析容器信息
		if r.Containers != "" {
			var containers []kubeletutil.ContainerInfo
			if err := json.Unmarshal([]byte(r.Containers), &containers); err == nil {
				fmt.Printf("\n  %s\n", cyan("【容器信息】"))
				for _, c := range containers {
					fmt.Printf("  ├─ %s\n", magenta(c.Name))
					fmt.Printf("  │  Image: %s\n", c.Image)

					// 安全上下文
					var secFlags []string
					if c.Privileged {
						secFlags = append(secFlags, red("PRIVILEGED"))
					}
					if c.AllowPrivilegeEscalation {
						secFlags = append(secFlags, yellow("AllowPrivilegeEscalation"))
					}
					if c.RunAsUser != nil {
						if *c.RunAsUser == 0 {
							secFlags = append(secFlags, red("root(uid=0)"))
						} else {
							secFlags = append(secFlags, fmt.Sprintf("uid=%d", *c.RunAsUser))
						}
					}
					if c.RunAsGroup != nil {
						secFlags = append(secFlags, fmt.Sprintf("gid=%d", *c.RunAsGroup))
					}
					if c.ReadOnlyRootFilesystem {
						secFlags = append(secFlags, green("ReadOnlyRootFS"))
					}

					if len(secFlags) > 0 {
						fmt.Printf("  │  Security: %s\n", strings.Join(secFlags, ", "))
					}

					// 挂载路径
					if len(c.VolumeMounts) > 0 {
						fmt.Printf("  │  %s\n", cyan("Mounts:"))
						for _, mp := range c.VolumeMounts {
							fmt.Printf("  │    → %s\n", mp)
						}
					}
				}
			}
		}

		// 解析卷信息 (敏感卷)
		if r.Volumes != "" {
			var volumes []kubeletutil.SensitiveVolume
			if err := json.Unmarshal([]byte(r.Volumes), &volumes); err == nil && len(volumes) > 0 {
				fmt.Printf("\n  %s\n", cyan("【敏感挂载】"))
				for _, v := range volumes {
					switch v.Type {
					case "secret":
						fmt.Printf("  │ %s Secret: %s\n", yellow("◆"), yellow(v.SecretName))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "projected-secret":
						fmt.Printf("  │ %s Projected Secret: %s\n", yellow("◆"), yellow(v.SecretName))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "hostPath":
						fmt.Printf("  │ %s HostPath: %s\n", red("★"), red(v.HostPath))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					case "projected-sa-token":
						fmt.Printf("  │ %s SA Token (projected)\n", green("◆"))
						fmt.Printf("  │   └─ 挂载到: %s\n", v.MountPath)
					default:
						fmt.Printf("  │ [%s] %s → %s\n", v.Type, v.Name, v.MountPath)
					}
				}
			}
		}
		fmt.Println()
	}
}

// printMountsView 专门展示挂载和 Secret 信息的视图
func printMountsView(records []*kubeletutil.PodRecord) {
	cyan := color.New(color.FgCyan).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()

	// 使用工具函数聚合 Secret 和 HostPath
	secretMap := kubeletutil.AggregateSecrets(records)
	hostPathMap := kubeletutil.AggregateHostPaths(records)

	// 打印 Secret 汇总
	fmt.Println()
	fmt.Printf("%s\n", cyan("═══════════════════════════════════════════════════════════════"))
	fmt.Printf("                    %s\n", yellow("Secret 挂载汇总"))
	fmt.Printf("%s\n", cyan("═══════════════════════════════════════════════════════════════"))

	if len(secretMap) == 0 {
		fmt.Println("  (未发现挂载的 Secret)")
	} else {
		// 按 secret 名称排序
		var secretNames []string
		for name := range secretMap {
			secretNames = append(secretNames, name)
		}
		sort.Strings(secretNames)

		for _, secretName := range secretNames {
			pods := secretMap[secretName]
			fmt.Printf("\n%s %s (%d pods)\n", yellow("◆"), yellow(secretName), len(pods))
			for _, pod := range pods {
				fmt.Printf("    └─ %s\n", pod)
			}
		}
	}

	// 打印 HostPath 汇总
	fmt.Println()
	fmt.Printf("%s\n", cyan("═══════════════════════════════════════════════════════════════"))
	fmt.Printf("                    %s\n", red("HostPath 挂载汇总"))
	fmt.Printf("%s\n", cyan("═══════════════════════════════════════════════════════════════"))

	if len(hostPathMap) == 0 {
		fmt.Println("  (未发现挂载的 HostPath)")
	} else {
		var hostPaths []string
		for path := range hostPathMap {
			hostPaths = append(hostPaths, path)
		}
		sort.Strings(hostPaths)

		for _, hostPath := range hostPaths {
			pods := hostPathMap[hostPath]
			fmt.Printf("\n%s %s (%d pods)\n", red("★"), red(hostPath), len(pods))
			for _, pod := range pods {
				fmt.Printf("    └─ %s\n", pod)
			}
		}
	}

	// 打印每个 Pod 的详细挂载
	fmt.Println()
	fmt.Printf("%s\n", cyan("═══════════════════════════════════════════════════════════════"))
	fmt.Printf("                    %s\n", green("各 Pod 挂载详情"))
	fmt.Printf("%s\n", cyan("═══════════════════════════════════════════════════════════════"))

	for _, r := range records {
		var hasInteresting bool

		// 检查是否有感兴趣的挂载
		if r.Volumes != "" {
			var volumes []kubeletutil.SensitiveVolume
			if err := json.Unmarshal([]byte(r.Volumes), &volumes); err == nil && len(volumes) > 0 {
				hasInteresting = true
			}
		}

		if !hasInteresting {
			continue
		}

		fmt.Printf("\n%s %s/%s\n", cyan("●"), r.Namespace, r.Name)
		fmt.Printf("  ServiceAccount: %s\n", yellow(r.ServiceAccount))

		// 容器挂载点
		if r.Containers != "" {
			var containers []kubeletutil.ContainerInfo
			if err := json.Unmarshal([]byte(r.Containers), &containers); err == nil {
				for _, c := range containers {
					if len(c.VolumeMounts) > 0 {
						fmt.Printf("  Container [%s] mounts:\n", c.Name)
						for _, mp := range c.VolumeMounts {
							// 使用工具函数检查敏感路径
							if kubeletutil.IsSensitivePath(mp) {
								fmt.Printf("    %s %s\n", yellow("→"), mp)
							} else {
								fmt.Printf("      → %s\n", mp)
							}
						}
					}
				}
			}
		}

		// 敏感卷详情
		if r.Volumes != "" {
			var volumes []kubeletutil.SensitiveVolume
			if err := json.Unmarshal([]byte(r.Volumes), &volumes); err == nil {
				fmt.Println("  Sensitive volumes:")
				for _, v := range volumes {
					switch v.Type {
					case "secret":
						fmt.Printf("    %s [Secret] %s → %s\n", yellow("◆"), v.SecretName, v.MountPath)
					case "projected-secret":
						fmt.Printf("    %s [Projected Secret] %s → %s\n", yellow("◆"), v.SecretName, v.MountPath)
					case "hostPath":
						fmt.Printf("    %s [HostPath] %s → %s\n", red("★"), v.HostPath, v.MountPath)
					case "projected-sa-token":
						fmt.Printf("    %s [SA Token] → %s\n", green("◆"), v.MountPath)
					}
				}
			}
		}
	}

	fmt.Printf("\nTotal: %d secrets, %d hostPaths\n", len(secretMap), len(hostPathMap))
}

// listServiceAccounts 列出所有 ServiceAccount
func listServiceAccounts(db *kubeletutil.PodDB) {
	sas, err := db.GetServiceAccounts()
	if err != nil {
		log.Errorf("查询 ServiceAccount 失败: %v", err)
		Error.HandleFatal(err)
	}

	fmt.Println("ServiceAccounts in database:")
	for _, sa := range sas {
		fmt.Printf("  - %s\n", sa)
	}
	fmt.Printf("\nTotal: %d\n", len(sas))
}

// listNamespaces 列出所有命名空间
func listNamespaces(db *kubeletutil.PodDB) {
	namespaces, err := db.GetNamespaces()
	if err != nil {
		log.Errorf("查询命名空间失败: %v", err)
		Error.HandleFatal(err)
	}

	fmt.Println("Namespaces in database:")
	for _, ns := range namespaces {
		fmt.Printf("  - %s\n", ns)
	}
	fmt.Printf("\nTotal: %d\n", len(namespaces))
}

// clearDatabase 清空数据库
func clearDatabase() {
	db, err := kubeletutil.NewPodDB(flagDBPath)
	if err != nil {
		log.Errorf("打开数据库失败: %v", err)
		Error.HandleFatal(err)
	}
	defer func() { _ = db.Close() }()

	count, _ := db.GetPodCount()
	if err := db.ClearAll(); err != nil {
		log.Errorf("清空数据库失败: %v", err)
		Error.HandleFatal(err)
	}

	green := color.New(color.FgGreen).SprintFunc()
	fmt.Printf("%s 已清空 %d 条记录\n", green("✓"), count)
}
