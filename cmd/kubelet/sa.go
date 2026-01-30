package kubelet

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	Error "kctl/utils/Error"
	"kctl/utils/Print"
	kubeletutil "kctl/utils/kubelet"

	"github.com/fatih/color"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// sa 子命令的 flags
var (
	flagSADBPath    string // 数据库路径
	flagSARisky     bool   // 只显示有风险的 SA
	flagSAAdmin     bool   // 只显示集群管理员
	flagSANamespace string // 按命名空间过滤
	flagSAName      string // 按名称过滤
	flagSAShowToken bool   // 显示完整 Token
	flagSAShowPerms bool   // 显示权限详情
	flagSAShowPods  bool   // 显示关联 Pod
	flagSAStats     bool   // 显示统计信息
)

// 颜色打印函数
var (
	cRed    = color.New(color.FgRed).PrintfFunc()
	cYellow = color.New(color.FgYellow).PrintfFunc()
	cGreen  = color.New(color.FgGreen).PrintfFunc()
	cCyan   = color.New(color.FgCyan).PrintfFunc()
	cWhite  = color.New(color.FgWhite).PrintfFunc()
)

// saCmd 是 sa 子命令，查看数据库中的 ServiceAccount 信息
var saCmd = &cobra.Command{
	Use:   "sa",
	Short: "查看已收集的 ServiceAccount 信息",
	Long: `查看数据库中保存的 ServiceAccount 信息

此命令会读取数据库中保存的 ServiceAccount 数据并展示：
  - 基本信息：名称、命名空间、风险等级
  - Token 信息：过期时间、是否已过期
  - 权限信息：RBAC 权限列表（使用 --perms 显示）
  - 关联 Pod：使用该 SA 的 Pod 列表（使用 --pods 显示）

过滤选项：
  --risky      只显示有风险的 SA（ADMIN/CRITICAL/HIGH/MEDIUM）
  --admin      只显示集群管理员级别的 SA
  --namespace  按命名空间过滤
  --name       按 SA 名称过滤

示例：
  # 查看所有 SA
  kubelet sa

  # 只查看有风险的 SA
  kubelet sa --risky

  # 只查看集群管理员
  kubelet sa --admin

  # 按命名空间过滤
  kubelet sa --namespace kube-system

  # 查看特定 SA 的详细信息
  kubelet sa --namespace default --name my-sa --perms --pods

  # 显示统计信息
  kubelet sa --stats

  # 指定数据库路径
  kubelet sa --db /tmp/sa_tokens.db`,
	Run: runSA,
}

func init() {
	KubeletCmd.AddCommand(saCmd)

	saCmd.Flags().StringVar(&flagSADBPath, "db", "", "数据库文件路径 (默认: kubelet_pods.db)")
	saCmd.Flags().BoolVarP(&flagSARisky, "risky", "r", false, "只显示有风险的 ServiceAccount")
	saCmd.Flags().BoolVarP(&flagSAAdmin, "admin", "a", false, "只显示集群管理员级别的 ServiceAccount")
	saCmd.Flags().StringVarP(&flagSANamespace, "namespace", "n", "", "按命名空间过滤")
	saCmd.Flags().StringVar(&flagSAName, "name", "", "按 SA 名称过滤（需配合 --namespace 使用）")
	saCmd.Flags().BoolVarP(&flagSAShowToken, "token", "t", false, "显示完整 Token")
	saCmd.Flags().BoolVarP(&flagSAShowPerms, "perms", "p", false, "显示权限详情")
	saCmd.Flags().BoolVar(&flagSAShowPods, "pods", false, "显示关联的 Pod 列表")
	saCmd.Flags().BoolVarP(&flagSAStats, "stats", "s", false, "显示统计信息")
}

func runSA(cmd *cobra.Command, args []string) {
	// 确定数据库路径
	dbPath := flagSADBPath
	if dbPath == "" {
		dbPath = kubeletutil.DefaultDBPath()
	}

	// 检查数据库文件是否存在
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		cRed("数据库文件不存在: %s\n", dbPath)
		cYellow("提示: 请先运行 'kubelet scan' 扫描并保存 ServiceAccount 信息\n")
		cWhite("或者使用 --db 参数指定正确的数据库路径\n")
		return
	}

	fmt.Printf("使用数据库: %s\n", dbPath)

	// 打开数据库
	db, err := kubeletutil.NewPodDB(dbPath)
	if err != nil {
		fmt.Printf("打开数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// 如果只显示统计信息
	if flagSAStats {
		showSAStats(db)
		return
	}

	// 获取 SA 列表
	var sas []*kubeletutil.ServiceAccountRecord
	var queryErr error

	if flagSAName != "" && flagSANamespace != "" {
		// 查询特定 SA
		sa, err := db.GetServiceAccountByName(flagSANamespace, flagSAName)
		if err != nil {
			fmt.Printf("查询 ServiceAccount 失败: %v\n", err)
			os.Exit(1)
		}
		if sa == nil {
			cRed("未找到 ServiceAccount: %s/%s\n", flagSANamespace, flagSAName)
			return
		}
		sas = []*kubeletutil.ServiceAccountRecord{sa}
	} else if flagSAAdmin {
		// 只显示集群管理员
		sas, queryErr = db.GetClusterAdminServiceAccounts()
		if queryErr != nil {
			fmt.Printf("查询集群管理员 ServiceAccount 失败: %v\n", queryErr)
			os.Exit(1)
		}
	} else if flagSARisky {
		// 只显示有风险的
		sas, queryErr = db.GetRiskyServiceAccounts()
		if queryErr != nil {
			fmt.Printf("查询有风险的 ServiceAccount 失败: %v\n", queryErr)
			os.Exit(1)
		}
	} else {
		// 获取所有
		sas, queryErr = db.GetAllServiceAccounts()
		if queryErr != nil {
			fmt.Printf("查询 ServiceAccount 失败: %v\n", queryErr)
			os.Exit(1)
		}
	}

	fmt.Printf("查询到 %d 条记录\n", len(sas))

	// 按命名空间过滤
	if flagSANamespace != "" && flagSAName == "" {
		filtered := make([]*kubeletutil.ServiceAccountRecord, 0)
		for _, sa := range sas {
			if sa.Namespace == flagSANamespace {
				filtered = append(filtered, sa)
			}
		}
		sas = filtered
	}

	if len(sas) == 0 {
		cYellow("数据库中没有找到 ServiceAccount 记录\n")
		cWhite("提示: 运行 'kubelet scan' 扫描并保存 ServiceAccount 信息\n")
		return
	}

	// 显示结果
	displayServiceAccounts(sas)
}

// showSAStats 显示统计信息
func showSAStats(db *kubeletutil.PodDB) {
	stats, err := db.GetServiceAccountStats()
	if err != nil {
		log.Errorf("获取统计信息失败: %v", err)
		Error.HandleFatal(err)
	}

	total, err := db.GetServiceAccountCount()
	if err != nil {
		log.Errorf("获取总数失败: %v", err)
		Error.HandleFatal(err)
	}

	cCyan("\n==================== ServiceAccount 统计 ====================\n\n")

	cWhite("总数: %d\n\n", total)

	cWhite("按风险等级统计:\n")
	cRed("  ★ ADMIN (集群管理员): %d\n", stats["ADMIN"])
	cRed("  ★ CRITICAL (严重):    %d\n", stats["CRITICAL"])
	cYellow("  ★ HIGH (高危):        %d\n", stats["HIGH"])
	cYellow("  ★ MEDIUM (中危):      %d\n", stats["MEDIUM"])
	cGreen("  ○ LOW (低危):         %d\n", stats["LOW"])
	cWhite("  ○ NONE (无风险):      %d\n", stats["NONE"])

	fmt.Println()
}

// displayServiceAccounts 显示 ServiceAccount 列表
func displayServiceAccounts(sas []*kubeletutil.ServiceAccountRecord) {
	cCyan("\n==================== ServiceAccount 列表 ====================\n\n")
	cWhite("共 %d 个 ServiceAccount\n\n", len(sas))

	for i, sa := range sas {
		displaySingleSA(sa, i+1, len(sas))
	}
}

// displaySingleSA 显示单个 ServiceAccount 详情
func displaySingleSA(sa *kubeletutil.ServiceAccountRecord, index, total int) {
	// 标题行
	cCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	cWhite("[%d/%d] ", index, total)

	// 风险等级标识
	switch sa.RiskLevel {
	case "ADMIN":
		cRed("★ 集群管理员 ")
	case "CRITICAL":
		cRed("★ CRITICAL ")
	case "HIGH":
		cYellow("★ HIGH ")
	case "MEDIUM":
		cYellow("★ MEDIUM ")
	case "LOW":
		cGreen("○ LOW ")
	default:
		cWhite("○ NONE ")
	}

	cWhite("%s/%s\n", sa.Namespace, sa.Name)
	cCyan("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// 基本信息
	cWhite("  命名空间:   %s\n", sa.Namespace)
	cWhite("  名称:       %s\n", sa.Name)
	cWhite("  风险等级:   ")
	printRiskLevel(sa.RiskLevel)
	fmt.Println()

	// Token 过期信息
	if sa.TokenExpiration != "" {
		cWhite("  Token过期:  %s", sa.TokenExpiration)
		if sa.IsExpired {
			cRed(" [已过期]\n")
		} else {
			cGreen(" [有效]\n")
		}
	}

	// 集群管理员标识
	if sa.IsClusterAdmin {
		cRed("  管理员权限: 是 (拥有 * / * 通配符权限)\n")
	}

	// 收集信息
	cWhite("  收集时间:   %s\n", sa.CollectedAt.Format("2006-01-02 15:04:05"))
	if sa.KubeletIP != "" {
		cWhite("  来源节点:   %s\n", sa.KubeletIP)
	}

	// 显示 Token
	if flagSAShowToken && sa.Token != "" {
		cWhite("\n  Token:\n")
		cYellow("  %s\n", sa.Token)
	} else if sa.Token != "" {
		tokenPreview := sa.Token
		if len(tokenPreview) > 50 {
			tokenPreview = tokenPreview[:50] + "..."
		}
		cWhite("  Token:      %s (使用 --token 显示完整内容)\n", tokenPreview)
	}

	// 显示安全标识
	if sa.SecurityFlags != "" {
		var flags kubeletutil.SASecurityFlags
		if err := json.Unmarshal([]byte(sa.SecurityFlags), &flags); err == nil {
			if flags.Privileged || flags.AllowPrivilegeEscalation || flags.HasHostPath || flags.HasSecretMount {
				cWhite("\n  安全标识:\n")
				if flags.Privileged {
					cRed("    ⚠ 特权容器\n")
				}
				if flags.AllowPrivilegeEscalation {
					cYellow("    ⚠ 允许权限提升\n")
				}
				if flags.HasHostPath {
					cYellow("    ⚠ 挂载主机路径\n")
				}
				if flags.HasSecretMount {
					cYellow("    ⚠ 挂载 Secret\n")
				}
			}
		}
	}

	// 显示权限（默认显示）
	if sa.Permissions != "" {
		displayPermissions(sa)
	}

	// 显示关联 Pod
	if flagSAShowPods && sa.Pods != "" {
		displayPods(sa)
	}

	fmt.Println()
}

// printRiskLevel 打印风险等级（带颜色）
func printRiskLevel(level string) {
	switch level {
	case "ADMIN":
		cRed("集群管理员")
	case "CRITICAL":
		cRed("CRITICAL (严重)")
	case "HIGH":
		cYellow("HIGH (高危)")
	case "MEDIUM":
		cYellow("MEDIUM (中危)")
	case "LOW":
		cGreen("LOW (低危)")
	default:
		cWhite("NONE (无风险)")
	}
}

// displayPermissions 显示权限详情
func displayPermissions(sa *kubeletutil.ServiceAccountRecord) {
	cWhite("\n  权限列表:\n")

	// 如果是集群管理员，简化显示
	if sa.IsClusterAdmin {
		cRed("    ★ 集群管理员权限 (cluster-admin)\n")
		cRed("    ★ 拥有所有资源的所有操作权限 (* / *)\n")
		return
	}

	var permissions []kubeletutil.SAPermission
	if err := json.Unmarshal([]byte(sa.Permissions), &permissions); err != nil {
		cYellow("    (解析权限失败)\n")
		return
	}

	if len(permissions) == 0 {
		cWhite("    (无权限)\n")
		return
	}

	// 按资源分组显示
	resourcePerms := make(map[string][]string)
	for _, perm := range permissions {
		if perm.Allowed {
			key := perm.Resource
			if perm.Subresource != "" {
				key = fmt.Sprintf("%s/%s", perm.Resource, perm.Subresource)
			}
			resourcePerms[key] = append(resourcePerms[key], perm.Verb)
		}
	}

	for resource, verbs := range resourcePerms {
		fmt.Printf("    %s: %s\n", Print.White(resource), Print.Green(strings.Join(verbs, ", ")))
	}
}

// displayPods 显示关联的 Pod
func displayPods(sa *kubeletutil.ServiceAccountRecord) {
	cWhite("\n  关联 Pod:\n")

	var pods []kubeletutil.SAPodInfo
	if err := json.Unmarshal([]byte(sa.Pods), &pods); err != nil {
		cYellow("    (解析 Pod 列表失败)\n")
		return
	}

	if len(pods) == 0 {
		cWhite("    (无关联 Pod)\n")
		return
	}

	for _, pod := range pods {
		cWhite("    - %s/%s", pod.Namespace, pod.Name)
		if pod.Container != "" {
			cWhite(" (容器: %s)", pod.Container)
		}
		fmt.Println()
	}
}
