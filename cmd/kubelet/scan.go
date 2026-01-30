package kubelet

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	Error "kctl/utils/Error"
	"kctl/utils/Print"
	kubeletutil "kctl/utils/kubelet"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// scan 子命令的 flags
var (
	flagScanConcurrent int    // 并发数
	flagScanOnlyRisky  bool   // 只显示有风险权限的 SA
	flagScanSave       bool   // 是否保存到数据库
	flagScanDBPath     string // 数据库路径
)

// scanCmd 是 scan 子命令，扫描所有 Pod 的 SA Token 权限
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "扫描所有 Pod 的 ServiceAccount 权限",
	Long: `扫描所有 Pod 中绑定的 ServiceAccount Token 权限

此命令会：
  1. 获取节点上所有 Running 状态的 Pod
  2. 过滤出挂载了 SA Token 的 Pod
  3. 通过 exec 读取每个 Pod 中的 Token
  4. 使用 Token 查询 K8s API Server 的 RBAC 权限
  5. 标记高危/可利用的权限
  6. 默认保存到数据库 (使用 --save=false 禁用)

高危权限标记：
  ★ CRITICAL - 集群管理员级别权限（如 * 资源）
  ★ HIGH     - 可导致权限提升或敏感信息泄露
  ★ MEDIUM   - 可能被滥用的权限

示例：
  # 扫描所有 Pod 的 SA 权限（默认保存到数据库）
  kubelet scan

  # 只显示有风险权限的 SA
  kubelet scan --risky

  # 设置并发数为 5
  kubelet scan --concurrent 5

  # 不保存到数据库
  kubelet scan --save=false

  # 指定数据库路径
  kubelet scan --db /tmp/sa_tokens.db`,
	Run: runScan,
}

func init() {
	KubeletCmd.AddCommand(scanCmd)

	scanCmd.Flags().IntVarP(&flagScanConcurrent, "concurrent", "C", 3, "并发扫描数量")
	scanCmd.Flags().BoolVarP(&flagScanOnlyRisky, "risky", "r", false, "只显示有风险权限的 ServiceAccount")
	scanCmd.Flags().BoolVarP(&flagScanSave, "save", "s", true, "保存扫描结果到数据库 (默认开启)")
	scanCmd.Flags().StringVar(&flagScanDBPath, "db", "", "数据库文件路径 (默认: kubelet_pods.db)")
}

// SATokenResult 表示 SA Token 扫描结果
type SATokenResult struct {
	Namespace      string
	PodName        string
	Container      string
	ServiceAccount string
	Token          string
	TokenInfo      *kubeletutil.TokenInfo
	Permissions    []kubeletutil.PermissionCheck
	SecurityFlags  kubeletutil.SecurityFlags
	RiskLevel      string // CRITICAL, HIGH, MEDIUM, LOW, NONE
	IsClusterAdmin bool   // 是否是集群管理员
	Error          string
}

// 风险等级常量
const (
	RiskCritical = "CRITICAL"
	RiskHigh     = "HIGH"
	RiskMedium   = "MEDIUM"
	RiskLow      = "LOW"
	RiskNone     = "NONE"
	RiskAdmin    = "ADMIN" // 集群管理员
)

// 高危权限定义
var criticalPermissions = map[string][]string{
	"*":                   {"*"},                                                  // 所有资源所有操作
	"secrets":             {"get", "list", "watch", "create", "*"},                // secrets 读写
	"pods":                {"create", "*"},                                        // 创建 Pod
	"pods/exec":           {"create", "*"},                                        // Pod exec
	"clusterroles":        {"create", "update", "patch", "bind", "escalate", "*"}, // RBAC 修改
	"clusterrolebindings": {"create", "update", "patch", "*"},
	"roles":               {"create", "update", "patch", "bind", "escalate", "*"},
	"rolebindings":        {"create", "update", "patch", "*"},
	"serviceaccounts":     {"create", "impersonate", "*"},
	"nodes":               {"proxy", "*"},
	"nodes/proxy":         {"create", "get", "*"},
}

var highPermissions = map[string][]string{
	"configmaps":             {"get", "list", "create", "update", "*"},
	"deployments":            {"create", "update", "patch", "*"},
	"daemonsets":             {"create", "update", "patch", "*"},
	"cronjobs":               {"create", "update", "*"},
	"jobs":                   {"create", "*"},
	"pods/log":               {"get", "*"},
	"persistentvolumeclaims": {"create", "*"},
	"persistentvolumes":      {"create", "*"},
	"serviceaccounts/token":  {"create", "*"},
}

var mediumPermissions = map[string][]string{
	"services":        {"create", "update", "*"},
	"endpoints":       {"create", "update", "*"},
	"ingresses":       {"create", "update", "*"},
	"networkpolicies": {"create", "update", "delete", "*"},
}

func runScan(cmd *cobra.Command, args []string) {
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

	log.Infof("从 Kubelet %s:%d 获取 Pod 列表...", ip, port)

	// 获取所有 Pod
	pods, err := kubeletutil.FetchPodsWithContainersProxy(ip, port, token, ProxyURL)
	if err != nil {
		log.Errorf("获取 Pod 列表失败: %v", err)
		Error.HandleFatal(err)
	}

	// 过滤 Running 状态且挂载了 SA Token 的 Pod
	var targetPods []kubeletutil.PodContainerInfo
	for _, p := range pods {
		if p.Status == "Running" && p.SecurityFlags.HasSATokenMount {
			targetPods = append(targetPods, p)
		}
	}

	if len(targetPods) == 0 {
		log.Warn("没有找到挂载 SA Token 的 Running Pod")
		return
	}

	Print.PrintTitleWide("ServiceAccount 权限扫描")
	fmt.Printf("  目标 Pod 数量: %d (共 %d 个 Pod)\n", len(targetPods), len(pods))
	fmt.Printf("  并发数: %d\n", flagScanConcurrent)
	if flagScanSave {
		dbPath := flagScanDBPath
		if dbPath == "" {
			dbPath = kubeletutil.DefaultDBPath()
		}
		fmt.Printf("  保存到数据库: %s\n", Print.Green(dbPath))
	}
	fmt.Println()

	// 并发扫描
	results := make(chan SATokenResult, len(targetPods))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, flagScanConcurrent)

	for _, pod := range targetPods {
		wg.Add(1)
		go func(p kubeletutil.PodContainerInfo) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := scanPodToken(ip, port, token, p)
			results <- result
		}(pod)
	}

	// 等待所有扫描完成
	go func() {
		wg.Wait()
		close(results)
	}()

	// 收集结果
	var allResults []SATokenResult
	for result := range results {
		allResults = append(allResults, result)
	}

	// 按风险等级排序
	sortByRisk(allResults)

	// 统计
	stats := map[string]int{
		RiskAdmin:    0,
		RiskCritical: 0,
		RiskHigh:     0,
		RiskMedium:   0,
		RiskLow:      0,
		RiskNone:     0,
	}

	// 打印结果
	fmt.Println()
	Print.PrintSeparatorWide()

	printedCount := 0
	for _, result := range allResults {
		if result.Error != "" {
			continue
		}

		// 统计风险等级
		if result.IsClusterAdmin {
			stats[RiskAdmin]++
		} else {
			stats[result.RiskLevel]++
		}

		// 如果只显示有风险的，跳过无风险的
		if flagScanOnlyRisky && result.RiskLevel == RiskNone && !result.IsClusterAdmin {
			continue
		}

		printScanResult(result)
		printedCount++
	}

	// 保存到数据库
	if flagScanSave {
		savedCount, err := saveResultsToDB(allResults, ip)
		if err != nil {
			log.Errorf("保存到数据库失败: %v", err)
			Error.HandleError(err)
		} else {
			fmt.Println()
			Print.PrintSeparatorWide()
			fmt.Printf("\n  %s 已保存 %d 个 ServiceAccount 到数据库\n", Print.Green("✓"), savedCount)
		}
	}

	// 打印统计
	fmt.Println()
	Print.PrintSeparatorWide()
	fmt.Println()
	Print.PrintSection("扫描统计")
	if stats[RiskAdmin] > 0 {
		fmt.Printf("  %s: %d\n", Print.Red("⚠ ADMIN (集群管理员)"), stats[RiskAdmin])
	}
	fmt.Printf("  %s: %d\n", Print.Red("★ CRITICAL"), stats[RiskCritical])
	fmt.Printf("  %s: %d\n", Print.ColorWarning.Sprint("★ HIGH"), stats[RiskHigh])
	fmt.Printf("  %s: %d\n", Print.Yellow("★ MEDIUM"), stats[RiskMedium])
	fmt.Printf("  %s: %d\n", Print.Muted("○ LOW/NONE"), stats[RiskLow]+stats[RiskNone])
	fmt.Printf("\n  共扫描: %d 个 ServiceAccount\n", len(allResults))

	// 打印图例
	fmt.Println()
	Print.PrintSection("风险等级说明")
	fmt.Printf("  %s - 集群管理员权限，可完全控制集群\n", Print.Red("⚠ ADMIN"))
	fmt.Printf("  %s - 高危权限，接近管理员级别\n", Print.Red("★ CRITICAL"))
	fmt.Printf("  %s - 可权限提升或泄露敏感信息\n", Print.ColorWarning.Sprint("★ HIGH"))
	fmt.Printf("  %s - 可能被滥用的权限\n", Print.Yellow("★ MEDIUM"))
}

// saveResultsToDB 保存扫描结果到数据库
func saveResultsToDB(results []SATokenResult, kubeletIP string) (int, error) {
	dbPath := flagScanDBPath
	if dbPath == "" {
		dbPath = kubeletutil.DefaultDBPath()
	}

	db, err := kubeletutil.NewPodDB(dbPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()

	// 聚合相同 SA 的 Pod
	saMap := make(map[string]*kubeletutil.ServiceAccountRecord)

	for _, result := range results {
		if result.Error != "" || result.ServiceAccount == "" {
			continue
		}

		key := fmt.Sprintf("%s/%s", result.TokenInfo.Namespace, result.ServiceAccount)

		if existing, ok := saMap[key]; ok {
			// 追加 Pod 信息
			var pods []kubeletutil.SAPodInfo
			if existing.Pods != "" {
				_ = json.Unmarshal([]byte(existing.Pods), &pods)
			}
			pods = append(pods, kubeletutil.SAPodInfo{
				Name:      result.PodName,
				Namespace: result.Namespace,
				Container: result.Container,
			})
			podsJSON, _ := json.Marshal(pods)
			existing.Pods = string(podsJSON)
		} else {
			// 创建新记录
			record := &kubeletutil.ServiceAccountRecord{
				Name:           result.ServiceAccount,
				Namespace:      result.TokenInfo.Namespace,
				Token:          result.Token,
				IsClusterAdmin: result.IsClusterAdmin,
				CollectedAt:    time.Now(),
				KubeletIP:      kubeletIP,
			}

			// Token 过期时间
			if result.TokenInfo != nil && !result.TokenInfo.Expiration.IsZero() {
				record.TokenExpiration = result.TokenInfo.Expiration.Format(time.RFC3339)
				record.IsExpired = result.TokenInfo.IsExpired
			}

			// 风险等级
			if result.IsClusterAdmin {
				record.RiskLevel = RiskAdmin
			} else {
				record.RiskLevel = result.RiskLevel
			}

			// 权限列表
			var permissions []kubeletutil.SAPermission
			for _, p := range result.Permissions {
				if p.Allowed {
					permissions = append(permissions, kubeletutil.SAPermission{
						Resource:    p.Resource,
						Verb:        p.Verb,
						Group:       p.Group,
						Subresource: p.Subresource,
						Allowed:     p.Allowed,
					})
				}
			}
			permJSON, _ := json.Marshal(permissions)
			record.Permissions = string(permJSON)

			// 安全标识
			secFlags := kubeletutil.SASecurityFlags{
				Privileged:               result.SecurityFlags.Privileged,
				AllowPrivilegeEscalation: result.SecurityFlags.AllowPrivilegeEscalation,
				HasHostPath:              result.SecurityFlags.HasHostPath,
				HasSecretMount:           result.SecurityFlags.HasSecretMount,
				HasSATokenMount:          result.SecurityFlags.HasSATokenMount,
			}
			secFlagsJSON, _ := json.Marshal(secFlags)
			record.SecurityFlags = string(secFlagsJSON)

			// Pod 信息
			pods := []kubeletutil.SAPodInfo{{
				Name:      result.PodName,
				Namespace: result.Namespace,
				Container: result.Container,
			}}
			podsJSON, _ := json.Marshal(pods)
			record.Pods = string(podsJSON)

			saMap[key] = record
		}
	}

	// 转换为切片并保存
	var records []*kubeletutil.ServiceAccountRecord
	for _, record := range saMap {
		records = append(records, record)
	}

	return db.SaveServiceAccounts(records)
}

// scanPodToken 扫描单个 Pod 的 Token 权限
func scanPodToken(kubeletIP string, kubeletPort int, kubeletToken string, pod kubeletutil.PodContainerInfo) SATokenResult {
	result := SATokenResult{
		Namespace:     pod.Namespace,
		PodName:       pod.PodName,
		RiskLevel:     RiskNone,
		SecurityFlags: pod.SecurityFlags, // 复制安全标识
	}

	// 选择第一个容器
	if len(pod.Containers) == 0 {
		result.Error = "Pod 没有容器"
		return result
	}
	result.Container = pod.Containers[0]

	// 读取 Token
	command := []string{"cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"}
	opts := &kubeletutil.ExecOptions{
		IP:        kubeletIP,
		Port:      kubeletPort,
		Token:     kubeletToken,
		Namespace: pod.Namespace,
		Pod:       pod.PodName,
		Container: result.Container,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}

	execResult, err := kubeletutil.ExecInPod(opts)
	if err != nil {
		result.Error = fmt.Sprintf("exec 失败: %v", err)
		return result
	}

	if execResult.Error != "" {
		result.Error = fmt.Sprintf("读取 Token 失败: %s", execResult.Error)
		return result
	}

	result.Token = strings.TrimSpace(execResult.Stdout)
	if result.Token == "" {
		result.Error = "Token 为空"
		return result
	}

	// 解析 Token 信息
	tokenInfo, err := kubeletutil.ParseTokenInfo(result.Token)
	if err != nil {
		result.Error = fmt.Sprintf("解析 Token 失败: %v", err)
		return result
	}
	result.TokenInfo = tokenInfo
	result.ServiceAccount = tokenInfo.ServiceAccount

	// 检查权限
	permissions, err := kubeletutil.CheckCommonPermissions(result.Token, "", tokenInfo.Namespace)
	if err != nil {
		result.Error = fmt.Sprintf("检查权限失败: %v", err)
		return result
	}
	result.Permissions = permissions

	// 检查是否是集群管理员
	result.IsClusterAdmin = isClusterAdmin(permissions)

	// 计算风险等级
	if result.IsClusterAdmin {
		result.RiskLevel = RiskAdmin
	} else {
		result.RiskLevel = calculateRiskLevel(permissions)
	}

	return result
}

// calculateRiskLevel 计算权限的风险等级
func calculateRiskLevel(permissions []kubeletutil.PermissionCheck) string {
	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		resource := p.Resource
		if p.Subresource != "" {
			resource = p.Resource + "/" + p.Subresource
		}

		// 检查 CRITICAL 权限
		if verbs, ok := criticalPermissions[resource]; ok {
			for _, v := range verbs {
				if v == p.Verb || v == "*" {
					return RiskCritical
				}
			}
		}
		// 通配符资源
		if p.Resource == "*" {
			return RiskCritical
		}
	}

	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		resource := p.Resource
		if p.Subresource != "" {
			resource = p.Resource + "/" + p.Subresource
		}

		// 检查 HIGH 权限
		if verbs, ok := highPermissions[resource]; ok {
			for _, v := range verbs {
				if v == p.Verb || v == "*" {
					return RiskHigh
				}
			}
		}
	}

	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		resource := p.Resource
		if p.Subresource != "" {
			resource = p.Resource + "/" + p.Subresource
		}

		// 检查 MEDIUM 权限
		if verbs, ok := mediumPermissions[resource]; ok {
			for _, v := range verbs {
				if v == p.Verb || v == "*" {
					return RiskMedium
				}
			}
		}
	}

	// 检查是否有任何允许的权限
	for _, p := range permissions {
		if p.Allowed {
			return RiskLow
		}
	}

	return RiskNone
}

// sortByRisk 按风险等级排序
func sortByRisk(results []SATokenResult) {
	riskOrder := map[string]int{
		RiskAdmin:    0, // 管理员最高优先级
		RiskCritical: 1,
		RiskHigh:     2,
		RiskMedium:   3,
		RiskLow:      4,
		RiskNone:     5,
	}

	sort.Slice(results, func(i, j int) bool {
		// 先按 IsClusterAdmin 排序，管理员优先
		if results[i].IsClusterAdmin != results[j].IsClusterAdmin {
			return results[i].IsClusterAdmin
		}
		return riskOrder[results[i].RiskLevel] < riskOrder[results[j].RiskLevel]
	})
}

// isClusterAdmin 检查是否拥有集群管理员权限 (通配符权限 * / *)
func isClusterAdmin(permissions []kubeletutil.PermissionCheck) bool {
	for _, p := range permissions {
		if p.Allowed && p.Resource == "*" && p.Verb == "*" {
			return true
		}
	}
	return false
}

// printScanResult 打印扫描结果
func printScanResult(result SATokenResult) {
	// 风险等级标签
	var riskLabel string
	if result.IsClusterAdmin {
		riskLabel = Print.Red("⚠ ADMIN")
	} else {
		switch result.RiskLevel {
		case RiskCritical:
			riskLabel = Print.Red("★ CRITICAL")
		case RiskHigh:
			riskLabel = Print.ColorWarning.Sprint("★ HIGH")
		case RiskMedium:
			riskLabel = Print.Yellow("★ MEDIUM")
		case RiskLow:
			riskLabel = Print.Muted("○ LOW")
		default:
			riskLabel = Print.Muted("○ NONE")
		}
	}

	// 打印标题
	fmt.Printf("\n%s  %s\n", riskLabel, Print.Cyan(fmt.Sprintf("%s/%s", result.Namespace, result.PodName)))
	fmt.Printf("  ServiceAccount: %s\n", Print.Green(result.ServiceAccount))

	if result.TokenInfo != nil && !result.TokenInfo.Expiration.IsZero() {
		if result.TokenInfo.IsExpired {
			fmt.Printf("  Token 过期: %s\n", Print.Red(result.TokenInfo.Expiration.Format("2006-01-02 15:04:05")))
		} else {
			fmt.Printf("  Token 有效期至: %s\n", result.TokenInfo.Expiration.Format("2006-01-02 15:04:05"))
		}
	}

	// 检查是否是集群管理员权限
	if result.IsClusterAdmin {
		fmt.Printf("  %s\n", Print.Red("⚠ 集群管理员权限 (cluster-admin) - 可完全控制集群"))
		return
	}

	// 打印允许的权限（按风险分组）
	if len(result.Permissions) > 0 {
		var critical, high, medium, other []string

		for _, p := range result.Permissions {
			if !p.Allowed {
				continue
			}

			resource := p.Resource
			if p.Subresource != "" {
				resource = p.Resource + "/" + p.Subresource
			}

			permStr := fmt.Sprintf("%s [%s]", resource, p.Verb)

			// 分类
			if _, ok := criticalPermissions[resource]; ok {
				critical = append(critical, permStr)
			} else if _, ok := highPermissions[resource]; ok {
				high = append(high, permStr)
			} else if _, ok := mediumPermissions[resource]; ok {
				medium = append(medium, permStr)
			} else {
				other = append(other, permStr)
			}
		}

		if len(critical) > 0 {
			fmt.Printf("  %s:\n", Print.Red("危险权限"))
			for _, p := range critical {
				fmt.Printf("    %s %s\n", Print.Red("✗"), p)
			}
		}
		if len(high) > 0 {
			fmt.Printf("  %s:\n", Print.ColorWarning.Sprint("高危权限"))
			for _, p := range high {
				fmt.Printf("    %s %s\n", Print.ColorWarning.Sprint("!"), p)
			}
		}
		if len(medium) > 0 {
			fmt.Printf("  %s:\n", Print.Yellow("中危权限"))
			for _, p := range medium {
				fmt.Printf("    %s %s\n", Print.Yellow("△"), p)
			}
		}
		if len(other) > 0 && (result.RiskLevel != RiskNone || !flagScanOnlyRisky) {
			fmt.Printf("  其他权限:\n")
			for _, p := range other {
				fmt.Printf("    %s %s\n", Print.Muted("·"), p)
			}
		}
	}
}
