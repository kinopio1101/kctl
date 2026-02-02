package sa

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"kctl/config"
	k8sclient "kctl/internal/client/k8s"
	"kctl/internal/output"
	"kctl/internal/rbac"
	"kctl/internal/session"
	"kctl/pkg/token"
	"kctl/pkg/types"
)

type ScanCmd struct{}

func init() {
	Register(&ScanCmd{})
}

func (c *ScanCmd) Name() string        { return "scan" }
func (c *ScanCmd) Aliases() []string   { return nil }
func (c *ScanCmd) Description() string { return "扫描所有 Pod 的 SA Token 权限" }

func (c *ScanCmd) Usage() string {
	return `sa scan [options]

扫描所有 Pod 中的 ServiceAccount Token 权限

选项：
  --risky, -r     只显示有风险权限的 SA
  --perms, -p     显示完整权限列表
  --token, -t     显示 Token

示例：
  sa scan              扫描所有 SA
  sa scan --risky      只显示有风险的 SA
  sa scan --perms      显示完整权限`
}

type SATokenResult struct {
	Namespace      string
	PodName        string
	Container      string
	ServiceAccount string
	Token          string
	TokenInfo      *types.TokenInfo
	Permissions    []types.PermissionCheck
	SecurityFlags  types.SecurityFlags
	RiskLevel      config.RiskLevel
	IsClusterAdmin bool
	Error          string
}

func (c *ScanCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer
	ctx := context.Background()

	onlyRisky, showPerms, showToken := c.parseArgs(args)

	kubelet, err := sess.GetKubeletClient()
	if err != nil {
		return err
	}

	p.Printf("%s Scanning ServiceAccount tokens...\n", p.Colored(config.ColorBlue, "[*]"))

	pods, err := kubelet.GetPodsWithContainers(ctx)
	if err != nil {
		return fmt.Errorf("获取 Pod 列表失败: %w", err)
	}
	sess.CachePods(pods)

	targetPods := c.filterTargetPods(pods)
	if len(targetPods) == 0 {
		p.Warning("没有找到挂载 SA Token 的 Running Pod")
		return nil
	}

	p.Printf("%s Found %d pods with SA tokens\n", p.Colored(config.ColorBlue, "[*]"), len(targetPods))
	p.Printf("%s Checking permissions... (%d concurrent)\n", p.Colored(config.ColorBlue, "[*]"), sess.Config.Concurrency)

	allResults := c.scanConcurrently(ctx, sess, kubelet, targetPods)
	c.sortByRisk(allResults)

	savedCount := c.saveResults(sess, allResults)
	sess.MarkScanned()

	c.printResults(p, allResults, onlyRisky, showPerms, showToken, savedCount)

	return nil
}

func (c *ScanCmd) parseArgs(args []string) (onlyRisky, showPerms, showToken bool) {
	for _, arg := range args {
		switch arg {
		case "--risky", "-r":
			onlyRisky = true
		case "--perms", "-p":
			showPerms = true
		case "--token", "-t":
			showToken = true
		}
	}
	return
}

func (c *ScanCmd) filterTargetPods(pods []types.PodContainerInfo) []types.PodContainerInfo {
	var result []types.PodContainerInfo
	for _, pod := range pods {
		if pod.Status == "Running" && pod.SecurityFlags.HasSATokenMount {
			result = append(result, pod)
		}
	}
	return result
}

func (c *ScanCmd) scanConcurrently(ctx context.Context, sess *session.Session, kubelet interface {
	Exec(ctx context.Context, opts *types.ExecOptions) (*types.ExecResult, error)
}, pods []types.PodContainerInfo) []SATokenResult {
	results := make(chan SATokenResult, len(pods))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, sess.Config.Concurrency)

	for _, pod := range pods {
		wg.Add(1)
		go func(pod types.PodContainerInfo) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results <- c.scanPodToken(ctx, sess, kubelet, pod)
		}(pod)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allResults []SATokenResult
	for result := range results {
		allResults = append(allResults, result)
	}
	return allResults
}

func (c *ScanCmd) scanPodToken(ctx context.Context, sess *session.Session, kubelet interface {
	Exec(ctx context.Context, opts *types.ExecOptions) (*types.ExecResult, error)
}, pod types.PodContainerInfo) SATokenResult {
	result := SATokenResult{
		Namespace:     pod.Namespace,
		PodName:       pod.PodName,
		RiskLevel:     config.RiskNone,
		SecurityFlags: pod.SecurityFlags,
	}

	if len(pod.Containers) == 0 {
		result.Error = "Pod 没有容器"
		return result
	}
	result.Container = pod.Containers[0].Name

	execResult, err := kubelet.Exec(ctx, &types.ExecOptions{
		Namespace: pod.Namespace,
		Pod:       pod.PodName,
		Container: result.Container,
		Command:   []string{"cat", "/var/run/secrets/kubernetes.io/serviceaccount/token"},
		Stdout:    true,
		Stderr:    true,
	})
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

	tokenInfo, err := token.Parse(result.Token)
	if err != nil {
		result.Error = fmt.Sprintf("解析 Token 失败: %v", err)
		return result
	}
	result.TokenInfo = tokenInfo
	result.ServiceAccount = tokenInfo.ServiceAccount

	k8s, err := sess.GetK8sClient(result.Token)
	if err != nil {
		result.Error = fmt.Sprintf("创建 K8s 客户端失败: %v", err)
		return result
	}

	permissions, err := k8s.CheckCommonPermissions(ctx, tokenInfo.Namespace)
	if err != nil {
		result.Error = fmt.Sprintf("检查权限失败: %v", err)
		return result
	}
	result.Permissions = permissions
	result.IsClusterAdmin = rbac.IsClusterAdmin(permissions)

	if result.IsClusterAdmin {
		result.RiskLevel = config.RiskAdmin
	} else {
		result.RiskLevel = rbac.CalculateRiskLevel(permissions)
	}

	return result
}

func (c *ScanCmd) sortByRisk(results []SATokenResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].IsClusterAdmin != results[j].IsClusterAdmin {
			return results[i].IsClusterAdmin
		}
		return config.RiskLevelOrder[results[i].RiskLevel] < config.RiskLevelOrder[results[j].RiskLevel]
	})
}

func (c *ScanCmd) saveResults(sess *session.Session, results []SATokenResult) int {
	saMap := make(map[string]*types.ServiceAccountRecord)

	for _, result := range results {
		if result.Error != "" || result.ServiceAccount == "" {
			continue
		}

		key := fmt.Sprintf("%s/%s", result.TokenInfo.Namespace, result.ServiceAccount)

		if existing, ok := saMap[key]; ok {
			c.mergeExistingRecord(existing, result)
		} else {
			saMap[key] = c.createNewRecord(sess, result)
		}
	}

	var records []*types.ServiceAccountRecord
	for _, record := range saMap {
		records = append(records, record)
	}

	if sess.SADB != nil {
		count, _ := sess.SADB.SaveBatch(records)
		return count
	}
	return len(records)
}

func (c *ScanCmd) mergeExistingRecord(existing *types.ServiceAccountRecord, result SATokenResult) {
	var pods []types.SAPodInfo
	json.Unmarshal([]byte(existing.Pods), &pods)
	pods = append(pods, types.SAPodInfo{
		Name:      result.PodName,
		Namespace: result.Namespace,
		Container: result.Container,
	})
	podsJSON, _ := json.Marshal(pods)
	existing.Pods = string(podsJSON)

	var existingFlags types.SASecurityFlags
	json.Unmarshal([]byte(existing.SecurityFlags), &existingFlags)
	existingFlags.Privileged = existingFlags.Privileged || result.SecurityFlags.Privileged
	existingFlags.AllowPrivilegeEscalation = existingFlags.AllowPrivilegeEscalation || result.SecurityFlags.AllowPrivilegeEscalation
	existingFlags.HasHostPath = existingFlags.HasHostPath || result.SecurityFlags.HasHostPath
	existingFlags.HasSecretMount = existingFlags.HasSecretMount || result.SecurityFlags.HasSecretMount
	existingFlags.HasSATokenMount = existingFlags.HasSATokenMount || result.SecurityFlags.HasSATokenMount
	flagsJSON, _ := json.Marshal(existingFlags)
	existing.SecurityFlags = string(flagsJSON)
}

func (c *ScanCmd) createNewRecord(sess *session.Session, result SATokenResult) *types.ServiceAccountRecord {
	record := &types.ServiceAccountRecord{
		Name:           result.ServiceAccount,
		Namespace:      result.TokenInfo.Namespace,
		Token:          result.Token,
		IsClusterAdmin: result.IsClusterAdmin,
		CollectedAt:    time.Now(),
		KubeletIP:      sess.Config.KubeletIP,
	}

	if result.TokenInfo != nil && !result.TokenInfo.Expiration.IsZero() {
		record.TokenExpiration = result.TokenInfo.Expiration.Format(time.RFC3339)
		record.IsExpired = result.TokenInfo.IsExpired
	}

	if result.IsClusterAdmin {
		record.RiskLevel = string(config.RiskAdmin)
	} else {
		record.RiskLevel = string(result.RiskLevel)
	}

	var permissions []types.SAPermission
	for _, p := range result.Permissions {
		if p.Allowed {
			permissions = append(permissions, types.SAPermission{
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

	secFlagsJSON, _ := json.Marshal(types.SASecurityFlags{
		Privileged:               result.SecurityFlags.Privileged,
		AllowPrivilegeEscalation: result.SecurityFlags.AllowPrivilegeEscalation,
		HasHostPath:              result.SecurityFlags.HasHostPath,
		HasSecretMount:           result.SecurityFlags.HasSecretMount,
		HasSATokenMount:          result.SecurityFlags.HasSATokenMount,
	})
	record.SecurityFlags = string(secFlagsJSON)

	podsJSON, _ := json.Marshal([]types.SAPodInfo{{
		Name:      result.PodName,
		Namespace: result.Namespace,
		Container: result.Container,
	}})
	record.Pods = string(podsJSON)

	return record
}

func (c *ScanCmd) printResults(p output.Printer, results []SATokenResult, onlyRisky, showPerms, showToken bool, savedCount int) {
	var rows []output.ScanResultRow
	for _, result := range results {
		if result.Error != "" {
			continue
		}
		if onlyRisky && result.RiskLevel == config.RiskNone && !result.IsClusterAdmin {
			continue
		}
		rows = append(rows, c.buildResultRow(p, result))
	}

	p.Println()
	output.NewTablePrinter().PrintScanResults(rows, showPerms, showToken)

	stats := c.calculateStats(results)
	p.Println()
	p.Printf("%s Scan complete: %d SAs", p.Colored(config.ColorGreen, "[+]"), savedCount)
	if stats.admin > 0 {
		p.Printf(", %s ADMIN", p.Colored(config.ColorRed, fmt.Sprintf("%d", stats.admin)))
	}
	if stats.critical > 0 {
		p.Printf(", %s CRITICAL", p.Colored(config.ColorRed, fmt.Sprintf("%d", stats.critical)))
	}
	if stats.high > 0 {
		p.Printf(", %s HIGH", p.Colored(config.ColorYellow, fmt.Sprintf("%d", stats.high)))
	}
	p.Println()
	p.Printf("%s Results cached in memory\n", p.Colored(config.ColorGreen, "[+]"))
}

type scanStats struct {
	admin, critical, high int
}

func (c *ScanCmd) calculateStats(results []SATokenResult) scanStats {
	var stats scanStats
	for _, r := range results {
		if r.IsClusterAdmin {
			stats.admin++
		} else {
			switch r.RiskLevel {
			case config.RiskCritical:
				stats.critical++
			case config.RiskHigh:
				stats.high++
			}
		}
	}
	return stats
}

func (c *ScanCmd) buildResultRow(p output.Printer, result SATokenResult) output.ScanResultRow {
	tokenStatus := p.Colored(config.ColorGreen, "有效")
	if result.TokenInfo != nil && result.TokenInfo.IsExpired {
		tokenStatus = p.Colored(config.ColorRed, "已过期")
	}

	return output.ScanResultRow{
		Risk:           formatRiskLabel(p, result.RiskLevel, result.IsClusterAdmin),
		Namespace:      result.Namespace,
		Pod:            result.PodName,
		ServiceAccount: result.ServiceAccount,
		TokenStatus:    tokenStatus,
		Flags:          buildFlagsFromSecurityFlags(p, result.SecurityFlags, result.Permissions),
		Permissions:    formatPermissionsFromChecks(p, result.Permissions, result.IsClusterAdmin),
		Token:          result.Token,
	}
}

var _ interface {
	CheckCommonPermissions(ctx context.Context, namespace string) ([]types.PermissionCheck, error)
} = (k8sclient.Client)(nil)
