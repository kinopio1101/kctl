package kubelet

import (
	"fmt"
	"strings"

	"kctl/utils/Print"
	kubeletutil "kctl/utils/kubelet"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// envCmd 是 env 子命令，用于查询并展示环境信息
var envCmd = &cobra.Command{
	Use:   "env",
	Short: "查询并展示 Kubelet 环境信息",
	Long: `查询并展示当前环境的 Kubelet 相关信息

包括：
  - Kubelet IP 地址
  - Kubelet 端口（含有效性验证）
  - Token 文件路径
  - Token 内容（部分显示）
  - ServiceAccount 信息
  - RBAC 权限（通过 K8s API Server 查询）`,
	Run: runEnv,
}

func init() {
	KubeletCmd.AddCommand(envCmd)
}

func runEnv(cmd *cobra.Command, args []string) {
	fmt.Println()

	// 获取 Token 路径
	tokenPath := FlagTokenFile
	if tokenPath == "" {
		tokenPath = kubeletutil.GetDefaultTokenPath()
	}

	// 读取 Token
	token, tokenErr := kubeletutil.ReadToken(tokenPath)

	// 获取 Kubelet IP
	var ip string
	var ipSource string
	if FlagIP != "" {
		ip = FlagIP
		ipSource = Print.Muted("(手动指定)")
	} else {
		var err error
		ip, err = kubeletutil.GetDefaultGateway()
		if err != nil {
			ip = Print.Red(fmt.Sprintf("✗ 获取失败: %v", err))
			ipSource = ""
		} else {
			ipSource = Print.Muted("(自动获取)")
		}
	}

	port := FlagPort

	// 验证 Kubelet 端口
	var portStatus string
	if ip != "" && !strings.HasPrefix(ip, "\x1b[31m") {
		probeResult := kubeletutil.ValidateKubeletPort(ip, port, token, kubeletutil.DefaultProbeTimeout)
		if !probeResult.Reachable {
			portStatus = Print.Red("✗ 端口不可达")
		} else if probeResult.IsKubelet {
			portStatus = Print.Green("✓ 有效 Kubelet 端口")
		} else {
			portStatus = Print.Yellow("⚠ 端口可达，无法确认是 Kubelet")
		}
	} else {
		portStatus = Print.Yellow("⚠ 无法验证")
	}

	// 打印基本信息
	printEnvInfo(ip, ipSource, port, portStatus, tokenPath, token, tokenErr)

	// 解析 Token 信息
	if tokenErr == nil {
		tokenInfo, err := kubeletutil.ParseTokenInfo(token)
		if err != nil {
			log.Warnf("解析 Token 信息失败: %v", err)
		} else {
			printTokenInfo(tokenInfo)
		}

		// 查询 RBAC 权限
		Print.PrintSection("RBAC 权限查询")
		namespace := ""
		if tokenInfo != nil {
			namespace = tokenInfo.Namespace
		}
		permissions, err := kubeletutil.CheckCommonPermissions(token, "", namespace)
		if err != nil {
			log.Warnf("查询权限失败: %v", err)
		} else {
			printPermissions(permissions)
		}
	}

	fmt.Println()
}

// printEnvInfo 打印环境信息
func printEnvInfo(ip, ipSource string, port int, portStatus, tokenPath, token string, tokenErr error) {
	Print.PrintSection("Kubelet 环境信息")

	Print.PrintKeyValueNote("Kubelet IP", ip, ipSource)
	Print.PrintKeyValueNote("Kubelet Port", fmt.Sprintf("%d", port), portStatus)
	Print.PrintKeyValue("Token Path", tokenPath)

	_, _ = Print.ColorLabel.Println("  Token         : ")
	if tokenErr != nil {
		Print.PrintError(fmt.Sprintf("读取失败: %v", tokenErr))
	} else {
		// 输出完整 Token，每行 80 个字符
		for i := 0; i < len(token); i += 80 {
			end := i + 80
			if end > len(token) {
				end = len(token)
			}
			fmt.Printf("    %s\n", token[i:end])
		}
	}
}

// printTokenInfo 打印 Token 信息
func printTokenInfo(info *kubeletutil.TokenInfo) {
	Print.PrintSection("ServiceAccount 信息")

	Print.PrintKeyValue("ServiceAccount", info.ServiceAccount)
	Print.PrintKeyValue("Namespace", info.Namespace)
	Print.PrintKeyValue("Issuer", info.Issuer)

	expTime := info.Expiration.Format("2006-01-02 15:04:05")
	if info.IsExpired {
		Print.PrintKeyValueNote("Expiration", expTime, Print.Red("✗ 已过期"))
	} else {
		Print.PrintKeyValueNote("Expiration", expTime, Print.Green("✓ 有效"))
	}
}

// printPermissions 打印权限检查结果
func printPermissions(permissions []kubeletutil.PermissionCheck) {
	// 分类统计
	var allowedPerms []kubeletutil.PermissionCheck
	var deniedPerms []kubeletutil.PermissionCheck
	var adminPerms []kubeletutil.PermissionCheck
	var dangerousPerms []kubeletutil.PermissionCheck
	var sensitivePerms []kubeletutil.PermissionCheck

	for _, p := range permissions {
		if !p.Allowed {
			deniedPerms = append(deniedPerms, p)
			continue
		}

		allowedPerms = append(allowedPerms, p)
		level := kubeletutil.GetPermissionLevel(p)
		switch level {
		case kubeletutil.PermLevelAdmin:
			adminPerms = append(adminPerms, p)
		case kubeletutil.PermLevelDangerous:
			dangerousPerms = append(dangerousPerms, p)
		case kubeletutil.PermLevelSensitive:
			sensitivePerms = append(sensitivePerms, p)
		}
	}

	// 输出统计摘要
	fmt.Println()
	if len(adminPerms) > 0 {
		_, _ = Print.ColorAdmin.Printf("  ⚠️  检测到 %d 个管理员级别权限!\n", len(adminPerms))
	}
	if len(dangerousPerms) > 0 {
		_, _ = Print.ColorDanger.Printf("  🔴 检测到 %d 个危险权限!\n", len(dangerousPerms))
	}
	if len(sensitivePerms) > 0 {
		_, _ = Print.ColorWarning.Printf("  🟡 检测到 %d 个敏感权限\n", len(sensitivePerms))
	}

	Print.PrintStats([]Print.StatItem{
		{Label: "✅ 允许", Value: len(allowedPerms), Color: Print.ColorSuccess},
		{Label: "❌ 拒绝", Value: len(deniedPerms), Color: Print.ColorMuted},
	})
	fmt.Println()

	// 如果有管理员权限，醒目显示
	if len(adminPerms) > 0 {
		printAdminPermissions(adminPerms)
	}

	// 如果有危险权限，醒目显示
	if len(dangerousPerms) > 0 {
		printDangerousPermissions(dangerousPerms)
	}

	// 如果有敏感权限，显示
	if len(sensitivePerms) > 0 {
		printSensitivePermissions(sensitivePerms)
	}

	// 按资源分组显示所有权限
	Print.PrintSubSection("完整权限列表")
	printPermissionsByResource(permissions)
}

// printAdminPermissions 打印管理员权限
func printAdminPermissions(perms []kubeletutil.PermissionCheck) {
	var lines []string
	for _, p := range perms {
		permStr := formatPermissionString(p)
		desc := kubeletutil.GetPermissionDescription(p)
		if desc != "" {
			lines = append(lines, permStr)
			lines = append(lines, "  → "+desc)
		} else {
			lines = append(lines, permStr)
		}
	}
	Print.PrintBox("⚠️  管理员权限 (ADMIN)", lines, Print.BoxStyleAdmin)
}

// printDangerousPermissions 打印危险权限
func printDangerousPermissions(perms []kubeletutil.PermissionCheck) {
	var lines []string
	for _, p := range perms {
		permStr := formatPermissionString(p)
		desc := kubeletutil.GetPermissionDescription(p)
		if desc != "" {
			lines = append(lines, permStr)
			lines = append(lines, "  → "+desc)
		} else {
			lines = append(lines, permStr)
		}
	}
	Print.PrintBox("🔴 危险权限 (DANGEROUS)", lines, Print.BoxStyleDanger)
}

// printSensitivePermissions 打印敏感权限
func printSensitivePermissions(perms []kubeletutil.PermissionCheck) {
	var lines []string
	for _, p := range perms {
		lines = append(lines, formatPermissionString(p))
	}
	Print.PrintBox("🟡 敏感权限 (SENSITIVE)", lines, Print.BoxStyleWarning)
}

// printPermissionsByResource 按资源分组打印权限
func printPermissionsByResource(permissions []kubeletutil.PermissionCheck) {
	// 按资源分组
	resourceMap := make(map[string][]kubeletutil.PermissionCheck)
	resourceOrder := []string{}

	for _, p := range permissions {
		key := p.Resource
		if p.Group != "" {
			key = p.Resource + "." + p.Group
		}
		if _, exists := resourceMap[key]; !exists {
			resourceOrder = append(resourceOrder, key)
		}
		resourceMap[key] = append(resourceMap[key], p)
	}

	for _, resourceKey := range resourceOrder {
		perms := resourceMap[resourceKey]

		// 资源名称
		resource := perms[0].Resource
		group := perms[0].Group

		if group != "" {
			fmt.Printf("  %s ", Print.Magenta(fmt.Sprintf("%-25s", resource+"."+group)))
		} else {
			fmt.Printf("  %s ", Print.Magenta(fmt.Sprintf("%-25s", resource)))
		}

		// 权限列表
		var parts []string
		for _, p := range perms {
			verbStr := p.Verb
			if p.Subresource != "" {
				verbStr = p.Verb + "/" + p.Subresource
			}

			level := kubeletutil.GetPermissionLevel(p)

			if p.Allowed {
				switch level {
				case kubeletutil.PermLevelAdmin:
					parts = append(parts, Print.Red("★"+verbStr))
				case kubeletutil.PermLevelDangerous:
					parts = append(parts, Print.Red("◆"+verbStr))
				case kubeletutil.PermLevelSensitive:
					parts = append(parts, Print.Yellow("●"+verbStr))
				default:
					parts = append(parts, Print.Green("✓"+verbStr))
				}
			} else {
				parts = append(parts, Print.Muted("✗"+verbStr))
			}
		}
		fmt.Println(strings.Join(parts, "  "))
	}
}

// formatPermissionString 格式化权限字符串
func formatPermissionString(p kubeletutil.PermissionCheck) string {
	var parts []string

	if p.Group != "" {
		parts = append(parts, p.Resource+"."+p.Group)
	} else {
		parts = append(parts, p.Resource)
	}

	if p.Subresource != "" {
		parts = append(parts, p.Verb+"/"+p.Subresource)
	} else {
		parts = append(parts, p.Verb)
	}

	return strings.Join(parts, " : ")
}
