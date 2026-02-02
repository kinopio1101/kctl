package sa

import (
	"encoding/json"
	"fmt"

	"kctl/config"
	"kctl/internal/output"
	"kctl/internal/session"
	"kctl/pkg/types"
)

type ListCmd struct{}

func init() {
	Register(&ListCmd{})
}

func (c *ListCmd) Name() string        { return "list" }
func (c *ListCmd) Aliases() []string   { return []string{"ls"} }
func (c *ListCmd) Description() string { return "列出已扫描的 ServiceAccount" }

func (c *ListCmd) Usage() string {
	return `sa list [options]

列出已扫描的 ServiceAccount

选项：
  --admin, -a     只显示 cluster-admin
  --risky, -r     只显示有风险权限的 SA
  -n <namespace>  按命名空间过滤
  --perms, -p     显示权限
  --token, -t     显示 Token

示例：
  sa list                 列出所有 SA
  sa list --admin         只显示 cluster-admin
  sa list --risky         只显示有风险的 SA
  sa list -n kube-system  只显示 kube-system 命名空间的 SA`
}

func (c *ListCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer

	if !sess.IsScanned {
		return fmt.Errorf("请先执行 'sa scan' 扫描 ServiceAccount")
	}

	onlyAdmin, onlyRisky, namespace, showPerms, showToken := c.parseArgs(args)

	sas, err := sess.SADB.GetAll()
	if err != nil {
		return fmt.Errorf("获取 ServiceAccount 失败: %w", err)
	}

	if len(sas) == 0 {
		p.Warning("没有找到 ServiceAccount，请先执行 'sa scan'")
		return nil
	}

	var rows []output.SARow
	for _, sa := range sas {
		if !c.matchesFilter(sa, namespace, onlyAdmin, onlyRisky) {
			continue
		}

		var secFlags types.SASecurityFlags
		var perms []types.SAPermission
		json.Unmarshal([]byte(sa.SecurityFlags), &secFlags)
		json.Unmarshal([]byte(sa.Permissions), &perms)

		rows = append(rows, output.SARow{
			Risk:        formatRiskLabel(p, config.RiskLevel(sa.RiskLevel), sa.IsClusterAdmin),
			Namespace:   sa.Namespace,
			Name:        sa.Name,
			TokenStatus: p.Colored(config.ColorGreen, "有效"),
			Flags:       buildFlagsFromSASecurityFlags(p, secFlags, perms),
			Permissions: formatPermissionsFromSAPerms(p, perms, sa.IsClusterAdmin),
			Token:       sa.Token,
		})
	}

	if len(rows) == 0 {
		p.Warning("没有符合条件的 ServiceAccount")
		return nil
	}

	p.Println()
	output.NewTablePrinter().PrintServiceAccounts(rows, showPerms, showToken)
	p.Printf("\n  共 %d 个 ServiceAccount\n\n", len(rows))

	return nil
}

func (c *ListCmd) parseArgs(args []string) (onlyAdmin, onlyRisky bool, namespace string, showPerms, showToken bool) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--admin", "-a":
			onlyAdmin = true
		case "--risky", "-r":
			onlyRisky = true
		case "-n":
			if i+1 < len(args) {
				namespace = args[i+1]
				i++
			}
		case "--perms", "-p":
			showPerms = true
		case "--token", "-t":
			showToken = true
		}
	}
	return
}

func (c *ListCmd) matchesFilter(sa *types.ServiceAccountRecord, namespace string, onlyAdmin, onlyRisky bool) bool {
	if namespace != "" && sa.Namespace != namespace {
		return false
	}
	if onlyAdmin && !sa.IsClusterAdmin {
		return false
	}
	if onlyRisky && sa.RiskLevel == string(config.RiskNone) && !sa.IsClusterAdmin {
		return false
	}
	return true
}
