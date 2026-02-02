package sa

import (
	"encoding/json"
	"fmt"

	"kctl/config"
	"kctl/internal/output"
	"kctl/internal/session"
	"kctl/pkg/types"
)

type InfoCmd struct{}

func init() {
	Register(&InfoCmd{})
}

func (c *InfoCmd) Name() string        { return "info" }
func (c *InfoCmd) Aliases() []string   { return nil }
func (c *InfoCmd) Description() string { return "显示当前 SA 详情" }

func (c *InfoCmd) Usage() string {
	return `sa info

显示当前 ServiceAccount 的详细信息

使用 'sa use <namespace/name>' 选择 SA 后，可以查看详情`
}

func (c *InfoCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer

	sa := sess.GetCurrentSA()
	if sa == nil {
		return fmt.Errorf("未选择 ServiceAccount，请先使用 'sa use <namespace/name>' 选择")
	}

	p.Println()
	p.Printf("  %s\n", p.Colored(config.ColorCyan, "ServiceAccount Information"))
	p.Println("  " + p.Colored(config.ColorGray, "─────────────────────────────────────────"))

	p.Printf("  %-16s: %s\n", "Name", sa.Name)
	p.Printf("  %-16s: %s\n", "Namespace", sa.Namespace)
	p.Printf("  %-16s: %s\n", "Risk Level", c.formatRiskDisplay(p, sa))
	p.Printf("  %-16s: %s\n", "Token Status", c.formatTokenStatus(p, sa))

	p.Println()
	c.printPermissions(p, sa)

	p.Println()
	c.printSecurityFlags(p, sa.SecurityFlags)

	p.Println()
	c.printPods(p, sa.Pods)

	p.Println()
	return nil
}

func (c *InfoCmd) formatRiskDisplay(p output.Printer, sa *types.ServiceAccountRecord) string {
	if sa.IsClusterAdmin {
		return p.Colored(config.ColorRed, "ADMIN (cluster-admin)")
	}
	display := config.RiskLevelDisplayConfig[config.RiskLevel(sa.RiskLevel)]
	return p.Colored(display.Color, display.Label)
}

func (c *InfoCmd) formatTokenStatus(p output.Printer, sa *types.ServiceAccountRecord) string {
	status := p.Colored(config.ColorGreen, "Valid")
	if sa.IsExpired {
		status = p.Colored(config.ColorRed, "Expired")
	}
	if sa.TokenExpiration != "" {
		status = fmt.Sprintf("%s (expires: %s)", status, sa.TokenExpiration)
	}
	return status
}

func (c *InfoCmd) printPermissions(p output.Printer, sa *types.ServiceAccountRecord) {
	p.Printf("  %s:\n", p.Colored(config.ColorYellow, "Permissions"))

	if sa.IsClusterAdmin {
		p.Printf("    %s\n", p.Colored(config.ColorRed, "*/* (cluster-admin)"))
		return
	}

	if sa.Permissions == "" || sa.Permissions == "[]" {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(not scanned - run 'sa scan' to check permissions)"))
		return
	}

	var perms []types.SAPermission
	if err := json.Unmarshal([]byte(sa.Permissions), &perms); err != nil {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(parse error)"))
		return
	}

	for _, perm := range perms {
		resource := buildFullResource(perm.Resource, perm.Subresource)
		permStr := fmt.Sprintf("%s:%s", resource, perm.Verb)
		if config.IsCriticalPermission(resource, perm.Verb) {
			permStr = p.Colored(config.ColorRed, permStr)
		} else if config.IsHighPermission(resource, perm.Verb) {
			permStr = p.Colored(config.ColorYellow, permStr)
		}
		p.Printf("    - %s\n", permStr)
	}
}

func (c *InfoCmd) printSecurityFlags(p output.Printer, flagsJSON string) {
	p.Printf("  %s:\n", p.Colored(config.ColorYellow, "Security Flags"))

	if flagsJSON == "" {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(none)"))
		return
	}

	var flags types.SASecurityFlags
	if err := json.Unmarshal([]byte(flagsJSON), &flags); err != nil {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(parse error)"))
		return
	}

	hasFlags := false
	if flags.Privileged {
		p.Printf("    - %s\n", p.Colored(config.ColorRed, "Privileged Container"))
		hasFlags = true
	}
	if flags.AllowPrivilegeEscalation {
		p.Printf("    - %s\n", p.Colored(config.ColorYellow, "Allow Privilege Escalation"))
		hasFlags = true
	}
	if flags.HasHostPath {
		p.Printf("    - %s\n", p.Colored(config.ColorRed, "HostPath Mount"))
		hasFlags = true
	}
	if flags.HasSecretMount {
		p.Printf("    - %s\n", p.Colored(config.ColorYellow, "Secret Mount"))
		hasFlags = true
	}
	if flags.HasSATokenMount {
		p.Printf("    - %s\n", p.Colored(config.ColorGreen, "ServiceAccount Token Mount"))
		hasFlags = true
	}

	if !hasFlags {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(none)"))
	}
}

func (c *InfoCmd) printPods(p output.Printer, podsJSON string) {
	p.Printf("  %s:\n", p.Colored(config.ColorYellow, "Associated Pods"))

	if podsJSON == "" || podsJSON == "[]" {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(none)"))
		return
	}

	var pods []types.SAPodInfo
	if err := json.Unmarshal([]byte(podsJSON), &pods); err != nil {
		p.Printf("    %s\n", p.Colored(config.ColorGray, "(parse error)"))
		return
	}

	for _, pod := range pods {
		line := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
		if pod.Container != "" {
			line += fmt.Sprintf(" (%s)", pod.Container)
		}
		p.Printf("    - %s\n", line)
	}
}
