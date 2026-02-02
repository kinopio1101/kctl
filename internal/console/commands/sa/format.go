package sa

import (
	"fmt"
	"strings"

	"kctl/config"
	"kctl/internal/output"
	"kctl/pkg/types"
)

func formatRiskLabel(p output.Printer, riskLevel config.RiskLevel, isClusterAdmin bool) string {
	if isClusterAdmin {
		return p.Colored(config.ColorRed, "ADMIN")
	}
	display := config.RiskLevelDisplayConfig[riskLevel]
	return p.Colored(display.Color, display.Label)
}

func buildFullResource(resource, subresource string) string {
	if subresource != "" {
		return resource + "/" + subresource
	}
	return resource
}

func buildFlagsFromSecurityFlags(p output.Printer, flags types.SecurityFlags, perms []types.PermissionCheck) string {
	var result []string
	hasPriv := false

	if flags.Privileged {
		result = append(result, p.Colored(config.ColorRed, "PRIV"))
		hasPriv = true
	}
	if flags.AllowPrivilegeEscalation {
		result = append(result, p.Colored(config.ColorYellow, "PE"))
	}
	if flags.HasHostPath {
		result = append(result, p.Colored(config.ColorRed, "HP"))
	}
	if flags.HasSecretMount {
		result = append(result, p.Colored(config.ColorYellow, "SEC"))
	}

	if !hasPriv {
		for _, perm := range perms {
			if !perm.Allowed {
				continue
			}
			resource := buildFullResource(perm.Resource, perm.Subresource)
			if config.IsPrivilegeEquivalent(resource, perm.Verb) {
				result = append(result, p.Colored(config.ColorRed, "PRIV"))
				break
			}
		}
	}

	if len(result) == 0 {
		return "-"
	}
	return strings.Join(result, ",")
}

func buildFlagsFromSASecurityFlags(p output.Printer, flags types.SASecurityFlags, perms []types.SAPermission) string {
	var result []string
	hasPriv := false

	if flags.Privileged {
		result = append(result, p.Colored(config.ColorRed, "PRIV"))
		hasPriv = true
	}
	if flags.AllowPrivilegeEscalation {
		result = append(result, p.Colored(config.ColorYellow, "PE"))
	}
	if flags.HasHostPath {
		result = append(result, p.Colored(config.ColorRed, "HP"))
	}
	if flags.HasSecretMount {
		result = append(result, p.Colored(config.ColorYellow, "SEC"))
	}

	if !hasPriv {
		for _, perm := range perms {
			resource := buildFullResource(perm.Resource, perm.Subresource)
			if config.IsPrivilegeEquivalent(resource, perm.Verb) {
				result = append(result, p.Colored(config.ColorRed, "PRIV"))
				break
			}
		}
	}

	if len(result) == 0 {
		return "-"
	}
	return strings.Join(result, ",")
}

func formatPermissionsFromChecks(p output.Printer, perms []types.PermissionCheck, isClusterAdmin bool) string {
	if isClusterAdmin {
		return p.Colored(config.ColorRed, "*/* (cluster-admin)")
	}

	seen := make(map[string]bool)
	var result []string

	for _, perm := range perms {
		if !perm.Allowed {
			continue
		}
		resource := buildFullResource(perm.Resource, perm.Subresource)
		key := fmt.Sprintf("%s:%s", resource, perm.Verb)
		if seen[key] {
			continue
		}
		seen[key] = true

		if config.IsCriticalPermission(resource, perm.Verb) {
			key = p.Colored(config.ColorRed, key)
		} else if config.IsHighPermission(resource, perm.Verb) {
			key = p.Colored(config.ColorYellow, key)
		}
		result = append(result, key)
	}

	if len(result) == 0 {
		return "-"
	}
	return strings.Join(result, "\n")
}

func formatPermissionsFromSAPerms(p output.Printer, perms []types.SAPermission, isClusterAdmin bool) string {
	if isClusterAdmin {
		return p.Colored(config.ColorRed, "*/* (cluster-admin)")
	}
	if len(perms) == 0 {
		return "-"
	}

	seen := make(map[string]bool)
	var result []string

	for _, perm := range perms {
		resource := buildFullResource(perm.Resource, perm.Subresource)
		key := fmt.Sprintf("%s:%s", resource, perm.Verb)
		if seen[key] {
			continue
		}
		seen[key] = true

		if config.IsCriticalPermission(resource, perm.Verb) {
			key = p.Colored(config.ColorRed, key)
		} else if config.IsHighPermission(resource, perm.Verb) {
			key = p.Colored(config.ColorYellow, key)
		}
		result = append(result, key)
	}

	if len(result) == 0 {
		return "-"
	}
	return strings.Join(result, "\n")
}
