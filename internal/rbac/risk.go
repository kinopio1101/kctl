package rbac

import (
	"kctl/config"
	"kctl/pkg/types"
)

// RiskAssessment 风险评估结果
type RiskAssessment struct {
	Level          config.RiskLevel
	IsClusterAdmin bool
	AdminPerms     []types.PermissionCheckResult
	DangerousPerms []types.PermissionCheckResult
	SensitivePerms []types.PermissionCheckResult
	NormalPerms    []types.PermissionCheckResult
}

// AssessRisk 评估权限风险
func AssessRisk(results []types.PermissionCheckResult) *RiskAssessment {
	assessment := &RiskAssessment{
		Level: config.RiskNone,
	}

	for _, r := range results {
		if !r.Allowed {
			continue
		}

		switch r.Level {
		case config.PermLevelAdmin:
			assessment.AdminPerms = append(assessment.AdminPerms, r)
		case config.PermLevelDangerous:
			assessment.DangerousPerms = append(assessment.DangerousPerms, r)
		case config.PermLevelSensitive:
			assessment.SensitivePerms = append(assessment.SensitivePerms, r)
		default:
			assessment.NormalPerms = append(assessment.NormalPerms, r)
		}
	}

	// 转换为 PermissionCheck 格式以便检查 IsClusterAdmin
	var permissions []types.PermissionCheck
	for _, r := range results {
		permissions = append(permissions, types.PermissionCheck{
			Resource:    r.Resource,
			Verb:        r.Verb,
			Group:       r.Group,
			Subresource: r.Subresource,
			Allowed:     r.Allowed,
		})
	}
	assessment.IsClusterAdmin = IsClusterAdmin(permissions)

	// 计算风险等级
	if assessment.IsClusterAdmin {
		assessment.Level = config.RiskAdmin
	} else if len(assessment.AdminPerms) > 0 {
		assessment.Level = config.RiskCritical
	} else if len(assessment.DangerousPerms) > 0 {
		assessment.Level = config.RiskHigh
	} else if len(assessment.SensitivePerms) > 0 {
		assessment.Level = config.RiskMedium
	} else if len(assessment.NormalPerms) > 0 {
		assessment.Level = config.RiskLow
	}

	return assessment
}

// AssessRiskFromPermissions 从权限检查结果评估风险（简化版）
func AssessRiskFromPermissions(permissions []types.PermissionCheck) *RiskAssessment {
	var results []types.PermissionCheckResult

	for _, p := range permissions {
		result := types.PermissionCheckResult{
			PermissionCheck: p,
		}
		if p.Allowed {
			result.Level, result.Description = GetPermissionInfo(p)
		}
		results = append(results, result)
	}

	return AssessRisk(results)
}

// CalculateRiskLevel 计算权限的风险等级（快速版本）
func CalculateRiskLevel(permissions []types.PermissionCheck) config.RiskLevel {
	// 先检查是否是集群管理员
	if IsClusterAdmin(permissions) {
		return config.RiskAdmin
	}

	// 检查 CRITICAL 权限
	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		resource := p.Resource
		if p.Subresource != "" {
			resource = p.Resource + "/" + p.Subresource
		}

		if verbs, ok := config.CriticalPermissions[resource]; ok {
			for _, v := range verbs {
				if v == p.Verb || v == "*" {
					return config.RiskCritical
				}
			}
		}
	}

	// 检查 HIGH 权限
	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		resource := p.Resource
		if p.Subresource != "" {
			resource = p.Resource + "/" + p.Subresource
		}

		if verbs, ok := config.HighPermissions[resource]; ok {
			for _, v := range verbs {
				if v == p.Verb || v == "*" {
					return config.RiskHigh
				}
			}
		}
	}

	// 检查 MEDIUM 权限
	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		resource := p.Resource
		if p.Subresource != "" {
			resource = p.Resource + "/" + p.Subresource
		}

		if verbs, ok := config.MediumPermissions[resource]; ok {
			for _, v := range verbs {
				if v == p.Verb || v == "*" {
					return config.RiskMedium
				}
			}
		}
	}

	// 检查是否有任何允许的权限
	for _, p := range permissions {
		if p.Allowed {
			return config.RiskLow
		}
	}

	return config.RiskNone
}

// IsClusterAdmin 检查是否拥有集群管理员权限
// 通过检查多个关键的高权限操作来判断
func IsClusterAdmin(permissions []types.PermissionCheck) bool {
	// 定义 cluster-admin 的关键权限指标
	// 如果一个 SA 拥有这些权限，基本可以确定是 cluster-admin
	adminIndicators := map[string]bool{
		"clusterrolebindings:create": false, // 可以创建集群角色绑定
		"clusterrolebindings:delete": false, // 可以删除集群角色绑定
		"nodes:delete":               false, // 可以删除节点
		"namespaces:delete":          false, // 可以删除命名空间
		"secrets:list":               false, // 可以列出 secrets
	}

	for _, p := range permissions {
		if !p.Allowed {
			continue
		}

		key := p.Resource + ":" + p.Verb
		if _, ok := adminIndicators[key]; ok {
			adminIndicators[key] = true
		}
	}

	// 检查是否所有关键权限都有
	for _, allowed := range adminIndicators {
		if !allowed {
			return false
		}
	}

	return true
}
