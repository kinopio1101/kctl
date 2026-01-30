package kubelet

// PermissionLevel 权限敏感级别
type PermissionLevel int

const (
	PermLevelNormal    PermissionLevel = iota // 普通权限
	PermLevelSensitive                        // 敏感权限
	PermLevelDangerous                        // 危险权限
	PermLevelAdmin                            // 管理员权限
)

// PermissionDef 权限检查定义
type PermissionDef struct {
	Resource    string
	Verb        string
	Group       string
	Subresource string
}

// SensitiveRule 敏感权限规则
type SensitiveRule struct {
	Resource    string          // 资源名，"*" 表示任意
	Verb        string          // 操作，"*" 表示任意
	Group       string          // API Group，"*" 表示任意
	Subresource string          // 子资源，"*" 表示任意
	Level       PermissionLevel // 敏感级别
	Description string          // 描述
}

// PermissionsToCheck 需要检查的权限列表
var PermissionsToCheck = []PermissionDef{
	// 基础 Pod 权限
	{"pods", "list", "", ""},
	{"pods", "get", "", ""},
	{"pods", "create", "", ""},
	{"pods", "delete", "", ""},
	// 危险: Pod exec/attach 权限 (可执行命令)
	{"pods", "create", "", "exec"},
	{"pods", "create", "", "attach"},
	// 敏感: Pod 日志
	{"pods", "get", "", "log"},
	// Secrets 权限 (敏感)
	{"secrets", "list", "", ""},
	{"secrets", "get", "", ""},
	{"secrets", "create", "", ""},
	{"secrets", "delete", "", ""},
	// ConfigMaps 权限
	{"configmaps", "list", "", ""},
	{"configmaps", "get", "", ""},
	// Services 权限
	{"services", "list", "", ""},
	{"services", "get", "", ""},
	// Nodes 权限
	{"nodes", "list", "", ""},
	{"nodes", "get", "", ""},
	// 危险: nodes/proxy 权限 (可访问 Kubelet API)
	{"nodes", "get", "", "proxy"},
	{"nodes", "create", "", "proxy"},
	// Namespaces 权限
	{"namespaces", "list", "", ""},
	{"namespaces", "get", "", ""},
	// Deployments 权限
	{"deployments", "list", "apps", ""},
	{"deployments", "get", "apps", ""},
	{"deployments", "create", "apps", ""},
	{"deployments", "delete", "apps", ""},
	// DaemonSets 权限
	{"daemonsets", "list", "apps", ""},
	{"daemonsets", "create", "apps", ""},
	// ServiceAccounts 权限
	{"serviceaccounts", "list", "", ""},
	{"serviceaccounts", "get", "", ""},
	{"serviceaccounts", "create", "", ""},
	// 危险: 创建 Token (可伪造身份)
	{"serviceaccounts", "create", "", "token"},
	// RBAC 权限 (管理员级别)
	{"clusterroles", "list", "rbac.authorization.k8s.io", ""},
	{"clusterroles", "create", "rbac.authorization.k8s.io", ""},
	{"clusterroles", "bind", "rbac.authorization.k8s.io", ""},
	{"clusterrolebindings", "list", "rbac.authorization.k8s.io", ""},
	{"clusterrolebindings", "create", "rbac.authorization.k8s.io", ""},
	{"roles", "list", "rbac.authorization.k8s.io", ""},
	{"roles", "create", "rbac.authorization.k8s.io", ""},
	{"rolebindings", "list", "rbac.authorization.k8s.io", ""},
	{"rolebindings", "create", "rbac.authorization.k8s.io", ""},
	// PersistentVolumes 权限
	{"persistentvolumes", "list", "", ""},
	{"persistentvolumes", "create", "", ""},
	{"persistentvolumeclaims", "list", "", ""},
	{"persistentvolumeclaims", "create", "", ""},
	// 通配符权限检查 (管理员)
	{"*", "*", "*", ""},
}

// SensitiveRules 敏感权限规则列表
// 按优先级从高到低排序，匹配到第一个规则即返回
var SensitiveRules = []SensitiveRule{
	// ========== 管理员权限 (Admin) ==========
	// 通配符权限 - 集群管理员
	{"*", "*", "*", "", PermLevelAdmin, "集群管理员权限 (cluster-admin)"},
	{"*", "*", "", "", PermLevelAdmin, "全资源管理权限"},

	// RBAC 权限提升 - 可以给自己或他人授权
	{"clusterroles", "create", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可创建集群角色"},
	{"clusterroles", "update", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可修改集群角色"},
	{"clusterroles", "patch", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可修补集群角色"},
	{"clusterroles", "bind", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可绑定集群角色"},
	{"clusterroles", "escalate", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可提升集群角色权限"},
	{"clusterrolebindings", "create", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可创建集群角色绑定"},
	{"clusterrolebindings", "update", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可修改集群角色绑定"},
	{"roles", "create", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可创建角色"},
	{"roles", "update", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可修改角色"},
	{"roles", "bind", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可绑定角色"},
	{"roles", "escalate", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可提升角色权限"},
	{"rolebindings", "create", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可创建角色绑定"},
	{"rolebindings", "update", "rbac.authorization.k8s.io", "", PermLevelAdmin, "可修改角色绑定"},

	// ========== 危险权限 (Dangerous) ==========
	// Pod 执行权限 - 可以在容器内执行命令
	{"pods", "create", "", "exec", PermLevelDangerous, "可在 Pod 内执行命令"},
	{"pods", "get", "", "exec", PermLevelDangerous, "可在 Pod 内执行命令"},
	{"pods", "*", "", "exec", PermLevelDangerous, "可在 Pod 内执行命令"},

	// Pod attach 权限 - 可以连接到容器
	{"pods", "create", "", "attach", PermLevelDangerous, "可连接到 Pod 容器"},
	{"pods", "get", "", "attach", PermLevelDangerous, "可连接到 Pod 容器"},
	{"pods", "*", "", "attach", PermLevelDangerous, "可连接到 Pod 容器"},

	// Pod portforward 权限
	{"pods", "create", "", "portforward", PermLevelDangerous, "可转发 Pod 端口"},
	{"pods", "get", "", "portforward", PermLevelDangerous, "可转发 Pod 端口"},

	// Node proxy 权限 - 可以访问 Kubelet API
	{"nodes", "get", "", "proxy", PermLevelDangerous, "可访问节点 Kubelet API"},
	{"nodes", "create", "", "proxy", PermLevelDangerous, "可访问节点 Kubelet API"},
	{"nodes", "*", "", "proxy", PermLevelDangerous, "可访问节点 Kubelet API"},

	// ServiceAccount Token 创建 - 可以伪造身份
	{"serviceaccounts", "create", "", "token", PermLevelDangerous, "可创建 ServiceAccount Token"},
	{"serviceaccounts", "*", "", "token", PermLevelDangerous, "可创建 ServiceAccount Token"},

	// CSR 权限 - 可以签发证书
	{"certificatesigningrequests", "create", "certificates.k8s.io", "", PermLevelDangerous, "可创建证书签名请求"},
	{"certificatesigningrequests", "update", "certificates.k8s.io", "approval", PermLevelDangerous, "可批准证书签名请求"},

	// Webhook 配置 - 可以拦截 API 请求
	{"mutatingwebhookconfigurations", "create", "admissionregistration.k8s.io", "", PermLevelDangerous, "可创建变更 Webhook"},
	{"mutatingwebhookconfigurations", "update", "admissionregistration.k8s.io", "", PermLevelDangerous, "可修改变更 Webhook"},
	{"validatingwebhookconfigurations", "create", "admissionregistration.k8s.io", "", PermLevelDangerous, "可创建验证 Webhook"},
	{"validatingwebhookconfigurations", "update", "admissionregistration.k8s.io", "", PermLevelDangerous, "可修改验证 Webhook"},

	// ========== 敏感权限 (Sensitive) ==========
	// Secrets - 可能包含凭据、密钥等
	{"secrets", "get", "", "", PermLevelSensitive, "可获取 Secret 内容"},
	{"secrets", "list", "", "", PermLevelSensitive, "可列出 Secrets"},
	{"secrets", "watch", "", "", PermLevelSensitive, "可监听 Secrets 变化"},
	{"secrets", "create", "", "", PermLevelSensitive, "可创建 Secrets"},
	{"secrets", "update", "", "", PermLevelSensitive, "可更新 Secrets"},
	{"secrets", "delete", "", "", PermLevelSensitive, "可删除 Secrets"},
	{"secrets", "*", "", "", PermLevelSensitive, "Secret 完全访问权限"},

	// Pod 日志 - 可能包含敏感信息
	{"pods", "get", "", "log", PermLevelSensitive, "可查看 Pod 日志"},
	{"pods", "*", "", "log", PermLevelSensitive, "可查看 Pod 日志"},

	// Pod 创建/删除 - 可以部署恶意工作负载
	{"pods", "create", "", "", PermLevelSensitive, "可创建 Pod"},
	{"pods", "delete", "", "", PermLevelSensitive, "可删除 Pod"},
	{"pods", "update", "", "", PermLevelSensitive, "可更新 Pod"},
	{"pods", "patch", "", "", PermLevelSensitive, "可修补 Pod"},

	// Deployments/DaemonSets/StatefulSets 创建 - 可以部署工作负载
	{"deployments", "create", "apps", "", PermLevelSensitive, "可创建 Deployment"},
	{"deployments", "update", "apps", "", PermLevelSensitive, "可更新 Deployment"},
	{"deployments", "delete", "apps", "", PermLevelSensitive, "可删除 Deployment"},
	{"daemonsets", "create", "apps", "", PermLevelSensitive, "可创建 DaemonSet"},
	{"daemonsets", "update", "apps", "", PermLevelSensitive, "可更新 DaemonSet"},
	{"daemonsets", "delete", "apps", "", PermLevelSensitive, "可删除 DaemonSet"},
	{"statefulsets", "create", "apps", "", PermLevelSensitive, "可创建 StatefulSet"},
	{"statefulsets", "update", "apps", "", PermLevelSensitive, "可更新 StatefulSet"},
	{"replicasets", "create", "apps", "", PermLevelSensitive, "可创建 ReplicaSet"},
	{"jobs", "create", "batch", "", PermLevelSensitive, "可创建 Job"},
	{"cronjobs", "create", "batch", "", PermLevelSensitive, "可创建 CronJob"},

	// ServiceAccount 创建/修改
	{"serviceaccounts", "create", "", "", PermLevelSensitive, "可创建 ServiceAccount"},
	{"serviceaccounts", "update", "", "", PermLevelSensitive, "可更新 ServiceAccount"},

	// PV/PVC - 可能访问持久化数据
	{"persistentvolumes", "create", "", "", PermLevelSensitive, "可创建 PersistentVolume"},
	{"persistentvolumes", "update", "", "", PermLevelSensitive, "可更新 PersistentVolume"},
	{"persistentvolumeclaims", "create", "", "", PermLevelSensitive, "可创建 PersistentVolumeClaim"},

	// RBAC 读取权限
	{"clusterroles", "list", "rbac.authorization.k8s.io", "", PermLevelSensitive, "可列出集群角色"},
	{"clusterroles", "get", "rbac.authorization.k8s.io", "", PermLevelSensitive, "可获取集群角色"},
	{"clusterrolebindings", "list", "rbac.authorization.k8s.io", "", PermLevelSensitive, "可列出集群角色绑定"},
	{"roles", "list", "rbac.authorization.k8s.io", "", PermLevelSensitive, "可列出角色"},
	{"rolebindings", "list", "rbac.authorization.k8s.io", "", PermLevelSensitive, "可列出角色绑定"},

	// Endpoints/Services - 服务发现信息
	{"endpoints", "list", "", "", PermLevelSensitive, "可列出服务端点"},
	{"endpointslices", "list", "discovery.k8s.io", "", PermLevelSensitive, "可列出服务端点切片"},
}

// GetPermissionLevel 获取权限的敏感级别
func GetPermissionLevel(p PermissionCheck) PermissionLevel {
	for _, rule := range SensitiveRules {
		if matchRule(p, rule) {
			return rule.Level
		}
	}
	return PermLevelNormal
}

// GetPermissionDescription 获取权限的描述
func GetPermissionDescription(p PermissionCheck) string {
	for _, rule := range SensitiveRules {
		if matchRule(p, rule) {
			return rule.Description
		}
	}
	return ""
}

// matchRule 检查权限是否匹配规则
func matchRule(p PermissionCheck, rule SensitiveRule) bool {
	// 资源匹配
	if rule.Resource != "*" && rule.Resource != p.Resource {
		return false
	}

	// 操作匹配
	if rule.Verb != "*" && rule.Verb != p.Verb {
		return false
	}

	// API Group 匹配
	if rule.Group != "*" && rule.Group != p.Group {
		return false
	}

	// 子资源匹配
	if rule.Subresource != "*" && rule.Subresource != p.Subresource {
		return false
	}

	return true
}

// GetLevelName 获取级别名称
func GetLevelName(level PermissionLevel) string {
	switch level {
	case PermLevelAdmin:
		return "管理员"
	case PermLevelDangerous:
		return "危险"
	case PermLevelSensitive:
		return "敏感"
	default:
		return "普通"
	}
}
