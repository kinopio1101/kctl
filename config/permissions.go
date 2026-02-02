package config

// ==================== 权限检查定义 ====================

// PermissionDef 权限定义
type PermissionDef struct {
	Resource    string
	Verb        string
	Group       string
	Subresource string
}

// PermissionsToCheck 需要检查的权限列表
// 按重要性排序，便于维护和扩展
var PermissionsToCheck = []PermissionDef{
	// ==================== Pod 相关权限 ====================
	// 基础操作
	{"pods", "list", "", ""},
	{"pods", "get", "", ""},
	{"pods", "create", "", ""},
	{"pods", "delete", "", ""},
	// 危险子资源
	{"pods", "create", "", "exec"},
	{"pods", "create", "", "attach"},
	{"pods", "get", "", "log"},

	// ==================== Secrets 权限（敏感）====================
	{"secrets", "list", "", ""},
	{"secrets", "get", "", ""},
	{"secrets", "create", "", ""},
	{"secrets", "delete", "", ""},

	// ==================== ConfigMaps 权限 ====================
	{"configmaps", "list", "", ""},
	{"configmaps", "get", "", ""},

	// ==================== Services 权限 ====================
	{"services", "list", "", ""},
	{"services", "get", "", ""},

	// ==================== Nodes 权限 ====================
	{"nodes", "list", "", ""},
	{"nodes", "get", "", ""},
	{"nodes", "delete", "", ""}, // 用于检测 admin 权限
	// 危险: nodes/proxy 权限 (可访问 Kubelet API)
	{"nodes", "get", "", "proxy"},
	{"nodes", "create", "", "proxy"},

	// ==================== Namespaces 权限 ====================
	{"namespaces", "list", "", ""},
	{"namespaces", "get", "", ""},
	{"namespaces", "delete", "", ""}, // 用于检测 admin 权限

	// ==================== Deployments 权限 ====================
	{"deployments", "list", "apps", ""},
	{"deployments", "get", "apps", ""},
	{"deployments", "create", "apps", ""},
	{"deployments", "delete", "apps", ""},

	// ==================== DaemonSets 权限 ====================
	{"daemonsets", "list", "apps", ""},
	{"daemonsets", "create", "apps", ""},

	// ==================== ServiceAccounts 权限 ====================
	{"serviceaccounts", "list", "", ""},
	{"serviceaccounts", "get", "", ""},
	{"serviceaccounts", "create", "", ""},
	// 危险: 创建 Token (可伪造身份)
	{"serviceaccounts", "create", "", "token"},

	// ==================== RBAC 权限（管理员级别）====================
	{"clusterroles", "list", "rbac.authorization.k8s.io", ""},
	{"clusterroles", "create", "rbac.authorization.k8s.io", ""},
	{"clusterroles", "bind", "rbac.authorization.k8s.io", ""},
	{"clusterrolebindings", "list", "rbac.authorization.k8s.io", ""},
	{"clusterrolebindings", "create", "rbac.authorization.k8s.io", ""},
	{"clusterrolebindings", "delete", "rbac.authorization.k8s.io", ""}, // 用于检测 admin 权限
	{"roles", "list", "rbac.authorization.k8s.io", ""},
	{"roles", "create", "rbac.authorization.k8s.io", ""},
	{"rolebindings", "list", "rbac.authorization.k8s.io", ""},
	{"rolebindings", "create", "rbac.authorization.k8s.io", ""},

	// ==================== PersistentVolumes 权限 ====================
	{"persistentvolumes", "list", "", ""},
	{"persistentvolumes", "create", "", ""},
	{"persistentvolumeclaims", "list", "", ""},
	{"persistentvolumeclaims", "create", "", ""},
}
