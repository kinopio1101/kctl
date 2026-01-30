package kubelet

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // 纯 Go 实现的 SQLite，无需 CGO
)

// PodRecord 表示存储在数据库中的 Pod 记录（有安全利用价值的字段）
type PodRecord struct {
	ID                int64     `json:"id"`
	Name              string    `json:"name"`
	Namespace         string    `json:"namespace"`
	UID               string    `json:"uid"`
	NodeName          string    `json:"nodeName"`
	PodIP             string    `json:"podIP"`
	HostIP            string    `json:"hostIP"`
	Phase             string    `json:"phase"`
	ServiceAccount    string    `json:"serviceAccount"`
	CreationTimestamp string    `json:"creationTimestamp"`
	Containers        string    `json:"containers"`      // JSON 格式的容器信息
	Volumes           string    `json:"volumes"`         // JSON 格式的敏感挂载信息
	SecurityContext   string    `json:"securityContext"` // JSON 格式的安全上下文
	CollectedAt       time.Time `json:"collectedAt"`     // 收集时间
	KubeletIP         string    `json:"kubeletIP"`       // 收集来源 Kubelet IP
}

// ContainerInfo 存储容器的安全相关信息
type ContainerInfo struct {
	Name                     string   `json:"name"`
	Image                    string   `json:"image"`
	RunAsUser                *int64   `json:"runAsUser,omitempty"`
	RunAsGroup               *int64   `json:"runAsGroup,omitempty"`
	Privileged               bool     `json:"privileged"`
	AllowPrivilegeEscalation bool     `json:"allowPrivilegeEscalation"`
	ReadOnlyRootFilesystem   bool     `json:"readOnlyRootFilesystem"`
	VolumeMounts             []string `json:"volumeMounts"` // 挂载路径列表
}

// SensitiveVolume 存储敏感卷信息
type SensitiveVolume struct {
	Name       string `json:"name"`
	Type       string `json:"type"` // secret, configMap, hostPath, projected, emptyDir
	SecretName string `json:"secretName,omitempty"`
	HostPath   string `json:"hostPath,omitempty"`
	MountPath  string `json:"mountPath,omitempty"` // 挂载到容器的路径
}

// ServiceAccountRecord 表示存储在数据库中的 ServiceAccount 记录
type ServiceAccountRecord struct {
	ID              int64     `json:"id"`
	Name            string    `json:"name"`            // SA 名称
	Namespace       string    `json:"namespace"`       // 命名空间
	Token           string    `json:"token"`           // Token 内容
	TokenExpiration string    `json:"tokenExpiration"` // Token 过期时间
	IsExpired       bool      `json:"isExpired"`       // 是否已过期
	RiskLevel       string    `json:"riskLevel"`       // 风险等级: CRITICAL, HIGH, MEDIUM, LOW, NONE, ADMIN
	Permissions     string    `json:"permissions"`     // JSON 格式的权限列表
	IsClusterAdmin  bool      `json:"isClusterAdmin"`  // 是否是集群管理员
	SecurityFlags   string    `json:"securityFlags"`   // JSON 格式的安全标识
	Pods            string    `json:"pods"`            // JSON 格式的关联 Pod 列表
	CollectedAt     time.Time `json:"collectedAt"`     // 收集时间
	KubeletIP       string    `json:"kubeletIP"`       // 收集来源 Kubelet IP
}

// SAPermission 存储单个权限信息
type SAPermission struct {
	Resource    string `json:"resource"`
	Verb        string `json:"verb"`
	Group       string `json:"group,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Allowed     bool   `json:"allowed"`
}

// SASecurityFlags 存储安全标识
type SASecurityFlags struct {
	Privileged               bool `json:"privileged"`
	AllowPrivilegeEscalation bool `json:"allowPrivilegeEscalation"`
	HasHostPath              bool `json:"hasHostPath"`
	HasSecretMount           bool `json:"hasSecretMount"`
	HasSATokenMount          bool `json:"hasSATokenMount"`
}

// SAPodInfo 存储关联的 Pod 信息
type SAPodInfo struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Container string `json:"container"`
}

// PodDB 封装数据库操作
type PodDB struct {
	db     *sql.DB
	dbPath string
}

// DefaultDBPath 返回默认的数据库路径
func DefaultDBPath() string {
	// 默认在当前目录下创建
	return "kubelet_pods.db"
}

// NewPodDB 创建或打开数据库
func NewPodDB(dbPath string) (*PodDB, error) {
	if dbPath == "" {
		dbPath = DefaultDBPath()
	}

	// 确保目录存在
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建数据库目录失败: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}

	podDB := &PodDB{
		db:     db,
		dbPath: dbPath,
	}

	if err := podDB.initSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}

	return podDB, nil
}

// initSchema 初始化数据库表结构
func (p *PodDB) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS pods (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		namespace TEXT NOT NULL,
		uid TEXT UNIQUE NOT NULL,
		node_name TEXT,
		pod_ip TEXT,
		host_ip TEXT,
		phase TEXT,
		service_account TEXT,
		creation_timestamp TEXT,
		containers TEXT,
		volumes TEXT,
		security_context TEXT,
		collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		kubelet_ip TEXT
	);
	
	CREATE INDEX IF NOT EXISTS idx_pods_namespace ON pods(namespace);
	CREATE INDEX IF NOT EXISTS idx_pods_node ON pods(node_name);
	CREATE INDEX IF NOT EXISTS idx_pods_service_account ON pods(service_account);
	CREATE INDEX IF NOT EXISTS idx_pods_collected_at ON pods(collected_at);

	CREATE TABLE IF NOT EXISTS service_accounts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		namespace TEXT NOT NULL,
		token TEXT,
		token_expiration TEXT,
		is_expired BOOLEAN DEFAULT FALSE,
		risk_level TEXT,
		permissions TEXT,
		is_cluster_admin BOOLEAN DEFAULT FALSE,
		security_flags TEXT,
		pods TEXT,
		collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		kubelet_ip TEXT,
		UNIQUE(name, namespace)
	);

	CREATE INDEX IF NOT EXISTS idx_sa_namespace ON service_accounts(namespace);
	CREATE INDEX IF NOT EXISTS idx_sa_risk_level ON service_accounts(risk_level);
	CREATE INDEX IF NOT EXISTS idx_sa_is_cluster_admin ON service_accounts(is_cluster_admin);
	CREATE INDEX IF NOT EXISTS idx_sa_collected_at ON service_accounts(collected_at);
	`

	_, err := p.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("初始化数据库表结构失败: %w", err)
	}

	return nil
}

// Close 关闭数据库连接
func (p *PodDB) Close() error {
	return p.db.Close()
}

// SavePod 保存或更新 Pod 记录
func (p *PodDB) SavePod(record *PodRecord) error {
	query := `
	INSERT OR REPLACE INTO pods (
		name, namespace, uid, node_name, pod_ip, host_ip, phase,
		service_account, creation_timestamp, containers, volumes,
		security_context, collected_at, kubelet_ip
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := p.db.Exec(query,
		record.Name,
		record.Namespace,
		record.UID,
		record.NodeName,
		record.PodIP,
		record.HostIP,
		record.Phase,
		record.ServiceAccount,
		record.CreationTimestamp,
		record.Containers,
		record.Volumes,
		record.SecurityContext,
		record.CollectedAt,
		record.KubeletIP,
	)

	return err
}

// SavePods 批量保存 Pod 记录
func (p *PodDB) SavePods(records []*PodRecord) (int, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO pods (
			name, namespace, uid, node_name, pod_ip, host_ip, phase,
			service_account, creation_timestamp, containers, volumes,
			security_context, collected_at, kubelet_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("准备语句失败: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	saved := 0
	for _, record := range records {
		_, err := stmt.Exec(
			record.Name,
			record.Namespace,
			record.UID,
			record.NodeName,
			record.PodIP,
			record.HostIP,
			record.Phase,
			record.ServiceAccount,
			record.CreationTimestamp,
			record.Containers,
			record.Volumes,
			record.SecurityContext,
			record.CollectedAt,
			record.KubeletIP,
		)
		if err != nil {
			return saved, fmt.Errorf("保存 Pod %s/%s 失败: %w", record.Namespace, record.Name, err)
		}
		saved++
	}

	if err := tx.Commit(); err != nil {
		return saved, fmt.Errorf("提交事务失败: %w", err)
	}

	return saved, nil
}

// GetAllPods 获取所有 Pod 记录
func (p *PodDB) GetAllPods() ([]*PodRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, uid, node_name, pod_ip, host_ip, phase,
			   service_account, creation_timestamp, containers, volumes,
			   security_context, collected_at, kubelet_ip
		FROM pods ORDER BY collected_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanPodRows(rows)
}

// GetPodsByNamespace 按命名空间获取 Pod
func (p *PodDB) GetPodsByNamespace(namespace string) ([]*PodRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, uid, node_name, pod_ip, host_ip, phase,
			   service_account, creation_timestamp, containers, volumes,
			   security_context, collected_at, kubelet_ip
		FROM pods WHERE namespace = ? ORDER BY name
	`, namespace)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanPodRows(rows)
}

// GetPodsByServiceAccount 按 ServiceAccount 获取 Pod
func (p *PodDB) GetPodsByServiceAccount(sa string) ([]*PodRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, uid, node_name, pod_ip, host_ip, phase,
			   service_account, creation_timestamp, containers, volumes,
			   security_context, collected_at, kubelet_ip
		FROM pods WHERE service_account = ? ORDER BY namespace, name
	`, sa)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanPodRows(rows)
}

// GetPrivilegedPods 获取特权 Pod
func (p *PodDB) GetPrivilegedPods() ([]*PodRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, uid, node_name, pod_ip, host_ip, phase,
			   service_account, creation_timestamp, containers, volumes,
			   security_context, collected_at, kubelet_ip
		FROM pods 
		WHERE containers LIKE '%"privileged":true%'
		   OR containers LIKE '%"allowPrivilegeEscalation":true%'
		ORDER BY namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanPodRows(rows)
}

// GetPodsWithSecrets 获取挂载了 Secret 的 Pod
func (p *PodDB) GetPodsWithSecrets() ([]*PodRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, uid, node_name, pod_ip, host_ip, phase,
			   service_account, creation_timestamp, containers, volumes,
			   security_context, collected_at, kubelet_ip
		FROM pods 
		WHERE volumes LIKE '%"type":"secret"%'
		ORDER BY namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanPodRows(rows)
}

// GetPodsWithHostPath 获取挂载了主机路径的 Pod
func (p *PodDB) GetPodsWithHostPath() ([]*PodRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, uid, node_name, pod_ip, host_ip, phase,
			   service_account, creation_timestamp, containers, volumes,
			   security_context, collected_at, kubelet_ip
		FROM pods 
		WHERE volumes LIKE '%"type":"hostPath"%'
		ORDER BY namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanPodRows(rows)
}

// GetPodCount 获取 Pod 总数
func (p *PodDB) GetPodCount() (int, error) {
	var count int
	err := p.db.QueryRow("SELECT COUNT(*) FROM pods").Scan(&count)
	return count, err
}

// GetNamespaces 获取所有命名空间
func (p *PodDB) GetNamespaces() ([]string, error) {
	rows, err := p.db.Query("SELECT DISTINCT namespace FROM pods ORDER BY namespace")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var namespaces []string
	for rows.Next() {
		var ns string
		if err := rows.Scan(&ns); err != nil {
			return nil, err
		}
		namespaces = append(namespaces, ns)
	}

	return namespaces, nil
}

// GetServiceAccounts 获取所有 ServiceAccount
func (p *PodDB) GetServiceAccounts() ([]string, error) {
	rows, err := p.db.Query("SELECT DISTINCT service_account FROM pods WHERE service_account != '' ORDER BY service_account")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var sas []string
	for rows.Next() {
		var sa string
		if err := rows.Scan(&sa); err != nil {
			return nil, err
		}
		sas = append(sas, sa)
	}

	return sas, nil
}

// ClearAll 清空所有记录
func (p *PodDB) ClearAll() error {
	_, err := p.db.Exec("DELETE FROM pods")
	return err
}

// scanPodRows 扫描数据库行并返回 PodRecord 切片
func scanPodRows(rows *sql.Rows) ([]*PodRecord, error) {
	var pods []*PodRecord
	for rows.Next() {
		var pod PodRecord
		err := rows.Scan(
			&pod.ID,
			&pod.Name,
			&pod.Namespace,
			&pod.UID,
			&pod.NodeName,
			&pod.PodIP,
			&pod.HostIP,
			&pod.Phase,
			&pod.ServiceAccount,
			&pod.CreationTimestamp,
			&pod.Containers,
			&pod.Volumes,
			&pod.SecurityContext,
			&pod.CollectedAt,
			&pod.KubeletIP,
		)
		if err != nil {
			return nil, err
		}
		pods = append(pods, &pod)
	}

	return pods, nil
}

// ParseContainers 解析容器 JSON 字符串
func ParseContainers(containersJSON string) ([]ContainerInfo, error) {
	if containersJSON == "" {
		return nil, nil
	}
	var containers []ContainerInfo
	err := json.Unmarshal([]byte(containersJSON), &containers)
	return containers, err
}

// ParseVolumes 解析卷 JSON 字符串
func ParseVolumes(volumesJSON string) ([]SensitiveVolume, error) {
	if volumesJSON == "" {
		return nil, nil
	}
	var volumes []SensitiveVolume
	err := json.Unmarshal([]byte(volumesJSON), &volumes)
	return volumes, err
}

// ==================== ServiceAccount 相关方法 ====================

// SaveServiceAccount 保存或更新 ServiceAccount 记录
func (p *PodDB) SaveServiceAccount(record *ServiceAccountRecord) error {
	query := `
	INSERT OR REPLACE INTO service_accounts (
		name, namespace, token, token_expiration, is_expired,
		risk_level, permissions, is_cluster_admin, security_flags,
		pods, collected_at, kubelet_ip
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := p.db.Exec(query,
		record.Name,
		record.Namespace,
		record.Token,
		record.TokenExpiration,
		record.IsExpired,
		record.RiskLevel,
		record.Permissions,
		record.IsClusterAdmin,
		record.SecurityFlags,
		record.Pods,
		record.CollectedAt,
		record.KubeletIP,
	)

	return err
}

// SaveServiceAccounts 批量保存 ServiceAccount 记录
func (p *PodDB) SaveServiceAccounts(records []*ServiceAccountRecord) (int, error) {
	tx, err := p.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("开始事务失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT OR REPLACE INTO service_accounts (
			name, namespace, token, token_expiration, is_expired,
			risk_level, permissions, is_cluster_admin, security_flags,
			pods, collected_at, kubelet_ip
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("准备语句失败: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	saved := 0
	for _, record := range records {
		_, err := stmt.Exec(
			record.Name,
			record.Namespace,
			record.Token,
			record.TokenExpiration,
			record.IsExpired,
			record.RiskLevel,
			record.Permissions,
			record.IsClusterAdmin,
			record.SecurityFlags,
			record.Pods,
			record.CollectedAt,
			record.KubeletIP,
		)
		if err != nil {
			return saved, fmt.Errorf("保存 SA %s/%s 失败: %w", record.Namespace, record.Name, err)
		}
		saved++
	}

	if err := tx.Commit(); err != nil {
		return saved, fmt.Errorf("提交事务失败: %w", err)
	}

	return saved, nil
}

// GetAllServiceAccounts 获取所有 ServiceAccount 记录
func (p *PodDB) GetAllServiceAccounts() ([]*ServiceAccountRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, token, token_expiration, is_expired,
			   risk_level, permissions, is_cluster_admin, security_flags,
			   pods, collected_at, kubelet_ip
		FROM service_accounts ORDER BY 
			CASE risk_level 
				WHEN 'ADMIN' THEN 0
				WHEN 'CRITICAL' THEN 1 
				WHEN 'HIGH' THEN 2 
				WHEN 'MEDIUM' THEN 3 
				WHEN 'LOW' THEN 4 
				ELSE 5 
			END, namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanSARows(rows)
}

// GetServiceAccountsByRiskLevel 按风险等级获取 ServiceAccount
func (p *PodDB) GetServiceAccountsByRiskLevel(riskLevel string) ([]*ServiceAccountRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, token, token_expiration, is_expired,
			   risk_level, permissions, is_cluster_admin, security_flags,
			   pods, collected_at, kubelet_ip
		FROM service_accounts WHERE risk_level = ? ORDER BY namespace, name
	`, riskLevel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanSARows(rows)
}

// GetClusterAdminServiceAccounts 获取集群管理员级别的 ServiceAccount
func (p *PodDB) GetClusterAdminServiceAccounts() ([]*ServiceAccountRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, token, token_expiration, is_expired,
			   risk_level, permissions, is_cluster_admin, security_flags,
			   pods, collected_at, kubelet_ip
		FROM service_accounts WHERE is_cluster_admin = TRUE ORDER BY namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanSARows(rows)
}

// GetRiskyServiceAccounts 获取有风险的 ServiceAccount (CRITICAL, HIGH, MEDIUM, ADMIN)
func (p *PodDB) GetRiskyServiceAccounts() ([]*ServiceAccountRecord, error) {
	rows, err := p.db.Query(`
		SELECT id, name, namespace, token, token_expiration, is_expired,
			   risk_level, permissions, is_cluster_admin, security_flags,
			   pods, collected_at, kubelet_ip
		FROM service_accounts 
		WHERE risk_level IN ('ADMIN', 'CRITICAL', 'HIGH', 'MEDIUM')
		ORDER BY 
			CASE risk_level 
				WHEN 'ADMIN' THEN 0
				WHEN 'CRITICAL' THEN 1 
				WHEN 'HIGH' THEN 2 
				WHEN 'MEDIUM' THEN 3 
				ELSE 4 
			END, namespace, name
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	return scanSARows(rows)
}

// GetServiceAccountByName 按名称和命名空间获取 ServiceAccount
func (p *PodDB) GetServiceAccountByName(namespace, name string) (*ServiceAccountRecord, error) {
	row := p.db.QueryRow(`
		SELECT id, name, namespace, token, token_expiration, is_expired,
			   risk_level, permissions, is_cluster_admin, security_flags,
			   pods, collected_at, kubelet_ip
		FROM service_accounts WHERE namespace = ? AND name = ?
	`, namespace, name)

	var sa ServiceAccountRecord
	err := row.Scan(
		&sa.ID,
		&sa.Name,
		&sa.Namespace,
		&sa.Token,
		&sa.TokenExpiration,
		&sa.IsExpired,
		&sa.RiskLevel,
		&sa.Permissions,
		&sa.IsClusterAdmin,
		&sa.SecurityFlags,
		&sa.Pods,
		&sa.CollectedAt,
		&sa.KubeletIP,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &sa, nil
}

// GetServiceAccountCount 获取 ServiceAccount 总数
func (p *PodDB) GetServiceAccountCount() (int, error) {
	var count int
	err := p.db.QueryRow("SELECT COUNT(*) FROM service_accounts").Scan(&count)
	return count, err
}

// GetServiceAccountStats 获取 ServiceAccount 统计信息
func (p *PodDB) GetServiceAccountStats() (map[string]int, error) {
	stats := make(map[string]int)

	rows, err := p.db.Query(`
		SELECT risk_level, COUNT(*) as count 
		FROM service_accounts 
		GROUP BY risk_level
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var level string
		var count int
		if err := rows.Scan(&level, &count); err != nil {
			return nil, err
		}
		stats[level] = count
	}

	// 获取集群管理员数量
	var adminCount int
	err = p.db.QueryRow("SELECT COUNT(*) FROM service_accounts WHERE is_cluster_admin = TRUE").Scan(&adminCount)
	if err != nil {
		return nil, err
	}
	stats["ADMIN"] = adminCount

	return stats, nil
}

// ClearServiceAccounts 清空所有 ServiceAccount 记录
func (p *PodDB) ClearServiceAccounts() error {
	_, err := p.db.Exec("DELETE FROM service_accounts")
	return err
}

// scanSARows 扫描数据库行并返回 ServiceAccountRecord 切片
func scanSARows(rows *sql.Rows) ([]*ServiceAccountRecord, error) {
	var sas []*ServiceAccountRecord
	for rows.Next() {
		var sa ServiceAccountRecord
		err := rows.Scan(
			&sa.ID,
			&sa.Name,
			&sa.Namespace,
			&sa.Token,
			&sa.TokenExpiration,
			&sa.IsExpired,
			&sa.RiskLevel,
			&sa.Permissions,
			&sa.IsClusterAdmin,
			&sa.SecurityFlags,
			&sa.Pods,
			&sa.CollectedAt,
			&sa.KubeletIP,
		)
		if err != nil {
			return nil, err
		}
		sas = append(sas, &sa)
	}

	return sas, nil
}

// ParseSAPermissions 解析权限 JSON 字符串
func ParseSAPermissions(permissionsJSON string) ([]SAPermission, error) {
	if permissionsJSON == "" {
		return nil, nil
	}
	var permissions []SAPermission
	err := json.Unmarshal([]byte(permissionsJSON), &permissions)
	return permissions, err
}

// ParseSAPods 解析 Pod 列表 JSON 字符串
func ParseSAPods(podsJSON string) ([]SAPodInfo, error) {
	if podsJSON == "" {
		return nil, nil
	}
	var pods []SAPodInfo
	err := json.Unmarshal([]byte(podsJSON), &pods)
	return pods, err
}
