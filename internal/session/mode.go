package session

// Mode 运行模式
type Mode string

const (
	// ModeKubelet Kubelet 模式 - 通过 Kubelet API (10250) 操作
	ModeKubelet Mode = "kubelet"

	// ModeKubernetes Kubernetes 模式 - 通过 API Server (6443) 操作
	ModeKubernetes Mode = "kubernetes"
)

// String 返回模式字符串
func (m Mode) String() string {
	return string(m)
}

// IsValid 检查模式是否有效
func (m Mode) IsValid() bool {
	return m == ModeKubelet || m == ModeKubernetes
}

// ParseMode 解析模式字符串
func ParseMode(s string) Mode {
	switch s {
	case "kubelet", "k":
		return ModeKubelet
	case "kubernetes", "k8s":
		return ModeKubernetes
	default:
		return ""
	}
}

// DefaultMode 默认模式
const DefaultMode = ModeKubelet
