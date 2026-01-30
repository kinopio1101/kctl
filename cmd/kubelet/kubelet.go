package kubelet

import (
	"kctl/cmd"

	"github.com/spf13/cobra"
)

// Flags 定义（使用 PersistentFlags 供子命令继承）
var (
	FlagIP        string // Kubelet IP 地址（可选，默认自动获取）
	FlagPort      int    // Kubelet 端口（可选，默认 10250）
	FlagTokenFile string // 自定义 Token 文件路径（可选）
	FlagShowToken bool   // 是否输出 Token 内容
	FlagTokenPath bool   // 是否输出 Token 文件路径
)

// KubeletCmd 是 kubelet 主命令
var KubeletCmd = &cobra.Command{
	Use:   "kubelet",
	Short: "Kubernetes Kubelet 工具集",
	Long: `Kubernetes Kubelet 工具集

提供以下功能：
  - 读取 Pod 内的 ServiceAccount Token
  - 自动获取 Kubelet IP 地址（通过路由表）
  - 测试 Kubelet 端口连通性
  - 获取 Kubelet 节点上的 Pod 信息
  - 查询 Token 的 RBAC 权限`,
	Run: func(cmd *cobra.Command, args []string) {
		// 直接执行 kubelet 命令时显示帮助信息
		_ = cmd.Help()
	},
}

func init() {
	// 注册到 RootCmd
	cmd.RootCmd.AddCommand(KubeletCmd)

	// 定义 PersistentFlags（子命令可继承）
	KubeletCmd.PersistentFlags().StringVar(&FlagIP, "ip", "", "Kubelet IP 地址（默认自动从路由表获取）")
	KubeletCmd.PersistentFlags().IntVar(&FlagPort, "port", 10250, "Kubelet 端口")
	KubeletCmd.PersistentFlags().StringVar(&FlagTokenFile, "token-file", "", "自定义 Token 文件路径")
	KubeletCmd.PersistentFlags().BoolVar(&FlagShowToken, "token", false, "输出 Token 内容")
	KubeletCmd.PersistentFlags().BoolVar(&FlagTokenPath, "token-path", false, "输出 Token 文件路径")
}
