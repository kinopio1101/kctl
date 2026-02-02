package console

import (
	"kctl/cmd"
	"kctl/internal/console"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// 命令行参数
	target    string
	port      int
	tokenFile string
	tokenStr  string
	proxy     string
	apiServer string
	apiPort   int
)

// ConsoleCmd 是 console 子命令
var ConsoleCmd = &cobra.Command{
	Use:     "console",
	Aliases: []string{"c"},
	Short:   "进入交互式控制台",
	Long: `进入交互式控制台，支持扫描、查询、执行等操作

特点：
  - 无文件落地：所有数据缓存在内存中，退出时自动清除
  - 一次扫描，多次查询：扫描结果缓存，避免重复扫描
  - 交互式操作：类似 MSF 的命令行界面，支持自动补全
  - 自动连接：进入时自动使用当前环境信息连接

在 Pod 内运行时会自动：
  - 检测 Kubelet IP（默认网关）
  - 读取 ServiceAccount Token
  - 使用内存数据库
  - 自动连接到 Kubelet

示例：
  # 进入交互式控制台（自动连接）
  kctl console

  # 指定目标进入
  kctl console -t 10.0.0.1

  # 指定完整连接参数
  kctl console -t 10.0.0.1 -p 10250 --token "eyJ..." --api-server 10.0.0.1 --api-port 6443

  # 使用 token 文件
  kctl console -t 10.0.0.1 --token-file /path/to/token

  # 在控制台中
  kctl [kube-system/cluster-admin ADMIN]> exec -- whoami`,
	Run: runConsole,
}

func init() {
	cmd.RootCmd.AddCommand(ConsoleCmd)

	// 添加命令行参数
	ConsoleCmd.Flags().StringVarP(&target, "target", "t", "", "Kubelet IP 地址")
	ConsoleCmd.Flags().IntVarP(&port, "port", "p", 10250, "Kubelet 端口")
	ConsoleCmd.Flags().StringVar(&tokenFile, "token-file", "", "Token 文件路径")
	ConsoleCmd.Flags().StringVar(&tokenStr, "token", "", "Token 字符串")
	ConsoleCmd.Flags().StringVar(&proxy, "proxy", "", "SOCKS5 代理地址")
	ConsoleCmd.Flags().StringVar(&apiServer, "api-server", "", "API Server 地址")
	ConsoleCmd.Flags().IntVar(&apiPort, "api-port", 443, "API Server 端口")
}

func runConsole(cmd *cobra.Command, args []string) {
	// 注册所有命令
	console.RegisterCommands()

	// 创建控制台，传入命令行参数
	opts := console.Options{
		Target:    target,
		Port:      port,
		TokenFile: tokenFile,
		Token:     tokenStr,
		Proxy:     proxy,
		APIServer: apiServer,
		APIPort:   apiPort,
	}

	c, err := console.NewWithOptions(opts)
	if err != nil {
		log.Errorf("创建控制台失败: %v", err)
		return
	}
	defer c.Close()

	// 运行控制台
	c.Run()
}
