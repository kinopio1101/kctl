package kubelet

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"kctl/utils/Error"
	kubeletutil "kctl/utils/kubelet"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
)

// ProxyFlags 定义 proxy 子命令的 flags
var (
	ProxyURL     string // SOCKS5 代理地址 (socks5://host:port)
	ProxyTimeout int    // 代理连接超时时间（秒）
	ProxyTestURL string // 测试用的目标 URL
)

// proxyCmd 是 proxy 子命令
var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "配置和测试 SOCKS5 代理连接",
	Long: `SOCKS5 代理配置和测试工具

支持通过 SOCKS5 代理访问 Kubelet API，适用于以下场景：
- 通过堡垒机或跳板机访问 Kubelet
- 在受限网络环境中访问 Kubelet
- 使用代理服务器进行安全访问

示例：
  # 测试代理连接
  kctl kubelet proxy --proxy socks5://127.0.0.1:1080 test

  # 通过代理扫描节点
  kctl kubelet --proxy socks5://127.0.0.1:1080 scan

  # 通过代理执行命令
  kctl kubelet --proxy socks5://127.0.0.1:1080 exec`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return cmd.Help()
		}
		return nil
	},
}

// proxyTestCmd 测试代理连接
var proxyTestCmd = &cobra.Command{
	Use:   "test",
	Short: "测试 SOCKS5 代理连接",
	Long:  `测试 SOCKS5 代理连接是否正常工作`,
	Run: func(cmd *cobra.Command, args []string) {
		testProxyConnection()
	},
}

// proxyInfoCmd 显示代理配置信息
var proxyInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "显示代理配置信息",
	Long:  `显示当前配置的代理信息`,
	Run: func(cmd *cobra.Command, args []string) {
		showProxyInfo()
	},
}

func init() {
	// 添加 proxy 子命令
	KubeletCmd.AddCommand(proxyCmd)

	// proxy 子命令的 flags
	proxyCmd.PersistentFlags().StringVar(&ProxyURL, "proxy", "", "SOCKS5 代理地址 (例如: socks5://127.0.0.1:1080)")
	proxyCmd.PersistentFlags().IntVar(&ProxyTimeout, "proxy-timeout", 10, "代理连接超时时间（秒）")
	proxyCmd.PersistentFlags().StringVar(&ProxyTestURL, "test-url", "", "测试连接的目标 URL（可选）")

	// 添加子命令
	proxyCmd.AddCommand(proxyTestCmd)
	proxyCmd.AddCommand(proxyInfoCmd)

	// 将 proxy 相关 flags 添加到 KubeletCmd，使其他子命令也能使用
	KubeletCmd.PersistentFlags().StringVar(&ProxyURL, "proxy", "", "SOCKS5 代理地址 (例如: socks5://127.0.0.1:1080)")
	KubeletCmd.PersistentFlags().IntVar(&ProxyTimeout, "proxy-timeout", 10, "代理连接超时时间（秒）")
}

// testProxyConnection 测试代理连接
func testProxyConnection() {
	if ProxyURL == "" {
		log.Error("请指定代理地址，使用 --proxy 参数")
		Error.HandleFatal(fmt.Errorf("未指定代理地址"))
	}

	log.Infof("测试代理连接: %s", ProxyURL)

	// 解析代理 URL
	proxyAddr, err := parseProxyURL(ProxyURL)
	if err != nil {
		log.Errorf("解析代理地址失败: %v", err)
		Error.HandleFatal(err)
	}

	// 创建代理连接
	dialer, err := createProxyDialer(proxyAddr)
	if err != nil {
		log.Errorf("创建代理连接失败: %v", err)
		Error.HandleFatal(err)
	}

	// 设置超时
	timeout := time.Duration(ProxyTimeout) * time.Second

	// 测试连接到 Kubelet
	targetIP := FlagIP
	if targetIP == "" {
		var err error
		targetIP, err = kubeletutil.GetDefaultGateway()
		if err != nil {
			log.Warnf("无法获取默认网关，使用默认 IP: %v", err)
			targetIP = "127.0.0.1"
		}
	}

	targetAddr := fmt.Sprintf("%s:%d", targetIP, FlagPort)
	log.Infof("尝试通过代理连接到: %s", targetAddr)

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Errorf("代理连接失败: %v", err)
		Error.HandleFatal(err)
	}
	defer func() { _ = conn.Close() }()

	log.Infof("成功通过代理连接到 %s", targetAddr)

	// 设置超时
	_ = conn.SetDeadline(time.Now().Add(timeout))

	log.Info("代理连接测试成功！")
}

// showProxyInfo 显示代理配置信息
func showProxyInfo() {
	fmt.Println("代理配置信息:")
	fmt.Println("=========================================")
	if ProxyURL == "" {
		fmt.Println("代理地址: 未配置")
	} else {
		fmt.Printf("代理地址: %s\n", ProxyURL)
	}
	fmt.Printf("连接超时: %d 秒\n", ProxyTimeout)
	fmt.Printf("目标端口: %d\n", FlagPort)
	if FlagIP != "" {
		fmt.Printf("目标 IP: %s\n", FlagIP)
	} else {
		fmt.Println("目标 IP: 自动从路由表获取")
	}
	fmt.Println("=========================================")
}

// parseProxyURL 解析代理 URL
func parseProxyURL(proxyURL string) (string, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "", fmt.Errorf("解析代理 URL 失败: %w", err)
	}

	if u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return "", fmt.Errorf("不支持的代理协议: %s，仅支持 socks5 或 socks5h", u.Scheme)
	}

	if u.Host == "" {
		return "", fmt.Errorf("代理地址不能为空")
	}

	return u.Host, nil
}

// createProxyDialer 创建代理拨号器
func createProxyDialer(proxyAddr string) (proxy.Dialer, error) {
	// 创建 SOCKS5 代理
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("创建 SOCKS5 代理失败: %w", err)
	}

	return dialer, nil
}

// GetProxyDialer 获取配置的代理拨号器（供其他模块使用）
func GetProxyDialer() (proxy.Dialer, error) {
	if ProxyURL == "" {
		return nil, nil // 没有配置代理
	}

	proxyAddr, err := parseProxyURL(ProxyURL)
	if err != nil {
		return nil, err
	}

	return createProxyDialer(proxyAddr)
}

// GetHTTPProxyClient 获取支持代理的 HTTP Client（供其他模块使用）
func GetHTTPProxyClient() *http.Client {
	dialer, err := GetProxyDialer()
	if err != nil {
		log.Warnf("创建代理失败: %v，将使用直连", err)
		return &http.Client{}
	}

	if dialer == nil {
		return &http.Client{}
	}

	// 创建自定义 Transport
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Duration(ProxyTimeout) * time.Second,
	}
}
