package commands

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"kctl/config"
	"kctl/internal/output"
	"kctl/internal/session"
	"kctl/pkg/types"
)

// 全局端口转发管理
var (
	activePortForward *portForwardInstance
	pfMutex           sync.Mutex
)

type portForwardInstance struct {
	stopChan chan struct{}
	stopPort int
}

// PortForwardCmd portforward 命令
type PortForwardCmd struct{}

func init() {
	Register(&PortForwardCmd{})
}

func (c *PortForwardCmd) Name() string {
	return "portforward"
}

func (c *PortForwardCmd) Aliases() []string {
	return []string{"pf"}
}

func (c *PortForwardCmd) Description() string {
	return "端口转发"
}

func (c *PortForwardCmd) Usage() string {
	return `portforward [options] <pod> <local_port>:<remote_port> [...]

通过 Kubelet /portForward API 进行端口转发

选项：
  -n <namespace>      指定命名空间
  --address <addr>    监听地址（默认: 127.0.0.1）
  --timeout <seconds> 超时时间（秒），0 表示无限（默认: 0）

子命令：
  stop                停止当前端口转发

示例：
  portforward nginx 8080:80                    转发本地 8080 到 Pod 的 80
  portforward -n kube-system coredns 5353:53  指定命名空间
  portforward nginx 8080:80 9090:9090         多端口转发
  portforward --address 0.0.0.0 nginx 8080:80 监听所有接口
  portforward nginx 8080:80 --timeout 60      60秒后自动停止
  pf stop                                      停止端口转发`
}

func (c *PortForwardCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer

	// 检查是否是 stop 子命令
	if len(args) > 0 && args[0] == "stop" {
		return stopPortForward(p)
	}

	ctx := context.Background()

	// 检查连接
	kubelet, err := sess.GetKubeletClient()
	if err != nil {
		return err
	}

	// 解析参数
	namespace := ""
	address := "127.0.0.1"
	podName := ""
	timeout := 0
	var ports []types.PortMapping

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n":
			if i+1 < len(args) {
				namespace = args[i+1]
				i++
			}
		case "--address":
			if i+1 < len(args) {
				address = args[i+1]
				i++
			}
		case "--timeout":
			if i+1 < len(args) {
				if t, err := strconv.Atoi(args[i+1]); err == nil && t > 0 {
					timeout = t
				}
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				// 检查是否是端口映射格式
				if strings.Contains(args[i], ":") {
					pm, err := parsePortMapping(args[i])
					if err != nil {
						return err
					}
					ports = append(ports, pm)
				} else if podName == "" {
					podName = args[i]
				}
			}
		}
	}

	if podName == "" {
		return fmt.Errorf("请指定 Pod 名称，或使用 'pf stop' 停止当前转发")
	}
	if len(ports) == 0 {
		return fmt.Errorf("请指定端口映射，格式: <local_port>:<remote_port>")
	}

	// 检查是否已有活动的端口转发
	pfMutex.Lock()
	if activePortForward != nil {
		pfMutex.Unlock()
		return fmt.Errorf("已有端口转发在运行，请先执行 'pf stop' 停止")
	}
	pfMutex.Unlock()

	// 从缓存查找 namespace
	if namespace == "" {
		pods := sess.GetCachedPods()
		for _, pod := range pods {
			if pod.PodName == podName {
				namespace = pod.Namespace
				break
			}
		}
	}
	if namespace == "" {
		namespace = "default"
	}

	opts := &types.PortForwardOptions{
		Namespace: namespace,
		Pod:       podName,
		Ports:     ports,
		Address:   address,
	}

	// 创建停止控制端口
	stopListener, stopPort, err := createStopListener()
	if err != nil {
		return fmt.Errorf("创建停止监听器失败: %w", err)
	}

	// 设置停止信号
	stopChan := make(chan struct{})

	// 注册活动的端口转发
	pfMutex.Lock()
	activePortForward = &portForwardInstance{
		stopChan: stopChan,
		stopPort: stopPort,
	}
	pfMutex.Unlock()

	// 显示信息
	p.Printf("%s Forwarding ports:\n", p.Colored(config.ColorBlue, "[*]"))
	for _, pm := range ports {
		p.Printf("    %s:%d -> %s/%s:%d\n",
			address, pm.Local, namespace, podName, pm.Remote)
	}
	p.Println()
	p.Printf("%s To stop: %s or %s\n",
		p.Colored(config.ColorGray, "[*]"),
		p.Colored(config.ColorCyan, "pf stop"),
		p.Colored(config.ColorGray, fmt.Sprintf("nc localhost %d", stopPort)))
	if timeout > 0 {
		p.Printf("%s Auto-stop in %d seconds\n", p.Colored(config.ColorGray, "[*]"), timeout)
	}
	p.Println()

	// 启动停止监听器
	go func() {
		conn, err := stopListener.Accept()
		if err != nil {
			return
		}
		conn.Close()
		stopListener.Close()
		triggerStop(p, "network signal")
	}()

	// 如果设置了超时，启动超时计时器
	if timeout > 0 {
		go func() {
			time.Sleep(time.Duration(timeout) * time.Second)
			triggerStop(p, "timeout")
		}()
	}

	// 开始端口转发（在后台运行）
	go func() {
		err := kubelet.PortForward(ctx, opts, stopChan)

		// 清理
		pfMutex.Lock()
		activePortForward = nil
		pfMutex.Unlock()
		stopListener.Close()

		if err != nil {
			p.Printf("%s Port forward error: %v\n", p.Colored(config.ColorRed, "[-]"), err)
		} else {
			p.Success("Port forward stopped")
		}
	}()

	// 立即返回，让用户可以继续使用 console
	p.Printf("%s Port forward running in background\n", p.Colored(config.ColorGreen, "[+]"))

	return nil
}

// stopPortForward 停止当前端口转发
func stopPortForward(p output.Printer) error {
	pfMutex.Lock()
	defer pfMutex.Unlock()

	if activePortForward == nil {
		return fmt.Errorf("没有正在运行的端口转发")
	}

	// 通过连接停止端口来触发停止
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", activePortForward.stopPort))
	if err != nil {
		// 如果连接失败，直接关闭 channel
		select {
		case <-activePortForward.stopChan:
			// 已经关闭
		default:
			close(activePortForward.stopChan)
		}
	} else {
		conn.Close()
	}

	return nil
}

// triggerStop 触发停止
func triggerStop(p output.Printer, reason string) {
	pfMutex.Lock()
	defer pfMutex.Unlock()

	if activePortForward == nil {
		return
	}

	select {
	case <-activePortForward.stopChan:
		// 已经关闭
	default:
		p.Printf("%s Stopping port forward (%s)...\n", p.Colored(config.ColorYellow, "[*]"), reason)
		close(activePortForward.stopChan)
	}
}

// createStopListener 创建一个用于停止端口转发的监听器
func createStopListener() (net.Listener, int, error) {
	// 使用随机端口
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, port, nil
}

// parsePortMapping 解析端口映射字符串
func parsePortMapping(s string) (types.PortMapping, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return types.PortMapping{}, fmt.Errorf("无效的端口映射格式: %s (应为 local:remote)", s)
	}

	local, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return types.PortMapping{}, fmt.Errorf("无效的本地端口: %s", parts[0])
	}

	remote, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return types.PortMapping{}, fmt.Errorf("无效的远程端口: %s", parts[1])
	}

	return types.PortMapping{
		Local:  uint16(local),
		Remote: uint16(remote),
	}, nil
}
