package commands

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"kctl/config"
	"kctl/internal/output"
	"kctl/internal/session"
	"kctl/pkg/network"
	"kctl/pkg/types"
)

// DiscoverCmd discover 命令
type DiscoverCmd struct{}

func init() {
	Register(&DiscoverCmd{})
}

func (c *DiscoverCmd) Name() string {
	return "discover"
}

func (c *DiscoverCmd) Aliases() []string {
	return []string{"disc"}
}

func (c *DiscoverCmd) Description() string {
	return "扫描网段发现 Kubelet 节点"
}

func (c *DiscoverCmd) Usage() string {
	return `discover <target> [options]

扫描网段发现 Kubelet 节点

目标格式：
  192.168.1.1           单个 IP
  192.168.1.0/24        CIDR 网段
  192.168.1.1-100       IP 范围

选项：
  -p, --port <ports>    端口 (默认: 10250)
                        支持: 10250,10255 或 10250-10260
  -c, --concurrency     并发数 (默认: 100)
  -t, --timeout         超时秒数 (默认: 3)
  --all                 显示所有开放端口，不仅是 Kubelet

示例：
  discover 10.0.0.0/24
  discover 10.0.0.1-254 -p 10250,10255
  discover 10.0.0.0/16 -c 200`
}

// discoverOptions 命令选项
type discoverOptions struct {
	target      string
	ports       []int
	concurrency int
	timeout     time.Duration
	showAll     bool
}

func (c *DiscoverCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer
	ctx := context.Background()

	// 解析参数
	opts, err := c.parseArgs(args)
	if err != nil {
		return err
	}

	// 解析目标
	targets, err := network.ParseTargets(opts.target)
	if err != nil {
		return fmt.Errorf("解析目标失败: %w", err)
	}

	totalTargets := len(targets) * len(opts.ports)
	p.Printf("%s Scanning %s (ports: %s, %d targets, %d concurrent)\n",
		p.Colored(config.ColorBlue, "[*]"),
		opts.target,
		formatPorts(opts.ports),
		totalTargets,
		opts.concurrency)

	// 创建扫描器
	scanner := network.NewScanner(network.ScanOptions{
		Targets:     targets,
		Ports:       opts.ports,
		Concurrency: opts.concurrency,
		Timeout:     opts.timeout,
	})

	// 进度条
	progress := newProgressBar(p, totalTargets)
	scanner.WithProgress(func(completed, total int) {
		progress.Update(completed)
	})

	// 执行扫描
	startTime := time.Now()
	var openPorts []network.ScanResult
	for result := range scanner.Scan(ctx) {
		if result.Open {
			openPorts = append(openPorts, result)
		}
	}
	progress.Finish()

	elapsed := time.Since(startTime)

	// 验证 Kubelet
	p.Printf("%s Validating Kubelet endpoints...\n",
		p.Colored(config.ColorBlue, "[*]"))

	kubelets := c.validateKubelets(ctx, sess, openPorts, opts.timeout)

	// 缓存结果
	sess.CacheKubelets(kubelets)

	// 显示结果
	c.printResults(p, openPorts, kubelets, opts.showAll, elapsed)

	return nil
}

// parseArgs 解析命令参数
func (c *DiscoverCmd) parseArgs(args []string) (*discoverOptions, error) {
	opts := &discoverOptions{
		ports:       []int{config.DefaultKubeletPort},
		concurrency: 100,
		timeout:     3 * time.Second,
		showAll:     false,
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("用法: discover <target> [options]")
	}

	// 第一个参数是目标
	opts.target = args[0]

	// 解析其他参数
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-p", "--port":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-p 需要指定端口")
			}
			i++
			ports, err := network.ParsePorts(args[i])
			if err != nil {
				return nil, err
			}
			opts.ports = ports

		case "-c", "--concurrency":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-c 需要指定并发数")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("无效的并发数: %s", args[i])
			}
			opts.concurrency = n

		case "-t", "--timeout":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("-t 需要指定超时秒数")
			}
			i++
			n, err := strconv.Atoi(args[i])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("无效的超时秒数: %s", args[i])
			}
			opts.timeout = time.Duration(n) * time.Second

		case "--all":
			opts.showAll = true
		}
	}

	return opts, nil
}

// validateKubelets 验证开放端口是否为 Kubelet
func (c *DiscoverCmd) validateKubelets(ctx context.Context, sess *session.Session, openPorts []network.ScanResult, timeout time.Duration) []types.KubeletNode {
	var kubelets []types.KubeletNode
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 并发验证
	semaphore := make(chan struct{}, 20)

	for _, port := range openPorts {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(ip string, portNum int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// 使用现有的 Kubelet 验证逻辑
			result := network.ValidateKubeletPort(ip, portNum, sess.Config.Token, timeout)

			node := types.KubeletNode{
				IP:           ip,
				Port:         portNum,
				Reachable:    result.Reachable,
				IsKubelet:    result.IsKubelet,
				HealthPath:   result.HealthPath,
				DiscoveredAt: time.Now(),
			}

			mu.Lock()
			kubelets = append(kubelets, node)
			mu.Unlock()
		}(port.IP, port.Port)
	}

	wg.Wait()
	return kubelets
}

// printResults 打印扫描结果
func (c *DiscoverCmd) printResults(p output.Printer, openPorts []network.ScanResult, kubelets []types.KubeletNode, showAll bool, elapsed time.Duration) {
	p.Println()

	// 构建 Kubelet 映射
	kubeletMap := make(map[string]types.KubeletNode)
	for _, k := range kubelets {
		key := fmt.Sprintf("%s:%d", k.IP, k.Port)
		kubeletMap[key] = k
	}

	// 过滤要显示的结果
	var displayResults []types.KubeletNode
	if showAll {
		// 显示所有开放端口
		for _, port := range openPorts {
			key := fmt.Sprintf("%s:%d", port.IP, port.Port)
			if node, ok := kubeletMap[key]; ok {
				displayResults = append(displayResults, node)
			} else {
				displayResults = append(displayResults, types.KubeletNode{
					IP:        port.IP,
					Port:      port.Port,
					Reachable: true,
					IsKubelet: false,
				})
			}
		}
	} else {
		// 只显示 Kubelet
		for _, k := range kubelets {
			if k.IsKubelet {
				displayResults = append(displayResults, k)
			}
		}
	}

	if len(displayResults) == 0 {
		p.Warning("没有发现 Kubelet 节点")
		return
	}

	// 打印表格
	tablePrinter := output.NewTablePrinter()
	var header []string
	var rows [][]string

	if showAll {
		header = []string{"IP", "PORT", "STATUS", "KUBELET", "HEALTH"}
		for _, r := range displayResults {
			status := p.Colored(config.ColorGreen, "Open")
			kubelet := p.Colored(config.ColorGray, "No")
			health := "-"
			if r.IsKubelet {
				kubelet = p.Colored(config.ColorGreen, "Yes")
				health = r.HealthPath
			}
			rows = append(rows, []string{
				r.IP,
				fmt.Sprintf("%d", r.Port),
				status,
				kubelet,
				health,
			})
		}
	} else {
		header = []string{"IP", "PORT", "HEALTH"}
		for _, r := range displayResults {
			rows = append(rows, []string{
				r.IP,
				fmt.Sprintf("%d", r.Port),
				r.HealthPath,
			})
		}
	}

	tablePrinter.PrintSimple(header, rows)

	// 统计
	kubeletCount := 0
	for _, k := range kubelets {
		if k.IsKubelet {
			kubeletCount++
		}
	}

	p.Println()
	p.Printf("%s Scan complete in %s: %d open ports, %d Kubelet nodes\n",
		p.Colored(config.ColorGreen, "[+]"),
		elapsed.Round(time.Millisecond),
		len(openPorts),
		kubeletCount)

	if kubeletCount > 0 {
		p.Printf("%s Use 'set target <ip>' to select target, then run commands\n",
			p.Colored(config.ColorBlue, "[*]"))
		p.Printf("%s Use 'show kubelets' to view cached results\n",
			p.Colored(config.ColorBlue, "[*]"))
	}
}

// formatPorts 格式化端口列表
func formatPorts(ports []int) string {
	if len(ports) == 1 {
		return fmt.Sprintf("%d", ports[0])
	}
	if len(ports) <= 3 {
		var strs []string
		for _, p := range ports {
			strs = append(strs, fmt.Sprintf("%d", p))
		}
		return strings.Join(strs, ",")
	}
	return fmt.Sprintf("%d-%d (%d ports)", ports[0], ports[len(ports)-1], len(ports))
}

// progressBar 简单的进度条
type progressBar struct {
	printer output.Printer
	total   int
	width   int
}

func newProgressBar(p output.Printer, total int) *progressBar {
	return &progressBar{
		printer: p,
		total:   total,
		width:   40,
	}
}

func (pb *progressBar) Update(completed int) {
	if pb.total == 0 {
		return
	}

	percent := float64(completed) / float64(pb.total)
	filled := int(percent * float64(pb.width))

	bar := strings.Repeat("=", filled) + strings.Repeat(" ", pb.width-filled)
	fmt.Printf("\r[%s] %3.0f%% (%d/%d)", bar, percent*100, completed, pb.total)
}

func (pb *progressBar) Finish() {
	fmt.Printf("\r[%s] 100%% (%d/%d)\n", strings.Repeat("=", pb.width), pb.total, pb.total)
}
