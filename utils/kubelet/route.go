package kubelet

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

// 路由表文件路径
const ProcNetRoute = "/proc/net/route"

// RouteEntry 表示路由表中的一条记录
type RouteEntry struct {
	Interface   string
	Destination string
	Gateway     string
	Flags       string
	Mask        string
}

// GetDefaultGateway 从 /proc/net/route 获取默认网关 IP
func GetDefaultGateway() (string, error) {
	file, err := os.Open(ProcNetRoute)
	if err != nil {
		return "", fmt.Errorf("无法打开路由表文件 %s: %w", ProcNetRoute, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)

	// 跳过标题行
	_ = scanner.Scan() // 第一行是标题：Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 8 {
			continue
		}

		// 字段：Iface, Destination, Gateway, Flags, RefCnt, Use, Metric, Mask
		destination := fields[1]
		gateway := fields[2]

		// 默认路由的 Destination 是 00000000
		if destination == "00000000" {
			ip, err := hexToIP(gateway)
			if err != nil {
				continue
			}
			return ip, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("读取路由表文件失败: %w", err)
	}

	return "", fmt.Errorf("未找到默认网关")
}

// hexToIP 将十六进制字符串转换为 IP 地址
// Linux 路由表中的 IP 是小端序的十六进制
func hexToIP(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("无效的十六进制 IP 长度: %s", hexStr)
	}

	// 解码十六进制
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("十六进制解码失败: %w", err)
	}

	// Linux 使用小端序，需要反转字节顺序
	// 例如：0101A8C0 -> 192.168.1.1
	ip := net.IPv4(bytes[3], bytes[2], bytes[1], bytes[0])
	return ip.String(), nil
}

// GetAllRoutes 获取所有路由表条目
func GetAllRoutes() ([]RouteEntry, error) {
	file, err := os.Open(ProcNetRoute)
	if err != nil {
		return nil, fmt.Errorf("无法打开路由表文件 %s: %w", ProcNetRoute, err)
	}
	defer func() { _ = file.Close() }()

	var routes []RouteEntry
	scanner := bufio.NewScanner(file)

	// 跳过标题行
	_ = scanner.Scan() // 标题行

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 8 {
			continue
		}

		destIP, _ := hexToIP(fields[1])
		gwIP, _ := hexToIP(fields[2])
		maskIP, _ := hexToIP(fields[7])

		routes = append(routes, RouteEntry{
			Interface:   fields[0],
			Destination: destIP,
			Gateway:     gwIP,
			Flags:       fields[3],
			Mask:        maskIP,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取路由表文件失败: %w", err)
	}

	return routes, nil
}
