package kubelet

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/moby/spdystream"
	"kctl/pkg/types"
)

// SPDY 端口转发协议常量
const (
	PortForwardProtocolV1Name  = "portforward.k8s.io"
	StreamTypeData             = "data"
	StreamTypeError            = "error"
	PortHeader                 = "port"
	PortForwardRequestIDHeader = "requestID"
	StreamType                 = "streamType"
)

// portForwarder 端口转发器
type portForwarder struct {
	client    *kubeletClient
	opts      *types.PortForwardOptions
	spdyConn  *spdystream.Connection
	listeners []net.Listener
	stopChan  <-chan struct{}
	errChan   chan error
}

// PortForward 实现端口转发
func (c *kubeletClient) PortForward(ctx context.Context, opts *types.PortForwardOptions, stopChan <-chan struct{}) error {
	pf := &portForwarder{
		client:   c,
		opts:     opts,
		stopChan: stopChan,
		errChan:  make(chan error, 1),
	}

	// 1. 建立 SPDY 连接
	if err := pf.dial(); err != nil {
		return fmt.Errorf("建立 SPDY 连接失败: %w", err)
	}
	defer pf.close()

	// 2. 为每个端口启动本地监听
	if err := pf.startListeners(); err != nil {
		return fmt.Errorf("启动本地监听失败: %w", err)
	}

	// 3. 等待停止信号或错误
	select {
	case <-stopChan:
		return nil
	case err := <-pf.errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// dial 建立 SPDY 连接
func (pf *portForwarder) dial() error {
	// 构建 URL
	path := fmt.Sprintf("/portForward/%s/%s", pf.opts.Namespace, pf.opts.Pod)

	// 建立 TLS 连接
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	addr := fmt.Sprintf("%s:%d", pf.client.ip, pf.client.port)

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS 连接失败: %w", err)
	}

	// 发送 HTTP Upgrade 请求
	req, err := http.NewRequest("POST", path, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "SPDY/3.1")
	req.Header.Set("X-Stream-Protocol-Version", PortForwardProtocolV1Name)
	req.Header.Set("Authorization", pf.client.authHeader())
	req.Host = addr

	if err := req.Write(conn); err != nil {
		conn.Close()
		return fmt.Errorf("发送请求失败: %w", err)
	}

	// 读取响应
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return fmt.Errorf("升级协议失败: HTTP %d", resp.StatusCode)
	}

	// 验证协议
	protocol := resp.Header.Get("X-Stream-Protocol-Version")
	if protocol != PortForwardProtocolV1Name {
		conn.Close()
		return fmt.Errorf("不支持的协议: %s", protocol)
	}

	// 创建 SPDY 连接
	spdyConn, err := spdystream.NewConnection(conn, false)
	if err != nil {
		conn.Close()
		return fmt.Errorf("创建 SPDY 连接失败: %w", err)
	}

	go spdyConn.Serve(spdystream.NoOpStreamHandler)
	pf.spdyConn = spdyConn

	return nil
}

// startListeners 为每个端口启动本地监听
func (pf *portForwarder) startListeners() error {
	for _, port := range pf.opts.Ports {
		addr := fmt.Sprintf("%s:%d", pf.opts.Address, port.Local)
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			// 关闭已创建的监听器
			pf.closeListeners()
			return fmt.Errorf("监听 %s 失败: %w", addr, err)
		}
		pf.listeners = append(pf.listeners, listener)

		// 启动 goroutine 处理连接
		go pf.handleListener(listener, port.Remote)
	}
	return nil
}

// handleListener 处理监听器上的连接
func (pf *portForwarder) handleListener(listener net.Listener, remotePort uint16) {
	requestID := 0
	for {
		conn, err := listener.Accept()
		if err != nil {
			// 检查是否是因为监听器关闭
			select {
			case <-pf.stopChan:
				return
			default:
				// 检查是否是 "use of closed network connection" 错误
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				continue
			}
		}

		go pf.handleConnection(conn, remotePort, requestID)
		requestID++
	}
}

// handleConnection 处理单个连接
func (pf *portForwarder) handleConnection(localConn net.Conn, remotePort uint16, requestID int) {
	defer localConn.Close()

	requestIDStr := strconv.Itoa(requestID)
	portStr := strconv.Itoa(int(remotePort))

	// 创建 error stream
	errorHeaders := http.Header{}
	errorHeaders.Set(StreamType, StreamTypeError)
	errorHeaders.Set(PortHeader, portStr)
	errorHeaders.Set(PortForwardRequestIDHeader, requestIDStr)

	errorStream, err := pf.spdyConn.CreateStream(errorHeaders, nil, false)
	if err != nil {
		return
	}
	// 关闭 error stream 的写入端（我们只读取错误）
	go func() {
		_, _ = io.Copy(io.Discard, errorStream)
	}()
	defer errorStream.Close()

	// 创建 data stream
	dataHeaders := http.Header{}
	dataHeaders.Set(StreamType, StreamTypeData)
	dataHeaders.Set(PortHeader, portStr)
	dataHeaders.Set(PortForwardRequestIDHeader, requestIDStr)

	dataStream, err := pf.spdyConn.CreateStream(dataHeaders, nil, false)
	if err != nil {
		return
	}
	defer dataStream.Close()

	// 双向数据转发
	var wg sync.WaitGroup
	wg.Add(2)

	// Local -> Remote
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dataStream, localConn)
		// 关闭写入方向，通知远端数据发送完毕
		_ = dataStream.Close()
	}()

	// Remote -> Local
	go func() {
		defer wg.Done()
		_, _ = io.Copy(localConn, dataStream)
	}()

	wg.Wait()
}

// closeListeners 关闭所有监听器
func (pf *portForwarder) closeListeners() {
	for _, listener := range pf.listeners {
		_ = listener.Close()
	}
	pf.listeners = nil
}

// close 关闭所有资源
func (pf *portForwarder) close() {
	pf.closeListeners()
	if pf.spdyConn != nil {
		_ = pf.spdyConn.Close()
	}
}
