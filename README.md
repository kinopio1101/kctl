# kctl

Kubernetes Kubelet 工具集 - 专用于 Kubelet 节点的安全审计与权限评估

## 功能概览

kctl 是一个轻量级的命令行工具，专门针对 Kubernetes Kubelet 节点进行安全评估和权限分析。

### 核心功能

- **Pod 信息收集与管理** - 收集节点上所有 Pod 信息并保存到本地数据库
- **容器命令执行** - 通过 Kubelet API 在 Pod 容器中执行命令
- **ServiceAccount 权限扫描** - 扫描并评估 Pod 中 SA Token 的 RBAC 权限风险
- **环境信息查询** - 查询 Kubelet 环境、Token 和权限信息
- **SOCKS5 代理支持** - 通过代理访问受限网络环境的 Kubelet

## 快速开始

### 安装

```bash
git clone https://github.com/kinopio1101/kctl.git
cd kctl
make build
```

### 基本使用

```bash
# 查看环境信息
./kctl kubelet env

# 收集节点上的 Pod 信息
./kctl kubelet pods

# 扫描 ServiceAccount 权限
./kctl kubelet scan

# 在 Pod 中执行命令
./kctl kubelet exec -- cat /etc/passwd
```

## 命令说明

### kubelet env

查询 Kubelet 环境信息，包括：
- Kubelet IP 地址和端口验证
- Token 路径和内容
- ServiceAccount 信息
- RBAC 权限查询

```bash
kctl kubelet env
```

### kubelet pods

收集并管理 Kubelet Pod 信息：

```bash
# 收集 Pod 信息并保存到数据库
kctl kubelet pods

# 列出所有 Pod
kctl kubelet pods --list all

# 列出特权 Pod
kctl kubelet pods --list privileged

# 列出挂载 Secret 的 Pod
kctl kubelet pods --list secrets

# 列出挂载 HostPath 的 Pod
kctl kubelet pods --list hostpath

# 显示挂载汇总
kctl kubelet pods --list mounts
```

### kubelet exec

在 Pod 容器中执行命令：

```bash
# 列出所有可用的 Pod
kctl kubelet exec --list

# 交互式选择 Pod 执行命令
kctl kubelet exec -- whoami

# 指定 Pod 执行命令
kctl kubelet exec -n default -p nginx -c nginx -- cat /etc/passwd

# 获取交互式 shell
kctl kubelet exec -n default -p nginx -c nginx -it -- /bin/sh

# 批量在所有 Pod 中执行命令
kctl kubelet exec --all-pods -- id

# 过滤特定 Pod（排除 kube-system 命名空间）
kctl kubelet exec --all-pods --filter "kube-system" -- cat /etc/passwd
```

### kubelet scan

扫描所有 Pod 的 ServiceAccount 权限：

```bash
# 扫描所有 Pod 的 SA 权限（默认保存到数据库）
kctl kubelet scan

# 只显示有风险权限的 SA
kctl kubelet scan --risky

# 设置并发数为 5
kctl kubelet scan --concurrent 5

# 不保存到数据库
kctl kubelet scan --save=false
```

**风险等级：**
- ⚠ ADMIN - 集群管理员权限，可完全控制集群
- ★ CRITICAL - 高危权限，接近管理员级别
- ★ HIGH - 可权限提升或泄露敏感信息
- ★ MEDIUM - 可能被滥用的权限
- ○ LOW/NONE - 低危或无风险

### kubelet sa

查看已收集的 ServiceAccount 信息：

```bash
# 查看所有 SA
kctl kubelet sa

# 只查看有风险的 SA
kctl kubelet sa --risky

# 只查看集群管理员
kctl kubelet sa --admin

# 按命名空间过滤
kctl kubelet sa --namespace kube-system

# 查看特定 SA 的详细信息
kctl kubelet sa --namespace default --name my-sa --perms --pods

# 显示统计信息
kctl kubelet sa --stats
```

### kubelet proxy

配置和测试 SOCKS5 代理连接：

```bash
# 测试代理连接
kctl kubelet proxy --proxy socks5://127.0.0.1:1080 test

# 通过代理扫描节点
kctl kubelet --proxy socks5://127.0.0.1:1080 scan

# 通过代理执行命令
kctl kubelet --proxy socks5://127.0.0.1:1080 exec
```

## 全局参数

所有 `kubelet` 子命令都支持以下参数：

- `--ip` - Kubelet IP 地址（默认自动从路由表获取）
- `--port` - Kubelet 端口（默认 10250）
- `--token-file` - 自定义 Token 文件路径
- `--token` - 输出 Token 内容
- `--token-path` - 输出 Token 文件路径
- `--proxy` - SOCKS5 代理地址（例如：socks5://127.0.0.1:1080）
- `--proxy-timeout` - 代理连接超时时间（秒）
- `--logLevel` - 设置日志等级 (trace|debug|info|warn|error|fatal|panic)

## 数据库

所有扫描结果默认保存到 SQLite 数据库 `kubelet_pods.db`，可通过 `--db` 参数指定自定义路径。

## 注意事项

本工具仅用于合法的安全评估和权限管理，请遵守相关法律法规。

## 许可证

MIT License