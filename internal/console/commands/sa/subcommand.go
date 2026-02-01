package sa

import (
	"kctl/internal/session"
)

// SubCommand SA 子命令接口
type SubCommand interface {
	Name() string
	Aliases() []string
	Description() string
	Usage() string
	Execute(sess *session.Session, args []string) error
}

// 子命令注册表
var subCommands = make(map[string]SubCommand)

// Register 注册子命令
func Register(cmd SubCommand) {
	subCommands[cmd.Name()] = cmd
	for _, alias := range cmd.Aliases() {
		subCommands[alias] = cmd
	}
}

// Get 获取子命令
func Get(name string) (SubCommand, bool) {
	cmd, ok := subCommands[name]
	return cmd, ok
}

// GetAll 获取所有子命令（去重）
func GetAll() []SubCommand {
	seen := make(map[string]bool)
	var cmds []SubCommand
	for _, cmd := range subCommands {
		if !seen[cmd.Name()] {
			seen[cmd.Name()] = true
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

// Execute 执行 SA 子命令
func Execute(sess *session.Session, args []string) error {
	// 无参数或第一个参数不是子命令时，默认执行 list
	if len(args) == 0 {
		cmd, _ := Get("list")
		return cmd.Execute(sess, nil)
	}

	// 检查是否是子命令
	if cmd, ok := Get(args[0]); ok {
		return cmd.Execute(sess, args[1:])
	}

	// 不是子命令，可能是 list 的参数（如 --risky）
	cmd, _ := Get("list")
	return cmd.Execute(sess, args)
}

// Usage 返回 SA 命令的用法
func Usage() string {
	return `sa [subcommand] [options]

ServiceAccount 相关操作

子命令：
  list        列出已扫描的 SA (默认)
  scan        扫描所有 Pod 的 SA Token 权限
  use         选择 SA 作为当前身份
  info        显示当前 SA 详情

示例：
  sa                    列出所有 SA (等同于 sa list)
  sa list --risky       只显示有风险的 SA
  sa scan               扫描所有 SA
  sa use kube-system/default
  sa info`
}
