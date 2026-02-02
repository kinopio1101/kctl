package commands

import (
	"fmt"

	"kctl/config"
	"kctl/internal/session"
)

type ModeCmd struct{}

func init() {
	Register(&ModeCmd{})
}

func (c *ModeCmd) Name() string {
	return "mode"
}

func (c *ModeCmd) Aliases() []string {
	return nil
}

func (c *ModeCmd) Description() string {
	return "查看或切换运行模式"
}

func (c *ModeCmd) Usage() string {
	return `mode [kubelet|kubernetes]

查看或切换运行模式

模式说明：
  kubelet     通过 Kubelet API (10250) 操作单个节点
  kubernetes  通过 API Server (6443) 操作整个集群

示例：
  mode                 显示当前模式
  mode kubelet         切换到 Kubelet 模式
  mode kubernetes      切换到 Kubernetes 模式
  mode k8s             切换到 Kubernetes 模式（简写）`
}

func (c *ModeCmd) Execute(sess *session.Session, args []string) error {
	p := sess.Printer

	if len(args) == 0 {
		c.showCurrentMode(sess)
		return nil
	}

	newMode := session.ParseMode(args[0])
	if newMode == "" {
		return fmt.Errorf("无效的模式: %s，可选: kubelet, kubernetes", args[0])
	}

	oldMode := sess.GetMode()
	if oldMode == newMode {
		p.Printf("%s Already in %s mode\n",
			p.Colored(config.ColorBlue, "[*]"),
			newMode)
		return nil
	}

	if err := sess.SetMode(newMode); err != nil {
		return err
	}

	p.Printf("%s Switched to %s mode\n",
		p.Colored(config.ColorGreen, "[+]"),
		p.Colored(config.ColorCyan, string(newMode)))

	c.showModeInfo(sess, newMode)

	return nil
}

func (c *ModeCmd) showCurrentMode(sess *session.Session) {
	p := sess.Printer
	mode := sess.GetMode()
	target := sess.GetModeTarget()

	p.Printf("%s Current mode: %s\n",
		p.Colored(config.ColorBlue, "[*]"),
		p.Colored(config.ColorCyan, string(mode)))

	if target != "" {
		p.Printf("%s Target: %s\n",
			p.Colored(config.ColorBlue, "[*]"),
			target)
	}

	p.Println()
	p.Printf("Available modes:\n")
	p.Printf("  kubelet     - Kubelet API (10250), single node operations\n")
	p.Printf("  kubernetes  - API Server (6443), cluster-wide operations\n")
}

func (c *ModeCmd) showModeInfo(sess *session.Session, mode session.Mode) {
	p := sess.Printer

	switch mode {
	case session.ModeKubelet:
		if sess.Config.KubeletIP == "" {
			p.Warning("Kubelet IP not set. Use 'set target <ip>' to configure")
		} else {
			p.Printf("%s Target: %s:%d\n",
				p.Colored(config.ColorBlue, "[*]"),
				sess.Config.KubeletIP,
				sess.Config.KubeletPort)
		}
	case session.ModeKubernetes:
		if sess.Config.APIServer == "" {
			p.Warning("API Server not set. Use 'set api-server <addr>' to configure")
		} else {
			p.Printf("%s API Server: %s\n",
				p.Colored(config.ColorBlue, "[*]"),
				sess.Config.APIServer)
		}
	}
}
