package main

import (
	"kctl/cmd"
	_ "kctl/cmd/kubelet" // kubelet 工具集
	_ "kctl/cmd/version" // import sub command as module
)

func init() {
}

func main() {
	cmd.Execute()
}
