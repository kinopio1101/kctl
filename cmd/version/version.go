package version

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"kctl/cmd"
	"kctl/utils/Print"
)

// 这些变量在构建时通过 ldflags 注入
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

// init in modules will add self to RootCmd when init package.
func init() {
	cmd.RootCmd.AddCommand(SubCmd)
}

// SubCmd is core cobra.Command of subcommand
var SubCmd = &cobra.Command{
	Use:   "version",
	Short: "输出版本信息 (Print the version info)",
	Long:  "输出版本信息，包括版本号、Git Commit、构建时间等 (Print version info including version, git commit, build time, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		printVersion()
	},
}

// printVersion 打印版本信息
func printVersion() {
	Print.PrintSection("kctl 版本信息")

	Print.PrintKeyValue("Version", version)
	Print.PrintKeyValue("Git Commit", commit)
	Print.PrintKeyValue("Build Date", date)
	Print.PrintKeyValue("Built By", builtBy)
	Print.PrintKeyValue("Go Version", runtime.Version())
	Print.PrintKeyValue("OS/Arch", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
}

// GetVersion 返回版本号
func GetVersion() string {
	return version
}

// GetCommit 返回 Git Commit
func GetCommit() string {
	return commit
}

// GetBuildInfo 返回完整的构建信息
func GetBuildInfo() map[string]string {
	return map[string]string{
		"version":   version,
		"commit":    commit,
		"date":      date,
		"builtBy":   builtBy,
		"goVersion": runtime.Version(),
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
	}
}
