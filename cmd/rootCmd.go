package cmd

import (
	cc "github.com/ivanpirog/coloredcobra"
	"github.com/spf13/cobra"
	"kctl/utils/log"
	"os"
)

var RootCmd = &cobra.Command{
	Use:   "root",
	Short: "",
	Long: `
`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		log.Init(logLevel)
	},
	Run: func(cmd *cobra.Command, args []string) {

	},
}

var logLevel string

func init() {
	RootCmd.PersistentFlags().StringVar(&logLevel, "logLevel", "info", "设置日志等级 (Set log level) [trace|debug|info|warn|error|fatal|panic]")
	RootCmd.CompletionOptions.DisableDefaultCmd = true
}

func Execute() {
	cc.Init(&cc.Config{
		RootCmd:  RootCmd,
		Headings: cc.HiGreen + cc.Underline,
		Commands: cc.Cyan + cc.Bold,
		Example:  cc.Italic,
		ExecName: cc.Bold,
		Flags:    cc.Cyan + cc.Bold,
	})
	err := RootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
