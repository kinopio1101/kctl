package Print

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// ═══════════════════════════════════════════════════════════════════════════════
// 颜色定义 - 统一的颜色主题
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// 主题颜色
	ColorTitle     = color.New(color.FgCyan, color.Bold)
	ColorSubtitle  = color.New(color.FgYellow, color.Bold)
	ColorLabel     = color.New(color.FgWhite, color.Bold)
	ColorValue     = color.New(color.FgWhite)
	ColorHighlight = color.New(color.FgHiCyan)
	ColorMuted     = color.New(color.FgHiBlack)

	// 状态颜色
	ColorSuccess = color.New(color.FgGreen)
	ColorWarning = color.New(color.FgYellow)
	ColorError   = color.New(color.FgRed)
	ColorDanger  = color.New(color.FgRed, color.Bold)
	ColorAdmin   = color.New(color.FgHiRed, color.Bold)

	// 快捷方法
	Cyan    = color.New(color.FgCyan).SprintFunc()
	Yellow  = color.New(color.FgYellow).SprintFunc()
	Green   = color.New(color.FgGreen).SprintFunc()
	Red     = color.New(color.FgRed).SprintFunc()
	Magenta = color.New(color.FgMagenta).SprintFunc()
	White   = color.New(color.FgWhite).SprintFunc()
	Muted   = color.New(color.FgHiBlack).SprintFunc()
)

// ═══════════════════════════════════════════════════════════════════════════════
// 边框和分隔符
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// 宽度设置
	DefaultWidth = 80
	WideWidth    = 110

	// 边框字符
	BorderDouble = "═"
	BorderSingle = "─"
	BorderBold   = "━"
)

// Line 生成指定宽度的分隔线
func Line(char string, width int) string {
	return strings.Repeat(char, width)
}

// DoubleLine 生成双线分隔符
func DoubleLine(width int) string {
	return Line(BorderDouble, width)
}

// SingleLine 生成单线分隔符
func SingleLine(width int) string {
	return Line(BorderSingle, width)
}

// BoldLine 生成粗线分隔符
func BoldLine(width int) string {
	return Line(BorderBold, width)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 标题和区块
// ═══════════════════════════════════════════════════════════════════════════════

// PrintTitle 打印主标题 (带双线边框)
func PrintTitle(title string) {
	width := DefaultWidth
	fmt.Println()
	fmt.Println(ColorTitle.Sprint(BoldLine(width)))
	// 居中标题
	padding := (width - len(title)) / 2
	if padding > 0 {
		fmt.Printf("%s%s\n", strings.Repeat(" ", padding), ColorTitle.Sprint(title))
	} else {
		_, _ = ColorTitle.Println(title)
	}
	fmt.Println(ColorTitle.Sprint(BoldLine(width)))
}

// PrintTitleWide 打印宽标题
func PrintTitleWide(title string) {
	width := WideWidth
	fmt.Println()
	fmt.Println(ColorTitle.Sprint(BoldLine(width)))
	padding := (width - len(title)) / 2
	if padding > 0 {
		fmt.Printf("%s%s\n", strings.Repeat(" ", padding), ColorSubtitle.Sprint(title))
	} else {
		_, _ = ColorSubtitle.Println(title)
	}
	fmt.Println(ColorTitle.Sprint(BoldLine(width)))
	fmt.Println()
}

// PrintSection 打印章节标题
func PrintSection(title string) {
	fmt.Println()
	_, _ = ColorSubtitle.Printf("━━━ %s ━━━\n", title)
	fmt.Println()
}

// PrintSubSection 打印子章节标题
func PrintSubSection(title string) {
	fmt.Println()
	_, _ = ColorMuted.Printf("  ─── %s ───\n", title)
	fmt.Println()
}

// PrintSeparator 打印分隔线
func PrintSeparator() {
	fmt.Println(SingleLine(DefaultWidth))
}

// PrintSeparatorWide 打印宽分隔线
func PrintSeparatorWide() {
	fmt.Println(SingleLine(WideWidth))
}

// ═══════════════════════════════════════════════════════════════════════════════
// 键值对输出
// ═══════════════════════════════════════════════════════════════════════════════

// PrintKeyValue 打印键值对
func PrintKeyValue(key, value string) {
	_, _ = ColorLabel.Printf("  %-16s: ", key)
	fmt.Println(value)
}

// PrintKeyValueColored 打印带颜色的键值对
func PrintKeyValueColored(key, value string, valueColor *color.Color) {
	_, _ = ColorLabel.Printf("  %-16s: ", key)
	_, _ = valueColor.Println(value)
}

// PrintKeyValueNote 打印键值对带注释
func PrintKeyValueNote(key, value, note string) {
	_, _ = ColorLabel.Printf("  %-16s: ", key)
	fmt.Printf("%s %s\n", value, Muted(note))
}

// PrintKeyValueStatus 打印键值对带状态
func PrintKeyValueStatus(key, value string, ok bool) {
	_, _ = ColorLabel.Printf("  %-16s: ", key)
	if ok {
		fmt.Printf("%s %s\n", value, Green("✓"))
	} else {
		fmt.Printf("%s %s\n", value, Red("✗"))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 列表项输出
// ═══════════════════════════════════════════════════════════════════════════════

// ListItem 列表项数据结构
type ListItem struct {
	Index      int
	Status     string // Running, Pending, etc.
	Title      string // 主标题
	Subtitle   string // 副标题 (如 namespace/pod)
	Details    map[string]string
	Highlight  bool
	StatusMark string // ●, ○, etc.
}

// PrintListItem 打印列表项
func PrintListItem(item ListItem) {
	statusColor := ColorWarning
	statusMark := "○"

	if item.StatusMark != "" {
		statusMark = item.StatusMark
	}

	if item.Status == "Running" {
		statusColor = ColorSuccess
		statusMark = "●"
	}

	// 打印主行
	fmt.Printf("%s [%d] %s  %s\n",
		statusColor.Sprint(statusMark),
		item.Index,
		statusColor.Sprint(item.Status),
		ColorHighlight.Sprint(item.Subtitle)+"/"+item.Title)

	// 打印详情
	for key, value := range item.Details {
		fmt.Printf("     %s: %s\n", key, value)
	}

	fmt.Println()
}

// PrintListItems 批量打印列表项
func PrintListItems(items []ListItem) {
	for _, item := range items {
		PrintListItem(item)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 信息框 (Box)
// ═══════════════════════════════════════════════════════════════════════════════

// BoxStyle 框样式
type BoxStyle int

const (
	BoxStyleNormal BoxStyle = iota
	BoxStyleWarning
	BoxStyleDanger
	BoxStyleAdmin
)

// PrintBox 打印信息框
func PrintBox(title string, lines []string, style BoxStyle) {
	var boxColor *color.Color
	var topChar, midChar, botChar string

	switch style {
	case BoxStyleAdmin:
		boxColor = ColorAdmin
		topChar = "╔══════════════════════════════════════════════════════╗"
		midChar = "║"
		botChar = "╚══════════════════════════════════════════════════════╝"
	case BoxStyleDanger:
		boxColor = ColorDanger
		topChar = "┌──────────────────────────────────────────────────────┐"
		midChar = "│"
		botChar = "└──────────────────────────────────────────────────────┘"
	case BoxStyleWarning:
		boxColor = ColorWarning
		topChar = "┌─────────────────────────────────────────────────────"
		midChar = "│"
		botChar = "└──────────────────────────────────────────────────────"
	default:
		boxColor = ColorTitle
		topChar = "┌──────────────────────────────────────────────────────┐"
		midChar = "│"
		botChar = "└──────────────────────────────────────────────────────┘"
	}

	_, _ = boxColor.Println("  " + topChar)
	_, _ = boxColor.Printf("  %s            %s\n", midChar, title)
	_, _ = boxColor.Printf("  %s──────────────────────────────────────────────────────%s\n", midChar[:3], midChar[len(midChar)-3:])

	for _, line := range lines {
		_, _ = boxColor.Printf("  %s  %-50s %s\n", midChar, line, midChar)
	}

	_, _ = boxColor.Println("  " + botChar)
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════════════════
// 执行信息显示
// ═══════════════════════════════════════════════════════════════════════════════

// ExecInfo 执行命令信息
type ExecInfo struct {
	Target   string // namespace/pod/container
	Command  string
	Endpoint string // ip:port
}

// PrintExecInfo 打印执行信息
func PrintExecInfo(info ExecInfo) {
	fmt.Println()
	fmt.Println(ColorTitle.Sprint(BoldLine(66)))
	fmt.Printf("  %s %s\n", Cyan("目标:"), info.Target)
	fmt.Printf("  %s %s\n", Cyan("命令:"), Yellow(info.Command))
	fmt.Printf("  %s %s\n", Cyan("Kubelet:"), info.Endpoint)
	fmt.Println(ColorTitle.Sprint(BoldLine(66)))
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════════════════
// 摘要统计
// ═══════════════════════════════════════════════════════════════════════════════

// StatItem 统计项
type StatItem struct {
	Label string
	Value int
	Color *color.Color
}

// PrintStats 打印统计摘要
func PrintStats(items []StatItem) {
	var parts []string
	for _, item := range items {
		if item.Color != nil {
			parts = append(parts, item.Color.Sprintf("%s: %d", item.Label, item.Value))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %d", item.Label, item.Value))
		}
	}
	fmt.Printf("  %s\n", strings.Join(parts, "  "))
}

// PrintTotal 打印总计
func PrintTotal(label string, count int) {
	PrintSeparator()
	fmt.Printf("%s: %d\n", label, count)
}

// PrintTotalWide 打印总计（宽）
func PrintTotalWide(label string, count int) {
	PrintSeparatorWide()
	fmt.Printf("%s: %d\n", label, count)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 提示和帮助
// ═══════════════════════════════════════════════════════════════════════════════

// PrintTip 打印提示信息
func PrintTip(tip string) {
	fmt.Println()
	_, _ = ColorHighlight.Printf("💡 %s\n", tip)
}

// PrintUsageExample 打印使用示例
func PrintUsageExample(title string, examples []string) {
	fmt.Println()
	_, _ = ColorHighlight.Printf("%s:\n", title)
	for _, ex := range examples {
		fmt.Printf("  %s\n", ex)
	}
}

// PrintWarning 打印警告
func PrintWarning(msg string) {
	_, _ = ColorWarning.Printf("⚠️  %s\n", msg)
}

// PrintError 打印错误
func PrintError(msg string) {
	_, _ = ColorError.Printf("✗ %s\n", msg)
}

// PrintSuccess 打印成功
func PrintSuccess(msg string) {
	_, _ = ColorSuccess.Printf("✓ %s\n", msg)
}

// PrintInfo 打印信息
func PrintInfo(msg string) {
	_, _ = ColorHighlight.Printf("ℹ️  %s\n", msg)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 交互式提示
// ═══════════════════════════════════════════════════════════════════════════════

// PrintPrompt 打印输入提示
func PrintPrompt(prompt string) {
	fmt.Print(Cyan(prompt))
}

// PrintInteractiveHint 打印交互式操作提示
func PrintInteractiveHint(hint string) {
	fmt.Println()
	_, _ = ColorSubtitle.Printf("%s\n", hint)
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════════════════════
// 安全标识
// ═══════════════════════════════════════════════════════════════════════════════

// SecurityFlags 安全标识结构
type SecurityFlags struct {
	Privileged               bool // 特权容器
	AllowPrivilegeEscalation bool // 允许权限提升
	HasHostPath              bool // 挂载了 HostPath
	HasSecretMount           bool // 挂载了 Secret
}

// FormatSecurityFlags 格式化安全标识为字符串
func FormatSecurityFlags(flags SecurityFlags) string {
	var tags []string

	if flags.Privileged {
		tags = append(tags, ColorDanger.Sprint("★PRIV"))
	}
	if flags.AllowPrivilegeEscalation {
		tags = append(tags, ColorWarning.Sprint("★PE"))
	}
	if flags.HasHostPath {
		tags = append(tags, ColorAdmin.Sprint("★HP"))
	}
	if flags.HasSecretMount {
		tags = append(tags, Magenta("★SEC"))
	}

	if len(tags) == 0 {
		return ""
	}
	return strings.Join(tags, " ")
}

// PrintSecurityLegend 打印安全标识图例说明
func PrintSecurityLegend() {
	fmt.Println()
	_, _ = ColorMuted.Println("安全标识说明:")
	fmt.Printf("  %s - 特权容器    %s - 允许权限提升\n",
		ColorDanger.Sprint("★PRIV"), ColorWarning.Sprint("★PE"))
	fmt.Printf("  %s - HostPath挂载   %s - Secret挂载\n",
		ColorAdmin.Sprint("★HP"), Magenta("★SEC"))
}
